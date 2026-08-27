// Package identity owns helper-specific identity binding: resolving which
// JWT claim carries the Basic-auth-visible username, matching it against the
// requested username, and denying reserved local usernames. Generic JWT
// verification and generic verified-email/domain policy live upstream in
// github.com/altinity/go-mcp-oauth-sdk/oauth — this package composes that
// generic policy with helper-specific binding, it does not reimplement it.
package identity

import (
	"errors"
	"fmt"
	"strings"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
)

// Sentinel errors returned by Bind. They carry only safe metadata (claim
// names, the requested username) — never the JWT or any claim value that
// could itself be sensitive.
var (
	// ErrClaimMissing means the configured username claim was absent, empty,
	// or not a string on an otherwise cryptographically valid token.
	ErrClaimMissing = errors.New("identity: configured username claim is missing or empty")
	// ErrUsernameMismatch means the requested (Basic-auth) username does not
	// match the resolved claim value under the configured match mode.
	ErrUsernameMismatch = errors.New("identity: requested username does not match verified claim")
	// ErrReservedUsername means the requested username is present in the
	// operator's configured deny-list and cannot be claimed externally
	// regardless of how well-formed the token otherwise is.
	ErrReservedUsername = errors.New("identity: requested username is reserved and cannot be claimed externally")
)

// Config configures a Policy. UsernameClaim and MatchMode default when
// empty (see NewPolicy); DeniedUsernames defaults to empty so upgrading an
// existing deployment does not start denying previously accepted usernames.
type Config struct {
	UsernameClaim   string
	MatchMode       string
	DeniedUsernames []string
	ClaimPolicy     oauth.IdentityPolicy
}

// Principal is the identity a request authenticated as, after cryptographic
// validation, username-claim binding, and identity-claim policy all passed.
type Principal struct {
	Username string
	Issuer   string
	Subject  string
	Email    string
}

// StableSubject reports the verified (iss, sub) pair when both are present.
// ok is true only when both are non-empty. Phase 1 never requires a stable
// pair to authenticate an existing ch-jwt-verify request — callers must
// treat ok == false as an expected, non-error outcome for deployments that
// authenticate on username_claim: email without a sub claim, or on a
// pinned-JWKS/no-issuer configuration. Never synthesize a stable identity
// from email or the visible username when this reports false.
func (p Principal) StableSubject() (issuer, subject string, ok bool) {
	if p.Issuer != "" && p.Subject != "" {
		return p.Issuer, p.Subject, true
	}
	return "", "", false
}

// Policy is the immutable, validated form of Config produced by NewPolicy.
type Policy struct {
	usernameClaim   string
	matchMode       string
	deniedUsernames map[string]struct{}
	claimPolicy     oauth.IdentityPolicy
}

// NewPolicy validates and normalizes cfg. Unknown match modes fail
// construction rather than silently falling back to a permissive default —
// callers (config activation at startup) must treat an error here as fatal.
func NewPolicy(cfg Config) (*Policy, error) {
	usernameClaim := cfg.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = "email"
	}

	matchMode := cfg.MatchMode
	if matchMode == "" {
		matchMode = "lowercase_equal"
	}
	switch matchMode {
	case "exact", "lowercase_equal":
	default:
		return nil, fmt.Errorf("identity: unknown match_mode %q (must be %q or %q)", matchMode, "exact", "lowercase_equal")
	}

	denied := make(map[string]struct{}, len(cfg.DeniedUsernames))
	for _, u := range cfg.DeniedUsernames {
		norm := normalizeUsername(u)
		if norm == "" {
			continue
		}
		denied[norm] = struct{}{}
	}

	return &Policy{
		usernameClaim:   usernameClaim,
		matchMode:       matchMode,
		deniedUsernames: denied,
		claimPolicy:     cfg.ClaimPolicy,
	}, nil
}

// normalizeUsername is the case-insensitive, outer-whitespace-tolerant form
// used for reserved-username comparison, independent of the configured
// MatchMode (per the plan: "reject a configured denied username using
// trimmed case-insensitive comparison independent of MatchMode").
func normalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

// resolveClaim resolves the configured username claim from already
// cryptographically-validated claims.
func (p *Policy) resolveClaim(claims *oauth.Claims) (string, error) {
	switch p.usernameClaim {
	case "email":
		if e := strings.TrimSpace(claims.Email); e != "" {
			return e, nil
		}
		if e := oauth.EmailFromNamespacedExtra(claims.Extra); e != "" {
			return e, nil
		}
		return "", fmt.Errorf("%w: claim %q", ErrClaimMissing, "email")
	case "sub":
		if s := strings.TrimSpace(claims.Subject); s != "" {
			return s, nil
		}
		return "", fmt.Errorf("%w: claim %q", ErrClaimMissing, "sub")
	default:
		if raw, ok := claims.Extra[p.usernameClaim]; ok {
			if s, ok := raw.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					return trimmed, nil
				}
			}
		}
		return "", fmt.Errorf("%w: claim %q", ErrClaimMissing, p.usernameClaim)
	}
}

// matches compares requested against the resolved claim value under the
// configured MatchMode.
func (p *Policy) matches(requested, resolved string) bool {
	if p.matchMode == "exact" {
		return requested == resolved
	}
	return strings.EqualFold(strings.TrimSpace(requested), strings.TrimSpace(resolved))
}

// Bind runs the helper-specific identity pipeline after cryptographic
// validation: resolve the configured username claim, compare it against
// requestedUsername under MatchMode, apply the SDK's generic verified-email/
// domain policy, and reject a reserved requested username. It returns the
// bound Principal only when every step passes.
func (p *Policy) Bind(requestedUsername string, claims *oauth.Claims) (Principal, error) {
	if claims == nil {
		return Principal{}, fmt.Errorf("%w: claims are nil", ErrClaimMissing)
	}

	resolved, err := p.resolveClaim(claims)
	if err != nil {
		return Principal{}, err
	}

	if !p.matches(requestedUsername, resolved) {
		return Principal{}, fmt.Errorf("%w: requested user %q does not match %s claim", ErrUsernameMismatch, requestedUsername, p.usernameClaim)
	}

	if err := oauth.ValidateIdentityClaims(claims, p.claimPolicy); err != nil {
		return Principal{}, err
	}

	if _, denied := p.deniedUsernames[normalizeUsername(requestedUsername)]; denied {
		return Principal{}, fmt.Errorf("%w: %q", ErrReservedUsername, requestedUsername)
	}

	return Principal{
		Username: requestedUsername,
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Email:    claims.Email,
	}, nil
}
