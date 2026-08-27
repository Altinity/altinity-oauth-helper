package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"

	"github.com/altinity/altinity-oauth-helper/internal/identity"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// Config is the YAML configuration consumed by the ch-jwt-verify sidecar.
// Fields can also be overridden via environment variables, which is how the
// Helm chart injects deployment-time values without re-templating a config
// file. Env-var names follow `CH_JWT_VERIFY_<UPPER_SNAKE>` to avoid clashes
// with the colocated ClickHouse process.
type Config struct {
	Listen   ListenConfig   `yaml:"listen"`
	OAuth    OAuthConfig    `yaml:"oauth"`
	Identity IdentityConfig `yaml:"identity"`
	// SettingsFromScope maps an OAuth scope name to a set of ClickHouse
	// session settings the sidecar returns in its /verify response. The CH
	// http_authentication handler applies these settings for the duration
	// of the request only — they cannot escape the per-query scope.
	SettingsFromScope map[string]map[string]string `yaml:"settings_from_scope"`
	Cache             CacheConfig                  `yaml:"cache"`
}

// ListenConfig selects the transport. Exactly one of Unix or TCP must be set;
// validateConfig enforces that and rejects mixed configs. Unix sockets are
// preferred for trust isolation (no port surface, fs permissions gate access);
// TCP is for environments where bind-mounted sockets aren't practical.
type ListenConfig struct {
	Unix string `yaml:"unix"`
	TCP  string `yaml:"tcp"`
}

// OAuthConfig is the subset of go-mcp-oauth-sdk knobs the sidecar needs. We
// don't reuse oauth.OAuthConfig verbatim because that struct carries
// broker-mode fields (client_id/client_secret/refresh-token TTL) which are
// meaningless on the sidecar — keeping a narrow type rejects misconfiguration
// at parse time.
//
// Audience has two forms: the legacy singular Audience (kept for backward
// compatibility with every existing deployment) and the canonical plural
// ExpectedAudiences. validateConfig rejects configuring both non-empty at
// once — see effectiveAudiences and the "Audience normalization rules"
// section of the phase-1 plan.
type OAuthConfig struct {
	Issuer  string `yaml:"issuer"`
	JWKSURL string `yaml:"jwks_url"`
	// Audience is the legacy singular compatibility form. Still the only
	// form the CH_JWT_VERIFY_OAUTH_AUDIENCE env override writes to.
	Audience string `yaml:"audience"`
	// ExpectedAudiences is the canonical plural form. Mutually exclusive
	// with Audience after YAML+env layering.
	ExpectedAudiences []string `yaml:"expected_audiences"`
	// VerifierLeeway bounds the clock-skew tolerance applied to exp/nbf/iat.
	// Defaults to 60s (defaultConfig), preserving the SDK's previously
	// fixed internal tolerance. An explicitly configured 0s means no
	// tolerance. Negative values fail config activation.
	VerifierLeeway   time.Duration `yaml:"verifier_leeway"`
	RequiredScopes   []string      `yaml:"required_scopes"`
	JWKSCacheTTL     time.Duration `yaml:"jwks_cache_ttl"`
	JWKSRefreshAhead time.Duration `yaml:"jwks_refresh_ahead"`
}

// IdentityConfig encapsulates the user-vs-claim matching rule and the domain
// allow-lists. UsernameClaim picks which JWT claim to match against the Basic
// header's user half (`email` for OIDC-style deployments, `sub` for opaque
// principals). MatchMode selects the comparison: `exact` requires byte-equal,
// `lowercase_equal` (the default) tolerates case differences common when
// operators provision CH users in lowercase. DeniedUsernames defaults to
// empty so merely upgrading an existing deployment does not begin denying
// previously accepted usernames.
type IdentityConfig struct {
	UsernameClaim        string   `yaml:"username_claim"`
	MatchMode            string   `yaml:"match_mode"`
	RequireEmailVerified bool     `yaml:"require_email_verified"`
	AllowedEmailDomains  []string `yaml:"allowed_email_domains"`
	AllowedHostedDomains []string `yaml:"allowed_hosted_domains"`
	DeniedUsernames      []string `yaml:"denied_usernames"`
}

// CacheConfig governs the per-JWT verification cache. Positive entries are
// keyed by SHA256(username + NUL + JWT) and short-lived — capped at the raw
// JWT exp regardless of PositiveTTL (see internal/verification). Negative
// entries reuse the same key to suppress repeated cryptographic checks when
// an upstream replays a bad token.
type CacheConfig struct {
	PositiveTTL time.Duration `yaml:"positive_ttl"`
	NegativeTTL time.Duration `yaml:"negative_ttl"`
}

// LoadConfig reads cfgPath as YAML, then layers env-var overrides for the
// deployment-time fields the Helm chart sets. Returns the parsed config plus
// any validation error.
func LoadConfig(cfgPath string) (*Config, error) {
	cfg := defaultConfig()

	if cfgPath != "" {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	applyEnvOverrides(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaultConfig sets values that the operator usually doesn't need to tune:
// JWKS cache TTL, verifier leeway, identity-policy defaults, cache windows.
func defaultConfig() *Config {
	return &Config{
		OAuth: OAuthConfig{
			JWKSCacheTTL:     5 * time.Minute,
			JWKSRefreshAhead: 1 * time.Minute,
			VerifierLeeway:   60 * time.Second,
		},
		Identity: IdentityConfig{
			UsernameClaim:        "email",
			MatchMode:            "lowercase_equal",
			RequireEmailVerified: true,
		},
		Cache: CacheConfig{
			PositiveTTL: 30 * time.Second,
			NegativeTTL: 5 * time.Minute,
		},
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_LISTEN_UNIX")); v != "" {
		cfg.Listen.Unix = v
	}
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_LISTEN_TCP")); v != "" {
		cfg.Listen.TCP = v
	}
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_OAUTH_ISSUER")); v != "" {
		cfg.OAuth.Issuer = v
	}
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_OAUTH_JWKS_URL")); v != "" {
		cfg.OAuth.JWKSURL = v
	}
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_OAUTH_AUDIENCE")); v != "" {
		cfg.OAuth.Audience = v
	}
}

func validateConfig(cfg *Config) error {
	if cfg.Listen.Unix == "" && cfg.Listen.TCP == "" {
		return fmt.Errorf("listen: either unix or tcp must be set")
	}
	if cfg.Listen.Unix != "" && cfg.Listen.TCP != "" {
		return fmt.Errorf("listen: unix and tcp are mutually exclusive")
	}
	if strings.TrimSpace(cfg.OAuth.Issuer) == "" && strings.TrimSpace(cfg.OAuth.JWKSURL) == "" {
		return fmt.Errorf("oauth: either issuer or jwks_url must be set")
	}

	rawPluralConfigured := len(cfg.OAuth.ExpectedAudiences) > 0
	pluralNonEmpty := len(filterNonEmpty(cfg.OAuth.ExpectedAudiences)) > 0
	singularConfigured := strings.TrimSpace(cfg.OAuth.Audience) != ""

	switch {
	case rawPluralConfigured && !pluralNonEmpty:
		return fmt.Errorf("oauth: expected_audiences must contain at least one non-empty value")
	case pluralNonEmpty && singularConfigured:
		// Covers both the YAML-plural + YAML-singular case and the
		// YAML-plural + CH_JWT_VERIFY_OAUTH_AUDIENCE case (the env override
		// writes to the same singular field applyEnvOverrides always did) —
		// both are now populated, so config activation fails deterministically
		// rather than silently picking one.
		return fmt.Errorf("oauth: expected_audiences and audience (including CH_JWT_VERIFY_OAUTH_AUDIENCE) are mutually exclusive; configure exactly one")
	case !pluralNonEmpty && !singularConfigured:
		return fmt.Errorf("oauth: audience is required (set oauth.audience or oauth.expected_audiences, RFC 8707 byte-exact match)")
	}

	if cfg.OAuth.VerifierLeeway < 0 {
		return fmt.Errorf("oauth: verifier_leeway must not be negative")
	}

	return nil
}

// filterNonEmpty drops empty/whitespace-only entries from list while
// preserving the exact bytes of every retained entry — audience values are
// never trimmed or otherwise normalized before comparison, only tested for
// emptiness.
func filterNonEmpty(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if strings.TrimSpace(s) == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// dedupePreserveOrder removes duplicate strings, keeping the first
// occurrence's position.
func dedupePreserveOrder(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// effectiveAudiences resolves the configured audience form into the single
// list internal/verification compares against: the deduplicated plural
// expected_audiences when non-empty, otherwise the legacy singular audience
// as a one-element list. validateConfig has already established that at
// most one form is non-empty by the time this runs.
func effectiveAudiences(cfg OAuthConfig) []string {
	if list := filterNonEmpty(cfg.ExpectedAudiences); len(list) > 0 {
		return dedupePreserveOrder(list)
	}
	if strings.TrimSpace(cfg.Audience) != "" {
		return []string{cfg.Audience}
	}
	return nil
}

// toVerificationConfig builds the normalized internal/verification.Config
// this sidecar's shared verifier is constructed from.
func (cfg *Config) toVerificationConfig() verification.Config {
	return verification.Config{
		ExpectedIssuer:    cfg.OAuth.Issuer,
		JWKSURL:           cfg.OAuth.JWKSURL,
		ExpectedAudiences: effectiveAudiences(cfg.OAuth),
		VerifierLeeway:    cfg.OAuth.VerifierLeeway,
		RequiredScopes:    cfg.OAuth.RequiredScopes,
		JWKSCacheTTL:      cfg.OAuth.JWKSCacheTTL,
		PositiveTTL:       cfg.Cache.PositiveTTL,
		NegativeTTL:       cfg.Cache.NegativeTTL,
		Identity: identity.Config{
			UsernameClaim:   cfg.Identity.UsernameClaim,
			MatchMode:       cfg.Identity.MatchMode,
			DeniedUsernames: cfg.Identity.DeniedUsernames,
			ClaimPolicy: oauth.IdentityPolicy{
				RequireEmailVerified: cfg.Identity.RequireEmailVerified,
				AllowedEmailDomains:  cfg.Identity.AllowedEmailDomains,
				AllowedHostedDomains: cfg.Identity.AllowedHostedDomains,
			},
		},
	}
}
