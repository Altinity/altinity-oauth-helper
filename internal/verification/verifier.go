// Package verification composes the SDK's strict JWT verifier with the
// helper-specific identity policy and a bounded, positive/negative
// verification-result cache. This is the single owner of "verify a bearer
// presented as requestedUsername, and cache the outcome" for every
// altinity-oauth-helper binary — generic JWT/JWKS parsing itself remains in
// github.com/altinity/go-mcp-oauth-sdk/oauth.
package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"

	"github.com/altinity/altinity-oauth-helper/internal/identity"
)

// Config configures a Verifier.
type Config struct {
	ExpectedIssuer    string
	JWKSURL           string
	ExpectedAudiences []string
	VerifierLeeway    time.Duration
	RequiredScopes    []string
	JWKSCacheTTL      time.Duration

	PositiveTTL time.Duration
	NegativeTTL time.Duration

	Identity identity.Config
}

// Result is a verified, identity-bound outcome. Every Verify call — cache
// hit or miss — returns a Result whose Claims slice/map members are
// isolated copies: mutating a returned Result must never be observable by
// any other caller, including a subsequent cache hit for the same key.
type Result struct {
	Claims    oauth.Claims
	Principal identity.Principal
}

// Verifier validates a bearer token against the configured strict JWT policy
// and identity policy, and caches both positive and negative outcomes.
type Verifier struct {
	oauthVer *oauth.Verifier
	policy   oauth.StrictJWTPolicy
	identity *identity.Policy

	positiveTTL time.Duration
	negativeTTL time.Duration

	cache *cache
}

// hasNonEmptyAudience reports whether audiences contains at least one
// non-whitespace entry.
func hasNonEmptyAudience(audiences []string) bool {
	for _, a := range audiences {
		if strings.TrimSpace(a) != "" {
			return true
		}
	}
	return false
}

// New validates cfg and constructs a Verifier. Construction fails closed:
// an empty effective audience list, a negative leeway, or an invalid
// identity configuration (e.g. an unknown match mode) all fail New rather
// than falling back to a permissive default.
func New(cfg Config) (*Verifier, error) {
	if !hasNonEmptyAudience(cfg.ExpectedAudiences) {
		return nil, fmt.Errorf("verification: at least one non-empty expected audience is required")
	}
	if cfg.VerifierLeeway < 0 {
		return nil, fmt.Errorf("verification: verifier_leeway must not be negative")
	}

	idPolicy, err := identity.NewPolicy(cfg.Identity)
	if err != nil {
		return nil, err
	}

	oauthVer := oauth.NewVerifier(oauth.OAuthConfig{
		Enabled:       true,
		StrictJWTOnly: true,
		Issuer:        cfg.ExpectedIssuer,
		JWKSURL:       cfg.JWKSURL,
		JWKSCacheTTL:  cfg.JWKSCacheTTL,
	})

	return &Verifier{
		oauthVer: oauthVer,
		policy: oauth.StrictJWTPolicy{
			ExpectedIssuer:    cfg.ExpectedIssuer,
			ExpectedAudiences: cfg.ExpectedAudiences,
			Leeway:            cfg.VerifierLeeway,
			RequiredScopes:    cfg.RequiredScopes,
		},
		identity:    idPolicy,
		positiveTTL: cfg.PositiveTTL,
		negativeTTL: cfg.NegativeTTL,
		cache:       newCache(cacheMaxEntries),
	}, nil
}

// JWKSHealth surfaces the underlying SDK Verifier's JWKS-fetch health.
func (v *Verifier) JWKSHealth() (lastAttempt, lastSuccess time.Time, lastErr error) {
	return v.oauthVer.JWKSHealth()
}

// StartReaper launches a background goroutine that prunes expired cache
// entries every interval, exiting when ctx is cancelled. Optional —
// insertion-time eviction in the cache is the primary memory bound.
func (v *Verifier) StartReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				v.cache.pruneExpired()
			}
		}
	}()
}

// Verify validates token as presented under requestedUsername: on a cache
// hit it returns the cached outcome; on a miss it runs strict JWT
// validation followed by identity binding, then caches the outcome
// (positive entries capped at min(now+PositiveTTL, JWT exp); permanent
// negative entries at NegativeTTL; oauth.ErrTransient failures are never
// cached in either direction).
func (v *Verifier) Verify(ctx context.Context, requestedUsername, token string) (*Result, error) {
	key := cacheKey(requestedUsername, token)

	if entry, ok := v.cache.get(key); ok {
		if entry.ok {
			return cloneResult(entry.result), nil
		}
		return nil, entry.err
	}

	result, err := v.verifyUncached(ctx, requestedUsername, token)
	if err != nil {
		if !errors.Is(err, oauth.ErrTransient) {
			v.cache.set(key, cacheEntry{
				ok:        false,
				err:       err,
				expiresAt: time.Now().Add(v.negativeTTL),
			})
		}
		return nil, err
	}

	v.cachePositive(key, result)
	return cloneResult(result), nil
}

func (v *Verifier) verifyUncached(ctx context.Context, requestedUsername, token string) (*Result, error) {
	claims, err := v.oauthVer.ValidateStrictJWT(ctx, token, v.policy)
	if err != nil {
		return nil, err
	}
	principal, err := v.identity.Bind(requestedUsername, claims)
	if err != nil {
		return nil, err
	}
	return &Result{Claims: *claims, Principal: principal}, nil
}

// cachePositive stores result under key, capping its expiry at the raw JWT
// exp: the stored invariant is
//
//	cache_expiration = min(now + PositiveTTL, JWT.exp) <= JWT.exp
//
// never exp + Leeway. If that computed expiry isn't in the future (a token
// only accepted through Leeway, whose raw exp has already passed), the
// verified result for THIS request is still returned by the caller — it's
// simply never cached, since caching it would extend a credential's
// effective authorization past its own raw exp.
func (v *Verifier) cachePositive(key string, result *Result) {
	now := time.Now()
	ttlExpiry := now.Add(v.positiveTTL)
	jwtExpiry := time.Unix(result.Claims.ExpiresAt, 0)

	expiresAt := ttlExpiry
	if jwtExpiry.Before(expiresAt) {
		expiresAt = jwtExpiry
	}
	if !expiresAt.After(now) {
		return
	}
	v.cache.set(key, cacheEntry{ok: true, result: result, expiresAt: expiresAt})
}

// cacheKey hashes requestedUsername + NUL + token so a cached outcome can
// never be replayed under a different requested username than the one it
// was verified against — see internal/verification's package doc and
// CLAUDE.md's cache-key-correctness rule. The full SHA-256 hex digest (not a
// prefix) is used as the key; the token itself is never used as, or embedded
// in, the key material returned to any caller.
func cacheKey(requestedUsername, token string) string {
	sum := sha256.Sum256([]byte(requestedUsername + "\x00" + token))
	return hex.EncodeToString(sum[:])
}

// cloneResult returns a copy of r whose Claims.Audience, Claims.Scopes, and
// Claims.Extra (recursively, including every nested map/array value it
// contains) are independent of r's — so a caller mutating the returned
// Result (or any of those members, at any depth) can never affect the cached
// canonical copy, nor therefore any other caller's subsequent cache hit.
func cloneResult(r *Result) *Result {
	if r == nil {
		return nil
	}
	claims := r.Claims
	claims.Audience = append([]string(nil), r.Claims.Audience...)
	claims.Scopes = append([]string(nil), r.Claims.Scopes...)
	if r.Claims.Extra != nil {
		claims.Extra = make(map[string]interface{}, len(r.Claims.Extra))
		for k, val := range r.Claims.Extra {
			claims.Extra[k] = deepCloneJSONValue(val)
		}
	}
	return &Result{Claims: claims, Principal: r.Principal}
}

// deepCloneJSONValue returns a deep copy of v. Extra is populated straight
// from unmarshaling a JWT payload's non-standard claims into
// map[string]interface{} (github.com/altinity/go-mcp-oauth-sdk/oauth), so
// every value reachable from it is one of encoding/json's decode-into-
// interface{} types: map[string]interface{}, []interface{}, string,
// float64, bool, or nil. Composite types (map, slice) are cloned
// recursively; every other type is a value type already independent of its
// source and is returned as-is.
func deepCloneJSONValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, e := range val {
			out[k] = deepCloneJSONValue(e)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, e := range val {
			out[i] = deepCloneJSONValue(e)
		}
		return out
	default:
		return val
	}
}
