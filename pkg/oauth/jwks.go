package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog/log"
)

const (
	// jwksCacheTTL is the default TTL applied when OAuthConfig.JWKSCacheTTL
	// is zero.
	jwksCacheTTL = 5 * time.Minute
	// httpTimeout bounds outbound discovery + JWKS HTTP calls.
	httpTimeout = 10 * time.Second
)

// jwksCacheTTL resolves the effective JWKS / metadata cache TTL: the
// configured value when set, otherwise the package default.
func (v *Verifier) jwksCacheTTL() time.Duration {
	if v.cfg.JWKSCacheTTL > 0 {
		return v.cfg.JWKSCacheTTL
	}
	return jwksCacheTTL
}

// jitteredExpiry returns now+TTL with ±10% uniformly-distributed jitter, so
// a fleet of replicas rolled out together doesn't synchronise its JWKS
// refetches and thunder the IdP every cache-TTL boundary.
func jitteredExpiry(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return now
	}
	span := ttl / 5
	if span <= 0 {
		return now.Add(ttl)
	}
	jitter := time.Duration(rand.Int64N(int64(span))) - ttl/10
	return now.Add(ttl + jitter)
}

// Verifier validates OAuth tokens against an issuer's JWKS, caching both the
// JWKS document and the authorization-server metadata it needs to locate the
// JWKS URI. Safe for concurrent use.
type Verifier struct {
	cfg OAuthConfig

	jwksCache          jose.JSONWebKeySet
	jwksCacheURL       string
	jwksCacheExpiresAt time.Time
	jwksMu             sync.RWMutex

	asMetaCache     authServerMeta
	asMetaCacheURL  string
	asMetaExpiresAt time.Time
	asMetaMu        sync.RWMutex

	healthMu             sync.RWMutex
	jwksLastFetchAttempt time.Time
	jwksLastFetchSuccess time.Time
	jwksLastFetchError   error
}

// JWKSHealth returns the most recent JWKS-fetch attempt, the most recent
// success, and the most recent error (cleared on the next success). All
// zero values mean the Verifier has not yet attempted a fetch — callers
// should treat this as a boot-grace "ready" rather than a stale failure.
func (v *Verifier) JWKSHealth() (lastAttempt, lastSuccess time.Time, lastErr error) {
	v.healthMu.RLock()
	defer v.healthMu.RUnlock()
	return v.jwksLastFetchAttempt, v.jwksLastFetchSuccess, v.jwksLastFetchError
}

// NewVerifier builds a Verifier for the given OAuth configuration.
func NewVerifier(cfg OAuthConfig) *Verifier {
	return &Verifier{cfg: cfg}
}

// Config returns the OAuthConfig the Verifier was built with.
func (v *Verifier) Config() OAuthConfig {
	return v.cfg
}

// resolveJWKSURL resolves the JWKS URI by configuration override, then by
// OIDC / OAuth 2.0 Authorization Server Metadata discovery from the
// configured issuer. Returns an error if neither path succeeds.
func (v *Verifier) resolveJWKSURL(ctx context.Context) (string, error) {
	if explicit := strings.TrimSpace(v.cfg.JWKSURL); explicit != "" {
		return explicit, nil
	}
	issuer := strings.TrimSpace(v.cfg.Issuer)
	if issuer == "" {
		return "", fmt.Errorf("oauth issuer or jwks_url must be configured")
	}
	asMeta, err := v.fetchAuthServerMeta(ctx, issuer)
	if err != nil {
		return "", err
	}
	jwksURI := strings.TrimSpace(asMeta.JWKSURI)
	if jwksURI == "" {
		return "", fmt.Errorf("openid discovery did not return jwks_uri")
	}
	return jwksURI, nil
}

// fetchAuthServerMeta returns the cached or freshly-discovered authorization
// server metadata for issuer. Caches the result for jwksCacheTTL with ±10%
// jitter.
func (v *Verifier) fetchAuthServerMeta(ctx context.Context, issuer string) (*authServerMeta, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	v.asMetaMu.RLock()
	if v.asMetaCacheURL == issuer && v.asMetaExpiresAt.After(time.Now()) && v.asMetaCache.Issuer != "" {
		cached := v.asMetaCache
		v.asMetaMu.RUnlock()
		return &cached, nil
	}
	v.asMetaMu.RUnlock()

	httpClient := &http.Client{Timeout: httpTimeout}
	asMeta, err := getAuthServerMetadata(ctx, issuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to discover authorization server metadata for issuer %q: %w", issuer, err)
	}
	if asMeta == nil {
		return nil, fmt.Errorf("no authorization server metadata found for issuer %q", issuer)
	}

	v.asMetaMu.Lock()
	v.asMetaCache = *asMeta
	v.asMetaCacheURL = issuer
	v.asMetaExpiresAt = jitteredExpiry(time.Now(), v.jwksCacheTTL())
	v.asMetaMu.Unlock()
	return asMeta, nil
}

// FetchAuthServerMeta exposes the cached/discovered auth-server metadata for
// the given issuer. Returns the local (vendored) metadata type intentionally
// — callers needing more fields should fetch and parse independently.
func (v *Verifier) FetchAuthServerMeta(ctx context.Context, issuer string) (*authServerMeta, error) {
	return v.fetchAuthServerMeta(ctx, issuer)
}

// fetchJWKSet returns the cached or freshly-fetched JWKS for jwksURI.
func (v *Verifier) fetchJWKSet(ctx context.Context, jwksURI string) (result *jose.JSONWebKeySet, retErr error) {
	now := time.Now()

	v.jwksMu.RLock()
	if len(v.jwksCache.Keys) > 0 && v.jwksCacheURL == jwksURI && v.jwksCacheExpiresAt.After(now) {
		cached := v.jwksCache
		v.jwksMu.RUnlock()
		return &cached, nil
	}
	v.jwksMu.RUnlock()

	v.healthMu.Lock()
	v.jwksLastFetchAttempt = now
	v.healthMu.Unlock()
	defer func() {
		v.healthMu.Lock()
		defer v.healthMu.Unlock()
		if retErr == nil {
			v.jwksLastFetchSuccess = time.Now()
			v.jwksLastFetchError = nil
		} else {
			v.jwksLastFetchError = retErr
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build jwks request: %w", err)
	}
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks: %w: %w", ErrTransient, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Stack().Err(closeErr).Msgf("can't close %s response body", jwksURI)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read jwks response: %w: %w", ErrTransient, err)
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("jwks endpoint returned status %d: %w", resp.StatusCode, ErrTransient)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("failed to parse jwks response: %w", err)
	}

	v.jwksMu.Lock()
	v.jwksCache = keySet
	v.jwksCacheURL = jwksURI
	v.jwksCacheExpiresAt = jitteredExpiry(now, v.jwksCacheTTL())
	v.jwksMu.Unlock()
	return &keySet, nil
}

// invalidateJWKSCache forces the next fetchJWKSet call to re-fetch. Used
// when the upstream AS rotates its signing key (kid we just saw is absent
// from the cached set).
func (v *Verifier) invalidateJWKSCache() {
	v.jwksMu.Lock()
	v.jwksCacheExpiresAt = time.Time{}
	v.jwksMu.Unlock()
}
