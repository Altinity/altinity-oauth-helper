package verification

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/altinity/altinity-oauth-helper/internal/identity"
)

// testIdP is an in-process OIDC test fixture, independent of any fixture
// used by cmd/ch-jwt-verify's own tests — internal/verification is a
// standalone package with its own compile-time and test boundary.
//
// The signing key/kid it currently serves under /jwks is mutable (guarded by
// mu) rather than fixed at construction: redaction_matrix_test.go's
// pre-bump JWKS-rotation characterization test (plan §4.3) needs to warm the
// SDK Verifier's internal JWKS cache under one key, then swap the served key
// live — via rotateKey — to prove the real "kid changed since last fetch"
// re-fetch branch executes, not just a same-process construction-time
// fixture swap.
type testIdP struct {
	server   *httptest.Server
	issuer   string
	audience string

	mu   sync.Mutex
	priv *rsa.PrivateKey
	kid  string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	p := &testIdP{
		priv:     priv,
		kid:      "test-key",
		audience: "ch-jwt-verify.test",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &p.priv.PublicKey,
			KeyID:     p.kid,
			Algorithm: "RS256",
			Use:       "sig",
		}}}
		p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	p.server = srv
	p.issuer = srv.URL
	return p
}

// signerFor builds a fresh jose.Signer for an explicit key/kid pair,
// independent of p's currently-registered signing key — used both by
// currentSigner (below) and by mintJWTWithKeyKid, which deliberately signs
// with a key/kid combination that does NOT match what /jwks currently
// serves (wrong-signature and unknown-kid marker cases in
// redaction_matrix_test.go).
func signerFor(t *testing.T, key *rsa.PrivateKey, kid string) jose.Signer {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	require.NoError(t, err)
	return signer
}

// currentSigner returns a signer for p's currently-registered key/kid,
// reading both fields under mu so it can't race a concurrent rotateKey (or
// the /jwks handler, which reads the same fields per request).
func (p *testIdP) currentSigner(t *testing.T) jose.Signer {
	t.Helper()
	p.mu.Lock()
	key, kid := p.priv, p.kid
	p.mu.Unlock()
	return signerFor(t, key, kid)
}

// currentKID returns the kid p currently serves under /jwks.
func (p *testIdP) currentKID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.kid
}

// rotateKey atomically replaces the key/kid p's /jwks endpoint serves,
// simulating an IdP key rotation. It does not touch any cache already held
// by an oauth.Verifier that previously fetched the old JWKS — that
// cache/invalidate/re-fetch behavior is exactly what
// redaction_matrix_test.go's rotation characterization test exercises.
func (p *testIdP) rotateKey(newKey *rsa.PrivateKey, newKid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.priv = newKey
	p.kid = newKid
}

// mintJWT builds a token with claims layered over required defaults, signed
// with p's currently-registered key/kid; pass an explicit nil-valued key to
// omit a claim (e.g. claims["exp"] = nil).
func (p *testIdP) mintJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	return p.mintJWTWithSigner(t, p.currentSigner(t), claims)
}

// mintJWTWithKeyKid is mintJWT's counterpart for signing with an explicit
// key/kid pair rather than p's currently-registered one — see signerFor.
func (p *testIdP) mintJWTWithKeyKid(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	return p.mintJWTWithSigner(t, signerFor(t, key, kid), claims)
}

func (p *testIdP) mintJWTWithSigner(t *testing.T, signer jose.Signer, claims map[string]interface{}) string {
	t.Helper()
	final := map[string]interface{}{}
	if _, ok := claims["iss"]; !ok {
		final["iss"] = p.issuer
	}
	if _, ok := claims["aud"]; !ok {
		final["aud"] = p.audience
	}
	if _, ok := claims["exp"]; !ok {
		final["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		final["iat"] = time.Now().Unix()
	}
	for k, v := range claims {
		if v == nil {
			delete(final, k)
			continue
		}
		final[k] = v
	}
	token, err := josejwt.Signed(signer).Claims(final).Serialize()
	require.NoError(t, err)
	return token
}

func baseConfig(p *testIdP) Config {
	return Config{
		ExpectedIssuer:    p.issuer,
		JWKSURL:           p.server.URL + "/jwks",
		ExpectedAudiences: []string{p.audience},
		PositiveTTL:       30 * time.Second,
		NegativeTTL:       5 * time.Minute,
		Identity: identity.Config{
			UsernameClaim: "email",
			MatchMode:     "lowercase_equal",
		},
	}
}

// This file's top-level t.Parallel() calls (here and throughout) are safe
// next to redaction_matrix_test.go's serialized, non-parallel global-logger
// captures in the same package: Go's testing package only starts a
// parallel top-level test's body after every top-level test that never
// called t.Parallel() has already run to completion (see
// redaction_matrix_test.go's own header for the full rule this leans on),
// so none of this file's parallel tests can ever interleave with that
// file's process-global logger swap.
func TestNewRejectsEmptyAudiences(t *testing.T) {
	t.Parallel()
	_, err := New(Config{})
	require.Error(t, err)
}

func TestNewRejectsWhitespaceOnlyAudiences(t *testing.T) {
	t.Parallel()
	_, err := New(Config{ExpectedAudiences: []string{"  ", ""}})
	require.Error(t, err)
}

func TestNewRejectsNegativeLeeway(t *testing.T) {
	t.Parallel()
	_, err := New(Config{ExpectedAudiences: []string{"a"}, VerifierLeeway: -time.Second})
	require.Error(t, err)
}

func TestNewRejectsInvalidIdentityConfig(t *testing.T) {
	t.Parallel()
	cfg := Config{ExpectedAudiences: []string{"a"}, Identity: identity.Config{MatchMode: "bogus"}}
	_, err := New(cfg)
	require.Error(t, err)
}

func TestVerifyAcceptsValidJWT(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{"sub": "u-1", "email": "alice@example.com"})
	result, err := v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", result.Claims.Email)
	require.Equal(t, "alice@example.com", result.Principal.Username)
}

// TestVerifySupportsJWKSOnlyWithNoConfiguredIssuer is the compatibility
// regression: a pinned-JWKS deployment with no configured expected issuer
// must remain supported — an empty ExpectedIssuer must not become a new
// authentication prerequisite.
func TestVerifySupportsJWKSOnlyWithNoConfiguredIssuer(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.ExpectedIssuer = ""
	v, err := New(cfg)
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{"sub": "u-1", "email": "alice@example.com"})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)
}

// TestVerifySupportsEmailUsernameClaimWithoutSub is the compatibility
// regression: username_claim: email deployments never required sub.
func TestVerifySupportsEmailUsernameClaimWithoutSub(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{"email": "alice@example.com", "sub": nil})
	result, err := v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)
	_, _, ok := result.Principal.StableSubject()
	require.False(t, ok)
}

func TestVerifyRejectsAudienceMismatchExactly(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.ExpectedAudiences = []string{p.audience + "/"} // trailing-slash mismatch
	v, err := New(cfg)
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{"sub": "u-1", "email": "alice@example.com"})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.ErrorIs(t, err, oauth.ErrInvalidToken)
}

func TestVerifyAcceptsArrayAudienceIntersection(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.ExpectedAudiences = []string{"other-aud", p.audience}
	v, err := New(cfg)
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com",
		"aud": []string{"unrelated", p.audience},
	})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.ErrorIs(t, err, oauth.ErrTokenExpired)
}

func TestVerifyRejectsMissingExp(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{"sub": "u-1", "email": "alice@example.com", "exp": nil})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.ErrorIs(t, err, oauth.ErrInvalidToken)
}

func TestVerifyRejectsFutureNbfOutsideLeeway(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.VerifierLeeway = 10 * time.Second
	v, err := New(cfg)
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com",
		"nbf": time.Now().Add(time.Minute).Unix(), // well past the 10s leeway
	})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.ErrorIs(t, err, oauth.ErrInvalidToken)
}

func TestVerifyAcceptsFutureNbfInsideLeeway(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.VerifierLeeway = time.Minute
	v, err := New(cfg)
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com",
		"nbf": time.Now().Add(10 * time.Second).Unix(), // within the 1m leeway
	})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)
}

func TestVerifyRejectsMalformedNbf(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com",
		"nbf": "not-a-number",
	})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.ErrorIs(t, err, oauth.ErrInvalidToken)
}

func TestVerifyRejectsUsernameMismatch(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{"sub": "u-1", "email": "alice@example.com"})
	_, err = v.Verify(context.Background(), "bob@example.com", tok)
	require.ErrorIs(t, err, identity.ErrUsernameMismatch)
}

// TestVerifyCacheKeyIncludesUsername is the positive-replay regression: a
// token verified for one requested username must not be servable, via a
// cache hit, under a different requested username.
func TestVerifyCacheKeyIncludesUsername(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{"sub": "u-1", "email": "alice@example.com"})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), "bob@example.com", tok)
	require.ErrorIs(t, err, identity.ErrUsernameMismatch, "replaying alice's token as bob must not hit alice's cached positive entry")
}

// TestVerifyCacheKeyIsolatesNegativeCacheByUser is the symmetric direction:
// a wrong user's negative cache entry must not strand the legitimate owner
// of the same token.
func TestVerifyCacheKeyIsolatesNegativeCacheByUser(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.Identity.UsernameClaim = "clickhouse_user"
	cfg.Identity.MatchMode = "exact"
	v, err := New(cfg)
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com", "clickhouse_user": "ch-tenant-a",
	})

	_, err = v.Verify(context.Background(), "ch-tenant-b", tok)
	require.Error(t, err)

	_, err = v.Verify(context.Background(), "ch-tenant-a", tok)
	require.NoError(t, err, "ch-tenant-a's legitimate request must not be stranded by ch-tenant-b's negative cache entry")
}

func TestVerifyPermanentErrorIsNegativeCached(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.Identity.ClaimPolicy = oauth.IdentityPolicy{RequireEmailVerified: true}
	v, err := New(cfg)
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com", "email_verified": false,
	})

	_, err1 := v.Verify(context.Background(), "alice@example.com", tok)
	require.ErrorIs(t, err1, oauth.ErrEmailNotVerified)
	require.Equal(t, 1, v.cache.len(), "permanent rejection must populate the negative cache")

	// Second call is a cache hit and must preserve errors.Is/As identity.
	_, err2 := v.Verify(context.Background(), "alice@example.com", tok)
	require.ErrorIs(t, err2, oauth.ErrEmailNotVerified, "cached error must keep sentinel identity")
}

func TestVerifyTransientErrorIsNeverCached(t *testing.T) {
	t.Parallel()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.JWKSURL = bad.URL
	v, err := New(cfg)
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{"sub": "u-1", "email": "alice@example.com"})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.ErrorIs(t, err, oauth.ErrTransient)
	require.Equal(t, 0, v.cache.len(), "transient errors must never be cached")
}

// TestVerifyPositiveCacheCappedAtJWTExp proves the stored expiry is
// min(now+PositiveTTL, JWT.exp), never exp+Leeway and never a plain
// now+PositiveTTL when that would outlive the token.
func TestVerifyPositiveCacheCappedAtJWTExp(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.PositiveTTL = time.Hour // deliberately far longer than the token's lifetime
	v, err := New(cfg)
	require.NoError(t, err)

	shortExp := time.Now().Add(2 * time.Second).Unix()
	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com", "exp": shortExp,
	})
	_, err = v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)

	key := cacheKey("alice@example.com", tok)
	entry, ok := v.cache.get(key)
	require.True(t, ok)
	require.True(t, entry.ok)
	require.LessOrEqual(t, entry.expiresAt.Unix(), shortExp,
		"cache expiry must never exceed the raw JWT exp, regardless of PositiveTTL")
}

// TestVerifyLeewayAcceptedTokenNotCachedPastRawExp proves a token accepted
// only through Leeway (its raw exp is already in the past) is still
// returned to THIS caller, but is not cached beyond its own raw exp — i.e.
// it is not cached at all, since a cache entry can't have an expiry in the
// past.
func TestVerifyLeewayAcceptedTokenNotCachedPastRawExp(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.VerifierLeeway = time.Minute
	v, err := New(cfg)
	require.NoError(t, err)

	// exp 10s in the past: within the 60s leeway window, so verification
	// succeeds, but the raw exp itself has already elapsed.
	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com",
		"exp": time.Now().Add(-10 * time.Second).Unix(),
	})
	result, err := v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err, "leeway must let this request through")
	require.Equal(t, "alice@example.com", result.Claims.Email)

	key := cacheKey("alice@example.com", tok)
	_, found := v.cache.get(key)
	require.False(t, found, "a token only accepted through leeway must not be cached past its already-elapsed raw exp")
}

// TestVerifyCachedResultCannotBeMutatedThroughCallerAlias is the
// cache-ownership regression: mutating a Result returned from Verify must
// never be observable through a later cache hit for the same key.
func TestVerifyCachedResultCannotBeMutatedThroughCallerAlias(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com",
		"aud":    p.audience,
		"scope":  "mcp:read",
		"groups": []string{"g1"},
	})

	first, err := v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)

	// Mutate everything mutable on the returned Result.
	if len(first.Claims.Audience) > 0 {
		first.Claims.Audience[0] = "mutated-audience"
	}
	first.Claims.Scopes = append(first.Claims.Scopes, "injected-scope")
	if first.Claims.Extra == nil {
		first.Claims.Extra = map[string]interface{}{}
	}
	first.Claims.Extra["injected"] = "poison"

	second, err := v.Verify(context.Background(), "alice@example.com", tok) // cache hit
	require.NoError(t, err)

	require.NotContains(t, second.Claims.Scopes, "injected-scope")
	require.NotContains(t, second.Claims.Extra, "injected")
	if len(second.Claims.Audience) > 0 {
		require.NotEqual(t, "mutated-audience", second.Claims.Audience[0])
	}
}

// TestVerifyCachedResultCannotBeMutatedThroughNestedExtraAlias is the
// nested-value counterpart to
// TestVerifyCachedResultCannotBeMutatedThroughCallerAlias: cloneResult must
// deep-clone Claims.Extra, not just remake its top-level map, so mutating an
// element *inside* an existing nested array or map value returned under
// Extra must never be observable through a later cache hit for the same
// key. Unlike the sibling test (which adds a brand-new top-level Extra key —
// safe merely because the top-level map is remade), this mutates in place
// through the existing "groups" claim's backing array/map, which is exactly
// the failure mode a shallow top-level-only clone misses.
func TestVerifyCachedResultCannotBeMutatedThroughNestedExtraAlias(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":   "u-1",
		"email": "alice@example.com",
		"aud":   p.audience,
		// A JWT payload decodes non-standard claims into Extra via
		// encoding/json's interface{} unmarshal, so "groups" arrives as
		// []interface{}, and "profile" as map[string]interface{} — the
		// exact reference-typed shapes cloneResult must deep-copy.
		"groups": []string{"g1", "g2"},
		"profile": map[string]interface{}{
			"nickname": "original",
		},
	})

	first, err := v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)

	groups, ok := first.Claims.Extra["groups"].([]interface{})
	require.True(t, ok, "groups must decode to []interface{}")
	require.NotEmpty(t, groups)
	groups[0] = "poisoned-group"

	profile, ok := first.Claims.Extra["profile"].(map[string]interface{})
	require.True(t, ok, "profile must decode to map[string]interface{}")
	profile["nickname"] = "poisoned-nickname"

	second, err := v.Verify(context.Background(), "alice@example.com", tok) // cache hit
	require.NoError(t, err)

	secondGroups, ok := second.Claims.Extra["groups"].([]interface{})
	require.True(t, ok)
	require.Equal(t, "g1", secondGroups[0], "mutation through the first caller's nested array alias must not leak into a later cache hit")

	secondProfile, ok := second.Claims.Extra["profile"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "original", secondProfile["nickname"], "mutation through the first caller's nested map alias must not leak into a later cache hit")

	// Mutating the second (independently cloned) result must likewise not
	// affect a third cache hit — proves the isolation holds symmetrically,
	// not just on the first clone off the cached canonical copy.
	secondGroups[0] = "poisoned-again"
	secondProfile["nickname"] = "poisoned-again"

	third, err := v.Verify(context.Background(), "alice@example.com", tok)
	require.NoError(t, err)
	thirdGroups := third.Claims.Extra["groups"].([]interface{})
	thirdProfile := third.Claims.Extra["profile"].(map[string]interface{})
	require.Equal(t, "g1", thirdGroups[0])
	require.Equal(t, "original", thirdProfile["nickname"])
}

func TestCacheCapEvicts(t *testing.T) {
	t.Parallel()
	c := newCache(3)
	for i := 0; i < 4; i++ {
		c.set(string(rune('a'+i)), cacheEntry{ok: true, expiresAt: time.Now().Add(time.Hour)})
	}
	require.LessOrEqual(t, c.len(), 3, "cache must not exceed cap")
}

func TestCachePruneExpired(t *testing.T) {
	t.Parallel()
	c := newCache(0)
	c.set("live", cacheEntry{ok: true, expiresAt: time.Now().Add(time.Hour)})
	c.set("dead", cacheEntry{ok: true, expiresAt: time.Now().Add(-time.Hour)})

	c.pruneExpired()

	_, liveOK := c.get("live")
	_, deadOK := c.get("dead")
	require.True(t, liveOK, "live entry must survive prune")
	require.False(t, deadOK, "expired entry must be evicted")
}

// TestVerifyStartReaperPrunesExpiredEntries proves the background reaper
// actually reaches the cache, not just that pruneExpired works in isolation.
func TestVerifyStartReaperPrunesExpiredEntries(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	v.cache.set("dead", cacheEntry{ok: true, expiresAt: time.Now().Add(-time.Hour)})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.StartReaper(ctx, 10*time.Millisecond)

	require.Eventually(t, func() bool {
		return v.cache.len() == 0
	}, time.Second, 10*time.Millisecond)
}

// TestVerifyErrorMarkerNeverInErrorText proves a distinctive credential
// marker embedded in the (deliberately malformed) token/password never
// surfaces in any returned error's text, across several distinct failure
// causes.
func TestVerifyErrorMarkerNeverInErrorText(t *testing.T) {
	t.Parallel()
	const marker = "SECRET-MARKER-DO-NOT-LEAK"
	p := newTestIdP(t)
	v, err := New(baseConfig(p))
	require.NoError(t, err)

	cases := map[string]string{
		"malformed-token": "not-a-jwt-" + marker,
		"wrong-audience":  p.mintJWT(t, map[string]interface{}{"sub": marker, "email": "alice@example.com", "aud": "wrong-aud"}),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), "alice@example.com-"+marker, tok)
			require.Error(t, err)
			require.NotContains(t, err.Error(), marker)
		})
	}
}

// noop assertion to keep errors referenced if the file shrinks.
var _ = errors.Is
