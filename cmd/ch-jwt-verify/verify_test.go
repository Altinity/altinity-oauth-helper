package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

// testIdP is a tiny in-process OIDC test fixture: it generates one RSA signing
// key, serves /jwks, and can mint JWTs with arbitrary claims. We don't depend
// on pkg/server's testOAuthProvider helper because the sidecar is independent
// of pkg/server — the e2e test there is a separate vertical.
type testIdP struct {
	server   *httptest.Server
	signer   jose.Signer
	keyID    string
	privKey  *rsa.PrivateKey
	issuer   string
	audience string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "test-key"

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// The sidecar may resolve JWKS via OIDC discovery when JWKSURL isn't pinned.
		host := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   host,
			"jwks_uri": host + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Algorithm: "RS256",
			Use:       "sig",
		}}}
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testIdP{
		server:   srv,
		signer:   signer,
		keyID:    kid,
		privKey:  priv,
		issuer:   srv.URL,
		audience: "ch-jwt-verify.test",
	}
}

// mintJWT builds a token from claims layered over required defaults. Setting
// a key's value to nil in claims omits that claim entirely — used by the
// missing-exp/missing-sub compatibility regressions below, which need a
// genuinely absent claim rather than a zero/null value (a zero value
// exercises a different parser path than an absent one).
func (p *testIdP) mintJWT(t *testing.T, claims map[string]interface{}) string {
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
	token, err := josejwt.Signed(p.signer).Claims(final).Serialize()
	require.NoError(t, err)
	return token
}

// baseConfig uses the canonical plural expected_audiences form; legacy
// singular audience compatibility gets its own explicit tests below.
func baseConfig(p *testIdP) *Config {
	return &Config{
		OAuth: OAuthConfig{
			Issuer:            p.issuer,
			JWKSURL:           p.server.URL + "/jwks",
			ExpectedAudiences: []string{p.audience},
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

func newTestVerifier(t *testing.T, cfg *Config) *Verifier {
	t.Helper()
	v, err := NewVerifier(cfg)
	require.NoError(t, err)
	return v
}

// writeFile is a t.TempDir-friendly os.WriteFile wrapper for config-fixture
// tests.
func writeFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o600)
}

func basicHeader(user, token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+token))
}

func TestVerifierAcceptsValidJWT(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp verifyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "alice@example.com", resp.Email)
}

// TestVerifierAcceptsLegacySingularAudienceEndToEnd is the HTTP-level
// counterpart of TestValidateConfigAcceptsLegacySingularAudience: the
// legacy singular oauth.audience form must still authenticate a real
// request through the full Handler, not merely pass config activation.
func TestVerifierAcceptsLegacySingularAudienceEndToEnd(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.OAuth.ExpectedAudiences = nil
	cfg.OAuth.Audience = p.audience
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestVerifierRejectsWrongAudience(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"aud":            "some-other-api",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.NotEqual(t, http.StatusOK, rr.Code)
}

// TestVerifierRejectsAudienceExactly is the trailing-slash-mismatch
// regression: audience comparison is byte-exact, not slash-normalized.
func TestVerifierRejectsAudienceExactly(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.OAuth.ExpectedAudiences = []string{p.audience + "/"}
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}

// TestVerifierRejectsIssuerExactly is the issuer counterpart: a trailing
// slash on the configured issuer must not match a token whose iss omits it
// (or vice versa).
func TestVerifierRejectsIssuerExactly(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.OAuth.Issuer = p.issuer + "/"
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}

// TestVerifierSupportsJWKSOnlyWithNoConfiguredIssuer is a compatibility
// regression: a pinned-JWKS deployment without a configured issuer must
// keep working — an empty issuer must not become a new prerequisite.
func TestVerifierSupportsJWKSOnlyWithNoConfiguredIssuer(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.OAuth.Issuer = ""
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// TestVerifierSupportsEmailUsernameClaimWithoutSub is a compatibility
// regression: username_claim: email deployments never required sub, and
// phase 1 must not start requiring it.
func TestVerifierSupportsEmailUsernameClaimWithoutSub(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"email":          "alice@example.com",
		"email_verified": true,
		"sub":            nil, // genuinely absent, not zero/empty
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestVerifierRejectsExpiredJWT(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
		"exp":            time.Now().Add(-time.Hour).Unix(),
		"iat":            time.Now().Add(-2 * time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.NotEqual(t, http.StatusOK, rr.Code)
}

// TestVerifierRejectsMissingExp is the actual-omitted-claim regression: exp
// is mandatory, and a genuinely absent exp (not a zero value) must fail.
func TestVerifierRejectsMissingExp(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
		"exp":            nil,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestVerifierRejectsUserVsEmailMismatch(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	// Try to impersonate bob using alice's JWT.
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("bob@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	// The HTTP-facing body must be the fixed, non-disclosing message — see
	// TestVerifierHTTPBodyNeverDisclosesFailureReason for the full
	// cross-cause proof. It must NOT contain diagnostic details like "does
	// not match", the claim name, or either email address.
	require.Equal(t, errAuthenticationFailed.Error()+"\n", rr.Body.String())
}

func TestVerifierLowercaseEqualMatching(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "Alice@Example.com",
		"email_verified": true,
	})

	// Lowercase Basic user must match the email claim under lowercase_equal.
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestVerifierRejectsUnverifiedEmail(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": false,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestVerifierEnforcesAllowedEmailDomains(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.Identity.AllowedEmailDomains = []string{"altinity.com"}
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestVerifierEnforcesRequiredScopes(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.OAuth.RequiredScopes = []string{"mcp:read"}
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
		"scope":          "mcp:write",
	})
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

// TestVerifierRejectsReservedUsername proves denied_usernames is enforced
// end to end through the HTTP handler on an otherwise fully valid request.
func TestVerifierRejectsReservedUsername(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.Identity.UsernameClaim = "sub"
	cfg.Identity.MatchMode = "exact"
	cfg.Identity.RequireEmailVerified = false
	cfg.Identity.DeniedUsernames = []string{"default", "admin", "operator"}
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{"sub": "default"})
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("default", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

// TestVerifierDeniedUsernamesDefaultEmpty proves merely upgrading an
// existing deployment (no denied_usernames configured) does not begin
// rejecting a previously-accepted username.
func TestVerifierDeniedUsernamesDefaultEmpty(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.Identity.UsernameClaim = "sub"
	cfg.Identity.MatchMode = "exact"
	cfg.Identity.RequireEmailVerified = false
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{"sub": "default"})
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("default", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestVerifierAppliesScopeSettings(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.SettingsFromScope = map[string]map[string]string{
		"mcp:read": {"readonly": "1"},
	}
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
		"scope":          "mcp:read",
	})
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp verifyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "1", resp.Settings["readonly"])
}

func TestVerifierRejectsUnsupportedMethods(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/verify", nil)
		req.Header.Set("Authorization", basicHeader("alice@example.com", "irrelevant"))
		rr := httptest.NewRecorder()
		v.Handler().ServeHTTP(rr, req)
		require.Equal(t, http.StatusMethodNotAllowed, rr.Code, "method %s should be rejected", method)
		require.Equal(t, "GET, POST", rr.Header().Get("Allow"))
	}
}

// CH 26.1 Antalya invokes <http_authentication_servers> via GET; returning 405
// would silently break delegation (CH treats the server as unhealthy and
// reports WRONG_PASSWORD without forwarding). Verify GET is accepted and
// reaches the auth-header check.
func TestVerifierAcceptsGET(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	// No Authorization header → should be a 401 from parseBasicAuth, NOT a
	// 405 from the method gate. The 401 proves the request reached past the
	// method check.
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestVerifierRejectsMissingAuthHeader(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestVerifierNegativeCacheSuppressesRepeatedFailures(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": false, // → fail
	})

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/verify", nil)
		req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
		rr := httptest.NewRecorder()
		v.Handler().ServeHTTP(rr, req)
		require.Equal(t, http.StatusForbidden, rr.Code)
	}
}

func TestCacheHitPreservesEmail(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	// First request populates the cache.
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var first verifyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &first))
	require.Equal(t, "alice@example.com", first.Email)

	// Second request is a cache hit. Email must still surface.
	req2 := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req2.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr2 := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr2, req2)
	require.Equal(t, http.StatusOK, rr2.Code)
	var second verifyResponse
	require.NoError(t, json.Unmarshal(rr2.Body.Bytes(), &second))
	require.Equal(t, "alice@example.com", second.Email)
}

// TestCacheKeyIncludesUsername is the regression test for GH-13: the
// verification cache was keyed on sha256(token) alone, so once a token had
// been verified for one Basic-auth username, replaying the SAME token under
// a DIFFERENT username hit the cache and skipped the user-vs-claim check
// entirely — letting an attacker in possession of alice's JWT authenticate
// as bob (or any other configured user) after alice's first request warmed
// the cache.
func TestCacheKeyIncludesUsername(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	// First request as alice succeeds and populates the cache.
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// Replaying the SAME token as bob must still be rejected — a cache hit
	// keyed only on the token would incorrectly let bob in as alice.
	req2 := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req2.Header.Set("Authorization", basicHeader("bob@example.com", tok))
	rr2 := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr2, req2)
	require.Equal(t, http.StatusForbidden, rr2.Code, rr2.Body.String())
}

// TestCacheKeyIsolatesNegativeCacheByUser covers the symmetric direction of
// GH-13: with a token-only cache key, a mismatched user presenting someone
// else's JWT would populate the *negative* cache under a key derived only
// from the token. The legitimate owner of that JWT would then hit the same
// negative-cache entry and be wrongly rejected until negative_ttl expired.
//
// This mirrors the issue's exact reproduction: identity.username_claim set
// to a custom claim (clickhouse_user) with two tenant usernames.
func TestCacheKeyIsolatesNegativeCacheByUser(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.Identity.UsernameClaim = "clickhouse_user"
	cfg.Identity.MatchMode = "exact"
	v := newTestVerifier(t, cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":             "u-1",
		"clickhouse_user": "ch-tenant-a",
		"email":           "alice@example.com",
		"email_verified":  true,
	})

	// ch-tenant-b wrongly presents ch-tenant-a's JWT first. This must be
	// rejected and, being a permanent (non-transient) failure, negative-cached.
	reqWrong := httptest.NewRequest(http.MethodPost, "/verify", nil)
	reqWrong.Header.Set("Authorization", basicHeader("ch-tenant-b", tok))
	rrWrong := httptest.NewRecorder()
	v.Handler().ServeHTTP(rrWrong, reqWrong)
	require.Equal(t, http.StatusForbidden, rrWrong.Code, rrWrong.Body.String())

	// ch-tenant-a then presents the SAME token as its rightful owner. A cache
	// keyed only on the token would incorrectly serve ch-tenant-b's cached
	// negative result here and reject a legitimate request.
	reqRight := httptest.NewRequest(http.MethodPost, "/verify", nil)
	reqRight.Header.Set("Authorization", basicHeader("ch-tenant-a", tok))
	rrRight := httptest.NewRecorder()
	v.Handler().ServeHTTP(rrRight, reqRight)
	require.Equal(t, http.StatusOK, rrRight.Code, rrRight.Body.String())
}

func TestParseBasicAuth(t *testing.T) {
	t.Parallel()
	u, tk, ok := parseBasicAuth("Basic " + base64.StdEncoding.EncodeToString([]byte("alice@example.com:jwt-string")))
	require.True(t, ok)
	require.Equal(t, "alice@example.com", u)
	require.Equal(t, "jwt-string", tk)

	_, _, ok = parseBasicAuth("Bearer xyz")
	require.False(t, ok)

	_, _, ok = parseBasicAuth("")
	require.False(t, ok)
}

func TestSettingsFromScopes(t *testing.T) {
	t.Parallel()
	mapping := map[string]map[string]string{
		"mcp:read":  {"readonly": "1"},
		"mcp:write": {"max_memory_usage": "1000000000"},
	}
	got := settingsFromScopes([]string{"mcp:read"}, mapping)
	require.Equal(t, map[string]string{"readonly": "1"}, got)

	got = settingsFromScopes([]string{"unknown"}, mapping)
	require.Nil(t, got)

	got = settingsFromScopes(nil, mapping)
	require.Nil(t, got)
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	require.Equal(t, "email", cfg.Identity.UsernameClaim)
	require.Equal(t, "lowercase_equal", cfg.Identity.MatchMode)
	require.True(t, cfg.Identity.RequireEmailVerified)
	require.Equal(t, 60*time.Second, cfg.OAuth.VerifierLeeway)
}

func TestValidateConfigRejectsEmpty(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{})
	require.Error(t, err)
}

func TestValidateConfigRejectsBothListeners(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{
		Listen: ListenConfig{Unix: "/tmp/s", TCP: "127.0.0.1:1"},
		OAuth:  OAuthConfig{Issuer: "https://x", Audience: "a"},
	})
	require.ErrorContains(t, err, "mutually exclusive")
}

func TestValidateConfigRequiresAudience(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{
		Listen: ListenConfig{Unix: "/tmp/s"},
		OAuth:  OAuthConfig{Issuer: "https://x"},
	})
	require.ErrorContains(t, err, "audience")
}

// TestValidateConfigAcceptsLegacySingularAudience proves the legacy
// oauth.audience form alone still activates successfully.
func TestValidateConfigAcceptsLegacySingularAudience(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{
		Listen: ListenConfig{Unix: "/tmp/s"},
		OAuth:  OAuthConfig{Issuer: "https://x", Audience: "a"},
	})
	require.NoError(t, err)
}

// TestValidateConfigAcceptsPluralAudiences proves the canonical plural
// expected_audiences form alone activates successfully.
func TestValidateConfigAcceptsPluralAudiences(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{
		Listen: ListenConfig{Unix: "/tmp/s"},
		OAuth:  OAuthConfig{Issuer: "https://x", ExpectedAudiences: []string{"a", "b"}},
	})
	require.NoError(t, err)
}

// TestValidateConfigRejectsPluralAndSingularBothConfigured is the YAML
// plural + YAML legacy singular activation-failure regression.
func TestValidateConfigRejectsPluralAndSingularBothConfigured(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{
		Listen: ListenConfig{Unix: "/tmp/s"},
		OAuth: OAuthConfig{
			Issuer:            "https://x",
			Audience:          "a",
			ExpectedAudiences: []string{"b"},
		},
	})
	require.ErrorContains(t, err, "mutually exclusive")
}

// TestValidateConfigRejectsPluralWithOnlyEmptyEntries proves a plural list
// that's present but leaves nothing after discarding empty/whitespace-only
// entries is a config error, not silent fallback to "no audience configured".
func TestValidateConfigRejectsPluralWithOnlyEmptyEntries(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{
		Listen: ListenConfig{Unix: "/tmp/s"},
		OAuth:  OAuthConfig{Issuer: "https://x", ExpectedAudiences: []string{"", "   "}},
	})
	require.ErrorContains(t, err, "expected_audiences")
}

// TestValidateConfigRejectsNegativeVerifierLeeway proves a negative
// verifier_leeway fails config activation.
func TestValidateConfigRejectsNegativeVerifierLeeway(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{
		Listen: ListenConfig{Unix: "/tmp/s"},
		OAuth:  OAuthConfig{Issuer: "https://x", Audience: "a", VerifierLeeway: -time.Second},
	})
	require.ErrorContains(t, err, "verifier_leeway")
}

// TestLoadConfigOldYAMLTagsRemainValid parses a YAML fixture exercising
// every pre-existing tag (jwks_url, required_scopes, jwks_cache_ttl,
// jwks_refresh_ahead) to prove the refactor didn't silently rename any of
// them.
func TestLoadConfigOldYAMLTagsRemainValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/config.yaml"
	require.NoError(t, writeFile(path, `
listen:
  tcp: "127.0.0.1:9999"
oauth:
  issuer: "https://issuer.example.com"
  jwks_url: "https://issuer.example.com/jwks"
  audience: "ch-jwt-verify.test"
  required_scopes: ["mcp:read"]
  jwks_cache_ttl: 90s
  jwks_refresh_ahead: 30s
identity:
  username_claim: email
  match_mode: lowercase_equal
cache:
  positive_ttl: 15s
  negative_ttl: 2m
`))

	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com", cfg.OAuth.Issuer)
	require.Equal(t, "https://issuer.example.com/jwks", cfg.OAuth.JWKSURL)
	require.Equal(t, "ch-jwt-verify.test", cfg.OAuth.Audience)
	require.Equal(t, []string{"mcp:read"}, cfg.OAuth.RequiredScopes)
	require.Equal(t, 90*time.Second, cfg.OAuth.JWKSCacheTTL)
	require.Equal(t, 30*time.Second, cfg.OAuth.JWKSRefreshAhead)
	require.Equal(t, 15*time.Second, cfg.Cache.PositiveTTL)
	require.Equal(t, 2*time.Minute, cfg.Cache.NegativeTTL)
}

// TestLoadConfigPluralAudiencePlusLegacyEnvFailsActivation is the
// plural-YAML + CH_JWT_VERIFY_OAUTH_AUDIENCE activation-failure regression:
// the env override still writes to the legacy singular field, so both forms
// end up populated after layering and config activation must fail — not
// silently prefer one source over the other.
func TestLoadConfigPluralAudiencePlusLegacyEnvFailsActivation(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.yaml"
	require.NoError(t, writeFile(path, `
listen:
  tcp: "127.0.0.1:9999"
oauth:
  issuer: "https://issuer.example.com"
  expected_audiences: ["a", "b"]
`))

	t.Setenv("CH_JWT_VERIFY_OAUTH_AUDIENCE", "env-audience")
	defer os.Unsetenv("CH_JWT_VERIFY_OAUTH_AUDIENCE")

	_, err := LoadConfig(path)
	require.Error(t, err)
	require.ErrorContains(t, err, "mutually exclusive")
}

// TestTransientErrorSkipsNegativeCache asserts that a JWKS-fetch failure
// (network blip / upstream 5xx) does NOT populate the negative cache, so a
// retry on the next request is allowed to succeed once the upstream recovers.
// Otherwise multi-replica deployments would see asymmetric "one replica
// 403s every request for 5 minutes" failure modes after a single blip.
func TestTransientErrorSkipsNegativeCache(t *testing.T) {
	t.Parallel()
	// Point JWKSURL at a server that returns 503 — the verifier wraps this
	// with oauth.ErrTransient. We don't need to mint a real JWT: the
	// validation fails at the JWKS-fetch step, before signature checks.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	cfg := &Config{
		OAuth: OAuthConfig{
			Issuer:            "https://issuer.example.com",
			JWKSURL:           bad.URL,
			ExpectedAudiences: []string{"ch-jwt-verify.test"},
		},
		Identity: IdentityConfig{UsernameClaim: "email", MatchMode: "lowercase_equal"},
		Cache:    CacheConfig{PositiveTTL: 30 * time.Second, NegativeTTL: 5 * time.Minute},
	}
	v := newTestVerifier(t, cfg)

	// Mint a real-shaped JWT against a separate IdP just so the verifier
	// reaches the JWKS-fetch step — sign+aud don't matter because the
	// JWKS endpoint 503s first.
	p := newTestIdP(t)
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

// TestVerifierHTTPBodyNeverDisclosesFailureReason proves the security
// requirement this phase's integration work must add: the HTTP body must be
// byte-identical across every distinct failure cause (bad signature, wrong
// audience, wrong issuer, expired token, username mismatch, reserved
// username, unverified email, disallowed email domain, disallowed hosted
// domain, and a transient JWKS-fetch failure), so a caller can't distinguish
// which check failed from the response alone.
//
// The missing/malformed-Authorization-header case is deliberately out of
// scope here: it's a distinct, pre-existing 401 transport-level rejection,
// not a credential-validation failure — see TestVerifierRejectsMissingAuthHeader.
func TestVerifierHTTPBodyNeverDisclosesFailureReason(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.Identity.UsernameClaim = "sub"
	cfg.Identity.MatchMode = "exact"
	cfg.Identity.DeniedUsernames = []string{"reserved-user"}
	cfg.Identity.AllowedEmailDomains = []string{"allowed.example.com"}
	cfg.Identity.AllowedHostedDomains = []string{"allowed-hd.example.com"}
	v := newTestVerifier(t, cfg)

	otherIdP := newTestIdP(t)

	cases := map[string]struct {
		user string
		tok  string
	}{
		"bad_signature": {
			user: "u-1",
			tok:  otherIdP.mintJWT(t, map[string]interface{}{"sub": "u-1", "aud": p.audience, "iss": p.issuer}),
		},
		"wrong_audience": {
			user: "u-1",
			tok:  p.mintJWT(t, map[string]interface{}{"sub": "u-1", "aud": "wrong-aud"}),
		},
		"expired": {
			user: "u-1",
			tok:  p.mintJWT(t, map[string]interface{}{"sub": "u-1", "exp": time.Now().Add(-time.Hour).Unix()}),
		},
		"username_mismatch": {
			user: "someone-else",
			tok:  p.mintJWT(t, map[string]interface{}{"sub": "u-1"}),
		},
		"reserved_username": {
			user: "reserved-user",
			tok: p.mintJWT(t, map[string]interface{}{
				"sub": "reserved-user", "email": "alice@allowed.example.com", "email_verified": true,
				"hd": "allowed-hd.example.com",
			}),
		},
		"disallowed_email_domain": {
			user: "u-2",
			tok: p.mintJWT(t, map[string]interface{}{
				"sub": "u-2", "email": "alice@not-allowed.example.com", "email_verified": true,
			}),
		},
		"disallowed_hosted_domain": {
			user: "u-3",
			tok: p.mintJWT(t, map[string]interface{}{
				"sub": "u-3", "email": "alice@allowed.example.com", "email_verified": true,
				"hd": "not-allowed-hd.example.com",
			}),
		},
	}

	var bodies []string
	for name, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/verify", nil)
		req.Header.Set("Authorization", basicHeader(tc.user, tc.tok))
		rr := httptest.NewRecorder()
		v.Handler().ServeHTTP(rr, req)
		require.Equal(t, http.StatusForbidden, rr.Code, "case %s", name)
		bodies = append(bodies, rr.Body.String())
	}

	// A transient JWKS-fetch failure must produce the identical body too —
	// this uses its own Verifier (a different JWKS backend is what makes the
	// failure transient), so it's checked separately from the map above.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	transientCfg := baseConfig(p)
	transientCfg.OAuth.JWKSURL = bad.URL
	transientV := newTestVerifier(t, transientCfg)
	transientTok := p.mintJWT(t, map[string]interface{}{"sub": "u-1", "email": "alice@example.com", "email_verified": true})
	reqTransient := httptest.NewRequest(http.MethodPost, "/verify", nil)
	reqTransient.Header.Set("Authorization", basicHeader("alice@example.com", transientTok))
	rrTransient := httptest.NewRecorder()
	transientV.Handler().ServeHTTP(rrTransient, reqTransient)
	require.Equal(t, http.StatusForbidden, rrTransient.Code)
	bodies = append(bodies, rrTransient.Body.String())

	for i, b := range bodies {
		require.Equal(t, errAuthenticationFailed.Error()+"\n", b, "case index %d must return the fixed generic message", i)
	}
}

// TestVerifierHTTPBodyNeverContainsToken is the credential-leakage
// regression: neither the token nor the Basic-auth password ever appears in
// the HTTP response body.
func TestVerifierHTTPBodyNeverContainsToken(t *testing.T) {
	t.Parallel()
	const marker = "SECRET-TOKEN-MARKER"
	p := newTestIdP(t)
	v := newTestVerifier(t, baseConfig(p))

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", "not-a-jwt-"+marker))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
	require.NotContains(t, rr.Body.String(), marker)
}

// TestJWKSHealthTracking asserts the underlying go-mcp-oauth-sdk Verifier records
// fetch attempts/successes/errors that the sidecar's /readyz handler
// consumes. We don't HTTP-test /readyz directly because the handler lives in
// main.go and the wiring is trivial — the meaningful contract is the health
// triple's transitions.
func TestJWKSHealthTracking(t *testing.T) {
	t.Parallel()

	t.Run("zero_before_any_fetch", func(t *testing.T) {
		t.Parallel()
		p := newTestIdP(t)
		v := newTestVerifier(t, baseConfig(p))
		lastAttempt, lastSuccess, lastErr := v.JWKSHealth()
		require.True(t, lastAttempt.IsZero())
		require.True(t, lastSuccess.IsZero())
		require.NoError(t, lastErr)
	})

	t.Run("success_marks_both_attempt_and_success", func(t *testing.T) {
		t.Parallel()
		p := newTestIdP(t)
		v := newTestVerifier(t, baseConfig(p))
		tok := p.mintJWT(t, map[string]interface{}{
			"sub":            "u-1",
			"email":          "alice@example.com",
			"email_verified": true,
		})
		req := httptest.NewRequest(http.MethodPost, "/verify", nil)
		req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
		rr := httptest.NewRecorder()
		v.Handler().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		lastAttempt, lastSuccess, lastErr := v.JWKSHealth()
		require.False(t, lastAttempt.IsZero())
		require.False(t, lastSuccess.IsZero())
		require.NoError(t, lastErr)
		require.False(t, lastSuccess.Before(lastAttempt),
			"successful fetch must record success >= attempt")
	})

	t.Run("failure_records_error_with_attempt_after_success", func(t *testing.T) {
		t.Parallel()
		// Point JWKSURL at a server that 503s — the fetch attempt is
		// recorded but lastSuccess stays in the past relative to lastAttempt.
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer bad.Close()
		cfg := &Config{
			OAuth: OAuthConfig{
				Issuer:            "https://issuer.example.com",
				JWKSURL:           bad.URL,
				ExpectedAudiences: []string{"ch-jwt-verify.test"},
			},
			Identity: IdentityConfig{UsernameClaim: "email", MatchMode: "lowercase_equal"},
			Cache:    CacheConfig{PositiveTTL: 30 * time.Second, NegativeTTL: 5 * time.Minute},
		}
		v := newTestVerifier(t, cfg)
		p := newTestIdP(t)
		tok := p.mintJWT(t, map[string]interface{}{
			"sub":            "u-1",
			"email":          "alice@example.com",
			"email_verified": true,
		})
		req := httptest.NewRequest(http.MethodPost, "/verify", nil)
		req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
		rr := httptest.NewRecorder()
		v.Handler().ServeHTTP(rr, req)
		require.Equal(t, http.StatusForbidden, rr.Code)
		lastAttempt, lastSuccess, lastErr := v.JWKSHealth()
		require.False(t, lastAttempt.IsZero())
		require.True(t, lastSuccess.Before(lastAttempt),
			"after a failed fetch lastSuccess must be older than lastAttempt — that's how /readyz detects unhealthy")
		require.Error(t, lastErr)
	})
}

// noop assertions to keep `context` referenced if the file shrinks.
var _ = context.Background
