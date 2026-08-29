package verification

// This file covers plan-19p5 §5.6 (shared verifier redaction marker matrix)
// and §4.4 (post-bump JWKS-rotation proof that the now-closed
// SDK_REDACTION_AUTHORIZATION_GATE blocker stays fixed), per the phase-5
// plan's §23.6 implementation-order step 6.
//
// --- A2 global-logger-capture discipline (binding on this file) ---
//
// zerolog's process-global logger (github.com/rs/zerolog/log's package-level
// Logger var) and its process-global level are shared by every importer of
// that package, including github.com/altinity/go-mcp-oauth-sdk/oauth. Any
// test here that wants to observe what the shared JWT-verification path logs
// — including the SDK's debug/info/trace-level sinks, which are silent
// unless the global level is raised — must swap that single global var and
// raise that single global level for the duration of the assertion, via
// captureLog below. That is a mutation of process-wide state, so:
//
//   - every test/subtest in this file that calls captureLog must NOT call
//     t.Parallel(), neither on itself nor on any t.Run group containing it;
//   - in practice, every top-level test in THIS file calls captureLog (both
//     TestRedactionMatrix_RejectionCases and
//     TestJWKSRotation_KidNeverLogged do), so neither one — nor
//     either one's t.Run subtests — ever calls t.Parallel() here; a test
//     that only asserted on the returned error, with no log capture at
//     all, would be free to call t.Parallel() as usual, but that
//     hypothetical case has no example in this file today;
//   - this relies on the same repo-wide convention documented at
//     cmd/ch-jwt-verify/verify_test.go's
//     TestVerifyRejectionLogRedactsCredentialShapedRequestedUsername: Go
//     only starts a parallel top-level test's *body* once every top-level
//     test that never called t.Parallel() has already run to completion, so
//     a capturing (non-parallel) test here can never interleave with a
//     parallel sibling's own logging.
//
// --- §5.5 JWKS response-close warning: determined unreachable here ---
//
// oauth.jwks.go's fetchJWKSet logs a Warn-level line only when
// resp.Body.Close() itself returns a non-nil error. oauth.OAuthConfig
// exposes no http.Client / http.RoundTripper override, and fetchJWKSet
// always uses its own internal `&http.Client{Timeout: httpTimeout}` — so
// nothing reachable from internal/verification's exported surface (Config,
// New, Verify) can inject a Closer that fails to close. This audit item is
// therefore not exercisable as a black-box test at this layer; it stays
// owned by whatever redaction-inventory test drives the SDK package
// directly (see plan §5.1/§5.5), not this file.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/altinity/altinity-oauth-helper/internal/identity"
)

// Distinctive, alphanumeric-only markers (no '.' — so none of them can ever
// accidentally satisfy identity.looksCredentialShaped's three-dot-segment
// check on their own) embedded respectively in JWT header fields, payload
// claim values, and raw signature bytes across this file's cases.
const (
	headerMarker  = "MRKHDR7f3c9a1e2b"
	payloadMarker = "MRKPAY2b6d4f08c1"
	sigMarker     = "MRKSIG91ac5e77d3"
)

// captureLog swaps the process-global zerolog logger for a buffer sink and
// raises the process-global level to Trace for the duration of the calling
// test, restoring both via t.Cleanup. See the file header: callers must not
// be, or be inside, a t.Parallel() test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	prevLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	prevLogger := log.Logger
	buf := &bytes.Buffer{}
	log.Logger = zerolog.New(buf).Level(zerolog.TraceLevel)
	t.Cleanup(func() {
		log.Logger = prevLogger
		zerolog.SetGlobalLevel(prevLevel)
	})
	return buf
}

// b64urlNoPad matches the unpadded base64url encoding compact JWT segments
// use.
func b64urlNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// rawCompactJWTWithHeader hand-constructs a compact-serialized JWT from an
// arbitrary header map, an arbitrary claims map, and an arbitrary raw
// signature segment — bypassing jose.Signer (which only accepts header
// values from its own known-shape enums and would refuse to build a token
// with marker content in arbitrary header fields). go-jose's
// jwt.ParseSigned sanitizes and validates the header before any signature
// verification happens, so callers that want a parse-time (pre-signature)
// rejection can put anything in sig — it is never read once the header
// itself is already rejected.
func rawCompactJWTWithHeader(t *testing.T, header map[string]interface{}, claims map[string]interface{}, sig []byte) string {
	t.Helper()
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	payloadBytes, err := json.Marshal(claims)
	require.NoError(t, err)
	return b64urlNoPad(headerBytes) + "." + b64urlNoPad(payloadBytes) + "." + b64urlNoPad(sig)
}

// rejectionCase is one row of TestRedactionMatrix_RejectionCases: build
// constructs the Verifier config, the requested username, and the token for
// this case; wantIs/wantIsNot assert errors.Is classification, which must
// survive redaction unchanged (plan §5.6: "preserving errors.Is/errors.As
// classification").
type rejectionCase struct {
	name      string
	build     func(t *testing.T, p *testIdP) (cfg Config, username, token string)
	wantIs    []error
	wantIsNot []error
}

// TestRedactionMatrix_RejectionCases is the plan §5.6 marker matrix: every
// listed rejection cause, each as its own subtest, each asserting that
// neither the returned error's text nor anything captured via zerolog ever
// contains the header/payload/signature markers embedded in that case's
// token — while errors.Is/errors.As classification (oauth.ErrInvalidToken
// vs oauth.ErrTransient, or the case's own specific sentinel) is preserved.
//
// The whole test runs non-parallel (see the file header): a single shared
// captured-log buffer spans every subtest, and each subtest's assertion
// checks the buffer's contents as of that point — so a leak in case N can
// never be masked by case N+1 not yet having run, nor attributed to the
// wrong case by a concurrently-running parallel sibling writing into the
// same buffer.
func TestRedactionMatrix_RejectionCases(t *testing.T) {
	p := newTestIdP(t)
	buf := captureLog(t)

	cases := []rejectionCase{
		{
			// looksLikeJWT (oauth/jwt.go) rejects before any JWKS work: not
			// even two dots.
			name: "malformed compact JWT",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				return baseConfig(p), "alice@example.com", "not-a-jwt-" + headerMarker + "-" + payloadMarker
			},
			wantIs:    []error{oauth.ErrInvalidToken},
			wantIsNot: []error{oauth.ErrTransient},
		},
		{
			// Bad alg (unsupported signature algorithm) forces go-jose's
			// jwt.ParseSigned to fail before any signature check, which the
			// SDK wraps as jwtHeaderParseError and sanitizes to a fixed
			// message. typ and kid are also marker-bearing here, to prove
			// the whole header — not just alg — is covered by that
			// sanitization, not enumerated field by field.
			name: "malformed header/type/algorithm",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				header := map[string]interface{}{
					"alg": "bogus-alg-" + headerMarker,
					"typ": "bogus-typ-" + headerMarker,
					"kid": "bogus-kid-" + headerMarker,
				}
				claims := map[string]interface{}{
					"sub":   "u-1",
					"email": "alice@example.com",
					"jti":   payloadMarker,
				}
				tok := rawCompactJWTWithHeader(t, header, claims, []byte("sig-"+sigMarker))
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs:    []error{oauth.ErrInvalidToken},
			wantIsNot: []error{oauth.ErrTransient},
		},
		{
			// A well-formed signature over a kid absent from the JWKS (and
			// still absent after the one-shot rotation re-fetch) is the
			// "unknown kid" ErrTransient path, sanitized so the raw kid
			// value (headerMarker here) never reaches the caller.
			name: "unknown kid",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWTWithKeyKid(t, p.priv, "unknown-"+headerMarker, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrTransient},
		},
		{
			// Signed with a key that is NOT the one published under this kid
			// — kid lookup succeeds, but parsed.Claims fails signature
			// verification for every candidate key. This is the one
			// deliberately unclassified case (see oauth's own
			// TestValidateStrictJWT_SignatureAndIssuer/"invalid signature
			// fails", which likewise only asserts require.Error): the SDK
			// returns a bare "failed to verify JWT signature" error, not
			// wrapped in ErrInvalidToken or ErrTransient.
			name: "invalid signature",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				tok := p.mintJWTWithKeyKid(t, wrongKey, p.currentKID(), map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIsNot: []error{oauth.ErrInvalidToken, oauth.ErrTransient},
		},
		{
			name: "issuer mismatch",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
					"iss": "https://wrong-issuer.example.com",
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrInvalidToken},
		},
		{
			name: "string audience mismatch",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
					"aud": "wrong-aud-" + payloadMarker,
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrInvalidToken},
		},
		{
			name: "array audience mismatch",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
					"aud": []string{"wrong-1-" + payloadMarker, "wrong-2"},
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrInvalidToken},
		},
		{
			name: "missing exp",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker, "exp": nil,
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrInvalidToken},
		},
		{
			name: "malformed exp",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
					"exp": "not-a-number-" + payloadMarker,
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrInvalidToken},
		},
		{
			name: "expired exp",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
					"exp": time.Now().Add(-time.Hour).Unix(),
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrTokenExpired},
		},
		{
			name: "invalid nbf",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
					"nbf": "not-a-number-" + payloadMarker,
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrInvalidToken},
		},
		{
			name: "invalid iat",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
					"iat": "not-a-number-" + payloadMarker,
				})
				return baseConfig(p), "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrInvalidToken},
		},
		{
			// The requested username itself is deliberately marker-free
			// here: a non-credential-shaped username is *safely* echoed
			// verbatim into ErrUsernameMismatch's text by design (see
			// identity.RedactUsername) — that is expected, not a leak. The
			// marker instead lives in the token's own "jti" claim, so this
			// case still proves the token's content doesn't leak on a
			// mismatch.
			name: "username mismatch",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
				})
				return baseConfig(p), "bob@example.com", tok
			},
			wantIs: []error{identity.ErrUsernameMismatch},
		},
		{
			name: "denied username",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				cfg := baseConfig(p)
				cfg.Identity.DeniedUsernames = []string{"carol@example.com"}
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "carol@example.com", "jti": payloadMarker,
				})
				return cfg, "carol@example.com", tok
			},
			wantIs: []error{identity.ErrReservedUsername},
		},
		{
			name: "email domain policy",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				cfg := baseConfig(p)
				cfg.Identity.ClaimPolicy = oauth.IdentityPolicy{AllowedEmailDomains: []string{"allowed.example.com"}}
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@notallowed.example.com", "jti": payloadMarker,
				})
				return cfg, "alice@notallowed.example.com", tok
			},
			wantIs: []error{oauth.ErrUnauthorizedDomain},
		},
		{
			name: "scopes",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				cfg := baseConfig(p)
				cfg.RequiredScopes = []string{"required-scope"}
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
					"scope": "other-scope-" + payloadMarker,
				})
				return cfg, "alice@example.com", tok
			},
			wantIs: []error{oauth.ErrInsufficientScopes},
		},
		{
			// A malformed/oddly-shaped "groups" claim must not crash claim
			// projection nor leak through a later, unrelated rejection
			// (username mismatch, which happens in identity.Bind — after
			// claimsFromRawClaims has already built Claims.Extra["groups"]
			// from this exact malformed value).
			name: "malformed groups claim",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com",
					"groups": map[string]interface{}{
						"unexpected-shape": payloadMarker,
						"nested":           []interface{}{1, 2, payloadMarker},
					},
				})
				// The requested username is deliberately marker-free — see
				// the "username mismatch" case's comment above for why.
				return baseConfig(p), "someone-else@example.com", tok
			},
			wantIs: []error{identity.ErrUsernameMismatch},
		},
		{
			name: "transient discovery/JWKS error",
			build: func(t *testing.T, p *testIdP) (Config, string, string) {
				bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				t.Cleanup(bad.Close)
				cfg := baseConfig(p)
				cfg.JWKSURL = bad.URL
				tok := p.mintJWT(t, map[string]interface{}{
					"sub": "u-1", "email": "alice@example.com", "jti": payloadMarker,
				})
				return cfg, "alice@example.com", tok
			},
			wantIs:    []error{oauth.ErrTransient},
			wantIsNot: []error{oauth.ErrInvalidToken},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, username, token := tc.build(t, p)
			v, err := New(cfg)
			require.NoError(t, err)

			_, err = v.Verify(context.Background(), username, token)
			require.Error(t, err)
			for _, want := range tc.wantIs {
				require.ErrorIs(t, err, want, "case %q: wrong error classification", tc.name)
			}
			for _, notWant := range tc.wantIsNot {
				require.False(t, errors.Is(err, notWant), "case %q: must NOT classify as %v", tc.name, notWant)
			}

			require.NotContains(t, err.Error(), headerMarker, "case %q: header marker leaked into returned error", tc.name)
			require.NotContains(t, err.Error(), payloadMarker, "case %q: payload marker leaked into returned error", tc.name)
			require.NotContains(t, err.Error(), sigMarker, "case %q: signature marker leaked into returned error", tc.name)
			require.NotContains(t, err.Error(), token, "case %q: raw compact JWT leaked into returned error", tc.name)

			logged := buf.String()
			require.NotContains(t, logged, headerMarker, "case %q: header marker leaked into logs", tc.name)
			require.NotContains(t, logged, payloadMarker, "case %q: payload marker leaked into logs", tc.name)
			require.NotContains(t, logged, sigMarker, "case %q: signature marker leaked into logs", tc.name)
			require.NotContains(t, logged, token, "case %q: raw compact JWT leaked into logs", tc.name)
		})
	}
}

// TestJWKSRotation_KidNeverLogged is plan §4.4's post-bump transition of
// what was plan §4.3's explicit pre-bump characterization of the confirmed
// go-mcp-oauth-sdk v0.2.0 defect gated by SDK_REDACTION_AUTHORIZATION_GATE
// (plan §4.1/§4.2): oauth/jwt.go's parseAndFetchKeys used to log the
// unverified JWT header's raw `kid` via `log.Info().Str("kid", keyID)...`
// on a successful post-rotation re-fetch. go-mcp-oauth-sdk@v0.2.1 fixes
// this: the rotation-success event now logs only a safe numeric
// `matched_keys` count (`log.Info().Int("matched_keys", n).Msg(...)`), never
// the `kid` value. SDK_REDACTION_AUTHORIZATION_GATE is closed
// (redaction-sites.tsv's parseAndFetchKeys row is now `safe`, not
// `blocked_external`) and this test asserts the fix positively: the
// rotation-success event still fires (proving the invalidate+re-fetch
// branch actually executed, not just its absence), but the `kid` marker
// must be ABSENT from the captured log at both default and trace level —
// the opposite assertion from this test's pre-bump predecessor,
// TestJWKSRotation_PreBumpCharacterization. A future regression that
// reintroduces the raw `kid` into this log line — or downgrades this row
// back to blocked_external without also flipping this assertion — is
// exactly what this test exists to catch; see plan §5.10's
// `phase5release`-tagged release gate for the complementary manifest-level
// check.
//
// The rotation fixture proves the targeted branch actually executed — not
// just its absence — by warming the SDK Verifier's real internal JWKS cache
// under key A (a Verify with a long JWKSCacheTTL so the cache entry can't
// simply expire on its own), then live-rotating the test IdP's /jwks
// endpoint to a distinct key B under a marker-bearing kid and verifying a
// token signed by B: the cached JWKS still only has A, so
// oauth.parseAndFetchKeys must invalidate its cache and re-fetch to find B,
// which is exactly the log.Info(...) call under test.
//
// This test does not call t.Parallel(): it captures the process-global
// zerolog logger — see the file header.
func TestJWKSRotation_KidNeverLogged(t *testing.T) {
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.JWKSCacheTTL = time.Hour // long enough that the cache can't expire on its own mid-test
	v, err := New(cfg)
	require.NoError(t, err)

	// Warm the SDK Verifier's internal JWKS cache under key A/kid
	// "test-key" (newTestIdP's default).
	warmupTok := p.mintJWT(t, map[string]interface{}{"sub": "u-1", "email": "alice@example.com"})
	_, err = v.Verify(context.Background(), "alice@example.com", warmupTok)
	require.NoError(t, err, "warm-up verification against key A must succeed before rotation")

	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const rotatedKidMarker = "rotated-kid-" + headerMarker
	p.rotateKey(newKey, rotatedKidMarker)

	const rotationPayloadMarker = "rotation-" + payloadMarker
	rotatedTok := p.mintJWT(t, map[string]interface{}{
		"sub": "u-1", "email": "alice@example.com", "jti": rotationPayloadMarker,
	})
	sigSegment := rotatedTok[strings.LastIndex(rotatedTok, ".")+1:]

	buf := captureLog(t)

	result, err := v.Verify(context.Background(), "alice@example.com", rotatedTok)
	require.NoError(t, err, "verification against the rotated key B must succeed once the SDK re-fetches the JWKS")
	require.Equal(t, "alice@example.com", result.Claims.Email)

	// captureLog runs the process-global zerolog logger at TraceLevel (see
	// the file header) — the most verbose level the SDK's rotation-success
	// log line could ever be emitted at. Any content absent from a
	// TraceLevel capture is therefore also absent at every quieter
	// (default/Info/etc.) level: this single capture proves absence at
	// default and trace level both, per plan §4.4.
	logged := buf.String()
	require.Contains(t, logged, "JWKS re-fetched after key rotation",
		"the rotation-success event must have fired — proves the invalidate+re-fetch branch actually executed, not just its absence")
	// Post-bump fix: go-mcp-oauth-sdk@v0.2.1 replaced the raw `kid` field on
	// this event with a safe `matched_keys` count. This is the closure of
	// SDK_REDACTION_AUTHORIZATION_GATE (plan §4.4) — the opposite assertion
	// from this test's pre-bump predecessor, TestJWKSRotation_PreBumpCharacterization,
	// which required the marker's PRESENCE against the audited v0.2.0.
	require.NotContains(t, logged, rotatedKidMarker,
		"SDK_REDACTION_AUTHORIZATION_GATE is closed: go-mcp-oauth-sdk@v0.2.1 must never log the raw kid on rotation — a reappearance here is a regression, not a known defect")

	require.NotContains(t, logged, rotatedTok, "the raw compact JWT (bearer) must never be logged, rotation or not")
	require.NotContains(t, logged, rotationPayloadMarker, "no payload claim value may be logged")
	require.NotContains(t, logged, sigSegment, "the raw signature segment must never be logged")
}
