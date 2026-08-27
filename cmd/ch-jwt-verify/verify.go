package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/altinity/altinity-oauth-helper/internal/identity"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// Verifier is the sidecar's thin HTTP adapter over the shared
// internal/verification core: Basic-auth parsing, the GET/POST /verify
// handler, and scope→settings response derivation are sidecar-specific;
// JWT/JWKS verification, identity binding, and the verification cache all
// live in internal/verification (and, beneath that, in
// github.com/altinity/go-mcp-oauth-sdk/oauth).
type Verifier struct {
	cfg  *Config
	core *verification.Verifier
}

// verifyResponse is the JSON body returned to ClickHouse on success. The
// `settings` field is the only one CH consumes; we include `email` so an
// operator inspecting sidecar access logs (under `kubectl logs`) can correlate
// queries to principals without grepping the JWT.
type verifyResponse struct {
	Settings map[string]string `json:"settings,omitempty"`
	Email    string            `json:"email,omitempty"`
}

// errAuthenticationFailed is the only error text ever returned for a
// request whose Authorization header parsed but whose credential then
// failed identity/token validation. Collapsing every distinct validation
// failure reason — bad signature, issuer mismatch, audience mismatch,
// missing/malformed/expired exp, username-claim mismatch, reserved
// username, verified-email/domain policy, insufficient scopes, or a
// transient JWKS/network failure — into this one fixed string is a
// deliberate security property, required by the issue's identity contract
// ("authentication failures should not disclose whether failure was caused
// by signature, issuer, audience, username mismatch, reserved username,
// email policy, or token expiry"), not an oversight or a simplification.
// The SDK's ValidateStrictJWT and internal/identity/internal/verification
// return distinct, specific typed errors internally — precisely so callers
// wanting errors.Is/As (like the verification cache, which must preserve
// error identity across cache hits — see CLAUDE.md's cache-correctness
// rule) can still do so. This sidecar is the trust boundary where that
// distinction must stop: operators get the real reason from the structured
// debug log line the handler emits alongside this response (see Handler),
// never from the HTTP body a caller (or anything relaying its response) can
// observe.
//
// This is distinct from the 401 the handler returns when the Authorization
// header itself is missing or unparseable (see the parseBasicAuth branch in
// Handler) — that's a transport-level precondition, not one of the
// identity/token checks this non-disclosure guarantee covers, so it
// intentionally isn't collapsed into this string.
var errAuthenticationFailed = errors.New("authentication failed")

// NewVerifier constructs a Verifier over the shared verification core built
// from cfg. Returns an error on invalid configuration (e.g. an empty
// effective audience list, a negative verifier_leeway, or an unknown
// identity.match_mode) — main.go treats this as a fatal startup error.
func NewVerifier(cfg *Config) (*Verifier, error) {
	core, err := verification.New(cfg.toVerificationConfig())
	if err != nil {
		return nil, err
	}
	return &Verifier{cfg: cfg, core: core}, nil
}

// JWKSHealth surfaces the shared verification core's JWKS-fetch health for
// /readyz. The triple is (last attempt, last success, last error). All-zero
// times mean "no fetch attempted yet" — readiness handlers treat that as a
// boot-grace OK so the kubelet doesn't keep the pod NotReady forever waiting
// for the first /verify request.
func (v *Verifier) JWKSHealth() (lastAttempt, lastSuccess time.Time, lastErr error) {
	return v.core.JWKSHealth()
}

// StartReaper launches a background goroutine that prunes expired
// verification-cache entries every interval and exits when ctx is
// cancelled. Called from main with the same signal-derived context the HTTP
// server uses.
func (v *Verifier) StartReaper(ctx context.Context, interval time.Duration) {
	v.core.StartReaper(ctx, interval)
}

// Handler returns the http.Handler for /verify. Any non-200 status tells
// ClickHouse to reject the authenticator response per CH's docs; the body is
// for the sidecar's log only.
//
// Accepts GET and POST. Earlier code restricted to POST citing the CH 24.x+
// docs, but the live Antalya 26.1 build invokes <http_authentication_servers>
// via GET; a 405 there breaks the delegation entirely (CH silently treats the
// server as unhealthy and reports WRONG_PASSWORD without forwarding). The
// credential-in-URL concern that motivated POST-only does not apply: this
// handler reads only the Authorization header (forwarded by CH per
// <forward_headers>) and discards everything else; the listener binds 127.0.0.1
// only and the in-pod URL never leaves loopback.
func (v *Verifier) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, token, ok := parseBasicAuth(r.Header.Get("Authorization"))
		if !ok {
			// Intentionally a distinct, transport-level rejection (401 +
			// its own message), not the generic credential-validation
			// failure below: there is no credential here to have failed a
			// check, so this isn't a case the errAuthenticationFailed
			// non-disclosure guarantee needs to cover. Do not collapse
			// this into errAuthenticationFailed.
			log.Debug().Msg("verify: missing or malformed Basic Authorization header")
			http.Error(w, "missing or malformed Authorization", http.StatusUnauthorized)
			return
		}

		result, err := v.core.Verify(r.Context(), user, token)
		if err != nil {
			// Full detail goes to the operator-facing debug log only. The
			// HTTP response never gets more than errAuthenticationFailed —
			// see that var's doc comment for why.
			// user is the raw, unvalidated Basic-auth username half —
			// parseBasicAuth places no format constraint on it, so on
			// any rejection path (even one where verification never got
			// far enough to inspect identity, e.g. a bad signature) it
			// could itself be an attacker-supplied JWT or other
			// credential-shaped value. Route it through
			// identity.RedactUsername rather than logging it raw.
			log.Debug().Err(err).Str("user", identity.RedactUsername(user)).Msg("verify: rejected")
			http.Error(w, errAuthenticationFailed.Error(), http.StatusForbidden)
			return
		}

		resp := &verifyResponse{
			Settings: settingsFromScopes(result.Claims.Scopes, v.cfg.SettingsFromScope),
			Email:    result.Claims.Email,
		}
		w.Header().Set("Content-Type", "application/json")
		// verifyResponse is two map[string]string + string fields — Encode
		// can't realistically fail here (no marshal hooks, no Writer
		// errors are surfaced past the header write). Drop deliberately.
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// parseBasicAuth pulls out the user:token pair from `Authorization: Basic …`.
// We don't import net/http's ParseBasicAuth because that lowercases the auth
// scheme; CH sends `Basic` with a fixed casing and we want the strict version.
func parseBasicAuth(header string) (user, token string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	idx := strings.IndexByte(string(decoded), ':')
	if idx < 0 {
		return "", "", false
	}
	return string(decoded[:idx]), string(decoded[idx+1:]), true
}
