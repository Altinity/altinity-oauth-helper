package ldap

// This file covers the phase-5 "LDAP boundary" redaction audit (plan
// §5.8/§8.3/A2/§23.6) against the real production server over TCP, reusing
// protocol_test.go's harness (startTestServer, dialTest, bindAs,
// membershipSearch, requireSuccess, requireInvalidCredentials, account,
// newFakeVerifier, newFakeRoles) unchanged — only this file's own
// markerFailVerifier/successVerifier/markerFailRoles fakes are new, and no
// production file is touched.
//
// Non-parallel rule (A2): every test in this file swaps the process-global
// zerolog log.Logger (and, for the "trace" mode, the process-global zerolog
// level) for the duration of one subtest tree. None of the top-level tests
// or their subtests below may call t.Parallel() — doing so would let this
// file's capture interleave with unrelated concurrent log output from
// another test in this package and produce a flaky false pass/fail. This
// mirrors the discipline already established for
// internal/verification/redaction_matrix_test.go's captureLog and
// cmd/ch-jwt-verify/verify_test.go's captureDebugLog.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	ldapserver "github.com/vjeantet/ldapserver"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"

	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// ---- capture helper (A2: non-parallel, serialized) -------------------------

// redactionCaptureMode names the two log levels A2 requires every marker
// test in this file to run under: "level=default" leaves zerolog's ambient
// global level untouched (bind.go/search.go's production log lines are all
// Info-level, so this is the level a real deployment runs at), and
// "level=trace" raises the global level to Trace so any hypothetical
// future debug/trace-level sink on this path would also be captured and
// checked, not silently skipped.
type redactionCaptureMode struct {
	name  string
	trace bool
}

var redactionCaptureModes = []redactionCaptureMode{
	{name: "level=default", trace: false},
	{name: "level=trace", trace: true},
}

// captureAppLog swaps the process-global zerolog log.Logger for a
// buffer-backed one for the duration of the calling test, restoring both
// the logger and (when mode.trace requested a level change) the global
// level via t.Cleanup. See the file header for why callers must not run in
// parallel with anything else touching these same process globals.
func captureAppLog(t *testing.T, mode redactionCaptureMode) *strings.Builder {
	t.Helper()

	var buf strings.Builder
	prevLogger := log.Logger
	prevLevel := zerolog.GlobalLevel()

	if mode.trace {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}
	log.Logger = zerolog.New(&buf)

	t.Cleanup(func() {
		log.Logger = prevLogger
		zerolog.SetGlobalLevel(prevLevel)
	})

	return &buf
}

// ---- fakes: verifier/roleResolver failures with attacker-shaped errors ----

// markerFailVerifier implements this package's own (unexported) verifier
// interface (server.go) and unconditionally returns err from Verify,
// regardless of the requested username/token — a deterministic stand-in for
// "the shared verifier rejected this credential for some reason whose text
// happens to be attacker-shaped".
type markerFailVerifier struct{ err error }

func (v markerFailVerifier) Verify(_ context.Context, _ string, _ string) (*verification.Result, error) {
	return nil, v.err
}

// successVerifier implements verifier and always returns result, nil — used
// to isolate the role-resolver-failure cases below from any verifier-side
// behavior.
type successVerifier struct{ result *verification.Result }

func (v successVerifier) Verify(_ context.Context, _ string, _ string) (*verification.Result, error) {
	return v.result, nil
}

// markerFailRoles implements this package's own (unexported) roleResolver
// interface (server.go) and unconditionally returns err from Roles.
type markerFailRoles struct{ err error }

func (r markerFailRoles) Roles(_ *oauth.Claims) ([]string, error) {
	return nil, r.err
}

// ---- marker fixtures --------------------------------------------------

const (
	// ldapBoundaryMarker is a distinctive, unmistakably-not-accidental
	// string embedded in every constructed error below.
	ldapBoundaryMarker = "LDAP-BOUNDARY-MARKER-7f3ac91d"
	// ldapBoundaryBearer is shaped like a real Authorization header value
	// (and, separately, like the three-dot-segment shape of a compact JWT)
	// so a naive "only check for the raw token variable" proof could not
	// pass by accident.
	ldapBoundaryBearer = "Bearer eyJhbGciOiJSUzI1NiJ9.LDAP-BOUNDARY-PAYLOAD-MARKER.ldap-boundary-signature-marker"
	// ldapBoundaryClaimJSON is claim-shaped JSON text, distinct from
	// ldapBoundaryMarker/ldapBoundaryBearer, so a fix that only strips one
	// of the three shapes cannot pass this file's assertions by accident.
	ldapBoundaryClaimJSON = `{"sub":"ldap-boundary-marker-subject","email":"marker@example.test","roles":["ldap-boundary-marker-role"]}`
	// ldapBoundaryRoleName is the marker-bearing role name the §8.3 Search
	// telemetry subtest below binds with, to prove finishSearch's safe
	// telemetry line never includes role values.
	ldapBoundaryRoleName = "LDAP-BOUNDARY-ROLE-MARKER-b19e04"
)

// wrappedBoundaryError builds a doubly-%w-wrapped error whose full Error()
// text contains ldapBoundaryBearer, ldapBoundaryMarker and
// ldapBoundaryClaimJSON together — proving a fix must survive both nested
// wrapping (errors.Unwrap-style causal chains, as a real SDK/verifier error
// might produce) and a single flat string.
func wrappedBoundaryError(context string) error {
	innermost := fmt.Errorf("jwt validation failed: bearer=%s claims=%s", ldapBoundaryBearer, ldapBoundaryClaimJSON)
	middle := fmt.Errorf("%s: marker=%s: %w", context, ldapBoundaryMarker, innermost)
	return fmt.Errorf("outer failure: %w", middle)
}

// flatBoundaryError builds a single, unwrapped error string containing the
// same three marker shapes, complementing wrappedBoundaryError's nested
// case.
func flatBoundaryError(context string) error {
	return fmt.Errorf("%s: bearer=%s marker=%s claims=%s", context, ldapBoundaryBearer, ldapBoundaryMarker, ldapBoundaryClaimJSON)
}

// ---- 1. table-driven verifier/role-resolver failures -----------------------

type ldapBoundaryCase struct {
	name   string
	source string // "verifier" or "roles"
	err    error
}

var ldapBoundaryCases = []ldapBoundaryCase{
	{
		name:   "verifier failure: wrapped bearer/marker/claims",
		source: "verifier",
		err:    wrappedBoundaryError("verifier rejected token"),
	},
	{
		name:   "verifier failure: flat bearer/marker/claims",
		source: "verifier",
		err:    flatBoundaryError("verify"),
	},
	{
		name:   "role-resolver failure: wrapped bearer/marker/claims",
		source: "roles",
		err:    wrappedBoundaryError("role pipeline rejected claims"),
	},
	{
		name:   "role-resolver failure: malformed-claim-shaped error with marker",
		source: "roles",
		err:    fmt.Errorf("malformed configured groups claim %s: not a list (bearer=%s claims=%s)", ldapBoundaryMarker, ldapBoundaryBearer, ldapBoundaryClaimJSON),
	},
}

// TestRedactionBoundary_LDAPFailureMarkersAbsent is the plan's §5.8 "LDAP
// boundary" table: for every case, either the fake verifier or the fake
// role-resolver fails with an error whose text contains the exact bearer, a
// distinctive marker, claim-like JSON, and (for most rows) nested
// %w-wrapped errors. bind.go's handleBind/failBind never pass the verifier's
// or role-resolver's own error to failBind's fixed diagnostic or to its own
// log line (only a short fixed internal "reason" literal is logged) — this
// test is the regression proof that stays true, run at both the default and
// (per A2) the Trace global log level.
//
// Every case must still converge on exactly the same fixed boundary: LDAP
// result code 49 (invalidCredentials), the fixed "invalid credentials"
// diagnostic, an empty matched DN, an unauthenticated session (a later
// Search on the same connection is rejected), and no marker anywhere in the
// captured application log.
func TestRedactionBoundary_LDAPFailureMarkersAbsent(t *testing.T) {
	for _, mode := range redactionCaptureModes {
		t.Run(mode.name, func(t *testing.T) {
			for _, tc := range ldapBoundaryCases {
				t.Run(tc.name, func(t *testing.T) {
					acct := account("boundary-alice", "https://idp.test/", "sub-boundary-alice", "jwt-boundary-alice", []string{"ch_a"})

					var v verifier
					var r roleResolver
					switch tc.source {
					case "verifier":
						v = markerFailVerifier{err: tc.err}
						r = newFakeRoles(acct) // must never be reached
					case "roles":
						v = successVerifier{result: acct.result}
						r = markerFailRoles{err: tc.err}
					default:
						t.Fatalf("unknown case source %q", tc.source)
					}

					addr, _, _ := startTestServer(t, v, r)
					buf := captureAppLog(t, mode)

					conn := dialTest(t, addr)
					err := bindAs(conn, protoBindDN("boundary-alice"), "jwt-boundary-alice")
					requireInvalidCredentials(t, tc.name, err)

					// Unauthenticated session: a Search on the same
					// connection after the failed Bind must not succeed —
					// require the exact rejection failSearch (search.go)
					// returns for an unauthenticated session, not just "no
					// entries", which a wrongly SUCCESSFUL empty-result
					// Search could also produce.
					_, searchErr := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("boundary-alice"), nil))
					requireResultCode(t, tc.name+": search after failed bind", searchErr, ldapserver.LDAPResultInsufficientAccessRights)

					logText := buf.String()
					for _, marker := range []string{ldapBoundaryBearer, ldapBoundaryMarker, ldapBoundaryClaimJSON} {
						if strings.Contains(logText, marker) {
							t.Fatalf("%s: captured application log contains a credential/claim marker (%q):\n%s", tc.name, marker, logText)
						}
					}
					if strings.Contains(logText, tc.err.Error()) {
						t.Fatalf("%s: captured application log contains the raw verifier/role-resolver error text:\n%s", tc.name, logText)
					}
				})
			}
		})
	}
}

// ---- 2. §8.3 Search telemetry never logs role values -----------------------

// TestRedactionBoundary_SearchTelemetryOmitsRoleValues covers the §8.3 safe
// Search-telemetry invariant: it binds successfully with a marker-bearing
// role name, performs a Search that legitimately returns that role to the
// client (proving the marker really was mapped, not silently dropped), and
// asserts the captured application log's search-success line never contains
// the role's value, at both the default and (per A2) Trace global log
// level.
//
// This deliberately asserts only the presence of the pre-existing
// "entries" numeric field as its non-vacuous-pass sanity check, not the
// full size_limit/time_limit/types_only/result field set T2's search.go
// change adds: at the time this test was written, this package's search.go
// only logs "entries" on the success path (see search.go's handleSearch).
// "entries" stays present in T2's extended finishSearch too, so this
// assertion — and the role-marker-absence assertion above it, which is the
// actual point of this test — remain valid unchanged after that change
// merges; it does not need to be re-tightened to keep passing.
func TestRedactionBoundary_SearchTelemetryOmitsRoleValues(t *testing.T) {
	for _, mode := range redactionCaptureModes {
		t.Run(mode.name, func(t *testing.T) {
			acct := account("telemetry-alice", "https://idp.test/", "sub-telemetry-alice", "jwt-telemetry-alice", []string{ldapBoundaryRoleName})
			addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

			buf := captureAppLog(t, mode)

			conn := dialTest(t, addr)
			requireSuccess(t, "bind", bindAs(conn, protoBindDN("telemetry-alice"), "jwt-telemetry-alice"))

			res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("telemetry-alice"), nil))
			if err != nil || len(res.Entries) != 1 {
				t.Fatalf("search: res=%+v, err=%v, want exactly the one marker-bearing entry", res, err)
			}
			// Sanity: the role really was mapped and returned to the
			// client — proving the assertion below is about logging, not
			// about the role silently never being emitted at all.
			if got := res.Entries[0].GetAttributeValue("cn"); !strings.Contains(got, ldapBoundaryRoleName) {
				t.Fatalf("search entry cn = %q, want it to contain the marker role name", got)
			}

			logText := buf.String()
			if strings.Contains(logText, ldapBoundaryRoleName) {
				t.Fatalf("captured application log contains the marker-bearing role name:\n%s", logText)
			}
			// Sanity: the buffer must actually contain the search-success
			// telemetry line — a fix that (incorrectly) stopped logging it
			// entirely would otherwise pass the assertion above vacuously.
			if !strings.Contains(logText, `"entries"`) {
				t.Fatalf("captured application log missing expected safe telemetry field \"entries\":\n%s", logText)
			}
		})
	}
}
