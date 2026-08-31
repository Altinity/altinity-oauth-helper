package profile

// This file is sub-task p2-11's TCP-level marker-redaction proof suite —
// the tests the redaction manifest (a later sub-task, p2-15's sibling)
// names by these exact, stable function names — covering the plan's
// "Redaction/security inventory" marker-proof list (L1065-1079) and the
// Response memory bound's marker-bearing oversized-role proof (L817).
// Every test drives the real Server end to end over a real TCP listener,
// reusing server_test.go's harness (newRunningServer/dial), frame.go's
// own readFrame/decodeEnvelope (called directly here, not through
// server_test.go's sendAndReadEnvelope, so this file can also capture the
// exact raw response bytes those helpers would otherwise discard),
// protocol_test.go's rawSearchRequestBytes, search_test.go's
// validMembershipFilter/scopeWholeSubtree/derefNever, search_limits_test.go's
// findLogLine, adversarial_test.go's markerPresent/assertMarkerAbsent, and
// fakes_test.go's fakeVerifier/fakeResolver/newVerificationResult/marker
// constants.
//
// Every test below runs its whole scenario twice — once with the ambient
// zerolog level left at Info (this package's own production log level)
// and once raised to Trace (the most permissive level this package could
// ever log at) — per the plan's "at default and trace levels" requirement,
// and captures both every line this package logs and the complete raw
// bytes of every response the server writes, so a marker leaking into
// either is caught regardless of which channel it took.

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// ---- capture plumbing: full log text + every raw response frame ----------

// redactionLevels is the plan's "at default and trace levels" pair.
var redactionLevels = []zerolog.Level{zerolog.InfoLevel, zerolog.TraceLevel}

// runRedactionScenario swaps the process-global zerolog logger for a
// buffer at level for the duration of fn, restoring it via t.Cleanup
// (rather than a plain statement after fn() returns) so the restore still
// runs even if an assertion inside fn calls t.Fatalf — which unwinds this
// goroutine via runtime.Goexit and would otherwise skip a post-fn
// statement, leaving the process-global logger swapped for whatever test
// runs next. Returns the complete captured log text plus every raw
// response byte slice fn recorded via the record callback it is handed.
func runRedactionScenario(t *testing.T, level zerolog.Level, fn func(record func(body []byte))) (logText string, raws [][]byte) {
	t.Helper()
	var buf strings.Builder
	prev := log.Logger
	log.Logger = zerolog.New(&buf).Level(level)
	t.Cleanup(func() { log.Logger = prev })
	fn(func(b []byte) { raws = append(raws, append([]byte(nil), b...)) })
	return buf.String(), raws
}

// readRawRecording reads and decodes one LDAPMessage response off conn,
// recording its raw (post-outer-SEQUENCE-header) bytes via record before
// decoding — the exact bytes frame.go's readFrame returns, which is what
// a marker leaking anywhere in a response (including inside an
// LDAPResult's diagnosticMessage OCTET STRING) would appear in.
func readRawRecording(t *testing.T, conn net.Conn, record func([]byte)) Envelope {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	body, err := readFrame(conn)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	record(body)
	env, err := decodeEnvelope(body)
	if err != nil {
		t.Fatalf("decodeEnvelope: %v", err)
	}
	return env
}

// sendAndReadRawRecording writes req, then reads/records/decodes exactly
// one response the same way readRawRecording does.
func sendAndReadRawRecording(t *testing.T, conn net.Conn, req []byte, record func([]byte)) Envelope {
	t.Helper()
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return readRawRecording(t, conn, record)
}

// parseLogLines decodes text (one zerolog JSON object per line) into a
// slice findLogLine (search_limits_test.go) can search.
func parseLogLines(t *testing.T, text string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(text), "\n") {
		if raw == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("captured log line is not valid JSON: %v (%s)", err, raw)
		}
		lines = append(lines, m)
	}
	return lines
}

// assertUnsupportedOpNeverLeaksMarker sends one non-critical Extended
// request (the one recognizable-but-unsupported operation whose fixed
// response actually carries a non-empty diagnostic — server.go's
// handleUnsupported: every other unsupported op gets diagEmpty, only the
// Extended case gets diagOperationUnsupported's "operation not supported"
// text) on conn, records its raw response, and asserts marker appears
// nowhere in it — the plan's "unsupported-operation diagnostics" channel.
// That diagnostic text is always one of the closed diagnostic enum's
// fixed literals (encode.go), so this is a defensive proof that no
// shared-buffer/aliasing bug from the preceding scenario could ever let a
// marker bleed into an unrelated later response, not a proof that the
// fixed literal itself could contain one.
func assertUnsupportedOpNeverLeaksMarker(t *testing.T, conn net.Conn, marker string, record func([]byte)) {
	t.Helper()
	env := sendAndReadRawRecording(t, conn, opaqueRequestBytes(90, byte(tagExtendedRequest), false), record)
	if env.ProtocolOp != tagExtendedResponse {
		t.Fatalf("protocolOp = %#x, want ExtendedResponse", byte(env.ProtocolOp))
	}
	result, _, diag := readLDAPResultFields(t, env.Content)
	if result != int(resultUnwillingToPerform) {
		t.Fatalf("unsupported-op result = %d, want %d", result, resultUnwillingToPerform)
	}
	if diag != diagOperationUnsupported.text() {
		t.Fatalf("unsupported-op diagnostic = %q, want %q", diag, diagOperationUnsupported.text())
	}
}

// ---------------------------------------------------------------------
// 1. JWT-shaped password on a successful Bind
// ---------------------------------------------------------------------

func TestProfileRedaction_JWTShapedPassword(t *testing.T) {
	for _, level := range redactionLevels {
		t.Run(level.String(), func(t *testing.T) {
			acct := newVerificationResult("alice", "https://idp.example/", "sub-redaction-jwt", time.Now().Add(time.Hour).Unix())
			v := newFakeVerifier().withSuccess(markerJWTPassword, acct)
			r := newFakeResolver().withRoles("sub-redaction-jwt", nil)
			h := newRunningServer(t, v, r, nil)
			defer h.stopAndWait(t, 5*time.Second)

			conn := dial(t, h.addr)
			defer conn.Close()

			logText, raws := runRedactionScenario(t, level, func(record func([]byte)) {
				env := sendAndReadRawRecording(t, conn, bindRequestBytes(1, testAliceDN, markerJWTPassword, false), record)
				result, _, _ := readLDAPResultFields(t, env.Content)
				if result != int(resultSuccess) {
					t.Fatalf("Bind result = %d, want success", result)
				}
			})

			haystacks := append(raws, []byte(logText))
			assertMarkerAbsent(t, markerJWTPassword, haystacks...)
		})
	}
}

// ---------------------------------------------------------------------
// 2. Hostile Bind DN
// ---------------------------------------------------------------------

func TestProfileRedaction_HostileBindDN(t *testing.T) {
	for _, level := range redactionLevels {
		t.Run(level.String(), func(t *testing.T) {
			v := newFakeVerifier()
			r := newFakeResolver()
			h := newRunningServer(t, v, r, nil)
			defer h.stopAndWait(t, 5*time.Second)

			conn := dial(t, h.addr)
			defer conn.Close()

			logText, raws := runRedactionScenario(t, level, func(record func([]byte)) {
				env := sendAndReadRawRecording(t, conn, bindRequestBytes(1, markerHostileDN, "whatever-password", false), record)
				result, _, diag := readLDAPResultFields(t, env.Content)
				if result != int(resultInvalidCredentials) {
					t.Fatalf("Bind result = %d, want invalidCredentials", result)
				}
				if diag != diagInvalidCredentials.text() {
					t.Fatalf("diagnostic = %q, want %q", diag, diagInvalidCredentials.text())
				}
				assertUnsupportedOpNeverLeaksMarker(t, conn, markerHostileDN, record)
			})

			haystacks := append(raws, []byte(logText))
			assertMarkerAbsent(t, markerHostileDN, haystacks...)
		})
	}
}

// ---------------------------------------------------------------------
// 3. Verifier error carrying a marker
// ---------------------------------------------------------------------

func TestProfileRedaction_VerifierErrorMarker(t *testing.T) {
	for _, level := range redactionLevels {
		t.Run(level.String(), func(t *testing.T) {
			v := newFakeVerifier().withFailure("alice-pw", errWithMarker(markerVerifierError))
			r := newFakeResolver()
			h := newRunningServer(t, v, r, nil)
			defer h.stopAndWait(t, 5*time.Second)

			conn := dial(t, h.addr)
			defer conn.Close()

			logText, raws := runRedactionScenario(t, level, func(record func([]byte)) {
				env := sendAndReadRawRecording(t, conn, bindRequestBytes(1, testAliceDN, "alice-pw", false), record)
				result, _, diag := readLDAPResultFields(t, env.Content)
				if result != int(resultInvalidCredentials) {
					t.Fatalf("Bind result = %d, want invalidCredentials", result)
				}
				if diag != diagInvalidCredentials.text() {
					t.Fatalf("diagnostic = %q, want %q", diag, diagInvalidCredentials.text())
				}
				assertUnsupportedOpNeverLeaksMarker(t, conn, markerVerifierError, record)
			})

			haystacks := append(raws, []byte(logText))
			assertMarkerAbsent(t, markerVerifierError, haystacks...)
		})
	}
}

// ---------------------------------------------------------------------
// 4. Resolver (role-derivation) error carrying a marker
// ---------------------------------------------------------------------

func TestProfileRedaction_ResolverErrorMarker(t *testing.T) {
	for _, level := range redactionLevels {
		t.Run(level.String(), func(t *testing.T) {
			acct := newVerificationResult("alice", "https://idp.example/", "sub-redaction-resolver", time.Now().Add(time.Hour).Unix())
			v := newFakeVerifier().withSuccess("alice-pw", acct)
			r := newFakeResolver().withError(errWithMarker(markerResolverError))
			h := newRunningServer(t, v, r, nil)
			defer h.stopAndWait(t, 5*time.Second)

			conn := dial(t, h.addr)
			defer conn.Close()

			logText, raws := runRedactionScenario(t, level, func(record func([]byte)) {
				env := sendAndReadRawRecording(t, conn, bindRequestBytes(1, testAliceDN, "alice-pw", false), record)
				result, _, diag := readLDAPResultFields(t, env.Content)
				if result != int(resultInvalidCredentials) {
					t.Fatalf("Bind result = %d, want invalidCredentials", result)
				}
				if diag != diagInvalidCredentials.text() {
					t.Fatalf("diagnostic = %q, want %q", diag, diagInvalidCredentials.text())
				}
				assertUnsupportedOpNeverLeaksMarker(t, conn, markerResolverError, record)
			})

			haystacks := append(raws, []byte(logText))
			assertMarkerAbsent(t, markerResolverError, haystacks...)
		})
	}
}

// ---------------------------------------------------------------------
// 5. Legitimate marker-bearing role: present ONLY in its own entry
// ---------------------------------------------------------------------

// TestProfileRedaction_LegitimateMarkerRole binds with a role whose name
// is itself a distinctive marker and legitimately Searches for it,
// proving that value is rendered into exactly its own authorized
// SearchResultEntry and appears nowhere else at all: not in the
// BindResponse, not in the terminal SearchResultDone, and not in any
// captured log line (search.go's telemetry logs only the entry count,
// never role values).
func TestProfileRedaction_LegitimateMarkerRole(t *testing.T) {
	for _, level := range redactionLevels {
		t.Run(level.String(), func(t *testing.T) {
			acct := newVerificationResult("alice", "https://idp.example/", "sub-redaction-legit-role", time.Now().Add(time.Hour).Unix())
			v := newFakeVerifier().withSuccess("alice-pw", acct)
			r := newFakeResolver().withRoles("sub-redaction-legit-role", []string{markerLegitimateRole})
			h := newRunningServer(t, v, r, nil)
			defer h.stopAndWait(t, 5*time.Second)

			conn := dial(t, h.addr)
			defer conn.Close()

			var buf strings.Builder
			prev := log.Logger
			log.Logger = zerolog.New(&buf).Level(level)
			t.Cleanup(func() { log.Logger = prev }) // see runRedactionScenario's doc comment on why Cleanup, not a plain post-call statement

			var bindRaw []byte
			bindEnv := sendAndReadRawRecording(t, conn, bindRequestBytes(1, testAliceDN, "alice-pw", false), func(b []byte) {
				bindRaw = append([]byte(nil), b...)
			})
			result, _, _ := readLDAPResultFields(t, bindEnv.Content)
			if result != int(resultSuccess) {
				t.Fatalf("Bind result = %d, want success", result)
			}

			groupBase := newTestConfig().GroupBaseDN
			req := rawSearchRequestBytes(2, groupBase, scopeWholeSubtree, derefNever, 0, 0, false, validMembershipFilter(testAliceDN), false, "cn")
			if _, err := conn.Write(req); err != nil {
				t.Fatalf("write search request: %v", err)
			}

			var entryRaws [][]byte
			var doneRaw []byte
			for {
				var raw []byte
				env := readRawRecording(t, conn, func(b []byte) { raw = append([]byte(nil), b...) })
				if env.ProtocolOp == tagSearchResultDone {
					doneRaw = raw
					code, _, _ := readLDAPResultFields(t, env.Content)
					if code != int(resultSuccess) {
						t.Fatalf("search result = %d, want success", code)
					}
					break
				}
				entryRaws = append(entryRaws, raw)
			}

			logText := buf.String()

			if len(entryRaws) != 1 {
				t.Fatalf("entries = %d, want 1", len(entryRaws))
			}
			if !markerPresent(markerLegitimateRole, entryRaws[0]) {
				t.Fatalf("marker-bearing role did not appear in its own authorized SearchResultEntry — it must have been mapped and returned")
			}
			assertMarkerAbsent(t, markerLegitimateRole, bindRaw, doneRaw, []byte(logText))
		})
	}
}

// ---------------------------------------------------------------------
// 6. Oversized marker-bearing role: admin-limit result, zero marker bytes
// ---------------------------------------------------------------------

// TestProfileRedaction_OversizedMarkerRole binds with an ordinary role
// followed by markerOversizedRole (long enough on its own to exceed
// encode.go's maxBodyBytes response-PDU cap — fakes_test.go), and proves
// executeSearch's entryPDUSize preflight rejects it before ever
// attempting to render or write it: exactly the one ordinary entry is
// emitted, the terminal SearchResultDone is result 11 (adminLimitExceeded)
// with an empty diagnostic and "entries" equal to the already-emitted
// count, and the marker appears in zero response bytes and zero log
// bytes anywhere — never even partially.
func TestProfileRedaction_OversizedMarkerRole(t *testing.T) {
	for _, level := range redactionLevels {
		t.Run(level.String(), func(t *testing.T) {
			acct := newVerificationResult("alice", "https://idp.example/", "sub-redaction-oversized-role", time.Now().Add(time.Hour).Unix())
			v := newFakeVerifier().withSuccess("alice-pw", acct)
			r := newFakeResolver().withRoles("sub-redaction-oversized-role", []string{"ch_ordinary_role", markerOversizedRole})
			h := newRunningServer(t, v, r, nil)
			defer h.stopAndWait(t, 5*time.Second)

			conn := dial(t, h.addr)
			defer conn.Close()

			var buf strings.Builder
			prev := log.Logger
			log.Logger = zerolog.New(&buf).Level(level)
			t.Cleanup(func() { log.Logger = prev }) // see runRedactionScenario's doc comment on why Cleanup, not a plain post-call statement

			bindEnv := sendAndReadRawRecording(t, conn, bindRequestBytes(1, testAliceDN, "alice-pw", false), func([]byte) {})
			result, _, _ := readLDAPResultFields(t, bindEnv.Content)
			if result != int(resultSuccess) {
				t.Fatalf("Bind result = %d, want success", result)
			}

			groupBase := newTestConfig().GroupBaseDN
			req := rawSearchRequestBytes(2, groupBase, scopeWholeSubtree, derefNever, 0, 0, false, validMembershipFilter(testAliceDN), false, "cn")
			if _, err := conn.Write(req); err != nil {
				t.Fatalf("write search request: %v", err)
			}

			var allRaws [][]byte
			var entryCount int
			var doneEnv Envelope
			for {
				var raw []byte
				env := readRawRecording(t, conn, func(b []byte) { raw = append([]byte(nil), b...) })
				allRaws = append(allRaws, raw)
				if env.ProtocolOp == tagSearchResultDone {
					doneEnv = env
					break
				}
				entryCount++
			}

			logText := buf.String()

			if entryCount != 1 {
				t.Fatalf("entries emitted = %d, want 1 (the one ordinary role, before the oversized one is hit)", entryCount)
			}
			code, matchedDN, diag := readLDAPResultFields(t, doneEnv.Content)
			if code != int(resultAdminLimitExceeded) {
				t.Fatalf("result = %d, want %d (adminLimitExceeded)", code, resultAdminLimitExceeded)
			}
			if matchedDN != "" || diag != "" {
				t.Fatalf("matchedDN=%q diag=%q, want both empty", matchedDN, diag)
			}

			line := findLogLine(t, parseLogLines(t, logText), "search", "ldap search administrative limit exceeded")
			if got, ok := line["entries"].(float64); !ok || int(got) != entryCount {
				t.Fatalf("log field entries = %v, want %d", line["entries"], entryCount)
			}

			haystacks := append(allRaws, []byte(logText))
			assertMarkerAbsent(t, markerOversizedRole, haystacks...)
		})
	}
}

// errWithMarker is a small helper building an error whose Error() text is
// exactly marker — used by the verifier/resolver error-injection tests
// above so the injected failure's text is unambiguous.
type markerError string

func (e markerError) Error() string { return string(e) }

func errWithMarker(marker string) error { return markerError(marker) }
