package profile

// This file is sub-task p2-11's TCP-level port of the plan's "Search
// request profile" sizeLimit/timeLimit sections (L536-561) and the "Exact
// logging contract" Search telemetry table (L967-997): every test here
// drives the real Server end to end over a real TCP listener (never
// handleSearch directly, unlike search_test.go's handler-level suite),
// reusing server_test.go's harness (newRunningServer/dial/
// sendAndReadEnvelope/readEnvelope/readLDAPResultFields), protocol_test.go's
// rawSearchRequestBytes/decodeSearchResultEntry/collectSearchResult,
// search_test.go's rolesNamed/validMembershipFilter/scopeWholeSubtree/
// derefNever, bind_test.go's testAliceDN, and fakes_test.go's
// fakeVerifier/fakeResolver/newVerificationResult.
//
// Legacy-only cases NOT ported here (see the plan's "Search request
// profile" §"After cutover" list and the disposition table's
// search_limits_test.go row): typesOnly=true (out of profile, result 50 —
// covered by search_test.go's field-policy table, not retested here),
// a bare "*" attribute selection, sole "1.1", an empty attribute list, and
// multi-attribute projection. All five are deliberate Phase-3-visible
// narrowings to a fixed result-50 rejection, not size/time-limit behavior,
// and stay exclusively legacy/handler-level concerns.

import (
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// ---- multi-line log capture -----------------------------------------------
//
// logging_test.go's captureLog requires exactly one captured line; a real
// end-to-end Bind+Search over TCP produces at least two ("ldap bind
// succeeded" then a search-terminal line), so this file captures every
// line and lets callers pick the one they need.

// captureAllLog swaps the process-global zerolog logger for a buffer at
// level for the duration of fn, restoring it before returning, and decodes
// every captured line (one JSON object per line) into a slice.
func captureAllLog(t *testing.T, level zerolog.Level, fn func()) []map[string]any {
	t.Helper()
	var buf strings.Builder
	prev := log.Logger
	log.Logger = zerolog.New(&buf).Level(level)
	fn()
	log.Logger = prev

	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
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

// findLogLine returns the first captured line whose "op"/"message" fields
// match, failing the test if none does.
func findLogLine(t *testing.T, lines []map[string]any, wantOp, wantMessage string) map[string]any {
	t.Helper()
	for _, m := range lines {
		if m["op"] == wantOp && m["message"] == wantMessage {
			return m
		}
	}
	t.Fatalf("no captured log line with op=%q message=%q found among %d lines: %+v", wantOp, wantMessage, len(lines), lines)
	return nil
}

func numericField(t *testing.T, line map[string]any, key string) float64 {
	t.Helper()
	v, ok := line[key].(float64)
	if !ok {
		t.Fatalf("log field %q missing or not numeric: %#v", key, line[key])
	}
	return v
}

func assertSearchTelemetry(t *testing.T, line map[string]any, sizeLimit, timeLimit, entries int64, username string) {
	t.Helper()
	if got := numericField(t, line, "size_limit"); got != float64(sizeLimit) {
		t.Fatalf("log field size_limit = %v, want %v", got, sizeLimit)
	}
	if got := numericField(t, line, "time_limit"); got != float64(timeLimit) {
		t.Fatalf("log field time_limit = %v, want %v", got, timeLimit)
	}
	if got, ok := line["types_only"].(bool); !ok || got != false {
		t.Fatalf("log field types_only = %#v, want false", line["types_only"])
	}
	if got := numericField(t, line, "entries"); got != float64(entries) {
		t.Fatalf("log field entries = %v, want %v", got, entries)
	}
	if got, _ := line["username"].(string); got != username {
		t.Fatalf("log field username = %q, want %q", got, username)
	}
}

// ---- ticking clock: deterministic timeLimit expiry over a real server ----
//
// A static fake clock cannot, on its own, make handleSearch's expired()
// check ever observe a time later than searchStart (both read the exact
// same value with no calls in between advancing it), and a sequenceClock
// pre-scripted by exact call index (search_test.go's handler-level
// approach) would be fragile here: driving the real Server over TCP
// inserts extra clock reads of its own (once per connection-loop
// iteration, for the read deadline) whose count is an implementation
// detail this file should not have to track. tickingClock sidesteps both
// problems: every call advances by step, so whatever value searchStart
// happens to read, the very next call handleSearch's executeSearch makes
// (expired()'s first check, for the first non-empty role) is exactly
// searchStart+step — deterministically past searchStart+timeLimit as long
// as step exceeds timeLimit in seconds, regardless of how many earlier
// calls (deadline-setting or otherwise) preceded searchStart's own read.
type tickingClock struct {
	mu   sync.Mutex
	next time.Time
	step time.Duration
}

func newTickingClock(start time.Time, step time.Duration) *tickingClock {
	return &tickingClock{next: start, step: step}
}

func (c *tickingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.next
	c.next = c.next.Add(c.step)
	return t
}

// ---- shared harness: bind alice with a given role snapshot ----------------

const searchLimitsSubject = "sub-search-limits-alice"
const searchLimitsPassword = "s3cr3t-search-limits"

// newBoundSearchServer starts a real server (optionally reconfigured via
// configure, e.g. to install a fake clock), Binds a real TCP connection as
// alice with roles as her Bind-time role snapshot, and returns both the
// running handle and the bound connection ready for a Search.
func newBoundSearchServer(t *testing.T, roles []string, configure func(*Server)) (*testServerHandle, net.Conn) {
	t.Helper()
	acct := newVerificationResult("alice", "https://idp.example/", searchLimitsSubject, time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess(searchLimitsPassword, acct)
	r := newFakeResolver().withRoles(searchLimitsSubject, roles)
	h := newRunningServer(t, v, r, configure)

	conn := dial(t, h.addr)
	env := sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, searchLimitsPassword, false))
	if result, _, _ := readLDAPResultFields(t, env.Content); result != int(resultSuccess) {
		t.Fatalf("bind result = %d, want success", result)
	}
	return h, conn
}

// sendSearch writes one raw SearchRequest (base=this profile's fixed
// GroupBaseDN, scope=wholeSubtree, deref=never, typesOnly=false, filter=the
// fixed membership filter naming alice's own bound DN, attributes=["cn"])
// with the given sizeLimit/timeLimit, and collects the response.
func sendSearch(t *testing.T, conn net.Conn, msgID, sizeLimit, timeLimit int64) (entries []Envelope, done Envelope) {
	t.Helper()
	groupBase := newTestConfig().GroupBaseDN
	req := rawSearchRequestBytes(msgID, groupBase, scopeWholeSubtree, derefNever, sizeLimit, timeLimit, false, validMembershipFilter(testAliceDN), false, "cn")
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write search request: %v", err)
	}
	return collectSearchResult(t, conn)
}

// ---------------------------------------------------------------------
// sizeLimit
// ---------------------------------------------------------------------

// TestSearchLimits_SizeLimitBoundariesOverTCP is this file's main table:
// sizeLimit 0 (unlimited) against a role count well above the legacy
// captured default of 256, the exact-256/256 boundary, the 256-of-257
// (N+1) truncation, and a generic small N/N+1 pair — every case driven
// over real TCP against the real Server, with exact telemetry assertions
// on the resulting terminal SearchResultDone's log line.
func TestSearchLimits_SizeLimitBoundariesOverTCP(t *testing.T) {
	cases := []struct {
		name        string
		sizeLimit   int64
		roleCount   int
		wantEntries int
		wantResult  int32
		wantMessage string
	}{
		{"sizeLimit_0_unlimited_300_roles", 0, 300, 300, resultSuccess, "ldap search succeeded"},
		{"sizeLimit_256_of_256_exact", 256, 256, 256, resultSuccess, "ldap search succeeded"},
		{"sizeLimit_256_of_257_truncates_at_256", 256, 257, 256, resultSizeLimitExceeded, "ldap search size limit exceeded"},
		{"generic_N_of_N_succeeds", 3, 3, 3, resultSuccess, "ldap search succeeded"},
		{"generic_N_of_N_plus_1_truncates", 3, 4, 3, resultSizeLimitExceeded, "ldap search size limit exceeded"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roles := rolesNamed(tc.roleCount, "role_")
			h, conn := newBoundSearchServer(t, roles, nil)
			defer h.stopAndWait(t, 5*time.Second)
			defer conn.Close()

			var entries []Envelope
			var done Envelope
			lines := captureAllLog(t, zerolog.InfoLevel, func() {
				entries, done = sendSearch(t, conn, 2, tc.sizeLimit, 0)
			})

			if len(entries) != tc.wantEntries {
				t.Fatalf("entries = %d, want %d", len(entries), tc.wantEntries)
			}
			for _, e := range entries {
				if e.ProtocolOp != tagSearchResultEntry {
					t.Fatalf("protocolOp = %#x, want SearchResultEntry", byte(e.ProtocolOp))
				}
			}
			code, matchedDN, diag := readLDAPResultFields(t, done.Content)
			if code != int(tc.wantResult) {
				t.Fatalf("result = %d, want %d", code, tc.wantResult)
			}
			if matchedDN != "" {
				t.Fatalf("matchedDN = %q, want empty", matchedDN)
			}
			if diag != "" {
				t.Fatalf("diagnostic = %q, want empty", diag)
			}

			line := findLogLine(t, lines, "search", tc.wantMessage)
			assertSearchTelemetry(t, line, tc.sizeLimit, 0, int64(tc.wantEntries), "alice")
			if got, ok := line["result"].(float64); !ok || int32(got) != tc.wantResult {
				t.Fatalf("log field result = %v, want %d", line["result"], tc.wantResult)
			}
		})
	}
}

// TestSearchLimits_EmptyRolesNeverConsumeSizeLimitBudget mirrors
// search_test.go's handler-level empty-role-skip proof, but over real TCP:
// an empty role must never count against a positive sizeLimit.
func TestSearchLimits_EmptyRolesNeverConsumeSizeLimitBudget(t *testing.T) {
	roles := []string{"", "role_a", "", "role_b", ""}
	h, conn := newBoundSearchServer(t, roles, nil)
	defer h.stopAndWait(t, 5*time.Second)
	defer conn.Close()

	entries, done := sendSearch(t, conn, 2, 2, 0)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2 (both non-empty roles, sizeLimit=2 never breached)", len(entries))
	}
	code, _, _ := readLDAPResultFields(t, done.Content)
	if code != int(resultSuccess) {
		t.Fatalf("result = %d, want success — empty roles must never consume sizeLimit budget", code)
	}
}

// ---------------------------------------------------------------------
// timeLimit
// ---------------------------------------------------------------------

// TestSearchLimits_TimeLimitZeroNeverExpires drives a real (non-fake)
// server clock: timeLimit=0 means no client Search deadline at all.
func TestSearchLimits_TimeLimitZeroNeverExpires(t *testing.T) {
	roles := []string{"ch_engineer", "ch_analyst"}
	h, conn := newBoundSearchServer(t, roles, nil)
	defer h.stopAndWait(t, 5*time.Second)
	defer conn.Close()

	var entries []Envelope
	var done Envelope
	lines := captureAllLog(t, zerolog.InfoLevel, func() {
		entries, done = sendSearch(t, conn, 2, 0, 0)
	})
	if len(entries) != len(roles) {
		t.Fatalf("entries = %d, want %d", len(entries), len(roles))
	}
	code, _, _ := readLDAPResultFields(t, done.Content)
	if code != int(resultSuccess) {
		t.Fatalf("result = %d, want success", code)
	}
	line := findLogLine(t, lines, "search", "ldap search succeeded")
	assertSearchTelemetry(t, line, 0, 0, int64(len(roles)), "alice")
}

// TestSearchLimits_TimeLimitPositiveNotExpiredSucceeds drives a real
// server clock with a generous positive timeLimit that a fast in-process
// Search can never actually breach.
func TestSearchLimits_TimeLimitPositiveNotExpiredSucceeds(t *testing.T) {
	roles := []string{"ch_engineer", "ch_analyst"}
	h, conn := newBoundSearchServer(t, roles, nil)
	defer h.stopAndWait(t, 5*time.Second)
	defer conn.Close()

	var entries []Envelope
	var done Envelope
	lines := captureAllLog(t, zerolog.InfoLevel, func() {
		entries, done = sendSearch(t, conn, 2, 0, 20)
	})
	if len(entries) != len(roles) {
		t.Fatalf("entries = %d, want %d", len(entries), len(roles))
	}
	code, _, _ := readLDAPResultFields(t, done.Content)
	if code != int(resultSuccess) {
		t.Fatalf("result = %d, want success", code)
	}
	line := findLogLine(t, lines, "search", "ldap search succeeded")
	assertSearchTelemetry(t, line, 0, 20, int64(len(roles)), "alice")
}

// TestSearchLimits_TimeLimitExpiresBeforeFirstEntry installs a
// tickingClock on the Server (step deliberately larger than the
// requested timeLimit) so the Search deadline is already past by the
// moment executeSearch checks it for the very first eligible role — zero
// entries must be emitted, and the terminal result must be
// timeLimitExceeded (3) with the exact "ldap search time limit exceeded"
// telemetry.
func TestSearchLimits_TimeLimitExpiresBeforeFirstEntry(t *testing.T) {
	const timeLimitSeconds = 1
	tc := newTickingClock(time.Now(), 3*time.Second) // step (3s) > timeLimit (1s)

	roles := rolesNamed(8, "role_")
	h, conn := newBoundSearchServer(t, roles, func(s *Server) { s.clock = tc.Now })
	defer h.stopAndWait(t, 5*time.Second)
	defer conn.Close()

	var entries []Envelope
	var done Envelope
	lines := captureAllLog(t, zerolog.InfoLevel, func() {
		entries, done = sendSearch(t, conn, 2, 0, timeLimitSeconds)
	})
	if len(entries) != 0 {
		t.Fatalf("entries = %d, want 0 (the Search deadline must already be past before the first eligible role)", len(entries))
	}
	code, matchedDN, diag := readLDAPResultFields(t, done.Content)
	if code != int(resultTimeLimitExceeded) {
		t.Fatalf("result = %d, want %d (timeLimitExceeded)", code, resultTimeLimitExceeded)
	}
	if matchedDN != "" || diag != "" {
		t.Fatalf("matchedDN=%q diag=%q, want both empty", matchedDN, diag)
	}
	line := findLogLine(t, lines, "search", "ldap search time limit exceeded")
	assertSearchTelemetry(t, line, 0, timeLimitSeconds, 0, "alice")
}

// ---------------------------------------------------------------------
// Response entry shape: exactly one cn attribute, one value, never
// objectClass/member
// ---------------------------------------------------------------------

// TestSearchLimits_EntryShapeIsExactlyOneCNAttribute decodes a real
// SearchResultEntry response raw (decodeSearchResultEntry, independent of
// encode.go's own code) and asserts it carries exactly one PartialAttribute
// — type "cn", exactly one value — proving the wire response never adds
// objectClass or member, regardless of what the client requested.
func TestSearchLimits_EntryShapeIsExactlyOneCNAttribute(t *testing.T) {
	roles := []string{"ch_engineer"}
	h, conn := newBoundSearchServer(t, roles, nil)
	defer h.stopAndWait(t, 5*time.Second)
	defer conn.Close()

	entries, done := sendSearch(t, conn, 2, 0, 0)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	code, _, _ := readLDAPResultFields(t, done.Content)
	if code != int(resultSuccess) {
		t.Fatalf("result = %d, want success", code)
	}

	objectName, attrType, attrValue := decodeSearchResultEntry(t, entries[0].Content)
	if attrType != "cn" {
		t.Fatalf("attribute type = %q, want %q", attrType, "cn")
	}
	if !strings.Contains(attrValue, "ch_engineer") {
		t.Fatalf("cn value = %q, want it to contain the mapped role name", attrValue)
	}
	if objectName == "" {
		t.Fatalf("objectName (entry DN) is empty")
	}
	// decodeSearchResultEntry itself already fails the test if a second
	// PartialAttribute or a second value is present (its own doc comment,
	// protocol_test.go) — this is the "no objectClass/member" proof by
	// construction, not a redundant substring scan.
	if strings.Contains(objectName, "objectClass") || strings.Contains(objectName, "member") {
		t.Fatalf("objectName unexpectedly mentions objectClass/member: %q", objectName)
	}
}
