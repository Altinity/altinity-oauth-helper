package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// captureLog swaps the shared zerolog logger for one writing a single
// newline-delimited JSON line into an in-memory buffer at the given level,
// runs fn (which must emit exactly one log line), restores the original
// logger, and returns the line's fields.
func captureLog(t *testing.T, level zerolog.Level, fn func()) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf).Level(level)
	fn()
	log.Logger = orig

	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatalf("no log line produced")
	}
	if strings.Contains(line, "\n") {
		t.Fatalf("expected exactly one log line, got multiple: %s", line)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		t.Fatalf("log line is not valid JSON: %v (%s)", err, line)
	}
	return fields
}

// TestCorrelationID_KnownVector pins correlationID's output for a fixed
// (issuer, subject) pair to a value computed once by the legacy algorithm
// (sha256(issuer + "\x00" + subject), first 8 bytes, lowercase hex — see
// internal/ldap/server.go:326-329). Any change to the separator, the
// truncation length, or the encoding changes this value.
func TestCorrelationID_KnownVector(t *testing.T) {
	const issuer = "https://idp.example.com/"
	const subject = "user-42"
	const want = "7c28a3bb8ee79fb3"

	got := correlationID(issuer, subject)
	if got != want {
		t.Fatalf("correlationID(%q, %q) = %q, want %q", issuer, subject, got, want)
	}
	if len(got) != 16 {
		t.Fatalf("correlationID length = %d, want 16 (8 bytes lowercase hex)", len(got))
	}
}

// TestCorrelationID_SeparatorAndTruncationSensitivity demonstrates, without
// touching production code, that the known vector above actually pins the
// separator and truncation choices: an independently computed hash using
// "\x01" instead of "\x00", or keeping 16 bytes instead of 8, both differ
// from correlationID's real output.
func TestCorrelationID_SeparatorAndTruncationSensitivity(t *testing.T) {
	const issuer = "https://idp.example.com/"
	const subject = "user-42"
	want := correlationID(issuer, subject)

	wrongSepSum := sha256.Sum256([]byte(issuer + "\x01" + subject))
	wrongSep := hex.EncodeToString(wrongSepSum[:8])
	if wrongSep == want {
		t.Fatalf("changing the separator to \\x01 must change the output, both were %q", want)
	}

	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	wrongTrunc := hex.EncodeToString(sum[:16])
	if wrongTrunc == want || len(wrongTrunc) == len(want) {
		t.Fatalf("taking 16 bytes must differ in both length and value from %q, got %q", want, wrongTrunc)
	}
}

// TestReason_TextTableComplete enumerates every reason constant, asserting
// its literal text, that no constant falls through to the "unknown"
// default, and that no two constants share the same text.
func TestReason_TextTableComplete(t *testing.T) {
	cases := []struct {
		r    reason
		want string
	}{
		{reasonEmptyBindDNOrPassword, "empty bind DN or password"},
		{reasonBindDNRejected, "bind DN rejected"},
		{reasonVerificationFailed, "verification failed"},
		{reasonRoleDerivationFailed, "role derivation failed"},
		{reasonUnauthenticated, "unauthenticated"},
		{reasonWrongBase, "wrong base"},
		{reasonWrongScope, "wrong scope"},
		{reasonUnauthorizedFilterShape, "unauthorized filter shape"},
		{reasonDerefAliasesOutOfProfile, "derefAliases out of profile"},
		{reasonTypesOnlyOutOfProfile, "typesOnly out of profile"},
		{reasonAttributeSelectionOutOfProfile, "attribute selection out of profile"},
		{reasonMemberDNMismatch, "member DN mismatch"},
	}
	if len(cases) != 12 {
		t.Fatalf("table has %d entries, expected exactly 12 reason constants", len(cases))
	}

	seen := make(map[string]reason, len(cases))
	for _, c := range cases {
		got := c.r.text()
		if got != c.want {
			t.Errorf("reason(%d).text() = %q, want %q", c.r, got, c.want)
		}
		if got == "" || got == "unknown" {
			t.Errorf("reason(%d).text() fell through to the default %q", c.r, got)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("reason %d and %d share the same text %q", c.r, other, got)
		}
		seen[got] = c.r
	}
}

// TestOp_ConstantsComplete enumerates every op constant and its exact
// logged literal.
func TestOp_ConstantsComplete(t *testing.T) {
	want := map[op]string{
		opBind:     "bind",
		opSearch:   "search",
		opAbandon:  "abandon",
		opUnbind:   "unbind",
		opAdd:      "add",
		opModify:   "modify",
		opDelete:   "delete",
		opCompare:  "compare",
		opModifyDN: "modifydn",
		opExtended: "extended",
	}
	if len(want) != 10 {
		t.Fatalf("table has %d entries, expected exactly 10 op constants", len(want))
	}
	for o, text := range want {
		if string(o) != text {
			t.Errorf("op constant = %q, want %q", string(o), text)
		}
	}
}

// TestLogHelpers_ExactMessagesAndKeys enumerates every log helper's exact
// message string and complete field-key set, captured at both an ordinary
// (Info) and a verbose (Trace) logger level — the field set logged by
// these Info-level calls must not change with the ambient level. This
// covers all 5 search-terminal messages, the search-rejected message, all
// 4 bind messages, the unsupported-operation message, and the
// critical-control message: every message this file can emit.
func TestLogHelpers_ExactMessagesAndKeys(t *testing.T) {
	bindKeys := []string{"level", "message", "op", "success", "result"}
	searchKeys := []string{"level", "message", "op", "success", "result", "username", "size_limit", "time_limit", "types_only", "entries"}

	cases := []struct {
		name    string
		fn      func()
		message string
		keys    []string
	}{
		{
			name:    "bind succeeded",
			fn:      func() { logBindSucceeded("alice", "https://idp.example.com/", "user-42", 3) },
			message: "ldap bind succeeded",
			keys:    append(append([]string{}, bindKeys...), "username", "correlation_id", "roles"),
		},
		{
			name:    "bind failed",
			fn:      func() { logBindFailed(reasonVerificationFailed) },
			message: "ldap bind failed",
			keys:    append(append([]string{}, bindKeys...), "reason"),
		},
		{
			name:    "bind unsupported authentication choice",
			fn:      logBindUnsupportedAuthChoice,
			message: "ldap bind rejected: unsupported authentication choice",
			keys:    bindKeys,
		},
		{
			name:    "bind unsupported protocol version",
			fn:      logBindUnsupportedProtocolVersion,
			message: "ldap bind rejected: unsupported protocol version",
			keys:    bindKeys,
		},
		{
			name:    "search succeeded",
			fn:      func() { logSearchTerminal("alice", 0, 0, false, 3, resultSuccess) },
			message: "ldap search succeeded",
			keys:    searchKeys,
		},
		{
			name:    "search succeeded zero roles",
			fn:      func() { logSearchTerminal("alice", 0, 0, false, 0, resultSuccess) },
			message: "ldap search succeeded (zero roles)",
			keys:    searchKeys,
		},
		{
			name:    "search size limit exceeded",
			fn:      func() { logSearchTerminal("alice", 2, 0, false, 2, resultSizeLimitExceeded) },
			message: "ldap search size limit exceeded",
			keys:    searchKeys,
		},
		{
			name:    "search time limit exceeded",
			fn:      func() { logSearchTerminal("alice", 0, 5, false, 1, resultTimeLimitExceeded) },
			message: "ldap search time limit exceeded",
			keys:    searchKeys,
		},
		{
			name:    "search administrative limit exceeded",
			fn:      func() { logSearchTerminal("alice", 0, 0, false, 1, resultAdminLimitExceeded) },
			message: "ldap search administrative limit exceeded",
			keys:    searchKeys,
		},
		{
			name:    "search rejected",
			fn:      func() { logSearchRejected(reasonWrongBase) },
			message: "ldap search rejected",
			keys:    []string{"level", "message", "op", "success", "result", "reason"},
		},
		{
			name:    "operation unsupported",
			fn:      func() { logOperationUnsupported(opAdd) },
			message: "ldap operation rejected: unsupported",
			keys:    []string{"level", "message", "op", "success", "result"},
		},
		{
			name:    "critical control rejected",
			fn:      func() { logCriticalControlRejected(opBind) },
			message: "ldap operation rejected: unsupported critical control",
			keys:    []string{"level", "message", "op", "success", "result"},
		},
	}

	levels := []zerolog.Level{zerolog.InfoLevel, zerolog.TraceLevel}

	for _, c := range cases {
		for _, lvl := range levels {
			t.Run(fmt.Sprintf("%s/level=%s", c.name, lvl), func(t *testing.T) {
				fields := captureLog(t, lvl, c.fn)

				if got, _ := fields["message"].(string); got != c.message {
					t.Fatalf("message = %q, want %q", got, c.message)
				}
				if len(fields) != len(c.keys) {
					t.Fatalf("field count = %d %v, want exactly %d %v", len(fields), fields, len(c.keys), c.keys)
				}
				for _, k := range c.keys {
					if _, ok := fields[k]; !ok {
						t.Fatalf("missing expected key %q, got %v", k, fields)
					}
				}
			})
		}
	}
}

// TestLogBindSucceeded_NoMarkerLeakOutsideUsername passes distinct marker
// strings as username and as the issuer/subject that feed correlation_id,
// and requires that only the username field ever reflects its own marker
// verbatim: issuer/subject must never appear raw anywhere in the log line,
// including inside correlation_id (which is a hash of them, never their
// text), op, or message.
func TestLogBindSucceeded_NoMarkerLeakOutsideUsername(t *testing.T) {
	const usernameMarker = "MARKER-USERNAME-7f3a"
	const issuerMarker = "MARKER-ISSUER-b91c"
	const subjectMarker = "MARKER-SUBJECT-2ed0"

	fields := captureLog(t, zerolog.InfoLevel, func() {
		logBindSucceeded(usernameMarker, issuerMarker, subjectMarker, 1)
	})

	username, _ := fields["username"].(string)
	if username != usernameMarker {
		t.Fatalf("username = %q, want %q", username, usernameMarker)
	}

	for key, v := range fields {
		if key == "username" {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if strings.Contains(s, issuerMarker) || strings.Contains(s, subjectMarker) {
			t.Fatalf("field %q = %q leaked the raw issuer/subject marker", key, s)
		}
	}
}
