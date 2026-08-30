package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// wireRecorderRawPayloadMarker/wireRecorderCredentialMarker are distinctive,
// unmistakably-not-accidental sentinel strings (mirroring
// internal/ldap/redaction_boundary_test.go's ldapBoundaryMarker/
// ldapBoundaryBearer convention) planted into raw PDU bytes and the
// stdin-supplied credential across every case below. wireRecorderBearer is
// additionally shaped like a real Authorization header value / compact JWT
// so a fix that only strips one shape cannot pass by accident.
const (
	wireRecorderRawPayloadMarker = "WIRECAPTURE-RAW-PAYLOAD-MARKER-4d81c2"
	wireRecorderCredentialMarker = "WIRECAPTURE-CREDENTIAL-MARKER-9be013"
	wireRecorderBearer           = "eyJhbGciOiJSUzI1NiJ9.WIRECAPTURE-BEARER-PAYLOAD-MARKER.wirecapture-bearer-signature-marker"
)

func assertNoMarkers(t *testing.T, caseName string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error", caseName)
	}
	text := err.Error()
	for _, marker := range []string{wireRecorderRawPayloadMarker, wireRecorderCredentialMarker, wireRecorderBearer} {
		if strings.Contains(text, marker) {
			t.Fatalf("%s: diagnostic text contains a credential/payload marker (%q):\n%s", caseName, marker, text)
		}
	}
}

// TestWireRecorderRedaction_MarkerNeverLogged is this package's plan-§36
// regression proof: six scenarios that are each reachable with credential-
// or raw-payload-bearing bytes in scope, each seeded with a distinctive
// marker in place of that sensitive content, asserting the resulting
// diagnostic text never contains any marker.
func TestWireRecorderRedaction_MarkerNeverLogged(t *testing.T) {
	t.Run("malformed frame", func(t *testing.T) {
		// A frame whose length field is well-formed but whose declared
		// content length runs past what is actually available; the
		// otherwise-valid prefix carries the raw-payload marker so a naive
		// "echo the bytes we did manage to read" error would leak it.
		raw := buildLDAPMessage(1, 0x63, []byte(wireRecorderRawPayloadMarker))
		truncated := raw[:len(raw)-3]
		_, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(truncated)))
		assertNoMarkers(t, "malformed frame", err)
	})

	t.Run("proxy error", func(t *testing.T) {
		// Exercise the REAL production call site (recordAndForward's
		// upstream-write failure) rather than a contrived error: the
		// client PDU actually being forwarded carries the marker in its
		// Bind password field, and forwarding fails because the upstream
		// writer always errors. errProxy only wraps the writer's own
		// (payload-free) failure text, never the PDU bytes it was asked
		// to write, so the marker must not appear in the result.
		clientBuf := buildBindRequest(1, "uid=alice,dc=test", wireRecorderRawPayloadMarker)
		clientR := bufio.NewReader(bytes.NewReader(clientBuf))
		rec := &Recorder{}
		var res ConnResult
		_, err := rec.recordAndForward(clientR, alwaysFailWriter{}, t.TempDir(), &res)
		assertNoMarkers(t, "proxy error", err)
	})

	t.Run("sanitize zero match", func(t *testing.T) {
		dir := t.TempDir()
		rawDir := filepath.Join(dir, "raw")
		writeRawConn(t, rawDir, "conn-0001", [][]byte{
			buildBindRequest(1, "uid=alice,dc=test", wireRecorderRawPayloadMarker),
		})
		_, err := Sanitize(SanitizeInput{
			RawDir:       rawDir,
			SanitizedDir: filepath.Join(dir, "sanitized"),
			Credential:   []byte(wireRecorderBearer), // deliberately absent from the raw PDU
		})
		assertNoMarkers(t, "sanitize zero match", err)
	})

	t.Run("sanitize multiple matches", func(t *testing.T) {
		dir := t.TempDir()
		rawDir := filepath.Join(dir, "raw")
		writeRawConn(t, rawDir, "conn-0001", [][]byte{
			buildBindRequest(1, "uid=alice,dc=test", wireRecorderCredentialMarker),
			buildBindRequest(2, "uid=alice,dc=test", wireRecorderCredentialMarker),
		})
		_, err := Sanitize(SanitizeInput{
			RawDir:       rawDir,
			SanitizedDir: filepath.Join(dir, "sanitized"),
			Credential:   []byte(wireRecorderCredentialMarker),
		})
		assertNoMarkers(t, "sanitize multiple matches", err)
	})

	t.Run("invalid metadata", func(t *testing.T) {
		dir := t.TempDir()
		// A session.json that embeds the marker inside an UNKNOWN field
		// (rejected by wirefixture's strict decode) — proving a decode
		// failure over marker-bearing bytes never echoes file content.
		bad := fmt.Sprintf(`{"schema_version":1,"line":"24.8","provenance":"captured-redacted","mode":"success","connection_count":1,"pdus":[],"unexpected_field":"%s"}`, wireRecorderRawPayloadMarker)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "session.json")
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		_, rerr := wirefixture.ReadSession(path)
		if rerr == nil {
			t.Fatal("expected strict decode to reject the unknown field")
		}
		err := errInvalidMetadata("read session.json", rerr)
		assertNoMarkers(t, "invalid metadata", err)
	})

	t.Run("constructed-generation error", func(t *testing.T) {
		// Exercise the REAL production call site: ConstructMessageIDBoundary
		// fails because its output directory collides with an existing
		// regular file. This never touches PDU/credential content at all
		// (the generator only ever succeeds or fails on a plain int
		// MessageID and a filesystem path) — proving the diagnostic stays
		// marker-free even though the surrounding fixture bytes it would
		// have written are marker-shaped in spirit (a real constructed
		// fixture's fixed non-JWT password, asserted marker-free too).
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocked")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ConstructMessageIDBoundary(ConstructInput{
			OutputDir:       filepath.Join(blocker, "constructed"), // blocker is a file, not a dir
			ApplicableLines: []string{"24.8"},
		})
		assertNoMarkers(t, "constructed-generation error", err)
	})
}

// alwaysFailWriter is a real, minimal io.Writer standing in for a broken
// upstream connection: its failure text never contains anything about the
// bytes it was asked to write, matching how a real net.Conn.Write failure
// behaves.
type alwaysFailWriter struct{}

func (alwaysFailWriter) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("write: connection reset by peer")
}
