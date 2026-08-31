package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// ---------------------------------------------------------------------
// A minimal in-process fake LDAP server.
//
// This does not reuse internal/ldap's production server: that server is
// wired to a full verifier/role-resolver pipeline this package must not
// import (the probe is intentionally a standalone, dependency-light
// binary — see the package doc comment). It also does not reuse
// internal/ldap/profile's decoder: the probe under test must be exercised
// exactly as any external client would be, over a real net.Conn, not by
// calling into either implementation.
//
// Instead this hand-builds just enough real LDAPv3 wire responses —
// BindResponse, SearchResultEntry, SearchResultDone — using this
// package's own cryptobyte-based encoders from ldapclient.go (the same
// tag constants and encodeMessage helper the probe's real client uses to
// build its requests), and decodes incoming requests with that same
// file's readFrame/decodeEnvelope. Neither github.com/go-ldap/ldap/v3 nor
// github.com/go-asn1-ber/asn1-ber is imported anywhere in this package.
// ---------------------------------------------------------------------

func bindResponseBytes(msgID int32, resultCode int) []byte {
	msg, err := encodeMessage(func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(msgID))
		b.AddASN1(tagBindResponse, func(b *cryptobyte.Builder) {
			b.AddASN1Enum(int64(resultCode))
			b.AddASN1OctetString(nil) // matchedDN
			b.AddASN1OctetString(nil) // diagnosticMessage
		})
	})
	if err != nil {
		panic(err) // test-only fixture construction; a build failure here is a test bug
	}
	return msg
}

func searchResultEntryBytes(msgID int32, dn, cnValue string) []byte {
	msg, err := encodeMessage(func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(msgID))
		b.AddASN1(tagSearchResultEntry, func(b *cryptobyte.Builder) {
			b.AddASN1OctetString([]byte(dn))
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) { // attributes
				b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) { // one PartialAttribute
					b.AddASN1OctetString([]byte("cn"))
					b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
						b.AddASN1OctetString([]byte(cnValue))
					})
				})
			})
		})
	})
	if err != nil {
		panic(err)
	}
	return msg
}

func searchResultDoneBytes(msgID int32, resultCode int) []byte {
	msg, err := encodeMessage(func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(msgID))
		b.AddASN1(tagSearchResultDone, func(b *cryptobyte.Builder) {
			b.AddASN1Enum(int64(resultCode))
			b.AddASN1OctetString(nil) // matchedDN
			b.AddASN1OctetString(nil) // diagnosticMessage
		})
	})
	if err != nil {
		panic(err)
	}
	return msg
}

// fakeServer accepts LDAP connections and answers exactly the two
// operations the probe issues: Bind (always success) and Search (returns
// a fixed, configured set of groupOfNames cn values, then optionally
// closes the connection after a configured number of Searches — modeling
// "the backend the probe is bound to gets killed").
type fakeServer struct {
	ln net.Listener

	mu                 sync.Mutex
	cnValues           []string
	closeAfterSearches int // 0 = never proactively close
	connections        int
	binds              int
	searchesTotal      int
}

func newFakeServer(t *testing.T, cnValues []string, closeAfterSearches int) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fs := &fakeServer{ln: ln, cnValues: cnValues, closeAfterSearches: closeAfterSearches}
	go fs.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return fs
}

func (fs *fakeServer) addr() string { return fs.ln.Addr().String() }

func (fs *fakeServer) serve() {
	for {
		conn, err := fs.ln.Accept()
		if err != nil {
			return
		}
		fs.mu.Lock()
		fs.connections++
		fs.mu.Unlock()
		go fs.handleConn(conn)
	}
}

func (fs *fakeServer) handleConn(conn net.Conn) {
	defer conn.Close()

	localSearches := 0
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return
		}
		body, err := readFrame(conn)
		if err != nil {
			return
		}
		env, err := decodeEnvelope(body)
		if err != nil {
			return
		}

		switch env.tag {
		case tagBindRequest:
			fs.mu.Lock()
			fs.binds++
			fs.mu.Unlock()
			if _, werr := conn.Write(bindResponseBytes(env.messageID, 0)); werr != nil {
				return
			}

		case tagSearchRequest:
			localSearches++
			fs.mu.Lock()
			fs.searchesTotal++
			cnValues := fs.cnValues
			closeAfter := fs.closeAfterSearches
			fs.mu.Unlock()

			for _, cn := range cnValues {
				dn := "cn=" + cn + ",ou=groups,dc=proto,dc=test"
				if _, werr := conn.Write(searchResultEntryBytes(env.messageID, dn, cn)); werr != nil {
					return
				}
			}
			if _, werr := conn.Write(searchResultDoneBytes(env.messageID, 0)); werr != nil {
				return
			}
			if closeAfter > 0 && localSearches >= closeAfter {
				return
			}

		default:
			// Ignore anything else this fake server doesn't need to model
			// (e.g. an Unbind — this package's own client never sends
			// one; it simply closes the socket).
		}
	}
}

func (fs *fakeServer) snapshot() (connections, binds, searches int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.connections, fs.binds, fs.searchesTotal
}

// ---------------------------------------------------------------------
// Credential ingestion (stdin only).
// ---------------------------------------------------------------------

func TestReadCredentials_JSONDocument(t *testing.T) {
	stdin := strings.NewReader(`{"username":"alice@example.com","jwt":"eyJhbGciOiJSUzI1NiJ9.test.sig"}`)
	username, token, err := readCredentials(stdin)
	if err != nil {
		t.Fatalf("readCredentials: %v", err)
	}
	if username != "alice@example.com" || token != "eyJhbGciOiJSUzI1NiJ9.test.sig" {
		t.Fatalf("unexpected credentials: username=%q token=%q", username, token)
	}
}

func TestReadCredentials_JSONDocumentTokenKey(t *testing.T) {
	stdin := strings.NewReader(`{"username":"bob","token":"tok-value"}`)
	username, token, err := readCredentials(stdin)
	if err != nil {
		t.Fatalf("readCredentials: %v", err)
	}
	if username != "bob" || token != "tok-value" {
		t.Fatalf("unexpected credentials: username=%q token=%q", username, token)
	}
}

func TestReadCredentials_TwoLines(t *testing.T) {
	stdin := strings.NewReader("carol@example.com\nsome.jwt.value\n")
	username, token, err := readCredentials(stdin)
	if err != nil {
		t.Fatalf("readCredentials: %v", err)
	}
	if username != "carol@example.com" || token != "some.jwt.value" {
		t.Fatalf("unexpected credentials: username=%q token=%q", username, token)
	}
}

func TestReadCredentials_RejectsIncompleteInput(t *testing.T) {
	for name, in := range map[string]string{
		"empty":            "",
		"one line only":    "just-a-username",
		"json missing jwt": `{"username":"alice"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := readCredentials(strings.NewReader(in)); err == nil {
				t.Fatalf("expected an error for input %q", in)
			}
		})
	}
}

// ---------------------------------------------------------------------
// argv/env credential refusal.
// ---------------------------------------------------------------------

func TestFindForbiddenInput_RejectsCredentialFlags(t *testing.T) {
	cases := [][]string{
		{"-username=alice"},
		{"-password", "hunter2"},
		{"--jwt=eyJhbGciOi"},
		{"-token=abc"},
		{"-bearer=abc"},
	}
	for _, args := range cases {
		if !findForbiddenInput(args, nil) {
			t.Errorf("expected forbidden input for args %v", args)
		}
	}
}

func TestFindForbiddenInput_RejectsCredentialEnv(t *testing.T) {
	cases := [][]string{
		{"LDAP_PASSWORD=secret"},
		{"PROBE_JWT=abc.def.ghi"},
		{"PROBE_TOKEN=abc"},
		{"SOME_BEARER_TOKEN=xyz"},
	}
	for _, environ := range cases {
		if !findForbiddenInput(nil, environ) {
			t.Errorf("expected forbidden input for environ %v", environ)
		}
	}
}

func TestFindForbiddenInput_AllowsSafeFlagsAndEnv(t *testing.T) {
	safeArgs := []string{
		"-addr=127.0.0.1:389",
		"-user-base-dn=ou=users,dc=test",
		"-rdn-attr=uid",
		"-group-base-dn=ou=groups,dc=test",
		"-role-cn-prefix=ch_",
		"-interval=2s",
		"-output=/tmp/probe.log",
	}
	safeEnviron := []string{
		"PATH=/usr/bin",
		"HOME=/root",
		"PWD=/work",
		"HOSTNAME=probe-1",
	}
	if findForbiddenInput(safeArgs, safeEnviron) {
		t.Fatalf("expected no forbidden input for safe args/environ")
	}
}

// ---------------------------------------------------------------------
// End-to-end: single connection, single Bind, same-connection heartbeats,
// nonzero exit + "failed" marker when the server closes the socket, and
// no credential bytes anywhere in the captured output.
// ---------------------------------------------------------------------

func TestRun_SingleConnectionHeartbeatsThenFailsOnClose(t *testing.T) {
	const (
		username = "hauser@example.com"
		token    = "super-secret-jwt-value"
	)

	fs := newFakeServer(t, []string{"ch_role_one", "ch_role_two"}, 3 /* close after 3 Searches */)

	args := []string{
		"-addr=" + fs.addr(),
		"-user-base-dn=ou=users,dc=proto,dc=test",
		"-rdn-attr=uid",
		"-group-base-dn=ou=groups,dc=proto,dc=test",
		"-interval=10ms",
	}

	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	code := run(ctx, args, nil, strings.NewReader(username+"\n"+token+"\n"), &stdout)

	if code == 0 {
		t.Fatalf("expected nonzero exit when the server closes the socket, got 0; output:\n%s", stdout.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "probe: bound") {
		t.Errorf("expected a bound marker; output:\n%s", out)
	}
	if got := strings.Count(out, "probe: heartbeat"); got < 3 {
		t.Errorf("expected at least 3 heartbeat markers, got %d; output:\n%s", got, out)
	}
	if !strings.Contains(out, "entries=2") {
		t.Errorf("expected heartbeats to report entries=2; output:\n%s", out)
	}
	if !strings.Contains(out, "probe: failed search-") {
		t.Errorf("expected a 'probe: failed search-*' marker after the server closed the socket; output:\n%s", out)
	}

	connections, binds, _ := fs.snapshot()
	if connections != 1 {
		t.Errorf("expected exactly one TCP connection, got %d", connections)
	}
	if binds != 1 {
		t.Errorf("expected exactly one Bind, got %d", binds)
	}

	if strings.Contains(out, username) {
		t.Errorf("output leaked the username: %s", out)
	}
	if strings.Contains(out, token) {
		t.Errorf("output leaked the token: %s", out)
	}
}

// TestRun_NoReconnectAfterFailure re-confirms, independently of the
// combined test above, that a single failed Search never triggers a
// second connection or a second Bind — the invariant the HA kill-A
// scenario depends on ("existing connection is not migrated").
func TestRun_NoReconnectAfterFailure(t *testing.T) {
	fs := newFakeServer(t, []string{"ch_role"}, 1 /* close after the first Search */)

	args := []string{
		"-addr=" + fs.addr(),
		"-user-base-dn=ou=users,dc=proto,dc=test",
		"-rdn-attr=uid",
		"-group-base-dn=ou=groups,dc=proto,dc=test",
		"-interval=5ms",
	}

	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	code := run(ctx, args, nil, strings.NewReader("user@example.com\njwt-token\n"), &stdout)
	if code == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}

	// Give any (incorrect) reconnect attempt time to happen before asserting.
	time.Sleep(50 * time.Millisecond)

	connections, binds, _ := fs.snapshot()
	if connections != 1 {
		t.Errorf("probe reconnected: expected 1 connection, got %d", connections)
	}
	if binds != 1 {
		t.Errorf("probe re-bound: expected 1 bind, got %d", binds)
	}
}

// ---------------------------------------------------------------------
// Refusal end-to-end through run(), and -h exiting 0.
// ---------------------------------------------------------------------

func TestRun_RefusesForbiddenFlagWithoutDialing(t *testing.T) {
	fs := newFakeServer(t, []string{"ch_role"}, 0)

	args := []string{
		"-addr=" + fs.addr(),
		"-user-base-dn=ou=users,dc=proto,dc=test",
		"-rdn-attr=uid",
		"-group-base-dn=ou=groups,dc=proto,dc=test",
		"-password=hunter2",
	}

	var stdout bytes.Buffer
	code := run(context.Background(), args, nil, strings.NewReader("u\nj\n"), &stdout)
	if code == 0 {
		t.Fatalf("expected nonzero exit for a credential-shaped flag")
	}
	if !strings.Contains(stdout.String(), "probe: failed forbidden-input") {
		t.Errorf("expected the forbidden-input marker; output:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "hunter2") {
		t.Errorf("output leaked the forbidden flag's value")
	}

	connections, _, _ := fs.snapshot()
	if connections != 0 {
		t.Errorf("expected no dial attempt at all, got %d connections", connections)
	}
}

func TestRun_RefusesForbiddenEnvWithoutDialing(t *testing.T) {
	fs := newFakeServer(t, []string{"ch_role"}, 0)

	args := []string{
		"-addr=" + fs.addr(),
		"-user-base-dn=ou=users,dc=proto,dc=test",
		"-rdn-attr=uid",
		"-group-base-dn=ou=groups,dc=proto,dc=test",
	}
	environ := []string{"PROBE_JWT=should-not-be-here"}

	var stdout bytes.Buffer
	code := run(context.Background(), args, environ, strings.NewReader("u\nj\n"), &stdout)
	if code == 0 {
		t.Fatalf("expected nonzero exit for a credential-shaped env var")
	}
	if !strings.Contains(stdout.String(), "probe: failed forbidden-input") {
		t.Errorf("expected the forbidden-input marker; output:\n%s", stdout.String())
	}

	connections, _, _ := fs.snapshot()
	if connections != 0 {
		t.Errorf("expected no dial attempt at all, got %d connections", connections)
	}
}

func TestRun_HelpExitsZero(t *testing.T) {
	var stdout bytes.Buffer
	code := run(context.Background(), []string{"-h"}, nil, strings.NewReader(""), &stdout)
	if code != 0 {
		t.Fatalf("expected -h to exit 0, got %d; output:\n%s", code, stdout.String())
	}
}

func TestRun_MissingRequiredFlagsFailsCleanly(t *testing.T) {
	var stdout bytes.Buffer
	code := run(context.Background(), []string{"-addr=127.0.0.1:1"}, nil, strings.NewReader(""), &stdout)
	if code == 0 {
		t.Fatalf("expected nonzero exit for missing required flags")
	}
}

// ---------------------------------------------------------------------
// Role-prefix filtering of the heartbeat entry count.
// ---------------------------------------------------------------------

func TestRun_RoleCNPrefixFiltersHeartbeatCount(t *testing.T) {
	fs := newFakeServer(t, []string{"ch_role_one", "other_group", "ch_role_two"}, 1)

	args := []string{
		"-addr=" + fs.addr(),
		"-user-base-dn=ou=users,dc=proto,dc=test",
		"-rdn-attr=uid",
		"-group-base-dn=ou=groups,dc=proto,dc=test",
		"-role-cn-prefix=ch_",
		"-interval=5ms",
	}

	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = run(ctx, args, nil, strings.NewReader("user@example.com\njwt\n"), &stdout)

	if !strings.Contains(stdout.String(), "entries=2") {
		t.Errorf("expected the ch_-prefixed count (2) in heartbeat output; output:\n%s", stdout.String())
	}
}

// ---------------------------------------------------------------------
// Graceful context cancellation (not itself a "failure").
// ---------------------------------------------------------------------

func TestRun_ContextCancellationStopsGracefully(t *testing.T) {
	fs := newFakeServer(t, []string{"ch_role"}, 0 /* never closes on its own */)

	args := []string{
		"-addr=" + fs.addr(),
		"-user-base-dn=ou=users,dc=proto,dc=test",
		"-rdn-attr=uid",
		"-group-base-dn=ou=groups,dc=proto,dc=test",
		"-interval=200ms",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	var stdout bytes.Buffer
	code := run(ctx, args, nil, strings.NewReader("user@example.com\njwt\n"), &stdout)
	if code != 0 {
		t.Fatalf("expected graceful shutdown to exit 0, got %d; output:\n%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "probe: stopped") {
		t.Errorf("expected a stopped marker; output:\n%s", stdout.String())
	}

	connections, binds, _ := fs.snapshot()
	if connections != 1 || binds != 1 {
		t.Errorf("expected exactly one connection/bind, got connections=%d binds=%d", connections, binds)
	}
}

// ---------------------------------------------------------------------
// Direct coverage of the raw client and its DN-escaping helper — the
// pieces main_test.go's end-to-end tests above exercise only indirectly.
// ---------------------------------------------------------------------

func TestEscapeDN(t *testing.T) {
	cases := map[string]string{
		"alice@example.com": "alice@example.com",
		" leading":          `\ leading`,
		"trailing ":         `trailing\ `,
		"#leading-hash":     `\#leading-hash`,
		`a,b+c;d<e>f\g"h`:   `a\,b\+c\;d\<e\>f\\g\"h`,
	}
	for in, want := range cases {
		if got := escapeDN(in); got != want {
			t.Errorf("escapeDN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProbeConn_BindAndSearchOnSameConnection(t *testing.T) {
	fs := newFakeServer(t, []string{"ch_role_a", "ch_role_b"}, 0)

	conn, err := dialProbe(fs.addr(), time.Second)
	if err != nil {
		t.Fatalf("dialProbe: %v", err)
	}
	defer conn.Close()

	if err := conn.simpleBind("uid=probe,ou=users,dc=test", "jwt", time.Second); err != nil {
		t.Fatalf("simpleBind: %v", err)
	}

	cns, err := conn.searchMembership("ou=groups,dc=test", "uid=probe,ou=users,dc=test", time.Second)
	if err != nil {
		t.Fatalf("searchMembership: %v", err)
	}
	if len(cns) != 2 || cns[0] != "ch_role_a" || cns[1] != "ch_role_b" {
		t.Fatalf("unexpected cn values: %v", cns)
	}

	// A second Search on the same, still-open connection must also
	// succeed — the probe's "repeated Search on one connection" shape.
	cns, err = conn.searchMembership("ou=groups,dc=test", "uid=probe,ou=users,dc=test", time.Second)
	if err != nil {
		t.Fatalf("second searchMembership: %v", err)
	}
	if len(cns) != 2 {
		t.Fatalf("unexpected cn values on second search: %v", cns)
	}

	connections, binds, searches := fs.snapshot()
	if connections != 1 || binds != 1 || searches != 2 {
		t.Fatalf("unexpected server-observed counts: connections=%d binds=%d searches=%d", connections, binds, searches)
	}
}

func TestProbeConn_BindInvalidCredentialsClassifiesCorrectly(t *testing.T) {
	// newFakeServer's Bind handler always returns success, so this test
	// dials a small one-shot listener directly to return a crafted
	// resultCode-49 BindResponse instead.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		body, err := readFrame(conn)
		if err != nil {
			return
		}
		env, err := decodeEnvelope(body)
		if err != nil || env.tag != tagBindRequest {
			return
		}
		_, _ = conn.Write(bindResponseBytes(env.messageID, ldapResultInvalidCredentials))
	}()

	conn, err := dialProbe(ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dialProbe: %v", err)
	}
	defer conn.Close()

	err = conn.simpleBind("uid=probe,ou=users,dc=test", "wrong-jwt", time.Second)
	if err == nil {
		t.Fatalf("expected a Bind failure for resultCode 49")
	}
	if classifyError(err) != "invalid-credentials" {
		t.Fatalf("classifyError(%v) = %q, want invalid-credentials", err, classifyError(err))
	}
}
