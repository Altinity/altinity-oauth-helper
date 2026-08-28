package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

// ---------------------------------------------------------------------
// A minimal in-process fake LDAP server.
//
// This does not reuse internal/ldap's production server: that server is
// wired to a full verifier/role-resolver pipeline this package must not
// import (the probe is intentionally a standalone, dependency-light
// binary — see the package doc comment). Instead this hand-builds just
// enough real LDAPv3 wire responses — BindResponse, SearchResultEntry,
// SearchResultDone — using the same github.com/go-asn1-ber/asn1-ber
// primitives go-ldap/ldap/v3 itself uses to encode requests, so the
// probe's real, unmodified go-ldap client decodes them exactly as it
// would decode a real server's responses.
// ---------------------------------------------------------------------

func ldapEnvelope(msgID int64, protocolOp *ber.Packet) []byte {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	envelope.AppendChild(protocolOp)
	return envelope.Bytes()
}

func bindResponseBytes(msgID int64, resultCode int) []byte {
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldap.ApplicationBindResponse), nil, "Bind Response")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(resultCode), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	return ldapEnvelope(msgID, resp)
}

func searchResultEntryBytes(msgID int64, dn, cnValue string) []byte {
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldap.ApplicationSearchResultEntry), nil, "Search Result Entry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Object Name"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "Attribute Name"))
	values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Values")
	values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, cnValue, "Attribute Value"))
	attr.AppendChild(values)
	attrs.AppendChild(attr)
	entry.AppendChild(attrs)

	return ldapEnvelope(msgID, entry)
}

func searchResultDoneBytes(msgID int64, resultCode int) []byte {
	done := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldap.ApplicationSearchResultDone), nil, "Search Result Done")
	done.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(resultCode), "resultCode"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	return ldapEnvelope(msgID, done)
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
		pkt, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		if len(pkt.Children) < 2 {
			continue
		}
		msgID, ok := pkt.Children[0].Value.(int64)
		if !ok {
			continue
		}
		op := pkt.Children[1]

		switch int(op.Tag) {
		case ldap.ApplicationBindRequest:
			fs.mu.Lock()
			fs.binds++
			fs.mu.Unlock()
			if _, werr := conn.Write(bindResponseBytes(msgID, 0)); werr != nil {
				return
			}

		case ldap.ApplicationSearchRequest:
			localSearches++
			fs.mu.Lock()
			fs.searchesTotal++
			cnValues := fs.cnValues
			closeAfter := fs.closeAfterSearches
			fs.mu.Unlock()

			for _, cn := range cnValues {
				dn := "cn=" + cn + ",ou=groups,dc=proto,dc=test"
				if _, werr := conn.Write(searchResultEntryBytes(msgID, dn, cn)); werr != nil {
					return
				}
			}
			if _, werr := conn.Write(searchResultDoneBytes(msgID, 0)); werr != nil {
				return
			}
			if closeAfter > 0 && localSearches >= closeAfter {
				return
			}

		case ldap.ApplicationUnbindRequest:
			return

		default:
			// Ignore anything else this fake server doesn't need to model.
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
