package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/altinity/altinity-oauth-helper/internal/roles"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// This exercises the command's real verifier, role pipeline, and production
// LDAP backend over one TCP connection. A fake verifier would skip the exact
// JWT claim resolution that made issue #67 possible.
func TestLDAPNamespacedEmailRequiresSameNamespaceVerification(t *testing.T) {
	const (
		email     = "victim@example.com"
		namespace = "https://example.com/"
		wantRole  = "clickhouse_ch_reader"
	)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "issue-67-test"))
	require.NoError(t, err)

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "issue-67-test", Algorithm: "RS256", Use: "sig",
		}}})
	}))
	t.Cleanup(idp.Close)

	cfg := validConfig()
	cfg.OAuth.ExpectedIssuer = idp.URL
	cfg.OAuth.JWKSURL = idp.URL + "/jwks"
	cfg.OAuth.ExpectedAudiences = []string{"clickhouse"}
	cfg.OAuth.UsernameClaim = "email"
	cfg.OAuth.GroupsClaim = "roles"
	cfg.Identity.RequireEmailVerified = true
	cfg.Roles.RolesMapping = map[string]string{"reader-team": "ch_reader"}

	verifier, err := verification.New(cfg.toVerificationConfig())
	require.NoError(t, err)
	rolePipeline, err := roles.New(cfg.toRolesConfig())
	require.NoError(t, err)
	srv, err := newLDAPServer(context.Background(), cfg, verifier, rolePipeline)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(listener) }()
	t.Cleanup(func() {
		srv.Stop()
		select {
		case err := <-serveDone:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("LDAP server did not stop")
		}
	})

	bindDN := "uid=" + email + "," + cfg.LDAP.UserBaseDN
	mint := func(extra map[string]any) string {
		t.Helper()
		claims := map[string]any{
			"iss": idp.URL, "aud": "clickhouse", "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "sub": "issue-67-victim", "roles": []string{"reader-team"},
			namespace + "email": email,
		}
		for k, v := range extra {
			claims[k] = v
		}
		token, err := josejwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)
		return token
	}

	verified := mint(map[string]any{namespace + "email_verified": true})
	for _, tc := range []struct {
		name  string
		extra map[string]any
	}{
		{name: "verification absent"},
		{name: "verification false", extra: map[string]any{namespace + "email_verified": false}},
		{name: "unrelated top-level true", extra: map[string]any{"email_verified": true}},
		{name: "same-namespace false despite top-level true", extra: map[string]any{
			namespace + "email_verified": false, "email_verified": true,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := dialIssue67LDAP(t, listener.Addr().String())
			password := mint(tc.extra)
			for i := 0; i < 2; i++ { // The second Bind also exercises the negative cache.
				require.Equal(t, 49, client.bind(bindDN, password))
			}
			entries, code := client.search(cfg.LDAP.GroupBaseDN, bindDN)
			require.Equal(t, 50, code)
			require.Empty(t, entries)
		})
	}

	t.Run("verified Bind, Search, rejected rebind clears session", func(t *testing.T) {
		client := dialIssue67LDAP(t, listener.Addr().String())
		require.Equal(t, 0, client.bind(bindDN, verified))
		entries, code := client.search(cfg.LDAP.GroupBaseDN, bindDN)
		require.Equal(t, 0, code)
		require.Equal(t, []string{wantRole}, entries)

		unverified := mint(map[string]any{namespace + "email_verified": false})
		require.Equal(t, 49, client.bind(bindDN, unverified))
		entries, code = client.search(cfg.LDAP.GroupBaseDN, bindDN)
		require.Equal(t, 50, code)
		require.Empty(t, entries)

		// A positive cache hit may authenticate a new Bind, but only after
		// another successful Bind restores this connection's state.
		require.Equal(t, 0, client.bind(bindDN, verified))
		entries, code = client.search(cfg.LDAP.GroupBaseDN, bindDN)
		require.Equal(t, 0, code)
		require.Equal(t, []string{wantRole}, entries)
	})
}

// issue67LDAPClient speaks only the fixed Bind/Search wire profile used by
// ClickHouse. Keeping it local makes this an independent command-level test.
type issue67LDAPClient struct {
	t      *testing.T
	conn   net.Conn
	nextID byte
}

func dialIssue67LDAP(t *testing.T, addr string) *issue67LDAPClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &issue67LDAPClient{t: t, conn: conn, nextID: 1}
}

func issue67TLV(tag byte, body []byte) []byte {
	var length []byte
	switch {
	case len(body) < 128:
		length = []byte{byte(len(body))}
	case len(body) < 256:
		length = []byte{0x81, byte(len(body))}
	default:
		length = []byte{0x82, byte(len(body) >> 8), byte(len(body))}
	}
	out := append([]byte{tag}, length...)
	return append(out, body...)
}

func issue67Join(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func (c *issue67LDAPClient) request(tag byte, body []byte) (byte, cryptobyte.String) {
	c.t.Helper()
	id := c.nextID
	c.nextID++
	message := issue67TLV(0x30, issue67Join(issue67TLV(0x02, []byte{id}), issue67TLV(tag, body)))
	require.NoError(c.t, c.conn.SetDeadline(time.Now().Add(5*time.Second)))
	n, err := c.conn.Write(message)
	require.NoError(c.t, err)
	require.Equal(c.t, len(message), n)
	return c.readResponse(id)
}

func (c *issue67LDAPClient) readResponse(id byte) (byte, cryptobyte.String) {
	c.t.Helper()
	var header [2]byte
	_, err := io.ReadFull(c.conn, header[:])
	require.NoError(c.t, err)
	require.Equal(c.t, byte(0x30), header[0])
	length := int(header[1])
	if header[1]&0x80 != 0 {
		octets := int(header[1] & 0x7f)
		require.LessOrEqual(c.t, octets, 2)
		require.Greater(c.t, octets, 0)
		var longLength [2]byte
		_, err = io.ReadFull(c.conn, longLength[:octets])
		require.NoError(c.t, err)
		length = 0
		for _, b := range longLength[:octets] {
			length = length<<8 | int(b)
		}
	}
	require.LessOrEqual(c.t, length, 65536)
	body := make([]byte, length)
	_, err = io.ReadFull(c.conn, body)
	require.NoError(c.t, err)
	content := cryptobyte.String(body)
	var responseID int
	require.True(c.t, content.ReadASN1Integer(&responseID))
	require.Equal(c.t, int(id), responseID)
	var op cryptobyte.String
	var opTag asn1.Tag
	require.True(c.t, content.ReadAnyASN1(&op, &opTag))
	require.True(c.t, content.Empty())
	return byte(opTag), op
}

func issue67Result(t *testing.T, op cryptobyte.String) int {
	t.Helper()
	var code int
	var matchedDN, diagnostic []byte
	require.True(t, op.ReadASN1Enum(&code))
	require.True(t, op.ReadASN1Bytes(&matchedDN, asn1.OCTET_STRING))
	require.True(t, op.ReadASN1Bytes(&diagnostic, asn1.OCTET_STRING))
	require.Empty(t, matchedDN)
	require.True(t, op.Empty())
	switch code {
	case 0:
		require.Empty(t, diagnostic)
	case 49:
		require.Equal(t, "invalid credentials", string(diagnostic))
	case 50:
		require.Equal(t, "insufficient access", string(diagnostic))
	}
	return code
}

func (c *issue67LDAPClient) bind(dn, password string) int {
	c.t.Helper()
	request := issue67Join(issue67TLV(0x02, []byte{3}), issue67TLV(0x04, []byte(dn)), issue67TLV(0x80, []byte(password)))
	tag, response := c.request(0x60, request)
	require.Equal(c.t, byte(0x61), tag)
	return issue67Result(c.t, response)
}

func (c *issue67LDAPClient) search(base, memberDN string) ([]string, int) {
	c.t.Helper()
	filter := issue67TLV(0xa0, issue67Join(
		issue67TLV(0xa3, issue67Join(issue67TLV(0x04, []byte("objectClass")), issue67TLV(0x04, []byte("groupOfNames")))),
		issue67TLV(0xa3, issue67Join(issue67TLV(0x04, []byte("member")), issue67TLV(0x04, []byte(memberDN)))),
	))
	request := issue67Join(
		issue67TLV(0x04, []byte(base)), issue67TLV(0x0a, []byte{2}), issue67TLV(0x0a, []byte{0}),
		issue67TLV(0x02, []byte{0}), issue67TLV(0x02, []byte{0}), issue67TLV(0x01, []byte{0}),
		filter, issue67TLV(0x30, issue67TLV(0x04, []byte("cn"))),
	)
	tag, response := c.request(0x63, request)
	var entries []string
	for tag == 0x64 {
		var dn []byte
		var attrs, attr, vals cryptobyte.String
		var name, value []byte
		require.True(c.t, response.ReadASN1Bytes(&dn, asn1.OCTET_STRING))
		require.True(c.t, response.ReadASN1(&attrs, asn1.SEQUENCE))
		require.True(c.t, attrs.ReadASN1(&attr, asn1.SEQUENCE))
		require.True(c.t, attr.ReadASN1Bytes(&name, asn1.OCTET_STRING))
		require.Equal(c.t, "cn", string(name))
		require.True(c.t, attr.ReadASN1(&vals, asn1.SET))
		require.True(c.t, vals.ReadASN1Bytes(&value, asn1.OCTET_STRING))
		require.True(c.t, vals.Empty())
		require.True(c.t, attr.Empty())
		require.True(c.t, attrs.Empty())
		require.True(c.t, response.Empty())
		require.Equal(c.t, "cn="+string(value)+","+base, string(dn))
		entries = append(entries, string(value))
		tag, response = c.readResponse(c.nextID - 1)
	}
	require.Equal(c.t, byte(0x65), tag)
	return entries, issue67Result(c.t, response)
}
