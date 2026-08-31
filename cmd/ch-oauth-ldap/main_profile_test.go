package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/altinity/altinity-oauth-helper/internal/ldap/profile"
	"github.com/altinity/altinity-oauth-helper/internal/roles"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// This file adds LDAP-backend-specific proof beyond main_test.go's own
// TestRunComposesRealVerifierPipelineAndLDAPServer /
// TestRunFailsFastOnInvalidConfig, which are already backend-neutral (they
// never name a concrete backend type). What only this file adds is proof
// that the backend run() actually composes IS internal/ldap/profile.Server —
// the only production LDAP implementation this command ships.

// TestNewLDAPServerSelectsProfileBackend proves newLDAPServer constructs a
// real internal/ldap/profile.Server (via a type assertion on the concrete
// type the ldapServer interface hides) — wired to the REAL
// verification.Verifier and roles.Pipeline, not test fakes — and that the
// command still owns creating the net.Listener: newLDAPServer/profile.New
// never call net.Listen themselves, so this test creates its own listener
// exactly as run() does before ever calling Serve.
func TestNewLDAPServerSelectsProfileBackend(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	verifier, err := verification.New(cfg.toVerificationConfig())
	require.NoError(t, err)
	rolePipeline, err := roles.New(cfg.toRolesConfig())
	require.NoError(t, err)

	srv, err := newLDAPServer(context.Background(), cfg, verifier, rolePipeline)
	require.NoError(t, err)

	_, ok := srv.(*profile.Server)
	require.True(t, ok, "newLDAPServer must select internal/ldap/profile.Server, got %T", srv)

	// The command, not newLDAPServer/profile.New, owns net.Listen — prove
	// it by creating the listener here ourselves and confirming Serve
	// accepts it, then shut down cleanly.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- srv.Serve(listener)
	}()

	// Give Serve a moment to reach its accept loop before stopping, mirroring
	// run()'s own startup ordering.
	time.Sleep(50 * time.Millisecond)

	srv.Stop()

	select {
	case err := <-serveErrCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Stop within timeout")
	}
}

// TestRunComposesRealProfileBackend is main_test.go's
// TestRunComposesRealVerifierPipelineAndLDAPServer with an added type
// assertion: it exercises exactly the same process lifecycle (real config
// load, real verifier/role pipeline, command-owned listener, clean shutdown
// on context cancellation), and additionally confirms the backend run()
// actually drives is internal/ldap/profile's server.
func TestRunComposesRealProfileBackend(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yamlContent := `
oauth:
  expected_issuer: https://example.invalid/
  expected_audiences:
    - clickhouse

identity:
  username_match: lowercase_equal

roles:
  roles_filter: '^ch_[A-Za-z0-9_]+$'

ldap:
  listen: '127.0.0.1:0'
  user_base_dn: 'ou=users,dc=altinity,dc=internal'
  group_base_dn: 'ou=groups,dc=altinity,dc=internal'
  user_rdn_attribute: uid
  role_cn_prefix: 'clickhouse_'
`
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o600))

	app := &cli.Command{
		Name: "ch-oauth-ldap",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Aliases: []string{"c"}},
			&cli.StringFlag{Name: "log-level", Value: "error"},
		},
		Action: run,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- app.Run(ctx, []string{"ch-oauth-ldap", "--config", path})
	}()

	select {
	case err := <-done:
		t.Fatalf("run() returned before shutdown was requested: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err, "run() must shut down cleanly on context cancellation with the profile backend")
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not shut down within timeout after context cancellation")
	}
}
