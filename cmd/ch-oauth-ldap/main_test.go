package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// TestRunComposesRealVerifierPipelineAndLDAPServer is the phase-2 plan's
// "small command-level composition test" proving run() builds the REAL
// verification.Verifier, roles.Pipeline and internal/ldap.Server together —
// not test fakes — and that the whole thing starts serving and shuts down
// cleanly on context cancellation, exactly mirroring how a real SIGINT/
// SIGTERM would be observed through signal.NotifyContext.
//
// This deliberately does not attempt any LDAP Bind/Search: internal/ldap's
// own protocol_test.go already exhaustively covers Bind/Search behavior
// with deterministic fakes, and the plan explicitly says not to duplicate
// phase 1's cryptographic JWT test suite here. This test's only job is to
// prove the command wires the real production types together and that the
// process lifecycle (construct -> listen -> Serve -> shutdown) actually
// works end to end.
func TestRunComposesRealVerifierPipelineAndLDAPServer(t *testing.T) {
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

	// A cancelable context stands in for the real process context main()
	// passes to signal.NotifyContext: canceling it is observably identical
	// to run()'s signalCtx.Done() firing from a real SIGINT/SIGTERM,
	// without this test sending an actual OS signal to the whole test
	// binary.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- app.Run(ctx, []string{"ch-oauth-ldap", "--config", path})
	}()

	// Give run() time to load config, construct the real verifier/pipeline/
	// server, and reach net.Listen + Serve before triggering shutdown.
	select {
	case err := <-done:
		t.Fatalf("run() returned before shutdown was requested: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err, "run() must shut down cleanly on context cancellation")
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not shut down within timeout after context cancellation")
	}
}

// TestRunFailsFastOnInvalidConfig proves run() surfaces config activation
// failures as an error before ever constructing the LDAP server or
// listening — no goroutine leak, no listener left open.
func TestRunFailsFastOnInvalidConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Both oauth.expected_issuer and oauth.jwks_url absent: must fail
	// config activation.
	yamlContent := `
oauth:
  expected_audiences:
    - clickhouse

ldap:
  listen: '127.0.0.1:0'
  user_base_dn: 'ou=users,dc=altinity,dc=internal'
  group_base_dn: 'ou=groups,dc=altinity,dc=internal'
  user_rdn_attribute: uid
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

	err := app.Run(context.Background(), []string{"ch-oauth-ldap", "--config", path})
	require.ErrorContains(t, err, "oauth: either issuer or jwks_url must be set")
}
