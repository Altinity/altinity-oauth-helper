// Command ch-oauth-ldap is a standalone LDAPv3 server that authenticates a
// simple-Bind request by treating the presented password as a JWT: it
// reuses the shared verifier (github.com/altinity/altinity-oauth-helper/
// internal/verification) and role pipeline
// (github.com/altinity/altinity-oauth-helper/internal/roles) already
// established by cmd/ch-jwt-verify, and answers a restricted, same-
// connection Search with synthetic groupOfNames entries representing the
// roles derived once at Bind time.
//
// This is phase 2 of issue #19: a standalone protocol-correct LDAP server.
// Real ClickHouse interoperability was certified in phases 3 and 4; see
// docs/clickhouse-ldap-wire-profile.md for the wire-compatibility evidence.
//
// # LDAP backend (issue #33 phase 4 production cutover)
//
// This command does not import internal/ldap/profile directly from this
// file. Instead it declares the minimal ldapServer interface (see
// ldap_backend.go) and calls newLDAPServer(...), which ldap_backend.go
// implements against internal/ldap/profile.Server — the only production LDAP
// implementation this command ships. There is no build tag, no YAML option,
// CLI flag, environment variable, or other runtime selector: every ordinary
// build and every ordinary test constructs the same backend.
package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"

	"github.com/altinity/altinity-oauth-helper/internal/roles"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

var version = "dev"

func main() {
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	app := &cli.Command{
		Name:    "ch-oauth-ldap",
		Usage:   "Standalone LDAPv3 server authenticating simple Bind against a JWT",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to YAML config file",
				Value:   "/etc/ch-oauth-ldap/config.yaml",
				Sources: cli.EnvVars("CH_OAUTH_LDAP_CONFIG"),
			},
			&cli.StringFlag{
				Name:    "log-level",
				Usage:   "Logging level (debug/info/warn/error)",
				Value:   "info",
				Sources: cli.EnvVars("CH_OAUTH_LDAP_LOG_LEVEL"),
			},
		},
		Action: run,
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal().Err(err).Msg("ch-oauth-ldap exited with error")
	}
}

// run executes the phase-2 plan's exact "Process and server lifecycle"
// ordering:
//
//  1. parse log level;
//  2. load and validate config;
//  3. create the signal-aware root context BEFORE constructing the LDAP
//     server, because that context is part of the runtime behavior passed
//     to every handler (see "Runtime context and cancellation" in the
//     plan);
//  4. construct the concrete verification.Verifier;
//  5. construct the concrete roles.Pipeline;
//  6. construct the LDAP backend (newLDAPServer, see ldapServer in
//     ldap_backend.go) with the signal context;
//  7. start the verifier's cache reaper from the same root signal context;
//  8. net.Listen on the configured LDAP address;
//  9. Serve in a goroutine, reporting its error through a buffered
//     channel;
//  10. select on process shutdown (Stop, wait, clean return) vs a genuine
//     Serve error.
//
// No TLS and no HTTP endpoint are ever served — this command is LDAP-only.
func run(ctx context.Context, cmd *cli.Command) error {
	if lvl, err := zerolog.ParseLevel(cmd.String("log-level")); err == nil {
		zerolog.SetGlobalLevel(lvl)
	}

	cfg, err := LoadConfig(cmd.String("config"))
	if err != nil {
		return err
	}

	// The signal-aware context must exist before the LDAP server is
	// constructed: it is threaded into the backend's New (newLDAPServer, see
	// ldap_backend.go) as the root lifecycle context every per-connection
	// handler derives its per-request context from, and it also governs the
	// verifier's background cache reaper below.
	signalCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	verifier, err := verification.New(cfg.toVerificationConfig())
	if err != nil {
		return err
	}

	rolePipeline, err := roles.New(cfg.toRolesConfig())
	if err != nil {
		return err
	}

	srv, err := newLDAPServer(signalCtx, cfg, verifier, rolePipeline)
	if err != nil {
		return err
	}

	// Background reaper prunes expired verification-cache entries on a
	// fixed cadence, mirroring the sibling ch-jwt-verify command's own
	// reaper cadence and lifecycle-context binding.
	verifier.StartReaper(signalCtx, 5*time.Minute)

	listener, err := net.Listen("tcp", cfg.LDAP.Listen)
	if err != nil {
		return err
	}
	log.Info().Str("network", "tcp").Str("address", cfg.LDAP.Listen).Str("version", version).Msg("ch-oauth-ldap listening")

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(listener)
	}()

	select {
	case <-signalCtx.Done():
		log.Info().Msg("ch-oauth-ldap shutting down")

		// Close OUR OWN reference to the listener directly, instead of
		// calling srv.Stop() first. internal/ldap/profile.Server's Stop is
		// safe to call concurrently with Serve, so this ordering costs it
		// nothing — it is kept anyway for the happens-before argument
		// below, which does not depend on that safety.
		//
		// Closing our own listener reference unblocks the background
		// goroutine's blocked Accept() call, which returns an error that
		// propagates through Serve() into errCh. Receiving from errCh
		// below is a channel synchronization point: by the time that
		// receive completes, the background goroutine's earlier read of
		// the listener (which happened at the very start of Serve, long
		// before Accept ever blocked) is guaranteed to have already
		// happened-before this goroutine's own close above matters. Only
		// then do we call srv.Stop() — any internal Listener.Close() it
		// performs now races against nothing, since the background
		// goroutine has already returned.
		if err := listener.Close(); err != nil {
			log.Warn().Err(err).Msg("closing LDAP listener during shutdown")
		}
		serveErr := <-errCh

		// Stop() is still required after the above for its graceful-drain
		// semantics (waiting for already-accepted client connections to
		// finish). Any internal Close() of the listener it performs is
		// now a no-op-shaped close of an already-closed listener, which
		// Stop() already ignores.
		srv.Stop()

		if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
			return serveErr
		}
		return nil
	case serveErr := <-errCh:
		return serveErr
	}
}
