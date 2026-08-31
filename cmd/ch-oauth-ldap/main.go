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
// Real ClickHouse 24.8 configuration/interoperability is phase 3 and is not
// claimed here. See the phase-2 plan for the full design and rationale.
//
// # Temporary phase3profile backend seam (issue #33 phase 3)
//
// This command imports neither LDAP backend directly. Instead it declares
// the minimal ldapServer interface below and calls the build-selected
// newLDAPServer(...): the ordinary (untagged) build compiles
// ldap_backend_legacy.go, which imports internal/ldap and is what
// production actually ships; a build with -tags=phase3profile compiles
// ldap_backend_phase3profile.go instead, which imports only
// internal/ldap/profile — issue #33's compatibility-profile replacement
// under certification. Exactly one of those two files is ever part of a
// given build; there is no YAML option, CLI flag, environment variable, or
// other runtime selector. This is temporary Phase 3 certification
// scaffolding: Phase 4 deletes the selector and the legacy adapter, making
// the profile backend the only, ordinary production code.
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

// ldapServer is the minimal backend surface run() depends on: whichever
// concrete LDAP server type the active build tag selects (internal/ldap's
// legacy *Server by default, internal/ldap/profile's *Server under
// -tags=phase3profile) must implement it. Neither backend's package is
// imported from this file.
type ldapServer interface {
	Serve(net.Listener) error
	Stop()
}

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
//  6. construct the build-selected LDAP backend (newLDAPServer, see
//     ldapServer above) with the signal context;
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
	// constructed: it is threaded into the build-selected backend's New
	// (newLDAPServer, see ldapServer above) as the root lifecycle context
	// every per-connection handler derives its per-request context from,
	// and it also governs the verifier's background cache reaper below.
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
		// calling srv.Stop() first. This ordering is preserved unchanged
		// across both LDAP backends the phase3profile build tag selects
		// (see ldapServer above):
		//
		//   - the ordinary (legacy internal/ldap) backend's vendored
		//     vjeantet/ldapserver dependency stores the listener in a
		//     plain, unsynchronized struct field (Server.Listener): Serve
		//     writes it (background goroutine, above) and Stop reads it
		//     with no lock between them — calling Stop() concurrently
		//     with the still-running Serve goroutine is a genuine data
		//     race in that dependency itself (confirmed with -race);
		//   - the internal/ldap/profile replacement backend's Stop is
		//     already safe to call concurrently with Serve, so this same
		//     ordering costs it nothing.
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
