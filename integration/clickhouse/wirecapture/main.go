// Command ldap-wire-recorder is the narrow-scope capture/sanitize/compare
// tool for issue #33 phase 1's ClickHouse LDAP wire-evidence corpus (plan
// §8.3/§22-§24/§28-§29). It understands only bounded LDAPMessage outer
// framing (plan §22) — never DN parsing, generic filters, attribute
// semantics, controls semantics, role logic, or recursive ASN.1 — and
// exposes exactly five subcommands:
//
//	ldap-wire-recorder serve --mode pass
//	ldap-wire-recorder serve --mode stall-after-bind
//	ldap-wire-recorder sanitize
//	ldap-wire-recorder construct-message-id-boundary
//	ldap-wire-recorder compare
//
// It writes profile.json/session.json ONLY through
// github.com/altinity/altinity-oauth-helper/internal/wirefixture's
// WriteProfile/WriteSession — this package declares no Profile/Session/PDU
// type of its own (plan §9's "writer ownership").
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin *os.File, stdout, stderr *fileWriter) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "wirecapture: missing subcommand (serve|sanitize|construct-message-id-boundary|compare)")
		return 2
	}
	sub, rest := args[0], args[1:]
	var err error
	switch sub {
	case "serve":
		err = runServe(rest, stdout)
	case "sanitize":
		err = runSanitize(rest, stdin, stdout)
	case "construct-message-id-boundary":
		err = runConstruct(rest, stdout)
	case "compare":
		err = runCompare(rest, stdout)
	default:
		fmt.Fprintf(stderr, "wirecapture: unknown subcommand %q\n", sub)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "wirecapture: %v\n", err)
		return 1
	}
	return 0
}

// fileWriter is the minimal io.Writer this file needs; kept as an alias so
// the exported run signature stays concrete (os.Stdout/os.Stderr) without
// pulling in an io.Writer-typed test double that could accidentally also
// satisfy os.File-specific stdlib APIs this package does not use.
type fileWriter = os.File

func runServe(args []string, stdout *fileWriter) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	mode := fs.String("mode", "", "pass | stall-after-bind")
	listen := fs.String("listen", ":389", "listen address")
	upstream := fs.String("upstream", "ldap-helper-upstream:389", "upstream LDAP helper address")
	rawDir := fs.String("raw-dir", "/run/ldap-wirecapture/raw", "private raw-capture directory")
	readyFile := fs.String("ready-file", "/run/ldap-wirecapture/ready", "readiness file written after Listen succeeds")
	stallDeadline := fs.Duration("stall-deadline", defaultStallDeadline, "hard deadline for stall-after-bind's Abandon/Unbind wait")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mode != "pass" && *mode != "stall-after-bind" {
		return fmt.Errorf("--mode must be \"pass\" or \"stall-after-bind\", got %q", *mode)
	}

	rec := &Recorder{
		Mode:          *mode,
		UpstreamAddr:  *upstream,
		RawDir:        *rawDir,
		ReadyFilePath: *readyFile,
		StallDeadline: *stallDeadline,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stdout, "wirecapture: serving mode=%s listen=%s upstream=%s\n", *mode, *listen, *upstream)
	return rec.ListenAndServe(ctx, *listen)
}

func runSanitize(args []string, stdin *fileWriter, stdout *fileWriter) error {
	fs := flag.NewFlagSet("sanitize", flag.ContinueOnError)
	rawDir := fs.String("raw-dir", "/run/ldap-wirecapture/raw", "private raw-capture directory")
	sanitizedDir := fs.String("sanitized-dir", "/run/ldap-wirecapture/sanitized", "sanitized staging directory (the only tree ever exported to the host)")
	line := fs.String("line", "", "tracked line label, e.g. 24.8")
	mode := fs.String("mode", "", "success | timeout-abandon")
	sql := fs.String("sql", "", "the controlled SQL statement issued for this session")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cred, err := readCredentialFromStdin(stdin)
	if err != nil {
		return err
	}

	session, err := Sanitize(SanitizeInput{
		RawDir:       *rawDir,
		SanitizedDir: *sanitizedDir,
		Credential:   cred,
		Line:         *line,
		Mode:         *mode,
		SQL:          *sql,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wirecapture: sanitized %d PDUs into %s\n", len(session.PDUs), *sanitizedDir)
	return nil
}

func runConstruct(args []string, stdout *fileWriter) error {
	fs := flag.NewFlagSet("construct-message-id-boundary", flag.ContinueOnError)
	outputDir := fs.String("output-dir", "", "output directory for the constructed bundle")
	lines := fs.String("lines", "", "comma-separated applicable tracked lines, e.g. 24.8,25.8")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outputDir == "" {
		return fmt.Errorf("--output-dir is required")
	}
	var applicable []string
	if *lines != "" {
		applicable = strings.Split(*lines, ",")
	}

	session, err := ConstructMessageIDBoundary(ConstructInput{
		OutputDir:       *outputDir,
		ApplicableLines: applicable,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wirecapture: constructed %d MessageID-boundary PDUs into %s\n", len(session.PDUs), *outputDir)
	return nil
}

func runCompare(args []string, stdout *fileWriter) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	committedDir := fs.String("committed-dir", "", "committed sanitized fixture directory")
	freshDir := fs.String("fresh-dir", "", "freshly captured+sanitized directory")
	committedProfileDir := fs.String("committed-profile-dir", "", "optional: committed profile.json directory")
	freshProfileDir := fs.String("fresh-profile-dir", "", "optional: fresh profile.json directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *committedDir == "" || *freshDir == "" {
		return fmt.Errorf("--committed-dir and --fresh-dir are required")
	}

	result, err := Compare(CompareInput{
		CommittedDir:         *committedDir,
		FreshDir:              *freshDir,
		CommittedProfileDir: *committedProfileDir,
		FreshProfileDir:      *freshProfileDir,
	})
	if err != nil {
		return err
	}
	if result.CredentialLengthMismatch {
		return fmt.Errorf("credential-length mismatch (fresh placeholder length does not match committed fixture)")
	}
	if !result.Equal {
		fmt.Fprintf(stdout, "wirecapture: compare FAILED (%d diffs):\n", len(result.Diffs))
		for _, d := range result.Diffs {
			fmt.Fprintf(stdout, "  - %s\n", d)
		}
		return fmt.Errorf("wire evidence does not match committed fixture")
	}
	fmt.Fprintln(stdout, "wirecapture: compare OK — stable metadata and sanitized PDUs match committed fixture")
	if result.SearchBeforeAbandon {
		fmt.Fprintln(stdout, "wirecapture: diagnostic — Search precedes Abandon as expected")
	}
	if result.TimeoutElapsedMSPositive {
		fmt.Fprintln(stdout, "wirecapture: diagnostic — observed_elapsed_ms is positive")
	}
	return nil
}
