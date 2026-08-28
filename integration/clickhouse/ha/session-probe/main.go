// Command ldap-session-probe holds one persistent LDAP connection through
// the HA fixture's HAProxy frontend and proves it never migrates backends.
//
// It exists solely for integration/clickhouse's Docker HA harness (see the
// phase-5 plan, §15.1/§18.1): the runner starts it against a specific
// authenticated-and-Bound helper replica, then kills that replica and
// requires the probe to fail — never silently reconnect to the surviving
// replica — because "old connection is not migrated" and "session state
// stays on the original TCP connection" are invariants the HA claim depends
// on (see the plan's §19 and §25 rows for both).
//
// # Threat model: no credentials on argv or in the environment
//
// The bound username and the JWT carried as the simple-Bind password are
// process secrets. Passing either on argv makes them visible to every other
// process on the host via /proc/<pid>/cmdline or `ps eww`, and to `docker
// inspect`/compose logs of the invoking command; passing them via the
// environment makes them visible via /proc/<pid>/environ and inherited by
// any child process. Neither is acceptable for a bearer credential, so this
// binary refuses even to start if anything credential-shaped appears on
// argv or in the environment, and reads the username and JWT exclusively
// from stdin — which the runner backs with a private 0600 file it pipes in,
// never a shell-visible argument.
//
// # Output contract
//
// Every printed line is one of a small fixed set of safe markers, each
// prefixed with an RFC3339Nano UTC timestamp:
//
//	<ts> probe: bound
//	<ts> probe: heartbeat n=<k> entries=<n>
//	<ts> probe: failed <class>
//	<ts> probe: stopped
//
// No marker ever contains the bind DN, the username, the JWT, or any raw
// underlying error text (library error strings are deliberately discarded
// in favor of a small closed set of failure classes) — the runner's leak
// scan treats this binary's own output as one of the artifacts it scans.
//
// # Wire behavior
//
// Exactly one TCP connection, one simple Bind, then one authorized Search
// under the group base DN repeated on that same connection every
// -interval — this binary never re-dials, so a killed backend is observed
// as a failure, not silently absorbed by a reconnect.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// forbiddenFlagNames are exact (case-insensitive) flag-name matches refused
// before any flag is parsed. Matched against the flag name only — the part
// before "=" and after any leading dashes — never the value, and never
// printed back: findForbiddenInput reports only a fixed safe marker.
//
// This is an exact-match set, not a substring match, so that legitimate
// safe flags such as -user-base-dn are never caught by a "user" substring
// check.
var forbiddenFlagNames = map[string]struct{}{
	"user":          {},
	"username":      {},
	"password":      {},
	"passwd":        {},
	"pwd":           {},
	"secret":        {},
	"token":         {},
	"jwt":           {},
	"bearer":        {},
	"credential":    {},
	"credentials":   {},
	"apikey":        {},
	"api-key":       {},
	"authorization": {},
	"auth":          {},
}

// forbiddenEnvSubstrings are matched case-insensitively against an
// environment variable's name only (never its value). This is a substring
// match, unlike forbiddenFlagNames, because env var names in the wild carry
// prefixes/suffixes (LDAP_JWT, PROBE_TOKEN, ...) that an exact match would
// miss.
//
// "PWD" is deliberately excluded: bash/sh export it as the current working
// directory on essentially every invocation, so treating it as
// credential-shaped would refuse to run in any normal shell or container.
var forbiddenEnvSubstrings = []string{
	"PASSWORD",
	"JWT",
	"TOKEN",
	"BEARER",
	"SECRET",
	"CREDENTIAL",
	"USERNAME",
}

// findForbiddenInput reports whether args or environ carry anything
// credential-shaped. It returns true on the first match; callers must not
// proceed to parse flags, read stdin, or dial when it does.
func findForbiddenInput(args []string, environ []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if _, bad := forbiddenFlagNames[strings.ToLower(name)]; bad {
			return true
		}
	}

	for _, e := range environ {
		key := e
		if eq := strings.IndexByte(e, '='); eq >= 0 {
			key = e[:eq]
		}
		upper := strings.ToUpper(key)
		for _, bad := range forbiddenEnvSubstrings {
			if strings.Contains(upper, bad) {
				return true
			}
		}
	}

	return false
}

// readCredentials reads the bind username and JWT from stdin, exclusively.
// Two forms are accepted:
//
//   - a tiny JSON document: {"username":"...","jwt":"..."} (a "token" key
//     is also accepted in place of "jwt");
//   - two newline-separated lines: username, then the JWT.
//
// Both forms are read from a single bounded buffer so a caller cannot make
// this binary block forever, or exhaust memory, by feeding it an
// unterminated stream.
func readCredentials(r io.Reader) (username, token string, err error) {
	const maxCredentialBytes = 1 << 20 // generous bound for a username+JWT
	data, err := io.ReadAll(io.LimitReader(r, maxCredentialBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("read stdin: %w", err)
	}
	if len(data) > maxCredentialBytes {
		return "", "", errors.New("stdin credential payload too large")
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return "", "", errors.New("empty stdin")
	}

	if strings.HasPrefix(trimmed, "{") {
		doc, jsonErr := parseCredentialJSON(trimmed)
		if jsonErr == nil {
			username = doc["username"]
			token = doc["jwt"]
			if token == "" {
				token = doc["token"]
			}
			if username == "" || token == "" {
				return "", "", errors.New("credential JSON missing username or jwt")
			}
			return username, token, nil
		}
	}

	lines := strings.SplitN(trimmed, "\n", 2)
	if len(lines) < 2 {
		return "", "", errors.New("expected two lines: username, then jwt")
	}
	username = strings.TrimSpace(lines[0])
	token = strings.TrimSpace(lines[1])
	if username == "" || token == "" {
		return "", "", errors.New("empty username or jwt on stdin")
	}
	return username, token, nil
}

// parseCredentialJSON is a tiny, dependency-free {"key":"value",...} object
// parser covering exactly the shape readCredentials needs. It intentionally
// avoids encoding/json's richer error messages, which can otherwise quote
// back fragments of the offending input.
func parseCredentialJSON(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, errors.New("not a JSON object")
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	out := map[string]string{}
	if inner == "" {
		return out, nil
	}
	for _, part := range strings.Split(inner, ",") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return nil, errors.New("malformed key:value pair")
		}
		key := unquoteJSONString(strings.TrimSpace(kv[0]))
		val := unquoteJSONString(strings.TrimSpace(kv[1]))
		if key == "" {
			return nil, errors.New("empty key")
		}
		out[key] = val
	}
	return out, nil
}

func unquoteJSONString(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return s[1 : len(s)-1]
	}
	return s
}

// classifyError maps a library error into one of a small closed set of
// safe classes. It deliberately never returns the underlying error text:
// go-ldap's own error strings are not documented as credential-free, so
// they are treated as unsafe to print by default.
func classifyError(err error) string {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultInvalidCredentials:
			return "invalid-credentials"
		case ldap.ErrorNetwork:
			return "network-error"
		default:
			return "ldap-result-error"
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		return "network-error"
	}

	if errors.Is(err, io.EOF) {
		return "connection-closed"
	}

	return "unknown-error"
}

func printMarker(w io.Writer, msg string) {
	fmt.Fprintf(w, "%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), msg)
}

// config holds only operator-safe, non-credential settings. Deliberately
// absent: username, password, JWT, token, or any other field that could
// hold a credential — see the package doc comment and findForbiddenInput.
type config struct {
	addr        string
	userBaseDN  string
	rdnAttr     string
	groupBaseDN string
	rolePrefix  string
	interval    time.Duration
	output      string
}

func parseFlags(fs *flag.FlagSet, args []string) (config, error) {
	var cfg config
	fs.StringVar(&cfg.addr, "addr", "", "LDAP address host:port reached through HAProxy (required)")
	fs.StringVar(&cfg.userBaseDN, "user-base-dn", "", "base DN the bind user's RDN is anchored under (required)")
	fs.StringVar(&cfg.rdnAttr, "rdn-attr", "uid", "RDN attribute used to build the bind DN")
	fs.StringVar(&cfg.groupBaseDN, "group-base-dn", "", "base DN the authorized group Search runs under (required)")
	fs.StringVar(&cfg.rolePrefix, "role-cn-prefix", "", "expected cn prefix on returned role groups (optional filter)")
	fs.DurationVar(&cfg.interval, "interval", 2*time.Second, "heartbeat Search interval on the persistent connection")
	fs.StringVar(&cfg.output, "output", "", "optional path to also append safe markers to (opened 0600)")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if cfg.addr == "" || cfg.userBaseDN == "" || cfg.rdnAttr == "" || cfg.groupBaseDN == "" {
		return config{}, errors.New("addr, user-base-dn, rdn-attr, and group-base-dn are required")
	}
	return cfg, nil
}

// run implements the whole probe lifecycle against injectable inputs so
// tests can drive it end-to-end without touching the real process
// environment. It returns the process exit code.
func run(ctx context.Context, args []string, environ []string, stdin io.Reader, stdout io.Writer) int {
	if findForbiddenInput(args, environ) {
		printMarker(stdout, "probe: failed forbidden-input")
		return 1
	}

	fs := flag.NewFlagSet("ldap-session-probe", flag.ContinueOnError)
	fs.SetOutput(stdout)

	cfg, err := parseFlags(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		printMarker(stdout, "probe: failed config")
		return 2
	}

	out := io.Writer(stdout)
	if cfg.output != "" {
		f, ferr := os.OpenFile(cfg.output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if ferr != nil {
			printMarker(stdout, "probe: failed config")
			return 2
		}
		defer f.Close()
		out = io.MultiWriter(stdout, f)
	}

	username, token, err := readCredentials(stdin)
	if err != nil {
		printMarker(out, "probe: failed stdin")
		return 1
	}

	bindDN := fmt.Sprintf("%s=%s,%s", cfg.rdnAttr, ldap.EscapeDN(username), cfg.userBaseDN)

	conn, err := ldap.DialURL("ldap://" + cfg.addr)
	if err != nil {
		printMarker(out, fmt.Sprintf("probe: failed dial-%s", classifyError(err)))
		return 1
	}
	defer conn.Close()
	conn.SetTimeout(5 * time.Second)

	if err := conn.Bind(bindDN, token); err != nil {
		printMarker(out, fmt.Sprintf("probe: failed bind-%s", classifyError(err)))
		return 1
	}
	printMarker(out, "probe: bound")

	filter := fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", ldap.EscapeFilter(bindDN))
	searchReq := ldap.NewSearchRequest(
		cfg.groupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // sizeLimit: unbounded — the probe just counts what it gets back
		0, // timeLimit: unbounded — conn.SetTimeout already bounds the round trip
		false,
		filter,
		[]string{"cn"},
		nil,
	)

	heartbeat := 0
	for {
		heartbeat++
		result, searchErr := conn.Search(searchReq)
		if searchErr != nil {
			printMarker(out, fmt.Sprintf("probe: failed search-%s", classifyError(searchErr)))
			return 1
		}

		entries := 0
		for _, e := range result.Entries {
			cn := e.GetAttributeValue("cn")
			if cfg.rolePrefix == "" || strings.HasPrefix(cn, cfg.rolePrefix) {
				entries++
			}
		}
		printMarker(out, fmt.Sprintf("probe: heartbeat n=%d entries=%d", heartbeat, entries))

		select {
		case <-ctx.Done():
			printMarker(out, "probe: stopped")
			return 0
		case <-time.After(cfg.interval):
		}
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Environ(), os.Stdin, os.Stdout))
}
