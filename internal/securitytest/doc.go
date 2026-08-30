// Package securitytest implements phase-5 automated security/redaction
// verification for altinity-oauth-helper (issue #19 phase 5, plan §5).
//
// It is not itself security-relevant production code: it exists purely to
// keep three things honest over time, all enforced by go/ast rather than by
// hand-maintained trust.
//
//  1. redaction_inventory_test.go AST-enumerates every zerolog terminal call
//     (.Msg/.Msgf/.Send), stdlib log.Print*, fmt.Errorf, errors.New/Join,
//     LDAP diagnostic construction (SetDiagnosticMessage, or — for
//     internal/ldap/profile only — a direct addLDAPResultFields(...) call,
//     sink kind ldap-profile-diagnostic, see inspectCall) and HTTP/LDAP
//     response-error construction (http.Error, fmt.Fprint*) across the
//     explicit audited scope list named by scopeDirs below —
//     cmd/ch-oauth-ldap, cmd/ch-jwt-verify, internal/ldap,
//     internal/verification, internal/identity, internal/roles,
//     internal/wirefixture, integration/clickhouse/wirecapture, and
//     internal/ldap/profile (issue #33 phase 1 added the wirefixture/
//     wirecapture pair, plan §10/§35, once the ClickHouse-wire-capture
//     tooling gave them non-test sinks of their own; issue #33 phase 2
//     added internal/ldap/profile once its Bind/Search/dispatch handlers
//     gave the replacement wire package non-test log/diagnostic sinks of
//     its own) — plus every vendored Logger.Print*/Printf/Println call in
//     the local third_party/ldapserver fork, and cross-checks the result
//     against the checked-in manifest at testdata/redaction-sites.tsv. It
//     fails on an unmapped (newly discovered, unregistered) sink, a stale
//     manifest row no longer backed by real source, a duplicate
//     fingerprint, a local credential-reachable sink lacking a
//     marker-based proof, or a manifest-referenced proof test that no
//     longer exists. Each scopeDirs entry is deliberately NOT
//     "everything under this path": discoverSites (below) reads only the
//     direct, non-test .go files of each named directory and does not
//     recurse into subdirectories — so a nested package added later under
//     an audited root (e.g. a future integration/clickhouse/wirecapture/foo,
//     or a future internal/ldap/profile/foo) is invisible to this inventory
//     until its own path is added to scopeDirs explicitly. Two mechanical
//     guards catch that gap going unnoticed, at two different
//     granularities: TestRedactionInventory_Phase1AuditedScopesRemainFlat
//     walks specifically internal/wirefixture and
//     integration/clickhouse/wirecapture recursively and fails the moment
//     either one stops being flat; TestRedactionInventory_NestedLDAPPackagesAreRegistered
//     generalizes that same check to every directory under internal/ldap/**
//     (which is where internal/ldap/profile itself lives) — it requires
//     every nested directory containing a non-test .go file to be either
//     its own scopeDirs entry or an explicitly documented, mechanically
//     verified test-only-tooling exception (nestedLDAPTestOnlyAllowlist in
//     redaction_inventory_test.go; empty today, since internal/ldap/profile
//     is registered outright rather than exempted). This audited-scope
//     list is also not a
//     claim that every credential-bearing tool in the repository is
//     covered: integration/clickhouse/ha/session-probe is a pre-existing
//     integration credential tool that remains outside scopeDirs (plan
//     §50) — recorded here honestly rather than silently implied covered.
//
//  2. sdk_contract_test.go uses runtime/debug.ReadBuildInfo (falling back to
//     parsing go.mod's require line per amendment A6 if the module is
//     somehow absent from build info) to assert that exactly one
//     github.com/altinity/go-mcp-oauth-sdk module is resolved, that its
//     version matches auditedSDKVersion below, and that it carries no
//     module replacement (the repo's own third_party goldap/ldapserver
//     replaces are expected and out of scope for this check). It also
//     AST-asserts that internal/verification's verifyUncached contains
//     exactly one call to v.oauthVer.ValidateStrictJWT and that no
//     ValidateToken selector exists anywhere in internal/verification —
//     the strict-entrypoint invariant every other redaction claim in this
//     package depends on.
//
//  3. release_gate_test.go, built only with -tags phase5release, is the
//     final closure gate: it fails while any manifest row remains
//     classified blocked_external, or the resolved SDK version diverges
//     from auditedSDKVersion. Per plan §4.4, SDK_REDACTION_AUTHORIZATION_GATE
//     was closed by bumping to go-mcp-oauth-sdk@v0.2.1 (which drops the raw
//     `kid` field from the JWKS-rotation success log), so this gate now
//     PASSES — the go-mcp-oauth-sdk@v0.2.0 kid-rotation row that used to be
//     the sole, expected, documented failure here no longer exists in the
//     manifest. A failure of this gate from this point on is a real
//     regression (a manifest row reverting to blocked_external, or the
//     resolved SDK version drifting from auditedSDKVersion) and must never
//     be silenced by relaxing the gate.
//
// See CLAUDE.md and plan-19p5.md §5 for the full security model this
// package enforces, and testdata/redaction-sites.tsv's own header comment
// for the manifest's column contract.
package securitytest

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// auditedSDKVersion is the exact github.com/altinity/go-mcp-oauth-sdk
// version this package's manifest and sdk_contract_test.go have audited.
// Bumping the dependency without updating this constant (and re-auditing
// every external-pinned manifest row) is exactly the drift sdk_contract_test
// exists to catch — see plan §5.3 and the high-risk invariant map's "SDK
// version is audited" row.
const auditedSDKVersion = "v0.2.1"

// sdkModulePath is the module path sdk_contract_test.go and
// release_gate_test.go look for in build info / go.mod.
const sdkModulePath = "github.com/altinity/go-mcp-oauth-sdk"

// manifestRelPath is testdata/redaction-sites.tsv's path relative to this
// package's directory.
const manifestRelPath = "testdata/redaction-sites.tsv"

// manifestColumns is the fixed, ordered column set of
// testdata/redaction-sites.tsv. Keep in lockstep with that file's own
// header comment and with ManifestRow's fields.
var manifestColumns = []string{
	"scope", "path", "function", "sink_kind", "fingerprint",
	"credential_reachable", "data_class", "ownership",
	"proof_type", "proof_test", "state", "gate",
}

// ManifestRow is one parsed, non-comment, non-header data row of
// testdata/redaction-sites.tsv.
type ManifestRow struct {
	Scope               string
	Path                string
	Function            string
	SinkKind            string
	Fingerprint         string
	CredentialReachable string // "yes" or "no"
	DataClass           string
	Ownership           string // "local" or "external-pinned"
	ProofType           string
	ProofTest           string // comma-separated test-function names, or empty
	State               string // "safe", "unreachable", or "blocked_external"
	Gate                string // authorization-gate name, non-empty only while a row is blocked_external
	sourceLine          int
}

// Key is the five-part manifest key the plan's §5.2 describes:
// "scope | path | function | sink-kind | normalized-AST-fingerprint".
func (r ManifestRow) Key() string {
	return strings.Join([]string{r.Scope, r.Path, r.Function, r.SinkKind, r.Fingerprint}, "\x1f")
}

// DiscoveredSite is one AST-discovered log/error/response-construction call
// site, before being cross-checked against the manifest.
type DiscoveredSite struct {
	Scope    string
	Path     string // slash-separated, relative to the module root
	Function string
	SinkKind string

	Fingerprint string

	// Detail is a short, human-readable description used only in test
	// failure messages (never persisted) — e.g. the literal message text —
	// so a failure names something a reviewer can grep for.
	Detail string
}

// Key mirrors ManifestRow.Key so a DiscoveredSite can be looked up in a
// map[string]ManifestRow keyed the same way.
func (d DiscoveredSite) Key() string {
	return strings.Join([]string{d.Scope, d.Path, d.Function, d.SinkKind, d.Fingerprint}, "\x1f")
}

// loadManifest parses testdata/redaction-sites.tsv (tab-separated, '#'
// full-line comments allowed, blank lines skipped, exactly len(manifestColumns)
// fields per data row, first non-comment line must be the header naming
// manifestColumns in order).
func loadManifest(path string) ([]ManifestRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("securitytest: open manifest: %w", err)
	}
	defer f.Close()

	var rows []ManifestRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	sawHeader := false
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if !sawHeader {
			if len(fields) != len(manifestColumns) {
				return nil, fmt.Errorf("securitytest: manifest header at line %d has %d columns, want %d", lineNo, len(fields), len(manifestColumns))
			}
			for i, want := range manifestColumns {
				if fields[i] != want {
					return nil, fmt.Errorf("securitytest: manifest header at line %d column %d is %q, want %q", lineNo, i, fields[i], want)
				}
			}
			sawHeader = true
			continue
		}
		if len(fields) != len(manifestColumns) {
			return nil, fmt.Errorf("securitytest: manifest data row at line %d has %d columns, want %d: %q", lineNo, len(fields), len(manifestColumns), line)
		}
		rows = append(rows, ManifestRow{
			Scope:               fields[0],
			Path:                fields[1],
			Function:            fields[2],
			SinkKind:            fields[3],
			Fingerprint:         fields[4],
			CredentialReachable: fields[5],
			DataClass:           fields[6],
			Ownership:           fields[7],
			ProofType:           fields[8],
			ProofTest:           fields[9],
			State:               fields[10],
			Gate:                fields[11],
			sourceLine:          lineNo,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("securitytest: scan manifest: %w", err)
	}
	if !sawHeader {
		return nil, fmt.Errorf("securitytest: manifest %s has no header row", path)
	}
	return rows, nil
}

// findModuleRoot walks upward from start looking for go.mod, so tests work
// regardless of the working directory `go test` happens to invoke them
// from.
func findModuleRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("securitytest: no go.mod found above %s", start)
		}
		dir = parent
	}
}

// moduleRoot returns the repository root, computed once relative to this
// source file's own package directory (which is what `go test`'s working
// directory always is), never relative to the caller's process cwd.
func moduleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return findModuleRoot(wd)
}

// scopeDirs is every first-party Go package scope redaction_inventory_test.go
// enumerates, per plan §5.1. Scope name doubles as the manifest's `scope`
// column and as the relative directory to walk.
var scopeDirs = []string{
	"cmd/ch-oauth-ldap",
	"cmd/ch-jwt-verify",
	"internal/ldap",
	"internal/verification",
	"internal/identity",
	"internal/roles",
	"internal/wirefixture",
	"integration/clickhouse/wirecapture",
	"internal/ldap/profile",
}

// vendoredScope is the separate third_party/ldapserver enumeration (plan
// §5.1's "Separately enumerate all Logger.Print* sites in the local
// third_party/ldapserver fork").
const vendoredScope = "third_party/ldapserver"

// externalScope tags manifest rows describing an externally-owned,
// non-AST-discoverable sink (the pinned SDK) — see plan §4.3.
const externalScope = "external-pinned"

// sinkKind constants. Keep these exactly in sync with the values written to
// testdata/redaction-sites.tsv.
const (
	sinkZerologTerminal       = "zerolog-terminal"        // .Msg / .Msgf / .Send
	sinkStdlibLogPrint        = "stdlib-log-print"        // log.Print*
	sinkFmtErrorf             = "fmt-errorf"              // fmt.Errorf
	sinkFmtFprint             = "fmt-fprint-response"     // fmt.Fprint*
	sinkErrorsNew             = "errors-new"              // errors.New
	sinkErrorsJoin            = "errors-join"             // errors.Join
	sinkLDAPDiagnostic        = "ldap-diagnostic"         // SetDiagnosticMessage
	sinkHTTPError             = "http-error"              // http.Error
	sinkVendoredLoggerPrint   = "vendored-logger-print"   // third_party/ldapserver Logger.Print*
	sinkJSONEncodeResponse    = "json-encode-response"    // json.NewEncoder(w).Encode
	sinkHTTPResponseWrite     = "http-response-write"     // http.ResponseWriter.Write (cmd/ch-jwt-verify only — see inspectCall)
	sinkLDAPProfileDiagnostic = "ldap-profile-diagnostic" // internal/ldap/profile's addLDAPResultFields(...) — see inspectCall
)

// profileScope is internal/ldap/profile's scopeDirs entry — the one scope
// inspectCall recognizes a direct addLDAPResultFields(...) call in (issue
// #33 phase 2's replacement package writes its diagnostic field through a
// plain package-level function, not a SetDiagnosticMessage method call, so
// it needs its own narrow, scope-guarded match distinct from
// sinkLDAPDiagnostic above).
const profileScope = "internal/ldap/profile"

// packageInitFunction is the synthesized `function` value for a call
// discovered inside a package-level var/const initializer, outside any
// func body.
const packageInitFunction = "<package-init>"

// discoverSites AST-enumerates every sink of the kinds listed in doc.go's
// package comment across every directory in scopeDirs, rooted at root.
func discoverSites(root string) ([]DiscoveredSite, error) {
	var out []DiscoveredSite
	for _, scope := range scopeDirs {
		dir := filepath.Join(root, filepath.FromSlash(scope))
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("securitytest: read scope dir %s: %w", scope, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			relPath := scope + "/" + e.Name()
			sites, err := discoverFileSites(filepath.Join(dir, e.Name()), scope, relPath)
			if err != nil {
				return nil, err
			}
			out = append(out, sites...)
		}
	}
	return out, nil
}

// discoverVendoredLoggerSites separately enumerates every Logger.Print /
// Logger.Printf / Logger.Println call in third_party/ldapserver's non-test
// Go files (Logger.Panic*/Fatal* are deliberately excluded — see plan §5.1
// and this sub-task's exact target line list, which likewise excludes
// server.go's Logger.Panicln).
func discoverVendoredLoggerSites(root string) ([]DiscoveredSite, error) {
	dir := filepath.Join(root, filepath.FromSlash(vendoredScope))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("securitytest: read vendored dir: %w", err)
	}
	var out []DiscoveredSite
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		relPath := vendoredScope + "/" + e.Name()
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("securitytest: parse %s: %w", relPath, err)
		}
		c := &siteCollector{scope: vendoredScope, path: relPath, vendoredLogger: true}
		c.walkFile(file)
		out = append(out, c.sites...)
	}
	return out, nil
}

func discoverFileSites(absPath, scope, relPath string) ([]DiscoveredSite, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, absPath, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("securitytest: parse %s: %w", relPath, err)
	}
	aliases := importAliases(file)
	c := &siteCollector{scope: scope, path: relPath, aliases: aliases}
	c.walkFile(file)
	return c.sites, nil
}

// importAliases maps a file's local package identifiers to their full
// import path, honoring an explicit alias (`foo "some/path"`) and
// defaulting to the import's base path segment otherwise (good enough for
// every import this codebase actually uses: fmt, errors, log, net/http all
// have a base segment equal to their conventional package name).
func importAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string, len(file.Imports))
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		aliases[name] = path
	}
	return aliases
}

// siteCollector accumulates DiscoveredSites while walking one file's AST.
type siteCollector struct {
	scope   string
	path    string
	aliases map[string]string // nil for vendoredLogger mode

	vendoredLogger bool // true only for the third_party/ldapserver enumeration

	sites []DiscoveredSite
}

func (c *siteCollector) walkFile(file *ast.File) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Body != nil {
				ast.Walk(&funcVisitor{c: c, funcName: funcDeclName(d)}, d.Body)
			}
		case *ast.GenDecl:
			if d.Tok == token.VAR || d.Tok == token.CONST {
				ast.Walk(&funcVisitor{c: c, funcName: packageInitFunction}, d)
			}
		}
	}
}

// funcDeclName renders a FuncDecl's name, prefixed with its receiver type
// (stripped of a leading pointer star) for methods, e.g. "Verifier.Handler".
func funcDeclName(d *ast.FuncDecl) string {
	if d.Recv != nil && len(d.Recv.List) == 1 {
		if t := recvTypeName(d.Recv.List[0].Type); t != "" {
			return t + "." + d.Name.Name
		}
	}
	return d.Name.Name
}

func recvTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return ""
	}
}

// funcVisitor implements ast.Visitor, carrying the name of the innermost
// enclosing function (or "<name>.closure" one level deeper per nested
// FuncLit) so every discovered call site records where it lives without
// requiring line numbers.
type funcVisitor struct {
	c        *siteCollector
	funcName string
}

func (v *funcVisitor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		return nil
	}
	switch node := n.(type) {
	case *ast.FuncLit:
		return &funcVisitor{c: v.c, funcName: v.funcName + ".closure"}
	case *ast.CallExpr:
		v.c.inspectCall(node, v.funcName)
	}
	return v
}

func (c *siteCollector) inspectCall(call *ast.CallExpr, funcName string) {
	if c.vendoredLogger {
		c.inspectVendoredLoggerCall(call, funcName)
		return
	}

	// internal/ldap/profile writes its diagnosticMessage field through a
	// direct package-level function call, addLDAPResultFields(builder,
	// resultCode, diagConstant) — not a method/selector call, so it can
	// never be matched by the SelectorExpr-based switch below. Narrowly
	// scoped to profileScope so an unrelated identically-named function
	// elsewhere can never collide with this sink kind.
	if c.scope == profileScope {
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "addLDAPResultFields" {
			var detail string
			if len(call.Args) == 3 {
				detail = normalizeExpr(call.Args[2])
			}
			c.record(funcName, sinkLDAPProfileDiagnostic, detail, detail)
			return
		}
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}

	switch sel.Sel.Name {
	case "Msg", "Msgf", "Send":
		c.record(funcName, sinkZerologTerminal, zerologFingerprint(call, sel), sel.Sel.Name)
		return
	case "SetDiagnosticMessage":
		var detail string
		if len(call.Args) == 1 {
			detail = normalizeExpr(call.Args[0])
		}
		c.record(funcName, sinkLDAPDiagnostic, detail, "SetDiagnosticMessage")
		return
	case "Encode":
		// json.NewEncoder(w).Encode(v) — response-body serialization. Only
		// matched when the immediate receiver is itself a
		// `<jsonAlias>.NewEncoder(...)` call, so an unrelated .Encode
		// method elsewhere can never collide with this sink kind.
		if inner, ok := sel.X.(*ast.CallExpr); ok {
			if innerSel, ok := inner.Fun.(*ast.SelectorExpr); ok && innerSel.Sel.Name == "NewEncoder" {
				if recv, isIdent := receiverIdentName(innerSel.X); isIdent && c.aliases[recv] == "encoding/json" {
					c.record(funcName, sinkJSONEncodeResponse, normalizeArgs(call.Args), "json.NewEncoder(...).Encode")
					return
				}
			}
		}
	case "Write":
		// http.ResponseWriter.Write(...): AST alone can't resolve `w`'s
		// static type (no go/types here), so this is deliberately narrow —
		// scoped to cmd/ch-jwt-verify (the only scope with a bare
		// `w.Write(...)` over an http.ResponseWriter today) and to the
		// conventional receiver name `w` used throughout that file, so it
		// can never collide with, say, internal/ldap's unrelated
		// ldapserver response-packet `w.Write(res)` calls in a different
		// scope.
		if c.scope == "cmd/ch-jwt-verify" {
			if recv, isIdent := receiverIdentName(sel.X); isIdent && recv == "w" {
				c.record(funcName, sinkHTTPResponseWrite, normalizeArgs(call.Args), "w.Write")
				return
			}
		}
	}

	recvName, isIdent := receiverIdentName(sel.X)
	if !isIdent {
		return
	}
	importPath := c.aliases[recvName]

	switch {
	case importPath == "log" && isStdlibLogPrintMethod(sel.Sel.Name):
		c.record(funcName, sinkStdlibLogPrint, normalizeArgs(call.Args), sel.Sel.Name)
	case importPath == "fmt" && sel.Sel.Name == "Errorf":
		c.record(funcName, sinkFmtErrorf, firstLiteralOrElse(call.Args, "<no-arg>"), "fmt.Errorf")
	case importPath == "fmt" && (sel.Sel.Name == "Fprintf" || sel.Sel.Name == "Fprint" || sel.Sel.Name == "Fprintln"):
		// args[0] is the io.Writer; fingerprint the remaining (message)
		// arguments.
		var rest []ast.Expr
		if len(call.Args) > 1 {
			rest = call.Args[1:]
		}
		c.record(funcName, sinkFmtFprint, normalizeArgs(rest), "fmt."+sel.Sel.Name)
	case importPath == "errors" && sel.Sel.Name == "New":
		c.record(funcName, sinkErrorsNew, firstLiteralOrElse(call.Args, "<no-arg>"), "errors.New")
	case importPath == "errors" && sel.Sel.Name == "Join":
		c.record(funcName, sinkErrorsJoin, normalizeArgs(call.Args), "errors.Join")
	case importPath == "net/http" && sel.Sel.Name == "Error":
		var msgArg []ast.Expr
		if len(call.Args) >= 2 {
			msgArg = call.Args[1:2]
		}
		c.record(funcName, sinkHTTPError, normalizeArgs(msgArg), "http.Error")
	}
}

func (c *siteCollector) inspectVendoredLoggerCall(call *ast.CallExpr, funcName string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	recvName, isIdent := receiverIdentName(sel.X)
	if !isIdent || recvName != "Logger" {
		return
	}
	switch sel.Sel.Name {
	case "Print", "Printf", "Println":
		c.record(funcName, sinkVendoredLoggerPrint, normalizeArgs(call.Args), "Logger."+sel.Sel.Name)
	}
}

func receiverIdentName(e ast.Expr) (string, bool) {
	id, ok := e.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

func isStdlibLogPrintMethod(name string) bool {
	switch name {
	case "Print", "Printf", "Println", "Fatal", "Fatalf", "Fatalln", "Panic", "Panicf", "Panicln":
		return true
	}
	return false
}

func (c *siteCollector) record(funcName, sinkKind, fingerprint, detail string) {
	c.sites = append(c.sites, DiscoveredSite{
		Scope:       c.scope,
		Path:        c.path,
		Function:    funcName,
		SinkKind:    sinkKind,
		Fingerprint: sanitizeFingerprint(fingerprint),
		Detail:      detail,
	})
}

// firstLiteralOrElse returns the normalized form of args[0] if present,
// else fallback.
func firstLiteralOrElse(args []ast.Expr, fallback string) string {
	if len(args) == 0 {
		return fallback
	}
	return normalizeExpr(args[0])
}

// zerologFingerprint builds the fingerprint for a zerolog terminal call
// (.Msg/.Msgf/.Send): the normalized chain of field-builder calls leading up
// to it, in source order, followed by the terminal call's own literal
// message text. Each chain link is the method name alone (e.g. "Err"), or
// the method name plus any literal string-KEY arguments (e.g. .Str("user",
// u) contributes "Str(user)" — the key literal only, never u's value or
// even its normalized shape, since the key is what defines the log
// schema and the value is exactly the kind of content this package must
// never persist to a checked-in fingerprint). This means adding, removing,
// or reordering a field on the chain — or changing the message literal —
// changes the fingerprint and forces a fresh manifest row; the previous
// "just the .Msg literal" fingerprint silently accepted all of that as the
// same site.
func zerologFingerprint(call *ast.CallExpr, msgSel *ast.SelectorExpr) string {
	var links []string
	cur := msgSel.X
	for i := 0; i < 32; i++ {
		innerCall, ok := cur.(*ast.CallExpr)
		if !ok {
			break
		}
		innerSel, ok := innerCall.Fun.(*ast.SelectorExpr)
		if !ok {
			break
		}
		if keys := zerologChainKeys(innerCall); len(keys) > 0 {
			links = append(links, innerSel.Sel.Name+"("+strings.Join(keys, ",")+")")
		} else {
			links = append(links, innerSel.Sel.Name)
		}
		cur = innerSel.X
	}
	// links were collected innermost-first (closest to .Msg); reverse to
	// source (left-to-right, outer-to-inner call) order.
	for i, j := 0, len(links)-1; i < j; i, j = i+1, j-1 {
		links[i], links[j] = links[j], links[i]
	}
	terminal := firstLiteralOrElse(call.Args, "<no-arg>")
	if len(links) == 0 {
		return terminal
	}
	return strings.Join(links, "|") + "|" + terminal
}

// zerologChainKeys returns only the literal string-KEY arguments of one
// field-builder call in a chained zerolog call (e.g. .Str("user", u) ->
// ["user"]; .Err(err) -> nil, since its sole argument is not a string
// literal). Deliberately never includes a non-literal argument's value or
// even its shape — only a static, checked-in-safe literal key.
func zerologChainKeys(call *ast.CallExpr) []string {
	var keys []string
	for _, a := range call.Args {
		lit, ok := a.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		if s, err := strconv.Unquote(lit.Value); err == nil {
			keys = append(keys, s)
		}
	}
	return keys
}

// normalizeArgs renders a stable, line-number-independent textual fingerprint
// for a call's argument list.
func normalizeArgs(args []ast.Expr) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = normalizeExpr(a)
	}
	return strings.Join(parts, ",")
}

// normalizeExpr renders expr as a stable fingerprint fragment: the exact
// text of a string literal (so message/format text is what makes two sites
// distinct or identical), a stable "constref:<name>" for a bare identifier
// (so renaming a referenced constant's VALUE — as opposed to renaming the
// constant itself — doesn't change the fingerprint), and a shape-only
// placeholder for everything else.
func normalizeExpr(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			if s, err := strconv.Unquote(v.Value); err == nil {
				return "lit:" + s
			}
		}
		return "lit:" + v.Value
	case *ast.Ident:
		return "constref:" + v.Name
	case *ast.SelectorExpr:
		return "sel:" + v.Sel.Name
	case *ast.CallExpr:
		return "call:" + normalizeExpr(v.Fun) + "(" + normalizeArgs(v.Args) + ")"
	case *ast.BinaryExpr:
		return "bin:" + normalizeExpr(v.X) + string(v.Op.String()[0]) + normalizeExpr(v.Y)
	case *ast.ParenExpr:
		return normalizeExpr(v.X)
	default:
		return "expr"
	}
}

// maxFingerprintLen bounds how much literal source text a fingerprint keeps
// verbatim before collapsing to a hash, so a long format/message string
// doesn't blow up the manifest file.
const maxFingerprintLen = 120

// sanitizeFingerprint collapses whitespace (a fingerprint must be a single
// TSV field) and truncates an overlong fingerprint to a stable short form.
func sanitizeFingerprint(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxFingerprintLen {
		return s
	}
	return s[:maxFingerprintLen-8] + "...#" + shortHash(s)
}

// shortHash returns a short, stable, dependency-free hex digest of s (FNV-1a),
// used only to keep an overlong fingerprint's truncated form unique.
func shortHash(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return strconv.FormatUint(uint64(h), 16)
}

// collectTestFuncNames returns the set of every top-level `func TestXxx(...)`
// declared in any *_test.go file under root (walked recursively, skipping
// .git and third_party — this repo's own security-relevant tests never live
// in a vendored fork).
func collectTestFuncNames(root string) (map[string]bool, error) {
	names := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "third_party" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("securitytest: parse %s: %w", path, err)
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil {
				continue
			}
			if strings.HasPrefix(fd.Name.Name, "Test") {
				names[fd.Name.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

// verifyUncachedFunc parses internal/verification/verifier.go and returns
// its verifyUncached FuncDecl, or nil if not found.
func parseVerifyUncached(root string) (*ast.FuncDecl, error) {
	path := filepath.Join(root, "internal", "verification", "verifier.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("securitytest: parse verifier.go: %w", err)
	}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Name.Name == "verifyUncached" {
			return fd, nil
		}
	}
	return nil, nil
}

// countValidateStrictJWTCalls counts calls of the exact shape
// `<recv>.oauthVer.ValidateStrictJWT(...)` inside fd.
func countValidateStrictJWTCalls(fd *ast.FuncDecl) int {
	count := 0
	if fd.Body == nil {
		return 0
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		outer, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || outer.Sel.Name != "ValidateStrictJWT" {
			return true
		}
		inner, ok := outer.X.(*ast.SelectorExpr)
		if !ok || inner.Sel.Name != "oauthVer" {
			return true
		}
		count++
		return true
	})
	return count
}

// findValidateTokenSelectors AST-scans every non-test *.go file directly in
// internal/verification for a `.ValidateToken` selector reference (call or
// otherwise — a reference alone would be enough to reintroduce the legacy,
// non-strict entrypoint) and returns the file:line of each occurrence found.
func findValidateTokenSelectors(root string) ([]string, error) {
	dir := filepath.Join(root, "internal", "verification")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		fset := token.NewFileSet()
		path := filepath.Join(dir, e.Name())
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("securitytest: parse %s: %w", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ValidateToken" {
				return true
			}
			pos := fset.Position(sel.Pos())
			found = append(found, fmt.Sprintf("%s:%d", e.Name(), pos.Line))
			return true
		})
	}
	sort.Strings(found)
	return found, nil
}

// sdkRequireLineRE extracts a version from a go.mod `require` line naming
// sdkModulePath, as the A6 fallback when runtime/debug.ReadBuildInfo lacks
// the entry (e.g. because the module hasn't yet been imported by a linked
// test binary).
var sdkRequireLineRE = regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(sdkModulePath) + `\s+(v\S+)`)

// resolveSDKVersionFromGoMod parses root/go.mod's require block for
// sdkModulePath's pinned version.
func resolveSDKVersionFromGoMod(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("securitytest: read go.mod: %w", err)
	}
	m := sdkRequireLineRE.FindSubmatch(data)
	if m == nil {
		return "", fmt.Errorf("securitytest: go.mod has no require line for %s", sdkModulePath)
	}
	return string(m[1]), nil
}
