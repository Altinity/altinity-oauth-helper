package securitytest

// This file implements the Phase 2 plan's "Mechanical diagnostic
// enforcement" (L887-898), "Mechanical architecture contract"
// (L1311-1337), Amendment 3 (the closed `reason` vocabulary must be
// enforced the same way as `diagnostic`), and Amendment 4 (this untagged
// file must keep `go vet -tags phase5release ./internal/securitytest`
// green, since it compiles alongside release_gate_test.go either way).
//
// It parses every non-test .go file directly under internal/ldap/profile
// with go/parser — deliberately go/ast only, no go/types, matching
// redaction_inventory_test.go's siteCollector discipline (see its
// "no go/types here" comment in doc.go) — and asserts the thirteen
// structural invariants the plan names:
//
//  1. exactly one production `go` statement exists;
//  2. it spawns serveConnection, inside the admission path;
//  3. (implied by 1) no other goroutine spawn exists;
//  4. the only map-typed field/var in the package is Server's
//     active-connection map (map[net.Conn]struct{});
//  5. no sync.Map;
//  6. no channel-typed field/var other than serveDone/stopDone;
//  7. no vjeantet/goldap, vjeantet/ldapserver, go-ldap, asn1-ber,
//     go-ntlmssp, wirefixture, or unsafe import;
//  8. decodeMembershipFilter never calls itself;
//  9. it calls the equality-child decoder (decodeEquality) exactly twice;
//  10. decodeEquality never calls decodeMembershipFilter;
//  11. diagnostic bytes reach the wire only through addLDAPResultFields,
//      every call site that supplies a diagnostic value (not merely
//      forwarding an already-diagnostic-typed parameter) is a
//      package-level diagnostic const, no `diagnostic(...)` conversion
//      exists, and diagnostic.text() is called from exactly one
//      production site — plus, per Amendment 3, the identical
//      constant-only/no-conversion rule applied to every `reason`
//      parameter (logBindFailed, logSearchRejected);
//  12. `.Verify` is referenced exactly once in production, inside bind.go;
//  13. `.Roles` is referenced exactly once in production, inside bind.go.
//
// Invariants 4 and 6 inspect struct fields and *ast.ValueSpec/StructType
// nodes with an explicit map/chan type, AND every AssignStmt whose RHS is a
// make(map[...]...)/make(chan ...) call — closing a review-finding gap
// where an idiomatic inferred short-variable-declaration (`pending :=
// make(map[int32]*request)`) parses to an AssignStmt with no
// ValueSpec/explicit-type node anywhere, so it used to pass both bans
// silently despite this file's own claim to be an absolute, mechanical one.
// Invariants 12 and 13 count every matching *ast.SelectorExpr node (see
// selectorHasFieldRoot/verifyOrRolesSelectorSites), not only ones
// immediately called — closing a second review-finding gap where
// extracting a method value first (`verify := c.verifier.Verify;
// verify(...)`) produced neither a selector-shaped CallExpr (the extraction
// is a bare SelectorExpr) nor a selector-shaped Fun on the later call
// (Fun is a plain Ident), so a second verification path introduced this way
// would have left the recorded count at 1 and passed silently.
// TestProfileArchitecture_DetectsInferredMakeMapAssignment,
// TestProfileArchitecture_DetectsInferredMakeChanAssignment,
// TestProfileArchitecture_DetectsVerifyMethodValueExtraction, and
// TestProfileArchitecture_SelectorHeuristicIgnoresUnrelatedRolesField are
// synthetic regression tests (parsing an in-memory source string, never the
// real profile package) proving each closed gap is actually caught, and
// that the broadened invariant-12/13 check still doesn't false-positive on
// this package's own unrelated `Roles` data-field accesses
// (`c.auth.Roles`, `newState.Roles` — see selectorHasFieldRoot's comment).
//
// Sabotage checks (run manually, restored afterward — see the sub-task
// return for the recorded results): `diagnostic(err.Error())` at a result
// callsite; a Verify call inserted into the unsupported-op dispatch; a
// second `go` statement; a `map[int32]*pending` field on Server; a
// request channel; a blank goldap import; making decodeMembershipFilter
// recurse; a `reason(fmt.Sprint(err))` conversion.
//
// importAliases/recvTypeName/funcDeclName/moduleRoot are shared helpers
// already defined in doc.go (same package) and are reused here rather
// than redefined.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// profileRelDir is the one package this file's mechanical contract
// covers — internal/ldap/profile, Phase 2's new first-party LDAP
// compatibility implementation.
const profileRelDir = "internal/ldap/profile"

// profileFile is one parsed, non-test .go file directly under
// profileRelDir.
type profileFile struct {
	name string // base filename, e.g. "server.go" — used for both messages and the bind.go-only checks below
	fset *token.FileSet
	file *ast.File
}

// pos renders p as "<filename>:<line>" for failure messages that name
// file:line, per the sub-task's requirement.
func (pf profileFile) pos(p token.Pos) string {
	position := pf.fset.Position(p)
	return fmt.Sprintf("%s:%d", pf.name, position.Line)
}

// loadProfileFiles parses every non-test .go file directly under
// internal/ldap/profile — never recursing (the package has no
// subdirectories) and never including a _test.go file, since every
// assertion here is about production code only.
func loadProfileFiles(t *testing.T) []profileFile {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	dir := filepath.Join(root, filepath.FromSlash(profileRelDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("securitytest: read %s: %v", profileRelDir, err)
	}

	var files []profileFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("securitytest: parse %s/%s: %v", profileRelDir, name, err)
		}
		files = append(files, profileFile{name: name, fset: fset, file: f})
	}
	if len(files) == 0 {
		t.Fatalf("securitytest: no non-test .go files found directly under %s — is the package missing or empty?", profileRelDir)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files
}

// formatNode renders n back to Go source text, for failure messages that
// need to show an offending type or expression.
func formatNode(pf profileFile, n ast.Node) string {
	var buf bytes.Buffer
	if err := format.Node(&buf, pf.fset, n); err != nil {
		return fmt.Sprintf("<unformattable: %v>", err)
	}
	return buf.String()
}

// calleeName extracts a call expression's callee identifier name,
// whether it's a bare function call (foo(...)) or a method/selector call
// (x.foo(...)) — the receiver, if any, is discarded, since every check
// below only needs the callee's own name.
func calleeName(fun ast.Expr) (name string, ok bool) {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name, true
	case *ast.SelectorExpr:
		return f.Sel.Name, true
	default:
		return "", false
	}
}

// fieldNames joins a struct field's declared names (a field with no name
// is an embedded type, which none of this package's structs use).
func fieldNames(f *ast.Field) string {
	if len(f.Names) == 0 {
		return "<embedded>"
	}
	names := make([]string, len(f.Names))
	for i, n := range f.Names {
		names[i] = n.Name
	}
	return strings.Join(names, ",")
}

func joinIdentNames(idents []*ast.Ident) string {
	names := make([]string, len(idents))
	for i, n := range idents {
		names[i] = n.Name
	}
	return strings.Join(names, ",")
}

// enclosingVisitor walks one file's AST tracking two things per node:
// label, a human-readable description of the innermost enclosing
// function for messages (deepened with ".closure" per nested FuncLit),
// and declFunc, the nearest enclosing *named* FuncDecl — deliberately
// NOT deepened by a FuncLit, since a closure sees its outer function's
// parameters by the same name (Go closures capture by reference), so a
// parameter-forwarding check must resolve against declFunc, not label.
type enclosingVisitor struct {
	pf       profileFile
	label    string
	declFunc string
	onCall   func(pf profileFile, call *ast.CallExpr, label, declFunc string)
	onGo     func(pf profileFile, stmt *ast.GoStmt, label string)
}

func (v *enclosingVisitor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		return nil
	}
	switch node := n.(type) {
	case *ast.FuncDecl:
		// label is funcDeclName's receiver-prefixed form for readable
		// messages (e.g. "connection.writeBindResponse"); declFunc is
		// deliberately the bare Name.Name — the same unprefixed form
		// calleeName resolves a selector call to (x.foo(...) only ever
		// yields "foo", never "connection.foo"), so a parameter-forward
		// lookup keyed by declFunc always matches paramInfoOfType's keys.
		return &enclosingVisitor{pf: v.pf, label: funcDeclName(node), declFunc: node.Name.Name, onCall: v.onCall, onGo: v.onGo}
	case *ast.FuncLit:
		return &enclosingVisitor{pf: v.pf, label: v.label + ".closure", declFunc: v.declFunc, onCall: v.onCall, onGo: v.onGo}
	case *ast.GoStmt:
		if v.onGo != nil {
			v.onGo(v.pf, node, v.label)
		}
	case *ast.CallExpr:
		if v.onCall != nil {
			v.onCall(v.pf, node, v.label, v.declFunc)
		}
	}
	return v
}

// walkProfile drives enclosingVisitor over every file, invoking onCall
// for every *ast.CallExpr and onGo for every *ast.GoStmt found anywhere
// (top-level code, function bodies, and nested closures alike). Either
// callback may be nil.
func walkProfile(
	files []profileFile,
	onCall func(pf profileFile, call *ast.CallExpr, label, declFunc string),
	onGo func(pf profileFile, stmt *ast.GoStmt, label string),
) {
	for _, pf := range files {
		ast.Walk(&enclosingVisitor{pf: pf, label: "<package-level>", onCall: onCall, onGo: onGo}, pf.file)
	}
}

// countFuncDecls counts top-level, non-method FuncDecls named name
// across every file.
func countFuncDecls(files []profileFile, name string) int {
	n := 0
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name {
				n++
			}
		}
	}
	return n
}

// findFuncDecl returns the first top-level, non-method FuncDecl named
// name, and the file it lives in.
func findFuncDecl(files []profileFile, name string) (profileFile, *ast.FuncDecl, bool) {
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name {
				return pf, fd, true
			}
		}
	}
	return profileFile{}, nil, false
}

// callsTo returns the file:line of every call to targetName found
// anywhere inside body.
func callsTo(pf profileFile, body ast.Node, targetName string) []string {
	var locs []string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name, ok := calleeName(call.Fun); ok && name == targetName {
			locs = append(locs, pf.pos(call.Pos()))
		}
		return true
	})
	return locs
}

// findTypeConversions finds every CallExpr whose callee is a bare
// identifier named typeName — the only shape a conversion to a
// same-package defined type (diagnostic(...), reason(...)) can take.
func findTypeConversions(files []profileFile, typeName string) []string {
	var out []string
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == typeName {
				out = append(out, fmt.Sprintf("%s: forbidden %s(...) conversion", pf.pos(call.Pos()), typeName))
			}
			return true
		})
	}
	return out
}

// constNamesOfType returns the set of package-level const identifiers
// whose type is typeName. It correctly follows the Go const-declaration
// rule that a ValueSpec with no expression list inherits both the type
// and the expression list of the nearest preceding ValueSpec in the same
// parenthesized block (the standard `T = iota` pattern every enum in
// this package uses).
func constNamesOfType(files []profileFile, typeName string) map[string]bool {
	out := map[string]bool{}
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			var lastType ast.Expr
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				var effType ast.Expr
				if len(vs.Values) == 0 {
					effType = lastType
				} else {
					effType = vs.Type
					lastType = vs.Type
				}
				if ident, ok := effType.(*ast.Ident); ok && ident.Name == typeName {
					for _, name := range vs.Names {
						out[name.Name] = true
					}
				}
			}
		}
	}
	return out
}

// paramInfo is where, positionally, a function's parameter of some
// tracked type sits, and what it's named (for pass-through matching).
type paramInfo struct {
	index int
	name  string
}

// paramInfoOfType maps every function name (method name only — receiver
// discarded, since no two same-named methods on different receivers
// collide in this package) to the position/name of its one parameter of
// type typeName, for every FuncDecl across the package that has one.
func paramInfoOfType(files []profileFile, typeName string) map[string]paramInfo {
	out := map[string]paramInfo{}
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Type.Params == nil {
				continue
			}
			idx := 0
			for _, field := range fd.Type.Params.List {
				n := len(field.Names)
				if n == 0 {
					n = 1
				}
				if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == typeName && len(field.Names) > 0 {
					out[fd.Name.Name] = paramInfo{index: idx, name: field.Names[0].Name}
				}
				idx += n
			}
		}
	}
	return out
}

// localConstOnlyVars computes, for every FuncDecl in the package, the set
// of that function's own local variable names every one of whose
// assignments (both the initial `:=` and any later plain `=`, such as
// handleUnsupported's `d := diagEmpty; if extended { d = diagCriticalControl }`)
// resolves — directly, or transitively through another already-verified
// local of the same function — to either a package-level typeName const
// or the function's own typeName-typed parameter (per params). A local
// variable with even one assignment that is not a bare identifier (a
// conversion such as diagnostic(err.Error()), a call result, or anything
// else computed) is never marked verified, so it cannot be used to
// launder a non-constant value past checkConstantOnlyCalls below.
func localConstOnlyVars(files []profileFile, consts map[string]bool, params map[string]paramInfo) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			assigns := map[string][]ast.Expr{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				a, ok := n.(*ast.AssignStmt)
				if !ok || len(a.Lhs) != len(a.Rhs) {
					return true
				}
				for i, lhs := range a.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
						assigns[id.Name] = append(assigns[id.Name], a.Rhs[i])
					}
				}
				return true
			})
			if len(assigns) == 0 {
				continue
			}

			outerParam, hasOuterParam := params[fd.Name.Name]
			verified := map[string]bool{}
			for changed := true; changed; {
				changed = false
				for name, exprs := range assigns {
					if verified[name] {
						continue
					}
					allOK := true
					for _, e := range exprs {
						ident, isIdent := e.(*ast.Ident)
						switch {
						case !isIdent:
							allOK = false
						case consts[ident.Name]:
						case hasOuterParam && outerParam.name == ident.Name:
						case verified[ident.Name]:
						default:
							allOK = false
						}
						if !allOK {
							break
						}
					}
					if allOK {
						verified[name] = true
						changed = true
					}
				}
			}
			if len(verified) > 0 {
				out[fd.Name.Name] = verified
			}
		}
	}
	return out
}

// checkConstantOnlyCalls implements the shared enforcement Amendment 3
// requires be identical for `diagnostic` and `reason`: for every call to
// a function known (via params, keyed by callee name) to accept a
// typeName-typed argument, the argument at that position must either be
// a package-level typeName const (consts, keyed by identifier name), or
// an *ast.Ident that is itself the enclosing function's own
// typeName-typed parameter (a pure, verified forward — never a computed
// value, and never a conversion, which is caught separately by
// findTypeConversions). This is checked transitively across every
// forwarding hop in the package (write*Response -> encode*Response ->
// addLDAPResultFields for diagnostic; the two log helpers for reason),
// so a value can only ever originate from a named constant, however many
// layers of pure forwarding sit between the origin and the wire/log. It
// also accepts localVars (localConstOnlyVars' output): a local variable
// whose every assignment already resolved to a const/forwarded-param is
// treated the same as a direct const reference (handleUnsupported's
// `d := diagEmpty; if extended { d = diagCriticalControl }` pattern).
func checkConstantOnlyCalls(files []profileFile, typeName string, params map[string]paramInfo, consts map[string]bool, localVars map[string]map[string]bool) []string {
	var violations []string
	onCall := func(pf profileFile, call *ast.CallExpr, label, declFunc string) {
		callee, ok := calleeName(call.Fun)
		if !ok {
			return
		}
		info, tracked := params[callee]
		if !tracked {
			return
		}
		if info.index >= len(call.Args) {
			violations = append(violations, fmt.Sprintf(
				"%s: call to %s (in %s) has too few arguments to reach its %s parameter",
				pf.pos(call.Pos()), callee, label, typeName))
			return
		}
		arg := call.Args[info.index]
		ident, isIdent := arg.(*ast.Ident)
		if !isIdent {
			violations = append(violations, fmt.Sprintf(
				"%s: call to %s (in %s) passes a non-constant %s argument %q — only a package-level %s const or a forwarded %s parameter is allowed",
				pf.pos(call.Pos()), callee, label, typeName, formatNode(pf, arg), typeName, typeName))
			return
		}
		if consts[ident.Name] {
			return
		}
		if outer, has := params[declFunc]; has && outer.name == ident.Name {
			return // pure passthrough of the enclosing function's own typeName parameter
		}
		if lv, has := localVars[declFunc]; has && lv[ident.Name] {
			return // a local variable every assignment of which already verified
		}
		violations = append(violations, fmt.Sprintf(
			"%s: call to %s (in %s) passes %q, which resolves to neither a package-level %s const nor the enclosing function's own %s parameter",
			pf.pos(call.Pos()), callee, label, ident.Name, typeName, typeName))
	}
	walkProfile(files, onCall, nil)
	return violations
}

// --- 1-3: exactly one production goroutine, spawning serveConnection ---

func TestProfileArchitecture_SingleGoroutineSpawnsServeConnection(t *testing.T) {
	files := loadProfileFiles(t)

	type spawnSite struct {
		loc      string
		label    string
		callee   string
		calleeOK bool
	}
	var spawns []spawnSite

	onGo := func(pf profileFile, stmt *ast.GoStmt, label string) {
		name, _ := calleeName(stmt.Call.Fun)
		spawns = append(spawns, spawnSite{
			loc:      pf.pos(stmt.Pos()),
			label:    label,
			callee:   name,
			calleeOK: name == "serveConnection",
		})
	}
	walkProfile(files, nil, onGo)

	if len(spawns) != 1 {
		var details []string
		for _, s := range spawns {
			details = append(details, fmt.Sprintf("%s (in %s, calls %s)", s.loc, s.label, s.callee))
		}
		t.Fatalf("expected exactly one production `go` statement (the admission spawn of serveConnection), found %d:\n%s",
			len(spawns), strings.Join(details, "\n"))
	}
	if s := spawns[0]; !s.calleeOK {
		t.Fatalf("%s: the package's one `go` statement (in %s) must spawn serveConnection, found a call to %q instead",
			s.loc, s.label, s.callee)
	}
}

// --- 4: only Server's active-connection map exists ---

// mapSite records one map-typed field, explicitly-typed var, or
// make(map[...]...)-initialized local variable found anywhere in the
// package.
type mapSite struct {
	loc        string
	fieldOrVar string
	structName string
	typeStr    string
}

// makeMapType reports whether call is a bare (unqualified — "make" is a
// builtin, never import-qualified) call to make() whose first argument is a
// map type, returning that *ast.MapType. This is what an idiomatic
// short-variable-declaration such as `pending := make(map[int32]*request)`
// looks like in the AST: the map type never appears as an explicit
// *ast.ValueSpec/struct-field Type (which the checks above this function
// already caught before this fix) — it appears only inside the make() call
// itself, so a check that inspects only ValueSpec/StructType nodes misses
// it entirely.
func makeMapType(call *ast.CallExpr) (*ast.MapType, bool) {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "make" || len(call.Args) == 0 {
		return nil, false
	}
	mt, ok := call.Args[0].(*ast.MapType)
	return mt, ok
}

// findMapTypedSites collects every map-typed site in files: struct fields,
// package/function-level vars with an explicit map type, AND — per the
// review finding that closed this gap — any assignment (`:=` or `=`) whose
// right-hand side is a make(map[...]...) call, however that call's map type
// was inferred rather than spelled out in a ValueSpec. Exported for reuse by
// both the real-package test and the synthetic regression test below that
// proves this exact inferred form is now caught.
func findMapTypedSites(files []profileFile) []mapSite {
	var sites []mapSite
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.TypeSpec:
				st, ok := node.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range st.Fields.List {
					if mt, ok := field.Type.(*ast.MapType); ok {
						sites = append(sites, mapSite{
							loc:        pf.pos(field.Pos()),
							fieldOrVar: fieldNames(field),
							structName: node.Name.Name,
							typeStr:    formatNode(pf, mt),
						})
					}
				}
			case *ast.ValueSpec:
				if mt, ok := node.Type.(*ast.MapType); ok {
					sites = append(sites, mapSite{
						loc:        pf.pos(node.Pos()),
						fieldOrVar: joinIdentNames(node.Names),
						typeStr:    formatNode(pf, mt),
					})
				}
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					call, ok := rhs.(*ast.CallExpr)
					if !ok {
						continue
					}
					mt, ok := makeMapType(call)
					if !ok {
						continue
					}
					name := "<non-ident-lhs>"
					if i < len(node.Lhs) {
						if id, ok := node.Lhs[i].(*ast.Ident); ok {
							name = id.Name
						}
					}
					sites = append(sites, mapSite{
						loc:        pf.pos(node.Pos()),
						fieldOrVar: name,
						typeStr:    formatNode(pf, mt),
					})
				}
			}
			return true
		})
	}
	return sites
}

func TestProfileArchitecture_OnlyActiveConnectionMapExists(t *testing.T) {
	files := loadProfileFiles(t)
	sites := findMapTypedSites(files)

	const wantType = "map[net.Conn]struct{}"
	found := 0
	var bad []string
	for _, s := range sites {
		if s.structName == "Server" && s.typeStr == wantType {
			found++
			continue
		}
		bad = append(bad, fmt.Sprintf("%s: field/var %q has map type %q (struct=%q) — only Server's active-connection map (%s) is permitted",
			s.loc, s.fieldOrVar, s.typeStr, s.structName, wantType))
	}
	if found != 1 {
		t.Fatalf("expected exactly one Server field of type %s (the active-connection map), found %d", wantType, found)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("found %d disallowed map-typed field/var declaration(s) in %s:\n%s", len(bad), profileRelDir, strings.Join(bad, "\n"))
	}
}

// TestProfileArchitecture_DetectsInferredMakeMapAssignment is a regression
// test for the review finding that findMapTypedSites' predecessor (which
// inspected only *ast.StructType fields and explicit *ast.ValueSpec
// MapType/ChanType declarations) missed an idiomatic inferred
// short-variable-declaration such as `pending := make(map[int32]*request)`
// — an AssignStmt with no ValueSpec/explicit-type node anywhere, so the
// mechanical ban was bypassable by ordinary Go syntax. It parses a small
// synthetic source file (never the real profile package) declaring exactly
// that pattern and asserts findMapTypedSites reports it.
func TestProfileArchitecture_DetectsInferredMakeMapAssignment(t *testing.T) {
	const src = `package synthetic

type request struct{}

func bad() {
	pending := make(map[int32]*request)
	_ = pending
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	pf := profileFile{name: "synthetic.go", fset: fset, file: f}

	sites := findMapTypedSites([]profileFile{pf})
	if len(sites) != 1 {
		t.Fatalf("expected findMapTypedSites to catch the inferred `pending := make(map[int32]*request)` assignment, found %d site(s): %+v", len(sites), sites)
	}
	if sites[0].fieldOrVar != "pending" || !strings.Contains(sites[0].typeStr, "map[int32]") {
		t.Fatalf("unexpected site detail for the inferred map assignment: %+v", sites[0])
	}
}

// --- 5: no sync.Map ---

func TestProfileArchitecture_NoSyncMap(t *testing.T) {
	files := loadProfileFiles(t)

	var bad []string
	for _, pf := range files {
		aliases := importAliases(pf.file)
		ast.Inspect(pf.file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if aliases[ident.Name] == "sync" && sel.Sel.Name == "Map" {
				bad = append(bad, fmt.Sprintf("%s: forbidden sync.Map usage", pf.pos(sel.Pos())))
			}
			return true
		})
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("found %d forbidden sync.Map usage(s) in %s:\n%s", len(bad), profileRelDir, strings.Join(bad, "\n"))
	}
}

// --- 6: no channel other than serveDone/stopDone ---

// chanSite records one channel-typed field, explicitly-typed var, or
// make(chan ...)-initialized local variable found anywhere in the package.
type chanSite struct {
	loc     string
	name    string
	typeStr string
}

// makeChanType is makeMapType's channel-typed counterpart: reports whether
// call is a bare make() call whose first argument is a channel type.
func makeChanType(call *ast.CallExpr) (*ast.ChanType, bool) {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "make" || len(call.Args) == 0 {
		return nil, false
	}
	ct, ok := call.Args[0].(*ast.ChanType)
	return ct, ok
}

// findChanTypedSites is findMapTypedSites' channel-typed counterpart,
// closing the identical gap for invariant 6: an idiomatic
// `work := make(chan request)` is an *ast.AssignStmt with no
// ValueSpec/explicit-type node, which the struct-field/ValueSpec-only scan
// below this function's predecessor used to miss entirely.
func findChanTypedSites(files []profileFile) []chanSite {
	var sites []chanSite
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.StructType:
				for _, field := range node.Fields.List {
					if _, ok := field.Type.(*ast.ChanType); ok {
						sites = append(sites, chanSite{
							loc:     pf.pos(field.Pos()),
							name:    fieldNames(field),
							typeStr: formatNode(pf, field.Type),
						})
					}
				}
			case *ast.ValueSpec:
				if _, ok := node.Type.(*ast.ChanType); ok {
					sites = append(sites, chanSite{
						loc:     pf.pos(node.Pos()),
						name:    joinIdentNames(node.Names),
						typeStr: formatNode(pf, node.Type),
					})
				}
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					call, ok := rhs.(*ast.CallExpr)
					if !ok {
						continue
					}
					ct, ok := makeChanType(call)
					if !ok {
						continue
					}
					name := "<non-ident-lhs>"
					if i < len(node.Lhs) {
						if id, ok := node.Lhs[i].(*ast.Ident); ok {
							name = id.Name
						}
					}
					sites = append(sites, chanSite{
						loc:     pf.pos(node.Pos()),
						name:    name,
						typeStr: formatNode(pf, ct),
					})
				}
			}
			return true
		})
	}
	return sites
}

func TestProfileArchitecture_OnlyAllowlistedChannelsExist(t *testing.T) {
	files := loadProfileFiles(t)
	sites := findChanTypedSites(files)

	allow := map[string]bool{"serveDone": true, "stopDone": true}
	var bad []string
	for _, s := range sites {
		for _, name := range strings.Split(s.name, ",") {
			if !allow[name] {
				bad = append(bad, fmt.Sprintf("%s: channel-typed field/var %q (type %s) is not on the serveDone/stopDone allow-list",
					s.loc, name, s.typeStr))
			}
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("found %d disallowed channel-typed declaration(s) in %s:\n%s", len(bad), profileRelDir, strings.Join(bad, "\n"))
	}
}

// TestProfileArchitecture_DetectsInferredMakeChanAssignment is
// TestProfileArchitecture_DetectsInferredMakeMapAssignment's channel-typed
// counterpart: a synthetic `work := make(chan request)` must be caught by
// findChanTypedSites even though it carries no explicit *ast.ChanType
// ValueSpec.
func TestProfileArchitecture_DetectsInferredMakeChanAssignment(t *testing.T) {
	const src = `package synthetic

type request struct{}

func bad() {
	work := make(chan request)
	_ = work
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	pf := profileFile{name: "synthetic.go", fset: fset, file: f}

	sites := findChanTypedSites([]profileFile{pf})
	if len(sites) != 1 {
		t.Fatalf("expected findChanTypedSites to catch the inferred `work := make(chan request)` assignment, found %d site(s): %+v", len(sites), sites)
	}
	if sites[0].name != "work" || !strings.Contains(sites[0].typeStr, "request") {
		t.Fatalf("unexpected site detail for the inferred channel assignment: %+v", sites[0])
	}
}

// --- 7: no old LDAP/BER/wirefixture/unsafe import ---

var forbiddenProfileImportPrefixes = []string{
	"github.com/vjeantet/goldap",
	"github.com/vjeantet/ldapserver",
	"github.com/go-ldap/ldap",
	"github.com/go-asn1-ber/asn1-ber",
	"github.com/Azure/go-ntlmssp",
	"github.com/altinity/altinity-oauth-helper/internal/wirefixture",
}

func TestProfileArchitecture_NoLegacyLDAPOrUnsafeImports(t *testing.T) {
	files := loadProfileFiles(t)

	var bad []string
	for _, pf := range files {
		for _, imp := range pf.file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "unsafe" {
				bad = append(bad, fmt.Sprintf("%s: forbidden import %q", pf.pos(imp.Pos()), path))
				continue
			}
			for _, forbidden := range forbiddenProfileImportPrefixes {
				if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
					bad = append(bad, fmt.Sprintf("%s: forbidden import %q", pf.pos(imp.Pos()), path))
				}
			}
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("found %d forbidden import(s) in %s:\n%s", len(bad), profileRelDir, strings.Join(bad, "\n"))
	}
}

// --- 8-10: decodeMembershipFilter is nonrecursive, two decodeEquality calls ---

func TestProfileArchitecture_MembershipFilterIsNonrecursiveTwoChild(t *testing.T) {
	files := loadProfileFiles(t)

	if n := countFuncDecls(files, "decodeMembershipFilter"); n != 1 {
		t.Fatalf("expected exactly one FuncDecl named decodeMembershipFilter in %s, found %d", profileRelDir, n)
	}
	pf, fd, ok := findFuncDecl(files, "decodeMembershipFilter")
	if !ok {
		t.Fatalf("expected a FuncDecl named decodeMembershipFilter in %s", profileRelDir)
	}

	if self := callsTo(pf, fd.Body, "decodeMembershipFilter"); len(self) > 0 {
		t.Fatalf("decodeMembershipFilter must be nonrecursive; found self-call(s) at: %s", strings.Join(self, ", "))
	}

	eqCalls := callsTo(pf, fd.Body, "decodeEquality")
	if len(eqCalls) != 2 {
		t.Fatalf("decodeMembershipFilter must call decodeEquality exactly twice (the fixed two-predicate walk), found %d call(s) at: %s",
			len(eqCalls), strings.Join(eqCalls, ", "))
	}

	if n := countFuncDecls(files, "decodeEquality"); n != 1 {
		t.Fatalf("expected exactly one FuncDecl named decodeEquality in %s, found %d", profileRelDir, n)
	}
	eqPF, eqFD, ok := findFuncDecl(files, "decodeEquality")
	if !ok {
		t.Fatalf("expected a FuncDecl named decodeEquality in %s", profileRelDir)
	}
	if calls := callsTo(eqPF, eqFD.Body, "decodeMembershipFilter"); len(calls) > 0 {
		t.Fatalf("decodeEquality must never call decodeMembershipFilter (it is the filter decoder's base case, not a recursive descent); found call(s) at: %s",
			strings.Join(calls, ", "))
	}
}

// --- 11: diagnostic is constant-only, single addLDAPResultFields, single text() site ---

func TestProfileArchitecture_DiagnosticIsConstantOnlyThroughAddLDAPResultFields(t *testing.T) {
	files := loadProfileFiles(t)

	if n := countFuncDecls(files, "addLDAPResultFields"); n != 1 {
		t.Fatalf("expected exactly one FuncDecl named addLDAPResultFields in %s, found %d", profileRelDir, n)
	}

	diagConsts := constNamesOfType(files, "diagnostic")
	if len(diagConsts) == 0 {
		t.Fatalf("found no package-level const of type diagnostic in %s — const discovery is broken", profileRelDir)
	}
	diagParams := paramInfoOfType(files, "diagnostic")
	if _, ok := diagParams["addLDAPResultFields"]; !ok {
		t.Fatalf("addLDAPResultFields does not appear to declare a diagnostic-typed parameter — signature drifted from the plan")
	}

	diagLocals := localConstOnlyVars(files, diagConsts, diagParams)
	if violations := checkConstantOnlyCalls(files, "diagnostic", diagParams, diagConsts, diagLocals); len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("found %d diagnostic call-site violation(s) in %s:\n%s", len(violations), profileRelDir, strings.Join(violations, "\n"))
	}

	if convs := findTypeConversions(files, "diagnostic"); len(convs) > 0 {
		sort.Strings(convs)
		t.Fatalf("found %d forbidden diagnostic(...) conversion(s) in %s:\n%s", len(convs), profileRelDir, strings.Join(convs, "\n"))
	}

	// Only addLDAPResultFields may call diagnostic.text() — i.e. the only
	// `.text()` call whose receiver identifier resolves (via the
	// enclosing named function's own parameter list) to a diagnostic-typed
	// parameter must be the one inside addLDAPResultFields itself.
	var textCalls []string
	onCall := func(pf profileFile, call *ast.CallExpr, label, declFunc string) {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "text" {
			return
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return
		}
		if info, has := diagParams[declFunc]; has && info.name == ident.Name {
			textCalls = append(textCalls, fmt.Sprintf("%s (in %s)", pf.pos(call.Pos()), label))
		}
	}
	walkProfile(files, onCall, nil)
	if len(textCalls) != 1 {
		t.Fatalf("expected diagnostic.text() to be referenced from exactly one production callsite (inside addLDAPResultFields), found %d: %s",
			len(textCalls), strings.Join(textCalls, ", "))
	}
	if !strings.Contains(textCalls[0], "addLDAPResultFields") {
		t.Fatalf("diagnostic.text()'s one production callsite must be inside addLDAPResultFields, found: %s", textCalls[0])
	}
}

// --- Amendment 3: reason is constant-only, identically to diagnostic ---

func TestProfileArchitecture_ReasonIsConstantOnlyAcrossLogHelpers(t *testing.T) {
	files := loadProfileFiles(t)

	reasonConsts := constNamesOfType(files, "reason")
	if len(reasonConsts) == 0 {
		t.Fatalf("found no package-level const of type reason in %s — const discovery is broken", profileRelDir)
	}
	reasonParams := paramInfoOfType(files, "reason")
	if len(reasonParams) == 0 {
		t.Fatalf("found no function parameter of type reason in %s — expected at least logBindFailed/logSearchRejected", profileRelDir)
	}

	reasonLocals := localConstOnlyVars(files, reasonConsts, reasonParams)
	if violations := checkConstantOnlyCalls(files, "reason", reasonParams, reasonConsts, reasonLocals); len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("found %d reason call-site violation(s) in %s:\n%s", len(violations), profileRelDir, strings.Join(violations, "\n"))
	}

	if convs := findTypeConversions(files, "reason"); len(convs) > 0 {
		sort.Strings(convs)
		t.Fatalf("found %d forbidden reason(...) conversion(s) in %s:\n%s", len(convs), profileRelDir, strings.Join(convs, "\n"))
	}
}

// --- 12-13: Verify/Roles referenced exactly once each, inside bind.go ---

// selectorHasFieldRoot reports whether sel's receiver expression is itself
// a *ast.SelectorExpr whose own Sel.Name is fieldName — the shape every
// production reference to the connection/Server's verifier/roles field
// takes (`c.verifier.Verify`, `c.roles.Roles`). This package's
// architecture-contract file is deliberately go/ast-only (no go/types, per
// the file's top comment matching redaction_inventory_test.go's
// discipline), so telling a genuine Verifier.Verify/RoleResolver.Roles
// reference apart from an unrelated, coincidentally same-named selector —
// a plain data field such as `c.auth.Roles` or `newState.Roles` — has to be
// done by this naming-convention heuristic rather than by resolved types.
func selectorHasFieldRoot(sel *ast.SelectorExpr, fieldName string) bool {
	inner, ok := sel.X.(*ast.SelectorExpr)
	return ok && inner.Sel.Name == fieldName
}

// verifyOrRolesSelectorSites finds every *ast.SelectorExpr anywhere in
// files matching selName/fieldName (see selectorHasFieldRoot), regardless
// of whether that selector is immediately called. This is deliberately
// broader than "every CallExpr whose Fun is such a selector": the review
// finding this closes showed that a method-value extraction
// (`verify := c.verifier.Verify` followed by a later `verify(...)` call)
// produces exactly that shape — a bare SelectorExpr assigned to a variable,
// with the later call's Fun being a plain *ast.Ident, not a SelectorExpr —
// so a check that only counted selector-shaped CallExprs would see zero
// occurrences for a second verification path introduced this way. Counting
// every matching SelectorExpr node instead means the extraction itself
// (assigning `c.verifier.Verify` anywhere, called or not) is what gets
// counted, so a second path is caught the moment it's written, independent
// of how many times or where the extracted value is later invoked.
func verifyOrRolesSelectorSites(files []profileFile, selName, fieldName string) []string {
	var sites []string
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != selName {
				return true
			}
			if !selectorHasFieldRoot(sel, fieldName) {
				return true
			}
			sites = append(sites, pf.pos(sel.Pos()))
			return true
		})
	}
	return sites
}

func TestProfileArchitecture_VerifyAndRolesOnlyOnceInBind(t *testing.T) {
	files := loadProfileFiles(t)

	checkOne := func(selName, fieldName string) {
		sites := verifyOrRolesSelectorSites(files, selName, fieldName)
		if len(sites) != 1 {
			t.Fatalf("expected exactly one .%s( reference (via .%s.%s) in %s, found %d: %s",
				selName, fieldName, selName, profileRelDir, len(sites), strings.Join(sites, ", "))
		}
		if !strings.HasPrefix(sites[0], "bind.go:") {
			t.Fatalf(".%s( reference must be inside bind.go, found: %s", selName, sites[0])
		}
	}

	checkOne("Verify", "verifier")
	checkOne("Roles", "roles")
}

// TestProfileArchitecture_DetectsVerifyMethodValueExtraction is a
// regression test for the review finding that the previous
// selector-CallExpr-only check could be bypassed by extracting a method
// value first (`verify := c.verifier.Verify; verify(...)`) — neither the
// extraction (a bare SelectorExpr, not a CallExpr) nor the later call
// (Fun is a plain Ident, not a SelectorExpr) was ever counted. It builds a
// synthetic two-site package — one legitimate `c.verifier.Verify(...)` call
// plus a second file that only extracts the method value without calling
// it — and asserts verifyOrRolesSelectorSites reports both, proving a
// second verification path introduced this way now trips the "exactly
// one" invariant.
func TestProfileArchitecture_DetectsVerifyMethodValueExtraction(t *testing.T) {
	const legit = `package synthetic

type connection struct {
	verifier interface {
		Verify()
	}
}

func (c *connection) handleBind() {
	c.verifier.Verify()
}
`
	const sneaky = `package synthetic

type other struct {
	verifier interface {
		Verify()
	}
}

func (o *other) sneak() {
	verify := o.verifier.Verify
	verify()
}
`
	parseOne := func(name, src string) profileFile {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source %s: %v", name, err)
		}
		return profileFile{name: name, fset: fset, file: f}
	}

	legitOnly := []profileFile{parseOne("bind.go", legit)}
	if sites := verifyOrRolesSelectorSites(legitOnly, "Verify", "verifier"); len(sites) != 1 {
		t.Fatalf("expected exactly one Verify site with only the legitimate call present, found %d: %v", len(sites), sites)
	}

	withSneak := []profileFile{parseOne("bind.go", legit), parseOne("sneaky.go", sneaky)}
	sites := verifyOrRolesSelectorSites(withSneak, "Verify", "verifier")
	if len(sites) != 2 {
		t.Fatalf("expected the method-value-extraction site in sneaky.go to be counted alongside the legitimate bind.go call (2 total), found %d: %v", len(sites), sites)
	}
}

// TestProfileArchitecture_SelectorHeuristicIgnoresUnrelatedRolesField
// proves selectorHasFieldRoot does not false-positive on the package's own
// legitimate non-method `Roles` field accesses (`c.auth.Roles`,
// `newState.Roles`) — the reason the broadened check above cannot simply
// count every SelectorExpr named "Roles" and must instead require the
// `.roles.Roles` receiver shape.
func TestProfileArchitecture_SelectorHeuristicIgnoresUnrelatedRolesField(t *testing.T) {
	const src = `package synthetic

type authState struct {
	Roles []string
}

type connection struct {
	auth authState
}

func (c *connection) readSnapshot() []string {
	roles := c.auth.Roles
	return roles
}

func assignField(newState *authState, roles []string) {
	newState.Roles = roles
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "search.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	pf := profileFile{name: "search.go", fset: fset, file: f}

	if sites := verifyOrRolesSelectorSites([]profileFile{pf}, "Roles", "roles"); len(sites) != 0 {
		t.Fatalf("expected zero Roles-method sites for plain data-field accesses (c.auth.Roles, newState.Roles), found %d: %v", len(sites), sites)
	}
}
