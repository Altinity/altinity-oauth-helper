package securitytest

// This file enforces the four TYPE-SEMANTIC architecture invariants over
// internal/ldap/profile — invariants 4, 6, 12, and 13 of the Phase 2 plan's
// "Mechanical architecture contract" (numbering shared with
// profile_architecture_contract_test.go, which keeps the purely syntactic
// invariants and documents the split):
//
//   4.  the only map-typed state in the package is Server's
//       active-connection map (map[net.Conn]struct{});
//   6.  the only channel-typed state is Server.serveDone / Server.stopDone
//       (both chan struct{});
//   12. Verifier.Verify is referenced exactly once in production, in bind.go;
//   13. RoleResolver.Roles is referenced exactly once in production, in
//       bind.go — where "referenced" means a method selection of any kind
//       (call, method value, method expression), and a struct FIELD named
//       Roles (c.auth.Roles, newState.Roles) is a data access that does not
//       count.
//
// Enforcement basis: go/types over the fully type-checked package, NOT
// go/ast shape enumeration. Three consecutive external review passes each
// found a new ordinary-Go bypass of the previous AST-only checker (make()
// forms; composite literals and method values; var-composite-literals,
// function result types, and transitive aliases), and a final architecture
// consultation identified counterexamples no shape enumerator can cover:
// maps.Clone(s.active) (a map-typed value with no map syntax anywhere near
// it), time.After(...) (a channel produced by a call), a call-expression
// receiver (currentVerifier(c).Verify(...)) that no alias tracker resolves,
// and a generic function returning T instantiated at a map type. The
// verdict was to stop extending the enumerator and make these four
// invariants type-aware. Mechanically:
//
//   - The package's non-test files are parsed with go/parser into ONE
//     shared FileSet and type-checked with go/types. Dependency export
//     data comes from a single deterministic
//     `go list -mod=readonly -deps -export -json` invocation
//     (resolveGoBinPath + deterministicGoListEnv, shared with
//     dependency_contract_test.go, so the toolchain choice and environment
//     are exactly the audited dependency-contract ones), fed to the stdlib
//     importer.ForCompiler(fset, "gc", lookup) whose lookup opens the
//     export file `go list` recorded for each import path. Stdlib-only,
//     module-correct, no golang.org/x/tools, no network.
//   - Invariants 4/6 (collectTypedSites): every object the type checker
//     defines (types.Info.Defs and .Implicits — package/local vars, struct
//     fields, named function and method signatures, named types) and every
//     VALUE expression it types (types.Info.Types, type expressions
//     excluded) whose type is, or structurally carries, a map/channel is a
//     site. "Carries" recurses through pointers, slices, arrays, structs,
//     tuples, function signatures, and interface method sets; a named type
//     is flagged when its own underlying type is a map/channel (so an
//     http.Header-alike from any package is caught) and is otherwise
//     opaque — an in-package named composite's components are flagged at
//     their own declaration idents, and an external named type's internals
//     are the other package's state, not this package's. The allowlist is
//     exactly the three Server fields, direct references to them, and the
//     initializer expressions assigned into them (composite-literal
//     key/value or assignment whose LHS resolves to an allowed field).
//   - Invariants 12/13 (methodSelectionSites): every entry in
//     types.Info.Selections — which covers method calls, method values
//     (verify := c.verifier.Verify), and method expressions
//     (Verifier.Verify), on any receiver expression including calls and
//     generic type parameters — whose selected object is a method with the
//     target name and whose receiver type implements the package's own
//     Verifier/RoleResolver interface (or whose selected object IS that
//     interface's method) is a site; types.FieldVal selections are
//     excluded by kind, not by naming convention. Exactly one site each is
//     required, in bind.go.
//
// What this proves, stated precisely: within the type-checked production
// package there is no map- or channel-typed declaration, signature, or
// value expression outside the allowlist, and no Verify/Roles method
// selection outside the single bind.go site — for every way such a type or
// selection can appear to the Go type checker, not for an enumerated list
// of syntax shapes. Residual limits, stated rather than hidden: reflection
// and unsafe could manufacture such values invisibly to go/types, but
// unsafe is forbidden by invariant 7's import ban (in
// profile_architecture_contract_test.go) and reflect-based laundering
// would still need a map/chan-typed expression at the point of use to be
// usable as state; and the checks run on the package as committed — they
// are a drift gate for this repository's tree, not a defense against an
// adversary who can also edit the checker.
//
// The synthetic regression tests below re-prove, through the SAME
// type-aware checker functions used on the real package, every historical
// bypass of the retired AST enumerator (make() in := and var forms, map
// composite literals in := and var forms, named map/chan type aliases,
// function and closure result types, method-value extraction, one-hop and
// transitive receiver aliases, interface-typed parameters) AND the
// architecture consultation's new counterexamples (maps.Clone of the
// allowed map, time.After's channel, a call-expression receiver, a generic
// identity function instantiated at the allowed map's type), plus the
// negative controls (allowlisted usage produces zero sites; struct-field
// Roles accesses are not method references).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// profileExportExtraPackages are the stdlib packages this file's synthetic
// regression sources import beyond the profile package's own dependency
// closure. They ride along in the one `go list -deps -export` invocation so
// their export data lands in the shared lookup index.
var profileExportExtraPackages = []string{"maps", "time"}

var (
	profileExportOnce sync.Once
	profileExportIdx  map[string]string
	profileExportErr  error
)

// profileExportIndex returns the import-path -> export-data-file index for
// the profile package's dependency closure (plus
// profileExportExtraPackages), built exactly once per test binary.
func profileExportIndex(t *testing.T) map[string]string {
	t.Helper()
	profileExportOnce.Do(func() {
		profileExportIdx, profileExportErr = buildProfileExportIndex()
	})
	if profileExportErr != nil {
		t.Fatalf("profile_types: build export-data index: %v", profileExportErr)
	}
	return profileExportIdx
}

// buildProfileExportIndex runs the deterministic `go list` invocation —
// same resolved go binary and same pinned GOOS=linux/GOARCH=amd64/
// CGO_ENABLED=0/GOWORK=off environment as dependency_contract_test.go —
// with -export, which compiles (or reuses from the build cache) each
// dependency and reports the export-data file the gc importer can read.
func buildProfileExportIndex() (map[string]string, error) {
	root, err := moduleRoot()
	if err != nil {
		return nil, fmt.Errorf("resolve module root: %w", err)
	}
	goBin, err := resolveGoBinPath()
	if err != nil {
		return nil, err
	}

	args := []string{"list", "-mod=readonly", "-deps", "-export", "-json=ImportPath,Export"}
	args = append(args, "./"+profileRelDir)
	args = append(args, profileExportExtraPackages...)
	cmd := exec.Command(goBin, args...) //nolint:gosec // fixed, deterministically-resolved go tool binary; fixed argv above
	cmd.Dir = root
	cmd.Env = deterministicGoListEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s list -deps -export failed: %w\nstderr:\n%s", filepath.Base(goBin), err, stderr.String())
	}

	idx := map[string]string{}
	dec := json.NewDecoder(&stdout)
	for {
		var row struct {
			ImportPath string
			Export     string
		}
		if err := dec.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode go list -json stream: %w", err)
		}
		if row.ImportPath == "unsafe" {
			// No export data exists for the pseudo-package; the gc importer
			// special-cases it internally (and invariant 7 forbids the
			// profile from importing it anyway).
			continue
		}
		if row.Export == "" {
			return nil, fmt.Errorf("go list -export recorded no export file for %q — a build failure or GOFLAGS interference; rerun with the same env to diagnose", row.ImportPath)
		}
		idx[row.ImportPath] = row.Export
	}
	if len(idx) == 0 {
		return nil, fmt.Errorf("go list -deps -export returned no packages")
	}
	return idx, nil
}

// typedPackage is one fully type-checked package: the real profile package
// or a synthetic regression package, both produced by the same loader so
// the checker functions below are proven against exactly what gates the
// real tree.
type typedPackage struct {
	fset  *token.FileSet
	files []*ast.File
	pkg   *types.Package
	info  *types.Info
}

// pos renders p as "<base filename>:<line>" for failure messages.
func (tp *typedPackage) pos(p token.Pos) string {
	position := tp.fset.Position(p)
	return fmt.Sprintf("%s:%d", filepath.Base(position.Filename), position.Line)
}

// render prints an AST node back to source text for failure messages.
func (tp *typedPackage) render(n ast.Node) string {
	var buf bytes.Buffer
	if err := format.Node(&buf, tp.fset, n); err != nil {
		return fmt.Sprintf("<unformattable: %v>", err)
	}
	return buf.String()
}

// typecheckPackage type-checks files (which must share fset) under the
// gc-export-data importer. Any type error is fatal: these contracts are
// only meaningful over a package that actually compiles.
func typecheckPackage(t *testing.T, path string, fset *token.FileSet, files []*ast.File) *typedPackage {
	t.Helper()
	exports := profileExportIndex(t)
	lookup := func(importPath string) (io.ReadCloser, error) {
		exp, ok := exports[importPath]
		if !ok {
			return nil, fmt.Errorf("profile_types: no export data recorded for import %q — if a synthetic source legitimately needs it, add it to profileExportExtraPackages", importPath)
		}
		return os.Open(exp)
	}
	conf := types.Config{
		Importer: importer.ForCompiler(fset, "gc", lookup),
		// deterministicGoListEnv pins the export data to linux/amd64; size
		// semantics here match that target for consistency.
		Sizes: types.SizesFor("gc", "amd64"),
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Implicits:  map[ast.Node]types.Object{},
	}
	pkg, err := conf.Check(path, fset, files, info)
	if err != nil {
		t.Fatalf("profile_types: type-check %s: %v", path, err)
	}
	return &typedPackage{fset: fset, files: files, pkg: pkg, info: info}
}

// typecheckProfilePackage parses every non-test .go file directly under
// internal/ldap/profile into one shared FileSet and fully type-checks the
// package.
func typecheckProfilePackage(t *testing.T) *typedPackage {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("profile_types: locate module root: %v", err)
	}
	dir := filepath.Join(root, filepath.FromSlash(profileRelDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("profile_types: read %s: %v", profileRelDir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		t.Fatalf("profile_types: no non-test .go files found directly under %s — is the package missing or empty?", profileRelDir)
	}
	sort.Strings(names)

	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range names {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("profile_types: parse %s/%s: %v", profileRelDir, name, err)
		}
		files = append(files, f)
	}
	return typecheckPackage(t, "github.com/altinity/altinity-oauth-helper/"+profileRelDir, fset, files)
}

// typecheckSynthetic type-checks the given name->source in-memory files as
// one package, through the same importer and checker configuration the
// real-package tests use — so a synthetic regression proof exercises the
// identical code path that gates the real tree.
func typecheckSynthetic(t *testing.T, files map[string]string) *typedPackage {
	t.Helper()
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, files[name], parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("profile_types: parse synthetic %s: %v", name, err)
		}
		parsed = append(parsed, f)
	}
	return typecheckPackage(t, "synthetic", fset, parsed)
}

// --- invariants 4/6: type-aware map/channel site enumeration ---

func isMapType(t types.Type) bool { _, ok := t.(*types.Map); return ok }

func isChanType(t types.Type) bool { _, ok := t.(*types.Chan); return ok }

// typeCarries reports whether t is, or structurally carries, a type matched
// by want. A named type (after alias resolution) is matched when its own
// underlying type matches, and is otherwise opaque: an in-package named
// composite's components are flagged at their own declaration idents by
// collectTypedSites' Defs walk, and an external named type's internals are
// the other package's state, not this package's — while a named type whose
// underlying IS a map/channel (an http.Header-alike, wherever it is
// declared) still matches here. seen guards against reference cycles.
func typeCarries(t types.Type, want func(types.Type) bool, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	if want(t.Underlying()) {
		return true
	}
	if _, isNamed := t.(*types.Named); isNamed {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return typeCarries(u.Elem(), want, seen)
	case *types.Slice:
		return typeCarries(u.Elem(), want, seen)
	case *types.Array:
		return typeCarries(u.Elem(), want, seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if typeCarries(u.Field(i).Type(), want, seen) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			if typeCarries(u.At(i).Type(), want, seen) {
				return true
			}
		}
	case *types.Signature:
		return typeCarries(u.Params(), want, seen) || typeCarries(u.Results(), want, seen)
	case *types.Interface:
		for i := 0; i < u.NumMethods(); i++ {
			if typeCarries(u.Method(i).Type(), want, seen) {
				return true
			}
		}
	}
	return false
}

// typeSite is one disallowed map/channel occurrence, for failure messages.
type typeSite struct {
	loc  string
	what string
	typ  string
}

func (s typeSite) String() string {
	return fmt.Sprintf("%s: %s has type %s", s.loc, s.what, s.typ)
}

func describeObj(obj types.Object) string {
	switch o := obj.(type) {
	case *types.Var:
		if o.IsField() {
			return fmt.Sprintf("field %q", o.Name())
		}
		return fmt.Sprintf("var %q", o.Name())
	case *types.Func:
		return fmt.Sprintf("func %q signature", o.Name())
	case *types.TypeName:
		return fmt.Sprintf("type %q", o.Name())
	}
	return fmt.Sprintf("object %q", obj.Name())
}

// refObj resolves expr, when it is a direct reference (identifier or
// selection, parenthesized or not), to the object it references; nil
// otherwise.
func (tp *typedPackage) refObj(expr ast.Expr) types.Object {
	for {
		p, ok := expr.(*ast.ParenExpr)
		if !ok {
			break
		}
		expr = p.X
	}
	switch e := expr.(type) {
	case *ast.Ident:
		if obj := tp.info.Uses[e]; obj != nil {
			return obj
		}
		return tp.info.Defs[e]
	case *ast.SelectorExpr:
		if sel := tp.info.Selections[e]; sel != nil {
			return sel.Obj()
		}
		return tp.info.Uses[e.Sel] // qualified identifier (pkg.X)
	}
	return nil
}

// allowedInitExprs marks every expression whose value is assigned INTO an
// allowlisted object: the RHS of an assignment whose LHS is a direct
// reference to an allowed object, and the value of a composite-literal
// key/value element whose key resolves to an allowed field (Server's
// construction literal in New). The value becomes the allowed state itself,
// so it is not a second map/channel location.
func (tp *typedPackage) allowedInitExprs(allowed map[types.Object]bool) map[ast.Expr]bool {
	out := map[ast.Expr]bool{}
	if len(allowed) == 0 {
		return out
	}
	for _, f := range tp.files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				if len(node.Lhs) != len(node.Rhs) {
					return true
				}
				for i, lhs := range node.Lhs {
					if obj := tp.refObj(lhs); obj != nil && allowed[obj] {
						out[node.Rhs[i]] = true
					}
				}
			case *ast.KeyValueExpr:
				if key, ok := node.Key.(*ast.Ident); ok && allowed[tp.info.Uses[key]] {
					out[node.Value] = true
				}
			}
			return true
		})
	}
	return out
}

// collectTypedSites is the invariant-4/6 checker: it returns every
// declaration (Defs/Implicits: vars, fields, function and method
// signatures, named types) and every value expression (Types) whose type
// is, or carries, a type matched by want — except the allowlisted objects
// themselves, direct references to them, and their initializer expressions.
// It works on any typedPackage, so the synthetic regression tests exercise
// exactly the function that gates the real package.
func collectTypedSites(tp *typedPackage, want func(types.Type) bool, allowed map[types.Object]bool) []typeSite {
	var sites []typeSite

	addObj := func(pos token.Pos, obj types.Object) {
		if obj == nil || allowed[obj] {
			return
		}
		switch obj.(type) {
		case *types.Var, *types.Func, *types.TypeName:
			// The kinds that can declare or carry map/channel-typed state.
		default:
			return // PkgName/Const/Label/Builtin/Nil cannot.
		}
		if typeCarries(obj.Type(), want, map[types.Type]bool{}) {
			sites = append(sites, typeSite{loc: tp.pos(pos), what: describeObj(obj), typ: obj.Type().String()})
		}
	}
	for id, obj := range tp.info.Defs {
		if obj == nil {
			continue
		}
		addObj(id.Pos(), obj)
	}
	for node, obj := range tp.info.Implicits {
		addObj(node.Pos(), obj)
	}

	allowedInit := tp.allowedInitExprs(allowed)
	for expr, tv := range tp.info.Types {
		if tv.IsType() || tv.Type == nil {
			continue
		}
		if tv.IsBuiltin() {
			// The builtin function ident itself (make/len/delete/close…):
			// its per-call pseudo-signature mentions the operand's type, but
			// a builtin is not a storable value — the operands and results
			// are what matter, and those are typed expressions checked here
			// on their own.
			continue
		}
		if !typeCarries(tv.Type, want, map[types.Type]bool{}) {
			continue
		}
		if obj := tp.refObj(expr); obj != nil && allowed[obj] {
			continue
		}
		if allowedInit[expr] {
			continue
		}
		sites = append(sites, typeSite{loc: tp.pos(expr.Pos()), what: fmt.Sprintf("expression %q", tp.render(expr)), typ: tv.Type.String()})
	}

	sort.Slice(sites, func(i, j int) bool {
		if sites[i].loc != sites[j].loc {
			return sites[i].loc < sites[j].loc
		}
		return sites[i].what < sites[j].what
	})
	return sites
}

func joinTypeSites(sites []typeSite) string {
	msgs := make([]string, len(sites))
	for i, s := range sites {
		msgs[i] = s.String()
	}
	return strings.Join(msgs, "\n")
}

// structFieldObj resolves the *types.Var for structName.fieldName from the
// package scope.
func structFieldObj(t *testing.T, tp *typedPackage, structName, fieldName string) types.Object {
	t.Helper()
	obj := tp.pkg.Scope().Lookup(structName)
	if obj == nil {
		t.Fatalf("profile_types: no package-scope type %q", structName)
	}
	tn, ok := obj.(*types.TypeName)
	if !ok {
		t.Fatalf("profile_types: %q is %T, not a type name", structName, obj)
	}
	st, ok := tn.Type().Underlying().(*types.Struct)
	if !ok {
		t.Fatalf("profile_types: %q's underlying type is %T, not a struct", structName, tn.Type().Underlying())
	}
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i).Name() == fieldName {
			return st.Field(i)
		}
	}
	t.Fatalf("profile_types: struct %q has no field %q", structName, fieldName)
	return nil
}

func TestProfileArchitecture_OnlyActiveConnectionMapExists(t *testing.T) {
	tp := typecheckProfilePackage(t)

	active := structFieldObj(t, tp, "Server", "active")
	const wantType = "map[net.Conn]struct{}"
	if got := active.Type().String(); got != wantType {
		t.Fatalf("Server.active must have type %s (the active-connection map), found %s", wantType, got)
	}

	sites := collectTypedSites(tp, isMapType, map[types.Object]bool{active: true})
	if len(sites) > 0 {
		t.Fatalf("found %d map-typed site(s) in %s beyond Server.active (%s) — the only permitted map state:\n%s",
			len(sites), profileRelDir, wantType, joinTypeSites(sites))
	}
}

func TestProfileArchitecture_OnlyAllowlistedChannelsExist(t *testing.T) {
	tp := typecheckProfilePackage(t)

	allowed := map[types.Object]bool{}
	for _, name := range []string{"serveDone", "stopDone"} {
		field := structFieldObj(t, tp, "Server", name)
		const wantType = "chan struct{}"
		if got := field.Type().String(); got != wantType {
			t.Fatalf("Server.%s must have type %s, found %s", name, wantType, got)
		}
		allowed[field] = true
	}

	sites := collectTypedSites(tp, isChanType, allowed)
	if len(sites) > 0 {
		t.Fatalf("found %d channel-typed site(s) in %s beyond Server.serveDone/Server.stopDone — the only permitted channels:\n%s",
			len(sites), profileRelDir, joinTypeSites(sites))
	}
}

// --- invariants 12/13: type-aware Verify/Roles selection enumeration ---

// lookupInterface resolves a package-scope interface type by name.
func lookupInterface(t *testing.T, tp *typedPackage, name string) *types.Interface {
	t.Helper()
	obj := tp.pkg.Scope().Lookup(name)
	if obj == nil {
		t.Fatalf("profile_types: no package-scope type %q", name)
	}
	tn, ok := obj.(*types.TypeName)
	if !ok {
		t.Fatalf("profile_types: %q is %T, not a type name", name, obj)
	}
	iface, ok := tn.Type().Underlying().(*types.Interface)
	if !ok {
		t.Fatalf("profile_types: %q's underlying type is %T, not an interface", name, tn.Type().Underlying())
	}
	return iface
}

// methodSelectionSites is the invariant-12/13 checker: every method
// selection (types.Info.Selections — method calls, method values, and
// method expressions alike, whatever the receiver expression) whose
// selected object is a method named methodName and whose receiver type
// implements iface (or whose selected object IS iface's own method, which
// also covers generic type-parameter receivers constrained by iface).
// types.FieldVal selections are excluded by kind: a struct FIELD with the
// same name is a data access, not a method reference. Returns sorted
// file:line positions.
func methodSelectionSites(tp *typedPackage, iface *types.Interface, methodName string) []string {
	ifaceMethods := map[*types.Func]bool{}
	for i := 0; i < iface.NumMethods(); i++ {
		ifaceMethods[iface.Method(i)] = true
	}

	var sites []string
	for expr, sel := range tp.info.Selections {
		if sel.Kind() == types.FieldVal {
			continue
		}
		fn, ok := sel.Obj().(*types.Func)
		if !ok || fn.Name() != methodName {
			continue
		}
		recv := sel.Recv()
		if ifaceMethods[fn] || ifaceMethods[fn.Origin()] ||
			types.Implements(recv, iface) || types.Implements(types.NewPointer(recv), iface) {
			sites = append(sites, tp.pos(expr.Pos()))
		}
	}
	sort.Strings(sites)
	return sites
}

func TestProfileArchitecture_VerifyAndRolesOnlyOnceInBind(t *testing.T) {
	tp := typecheckProfilePackage(t)

	check := func(ifaceName, methodName string) {
		iface := lookupInterface(t, tp, ifaceName)
		sites := methodSelectionSites(tp, iface, methodName)
		if len(sites) != 1 {
			t.Fatalf("expected exactly one %s.%s method selection in %s, found %d: %s",
				ifaceName, methodName, profileRelDir, len(sites), strings.Join(sites, ", "))
		}
		if !strings.HasPrefix(sites[0], "bind.go:") {
			t.Fatalf("%s.%s's one method selection must be inside bind.go, found: %s", ifaceName, methodName, sites[0])
		}
	}

	check("Verifier", "Verify")
	check("RoleResolver", "Roles")
}

// --- synthetic regression proofs: map/channel invariant (4/6) ---

// requireSiteMentioning asserts at least one collected site's type string
// contains wantTypeSubstr; desc names the bypass shape for the failure
// message.
func requireSiteMentioning(t *testing.T, sites []typeSite, wantTypeSubstr, desc string) {
	t.Helper()
	for _, s := range sites {
		if strings.Contains(s.typ, wantTypeSubstr) {
			return
		}
	}
	t.Fatalf("expected the type-aware checker to catch %s (a site whose type mentions %q), found %d site(s):\n%s",
		desc, wantTypeSubstr, len(sites), joinTypeSites(sites))
}

// TestProfileArchitecture_DetectsInferredMakeMapAssignment: the pass-1
// review bypass — an inferred short variable declaration
// (`pending := make(map[int32]*request)`) that the original explicit-type
// AST enumeration missed. Under go/types the local's declared object and
// the make() expression both carry the map type.
func TestProfileArchitecture_DetectsInferredMakeMapAssignment(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func bad() {
	pending := make(map[int32]*request)
	_ = pending
}
`})
	sites := collectTypedSites(tp, isMapType, nil)
	requireSiteMentioning(t, sites, "map[int32]", "the inferred `pending := make(map[int32]*request)` assignment")
}

// TestProfileArchitecture_DetectsInferredVarMakeMapAssignment: the `var`
// spelling of the same pass-1/2 bypass (`var pending = make(...)`, a
// ValueSpec with no explicit type node).
func TestProfileArchitecture_DetectsInferredVarMakeMapAssignment(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func bad() {
	var pending = make(map[int32]*request)
	_ = pending
}
`})
	sites := collectTypedSites(tp, isMapType, nil)
	requireSiteMentioning(t, sites, "map[int32]", "the inferred `var pending = make(map[int32]*request)` declaration")
}

// TestProfileArchitecture_DetectsMapCompositeLiteralAssignment: the pass-2
// bypass — a map composite literal (`pending := map[int32]*request{}`)
// whose type lives on the CompositeLit, not a make() call.
func TestProfileArchitecture_DetectsMapCompositeLiteralAssignment(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func bad() {
	pending := map[int32]*request{}
	_ = pending
}
`})
	sites := collectTypedSites(tp, isMapType, nil)
	requireSiteMentioning(t, sites, "map[int32]", "the `pending := map[int32]*request{}` composite literal")
}

// TestProfileArchitecture_DetectsVarMapCompositeLiteralAssignment: the
// pass-3 bypass — the same composite literal spelled with the `var`
// keyword, which fell through both of the AST enumerator's ValueSpec
// branches.
func TestProfileArchitecture_DetectsVarMapCompositeLiteralAssignment(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func bad() {
	var pending = map[int32]*request{}
	_ = pending
}
`})
	sites := collectTypedSites(tp, isMapType, nil)
	requireSiteMentioning(t, sites, "map[int32]", "the `var pending = map[int32]*request{}` declaration")
}

// TestProfileArchitecture_DetectsNamedMapTypeAliasField: the pass-2 bypass
// where a struct field is declared via a named map type
// (`type requestMap map[int32]*request; active requestMap`) — under
// go/types the named type's underlying map is visible with no alias
// resolution machinery at all, transitively through any number of type
// indirections.
func TestProfileArchitecture_DetectsNamedMapTypeAliasField(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

type requestMap map[int32]*request

type Server struct {
	active requestMap
}
`})
	sites := collectTypedSites(tp, isMapType, nil)
	requireSiteMentioning(t, sites, "requestMap", "the `active requestMap` named-map-type field")
}

// TestProfileArchitecture_DetectsTransitiveNamedMapType: a named type
// defined in terms of ANOTHER named map type — the "transitive alias"
// shape from the pass-3 review round that a one-hop resolver missed.
func TestProfileArchitecture_DetectsTransitiveNamedMapType(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

type requestMap = map[int32]*request

type indirection = requestMap

type Server struct {
	active indirection
}
`})
	sites := collectTypedSites(tp, isMapType, nil)
	// Alias types print their own name, not the map they resolve to, so the
	// assertion matches the alias name on the flagged field.
	requireSiteMentioning(t, sites, "indirection", "a struct field typed via a two-hop alias chain to a map type")
	var fieldSite bool
	for _, s := range sites {
		if strings.Contains(s.what, `field "active"`) {
			fieldSite = true
		}
	}
	if !fieldSite {
		t.Fatalf("expected the aliased field itself to be a site, found:\n%s", joinTypeSites(sites))
	}
}

// TestProfileArchitecture_DetectsFuncResultMapType: the pass-3 bypass — a
// function whose declared RESULT type is a map
// (`func newActive() map[int32]*request`), a signature no
// field/ValueSpec/AssignStmt case ever inspected.
func TestProfileArchitecture_DetectsFuncResultMapType(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func newActive() map[int32]*request {
	return nil
}
`})
	sites := collectTypedSites(tp, isMapType, nil)
	requireSiteMentioning(t, sites, "map[int32]", "newActive's declared map-typed result")
	var declSite bool
	for _, s := range sites {
		if strings.Contains(s.what, `func "newActive"`) {
			declSite = true
		}
	}
	if !declSite {
		t.Fatalf("expected newActive's own signature to be a site, found:\n%s", joinTypeSites(sites))
	}
}

// TestProfileArchitecture_DetectsFuncLitResultMapType: the closure
// counterpart — a map-typed result on an anonymous function literal. The
// FuncLit expression's signature type carries the map.
func TestProfileArchitecture_DetectsFuncLitResultMapType(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func bad() {
	newActive := func() map[int32]*request {
		return nil
	}
	_ = newActive
}
`})
	sites := collectTypedSites(tp, isMapType, nil)
	requireSiteMentioning(t, sites, "map[int32]", "the func literal's declared map-typed result")
}

// TestProfileArchitecture_DetectsMapTypedParameter: a function PARAMETER of
// map type — the signature-side shape symmetric to the result-type bypass,
// covered here because parameters are exactly how the interface-typed-
// parameter Verify bypass smuggled state past assignment tracking.
func TestProfileArchitecture_DetectsMapTypedParameter(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func consume(pending map[int32]*request) int {
	return len(pending)
}
`})
	sites := collectTypedSites(tp, isMapType, nil)
	requireSiteMentioning(t, sites, "map[int32]", "consume's map-typed parameter")
}

// TestProfileArchitecture_DetectsMapsCloneOfAllowedMap: the architecture
// consultation's headline counterexample — `pending := maps.Clone(s.active)`
// produces a map-typed value with NO map syntax anywhere near it (no make,
// no composite literal, no explicit type), from an expression whose only
// map-typed input is the allowlisted field itself. The call expression and
// the new local are both sites even though `s.active` is allowed.
func TestProfileArchitecture_DetectsMapsCloneOfAllowedMap(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"server.go": `package synthetic

import (
	"maps"
	"net"
)

type Server struct {
	active map[net.Conn]struct{}
}

func (s *Server) snapshot() {
	pending := maps.Clone(s.active)
	_ = pending
}
`})
	active := structFieldObj(t, tp, "Server", "active")
	sites := collectTypedSites(tp, isMapType, map[types.Object]bool{active: true})
	requireSiteMentioning(t, sites, "map[net.Conn]struct{}", "the `pending := maps.Clone(s.active)` clone of the allowlisted map")
}

// TestProfileArchitecture_DetectsGenericIdentityMapResult: the
// consultation's generics counterexample — a generic identity function
// instantiated at the allowed map's type. The instantiated call expression
// (and the local it initializes) has a map type even though the generic
// function's own declaration mentions no map at all and the only argument
// is the allowlisted field.
func TestProfileArchitecture_DetectsGenericIdentityMapResult(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"server.go": `package synthetic

import "net"

type Server struct {
	active map[net.Conn]struct{}
}

func id[T any](v T) T { return v }

func (s *Server) leak() {
	clone := id(s.active)
	_ = clone
}
`})
	active := structFieldObj(t, tp, "Server", "active")
	sites := collectTypedSites(tp, isMapType, map[types.Object]bool{active: true})
	requireSiteMentioning(t, sites, "map[net.Conn]struct{}", "the generic `clone := id(s.active)` identity instantiation at the map type")
}

// TestProfileArchitecture_DetectsInferredMakeChanAssignment /
// ...VarMakeChanAssignment / ...NamedChanTypeAliasField /
// ...FuncResultChanType: the channel-typed counterparts of the historical
// map bypasses, plus the consultation's time.After counterexample below.
func TestProfileArchitecture_DetectsInferredMakeChanAssignment(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func bad() {
	work := make(chan request)
	_ = work
}
`})
	sites := collectTypedSites(tp, isChanType, nil)
	requireSiteMentioning(t, sites, "chan synthetic.request", "the inferred `work := make(chan request)` assignment")
}

func TestProfileArchitecture_DetectsInferredVarMakeChanAssignment(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func bad() {
	var work = make(chan request)
	_ = work
}
`})
	sites := collectTypedSites(tp, isChanType, nil)
	requireSiteMentioning(t, sites, "chan synthetic.request", "the inferred `var work = make(chan request)` declaration")
}

func TestProfileArchitecture_DetectsNamedChanTypeAliasField(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

type requestChan chan request

type Server struct {
	work requestChan
}
`})
	sites := collectTypedSites(tp, isChanType, nil)
	requireSiteMentioning(t, sites, "requestChan", "the `work requestChan` named-channel-type field")
}

func TestProfileArchitecture_DetectsFuncResultChanType(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

type request struct{}

func newDone() chan request {
	return make(chan request)
}
`})
	sites := collectTypedSites(tp, isChanType, nil)
	requireSiteMentioning(t, sites, "chan synthetic.request", "newDone's declared channel-typed result")
}

// TestProfileArchitecture_DetectsTimeAfterChannel: the consultation's
// channel-from-a-call counterexample — `stop := time.After(...)` mints a
// channel with no chan syntax and no make() anywhere in the package.
func TestProfileArchitecture_DetectsTimeAfterChannel(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"synthetic.go": `package synthetic

import "time"

func bad() {
	stop := time.After(time.Second)
	_ = stop
}
`})
	sites := collectTypedSites(tp, isChanType, nil)
	requireSiteMentioning(t, sites, "chan time.Time", "the `stop := time.After(...)` channel-producing call")
}

// TestProfileArchitecture_TypeCheckerAllowsAllowlistedMapChanUsage is the
// negative control for invariants 4/6: a package shaped like the real
// server — the three allowlisted fields, their make() initializers inside
// the construction composite literal and via direct assignment, and every
// ordinary read/write of them (index-assign, delete, len, range, receive,
// close) — must produce ZERO sites. This pins down that the allowlist
// covers the field objects, direct references, and initializer expressions,
// so the real-package tests' "no sites" assertion is meaningful rather than
// vacuously strict.
func TestProfileArchitecture_TypeCheckerAllowsAllowlistedMapChanUsage(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"server.go": `package synthetic

import "net"

type Server struct {
	active   map[net.Conn]struct{}
	serveDone chan struct{}
	stopDone  chan struct{}
}

func newServer() *Server {
	return &Server{
		active:    make(map[net.Conn]struct{}),
		serveDone: make(chan struct{}),
		stopDone:  make(chan struct{}),
	}
}

func (s *Server) reset() {
	s.active = make(map[net.Conn]struct{})
}

func (s *Server) use(conn net.Conn) int {
	s.active[conn] = struct{}{}
	delete(s.active, conn)
	for c := range s.active {
		_ = c
	}
	<-s.serveDone
	close(s.stopDone)
	return len(s.active)
}
`})
	allowed := map[types.Object]bool{
		structFieldObj(t, tp, "Server", "active"):    true,
		structFieldObj(t, tp, "Server", "serveDone"): true,
		structFieldObj(t, tp, "Server", "stopDone"):  true,
	}
	if sites := collectTypedSites(tp, isMapType, allowed); len(sites) != 0 {
		t.Fatalf("expected zero map sites for allowlisted-only usage, found %d:\n%s", len(sites), joinTypeSites(sites))
	}
	if sites := collectTypedSites(tp, isChanType, allowed); len(sites) != 0 {
		t.Fatalf("expected zero channel sites for allowlisted-only usage, found %d:\n%s", len(sites), joinTypeSites(sites))
	}
}

// --- synthetic regression proofs: Verify/Roles invariant (12/13) ---

// syntheticVerifierLegit is the shared "legitimate" file for the Verify
// regression proofs: one interface, one carrier struct, one method call —
// mirroring bind.go's real shape.
const syntheticVerifierLegit = `package synthetic

type Verifier interface {
	Verify(x string) error
}

type connection struct {
	verifier Verifier
}

func (c *connection) handleBind() error {
	return c.verifier.Verify("x")
}
`

// syntheticVerifySites type-checks the legit file plus extraFiles as one
// package and returns methodSelectionSites for its Verifier.Verify —
// through the SAME checker the real-package test uses.
func syntheticVerifySites(t *testing.T, extraFiles map[string]string) []string {
	t.Helper()
	files := map[string]string{"bind.go": syntheticVerifierLegit}
	for name, src := range extraFiles {
		files[name] = src
	}
	tp := typecheckSynthetic(t, files)
	iface := lookupInterface(t, tp, "Verifier")
	return methodSelectionSites(tp, iface, "Verify")
}

// requireLegitPlusSneak asserts the legit-only package has exactly one
// Verify site (in bind.go) and the package with the sneaky file has exactly
// two — proving the bypass shape is counted and would trip the real
// "exactly one" invariant.
func requireLegitPlusSneak(t *testing.T, sneaky, desc string) {
	t.Helper()
	legitOnly := syntheticVerifySites(t, nil)
	if len(legitOnly) != 1 || !strings.HasPrefix(legitOnly[0], "bind.go:") {
		t.Fatalf("expected exactly one Verify site (in bind.go) with only the legitimate call present, found %d: %v", len(legitOnly), legitOnly)
	}
	withSneak := syntheticVerifySites(t, map[string]string{"sneaky.go": sneaky})
	if len(withSneak) != 2 {
		t.Fatalf("expected %s in sneaky.go to be counted alongside the legitimate bind.go call (2 total), found %d: %v",
			desc, len(withSneak), withSneak)
	}
}

// TestProfileArchitecture_DetectsVerifyMethodValueExtraction: the pass-2
// bypass — extracting a method value (`verify := o.verifier.Verify`)
// without ever writing a selector-shaped call.
func TestProfileArchitecture_DetectsVerifyMethodValueExtraction(t *testing.T) {
	requireLegitPlusSneak(t, `package synthetic

type other struct {
	verifier Verifier
}

func (o *other) sneak() {
	verify := o.verifier.Verify
	_ = verify
}
`, "the method-value extraction (verify := o.verifier.Verify)")
}

// TestProfileArchitecture_DetectsReceiverAliasVerifyCall: the pass-2/3
// bypass — a one-hop receiver alias (`v := o.verifier; v.Verify(...)`).
func TestProfileArchitecture_DetectsReceiverAliasVerifyCall(t *testing.T) {
	requireLegitPlusSneak(t, `package synthetic

type other struct {
	verifier Verifier
}

func (o *other) sneak() error {
	v := o.verifier
	return v.Verify("y")
}
`, "the receiver-alias call site (v := o.verifier; v.Verify(...))")
}

// TestProfileArchitecture_DetectsTransitiveReceiverAliasVerifyCall: the
// pass-3 bypass — a second-level alias (`v := o.verifier; w := v;
// w.Verify(...)`). Under go/types the receiver's TYPE is what matters, so
// alias depth is irrelevant by construction.
func TestProfileArchitecture_DetectsTransitiveReceiverAliasVerifyCall(t *testing.T) {
	requireLegitPlusSneak(t, `package synthetic

type other struct {
	verifier Verifier
}

func (o *other) sneak() error {
	v := o.verifier
	w := v
	return w.Verify("y")
}
`, "the second-level alias call site (v := o.verifier; w := v; w.Verify(...))")
}

// TestProfileArchitecture_DetectsInterfaceTypedParameterVerifyCall: the
// pass-3 bypass — a helper whose parameter is typed as the interface
// (`func helper(v Verifier) { v.Verify(...) }`, called as
// helper(o.verifier)).
func TestProfileArchitecture_DetectsInterfaceTypedParameterVerifyCall(t *testing.T) {
	requireLegitPlusSneak(t, `package synthetic

type other struct {
	verifier Verifier
}

func helper(v Verifier) error {
	return v.Verify("z")
}

func (o *other) sneak() error {
	return helper(o.verifier)
}
`, "the interface-typed-parameter call site (func helper(v Verifier) { v.Verify(...) })")
}

// TestProfileArchitecture_DetectsCallReceiverVerify: the architecture
// consultation's counterexample — the receiver is itself a call expression
// (`currentVerifier(o).Verify(...)`), which no assignment-based alias
// tracker can resolve but which types.Info.Selections records like any
// other method selection.
func TestProfileArchitecture_DetectsCallReceiverVerify(t *testing.T) {
	requireLegitPlusSneak(t, `package synthetic

type other struct {
	verifier Verifier
}

func currentVerifier(o *other) Verifier {
	return o.verifier
}

func (o *other) sneak() error {
	return currentVerifier(o).Verify("y")
}
`, "the call-expression-receiver site (currentVerifier(o).Verify(...))")
}

// TestProfileArchitecture_DetectsVerifyMethodExpression: a method
// expression (`Verifier.Verify`) — the remaining selection kind
// (types.MethodExpr), which references the method through the TYPE rather
// than a value.
func TestProfileArchitecture_DetectsVerifyMethodExpression(t *testing.T) {
	requireLegitPlusSneak(t, `package synthetic

type other struct {
	verifier Verifier
}

func (o *other) sneak() error {
	f := Verifier.Verify
	return f(o.verifier, "y")
}
`, "the method-expression site (f := Verifier.Verify)")
}

// TestProfileArchitecture_TypeCheckerIgnoresUnrelatedRolesFieldAccess is
// the negative control for invariants 12/13: struct FIELD accesses named
// Roles — the package's own legitimate c.auth.Roles reads and
// newState.Roles writes — are types.FieldVal selections and must not
// count, while the one genuine RoleResolver.Roles method call in the same
// package must. Under go/types this is a kind distinction, not the naming
// heuristic the AST checker needed.
func TestProfileArchitecture_TypeCheckerIgnoresUnrelatedRolesFieldAccess(t *testing.T) {
	tp := typecheckSynthetic(t, map[string]string{"bind.go": `package synthetic

type RoleResolver interface {
	Roles(claims string) []string
}

type authState struct {
	Roles []string
}

type connection struct {
	auth  authState
	roles RoleResolver
}

func (c *connection) bindOnce(claims string) {
	c.auth.Roles = c.roles.Roles(claims)
}

func (c *connection) readSnapshot() []string {
	roles := c.auth.Roles
	return roles
}

func assignField(newState *authState, roles []string) {
	newState.Roles = roles
}
`})
	iface := lookupInterface(t, tp, "RoleResolver")
	sites := methodSelectionSites(tp, iface, "Roles")
	if len(sites) != 1 || !strings.HasPrefix(sites[0], "bind.go:") {
		t.Fatalf("expected exactly one Roles METHOD site (c.roles.Roles) and zero for the c.auth.Roles/newState.Roles field accesses, found %d: %v",
			len(sites), sites)
	}
}
