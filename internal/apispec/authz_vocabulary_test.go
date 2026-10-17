package apispec

// The x-ctf-authz VOCABULARY is a closed set that is declared in three places
// — the Authz constants (route.go), the Routes that use them (non-test code
// under internal/ and cmd/), and the x-ctf-authz values in every
// docs/openapi-*.yaml — and ADR-0034 judgement (c) says a word is only
// allowed to exist if all three agree and something actually uses it. #374
// (app#346) deleted self-or-admin-write and guarded the deletion with a
// tombstone test naming that one word; #376 replaces it with the general
// form here, so the next dead word is caught without anyone having to know
// its name:
//
//	(a) every Authz constant is used by at least one Route in non-test code
//	(b) every x-ctf-authz value in every spec is a declared constant
//	(c) every declared constant appears in some spec (no dead vocabulary)
//	(d) AuthzIdentitySources (app#393) classifies exactly the declared
//	    constants: the table is a fourth place the vocabulary is written, so
//	    it agrees with the other three like they agree with each other
//
// "Declared" is decided by the TYPE CHECKER, not by the spelling of a
// declaration: every const or var whose type is apispec.Authz is found
// whether it is written `const X Authz = "x"`, `const X = Authz("x")`, as an
// implicit repetition inside a const group, as a function-local const, or as a
// var, and whether it sits in internal/apispec or (wrongly) anywhere else
// under internal/ and cmd/. The packages are type-checked from source with
// go/types (module packages recursively, stdlib through the source importer;
// a third-party import is left unresolved, which costs only the expressions
// that mention it). A const outside internal/apispec, and any var, is
// reported: the vocabulary has exactly one home.
//
// plus: the spec files scanned are exactly the ones the mux-owning binaries
// (mux_ownership_test.go) are derived to need, and nothing is scanned empty.
//
// "Used by a Route" in (a) is decided by the type checker too (app#393): a
// composite literal counts only when its type is apispec.Route, so a struct of
// another type with an Authz field (a table row, a helper) cannot keep a dead
// word alive.
//
// What the general form deliberately does NOT do: forbid a word by name. A
// new word that is declared, used by a Route, written in a spec and
// classified is a deliberate, reviewed vocabulary change, not drift.

import (
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// srcLoader type-checks packages from source for the declaration scan. Module
// packages (modulePrefix) are loaded recursively from root; the standard
// library goes through go/importer's "source" importer; anything else (a
// third-party module) is reported as unimportable, which go/types survives
// with a fake package. pre seeds packages by import path (the planted-forms
// tests inject their own apispec stand-in this way).
type srcLoader struct {
	t      *testing.T
	root   string
	fset   *token.FileSet
	std    types.Importer
	pkgs   map[string]*types.Package
	checks map[string]*checkedPkg
}

// checkedPkg is one type-checked package: its files, its type info and the
// type errors the checker reported (non-fatal for packages with third-party
// imports; asserted empty for internal/apispec itself).
type checkedPkg struct {
	pkg   *types.Package
	files []*ast.File
	info  *types.Info
	errs  []error
}

func newSrcLoader(t *testing.T, root string) *srcLoader {
	t.Helper()
	// The "source" importer reads go/build.Default when it imports, and for a
	// cgo package (net) it would run `go tool cgo`, which needs a C toolchain
	// this scan has no use for. The pure-Go variants carry the same exported
	// API, so cgo is switched off for the life of the loader and restored
	// after (no test in this package runs in parallel).
	cgo := build.Default.CgoEnabled
	build.Default.CgoEnabled = false
	t.Cleanup(func() { build.Default.CgoEnabled = cgo })
	fset := token.NewFileSet()
	return &srcLoader{
		t: t, root: root, fset: fset,
		std:    importer.ForCompiler(fset, "source", nil),
		pkgs:   map[string]*types.Package{},
		checks: map[string]*checkedPkg{},
	}
}

func (l *srcLoader) Import(path string) (*types.Package, error) {
	if p, ok := l.pkgs[path]; ok {
		return p, nil
	}
	switch {
	case strings.HasPrefix(path, modulePrefix):
		c := l.checkDir(path, filepath.Join(l.root, filepath.FromSlash(strings.TrimPrefix(path, modulePrefix))))
		return c.pkg, nil
	case !strings.Contains(strings.SplitN(path, "/", 2)[0], "."):
		return l.std.Import(path)
	}
	return nil, os.ErrNotExist // third-party: unresolved on purpose
}

// checkDir parses every non-test .go file in dir (build tags are NOT applied:
// a tagged file must not be a place to hide a declaration) and type-checks
// them as the package path.
func (l *srcLoader) checkDir(path, dir string) *checkedPkg {
	l.t.Helper()
	if c, ok := l.checks[path]; ok {
		return c
	}
	var files []*ast.File
	for _, p := range nonTestGoFiles(l.t, dir) {
		f, err := parser.ParseFile(l.fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			l.t.Fatalf("parse %s: %v", p, err)
		}
		files = append(files, f)
	}
	return l.check(path, files)
}

func (l *srcLoader) check(path string, files []*ast.File) *checkedPkg {
	l.t.Helper()
	c := &checkedPkg{files: files, info: &types.Info{
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
		Types: map[ast.Expr]types.TypeAndValue{},
	}}
	l.checks[path] = c // registered before Check: a module import cycle cannot recurse forever
	conf := types.Config{Importer: l, FakeImportC: true, Error: func(err error) { c.errs = append(c.errs, err) }}
	name := ""
	if len(files) > 0 {
		name = files[0].Name.Name
	}
	c.pkg, _ = conf.Check(path, l.fset, files, c.info)
	if c.pkg == nil {
		c.pkg = types.NewPackage(path, name)
	}
	l.pkgs[path] = c.pkg
	return c
}

// authzType returns the apispec.Authz named type out of the checked apispec
// package. Both a missing type and type errors in the package fail the test:
// the vocabulary home imports only the standard library, so nothing in it may
// be unresolved.
func authzType(t *testing.T, apispec *checkedPkg) *types.Named {
	t.Helper()
	for _, err := range apispec.errs {
		t.Errorf("internal/apispec does not type-check (it imports only the stdlib, so this is a broken scan, not a tolerated gap): %v", err)
	}
	return namedType(t, apispec, "Authz")
}

// namedType returns the defined type name out of the checked apispec package.
func namedType(t *testing.T, apispec *checkedPkg, name string) *types.Named {
	t.Helper()
	obj := apispec.pkg.Scope().Lookup(name)
	tn, ok := obj.(*types.TypeName)
	if !ok {
		t.Fatalf("internal/apispec declares no type %s (found %v) — the declaration scan is broken", name, obj)
	}
	named, ok := tn.Type().(*types.Named)
	if !ok {
		t.Fatalf("apispec.%s is %v, not a defined type", name, tn.Type())
	}
	return named
}

// authzDeclsIn finds, in one type-checked package, every const and var
// declaration (package level or inside a function) whose type is authz. A
// const yields name -> value in consts when home is true (the package is
// internal/apispec); a const anywhere else, and a var anywhere, is reported
// in bad with its position, so a word cannot be minted outside the one file
// that declares the vocabulary.
func authzDeclsIn(c *checkedPkg, fset *token.FileSet, authz *types.Named, home bool) (consts map[string]string, bad []string) {
	consts = map[string]string{}
	for _, f := range c.files {
		ast.Inspect(f, func(n ast.Node) bool {
			gd, ok := n.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				return true
			}
			for _, sp := range gd.Specs {
				for _, name := range sp.(*ast.ValueSpec).Names {
					obj := c.info.Defs[name]
					if obj == nil || !types.Identical(obj.Type(), authz) {
						continue
					}
					where := fset.Position(name.Pos()).String()
					switch o := obj.(type) {
					case *types.Const:
						if !home {
							bad = append(bad, where+": Authz constant "+name.Name+" is declared outside internal/apispec — the vocabulary has one home")
							continue
						}
						if o.Val().Kind() != constant.String {
							bad = append(bad, where+": Authz constant "+name.Name+" is not a string constant")
							continue
						}
						consts[name.Name] = constant.StringVal(o.Val())
					case *types.Var:
						bad = append(bad, where+": var "+name.Name+" has type apispec.Authz — a word is a constant in internal/apispec, never a variable")
					}
				}
			}
			return true
		})
	}
	return consts, bad
}

// authzUsesIn counts, per constant name, the composite literals of type
// apispec.Route in one type-checked package whose Authz field is an
// apispec.Authz constant (resolved by the checker, so an aliased import or a
// bare name inside internal/apispec counts the same). A literal of any other
// type is not a use (app#393: a table row with an Authz field is not a
// Route). Reported in bad, so an unmatched use fails instead of vanishing: a
// Route whose Authz is anything but a constant (a string literal, a
// variable, a call), a Route with positional fields, and a literal with an
// Authz key whose type the checker could not work out (it cannot be shown
// not to be a Route).
func authzUsesIn(c *checkedPkg, fset *token.FileSet, route, authz *types.Named) (uses map[string]int, bad []string) {
	uses = map[string]int{}
	for _, f := range c.files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			where := fset.Position(lit.Pos()).String()
			var value ast.Expr
			positional := false
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					positional = true
					continue
				}
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Authz" {
					value = kv.Value
				}
			}
			typ := c.info.Types[lit].Type
			if typ == nil || typ == types.Typ[types.Invalid] {
				if value != nil {
					bad = append(bad, where+": a literal with an Authz key has no type the checker could work out — it cannot be shown not to be an apispec.Route")
				}
				return true
			}
			if p, ok := typ.(*types.Pointer); ok {
				typ = p.Elem() // an elided &T{} in a []*T is recorded as *T
			}
			if !types.Identical(typ, route) {
				return true
			}
			if positional {
				bad = append(bad, where+": apispec.Route literal with positional fields — its Authz cannot be read")
				return true
			}
			if value == nil {
				return true // no Authz: the empty word fails V3b against the spec
			}
			id, _ := value.(*ast.Ident)
			if sel, ok := value.(*ast.SelectorExpr); ok {
				id = sel.Sel
			}
			if id != nil {
				if k, ok := c.info.Uses[id].(*types.Const); ok && k.Pkg() != nil && k.Pkg().Path() == apispecImportPath && types.Identical(k.Type(), authz) {
					uses[k.Name()]++
					return true
				}
			}
			bad = append(bad, where+": Route Authz is not an apispec.Authz* constant reference")
			return true
		})
	}
	return uses, bad
}

// repoAuthzSources reads the real vocabulary: the constants declared in
// internal/apispec (type-checked), every Authz-typed declaration elsewhere
// under internal/ and cmd/ (all reported in bad), and the Route uses in every
// type-checked package there. parsed is how many files the use scan covered
// and packages how many packages the scans type-checked.
func repoAuthzSources(t *testing.T, root string) (consts map[string]string, uses map[string]int, parsed, packages int, bad []string) {
	t.Helper()
	l := newSrcLoader(t, root)
	apispecDir := filepath.Join(root, "internal", "apispec")
	home := l.checkDir(apispecImportPath, apispecDir)
	authz, route := authzType(t, home), namedType(t, home, "Route")
	consts, b := authzDeclsIn(home, l.fset, authz, true)
	bad = append(bad, b...)
	uses = map[string]int{}
	scanUses := func(c *checkedPkg) {
		u, b := authzUsesIn(c, l.fset, route, authz)
		for k, n := range u {
			uses[k] += n
		}
		bad = append(bad, b...)
		parsed += len(c.files)
		packages++
	}
	scanUses(home)

	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// internal/apispec itself was checked above; its subpackages
				// (specparity, ingressparity) are checked like any other.
				if d.Name() == "testdata" || p == apispecDir || len(nonTestGoFilesIn(p)) == 0 {
					return nil
				}
				rel, _ := filepath.Rel(root, p)
				c := l.checkDir(modulePrefix+filepath.ToSlash(rel), p)
				_, b := authzDeclsIn(c, l.fset, authz, false)
				bad = append(bad, b...)
				scanUses(c)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return consts, uses, parsed, packages, bad
}

// nonTestGoFilesIn is nonTestGoFiles without a *testing.T (a directory that
// cannot be read counts as having none; the walk reports its own errors).
func nonTestGoFilesIn(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if n := e.Name(); !e.IsDir() && strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

// specAuthzValuesInYAML returns value -> operations ("METHOD path") that
// declare it as x-ctf-authz, plus the number of operations seen.
func specAuthzValuesInYAML(t *testing.T, name string, data []byte) (values map[string][]string, ops int) {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	values = map[string][]string{}
	for path, item := range doc.Paths {
		for method, raw := range item {
			op, ok := raw.(map[string]any)
			if !ok {
				continue // parameters:, summary:, $ref ... are not operations
			}
			switch strings.ToUpper(method) {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE":
			default:
				continue
			}
			ops++
			if v, ok := op["x-ctf-authz"].(string); ok {
				values[v] = append(values[v], name+": "+strings.ToUpper(method)+" "+path)
			}
		}
	}
	return values, ops
}

// repoSpecAuthzValues merges the x-ctf-authz values of every docs/openapi-*.yaml.
func repoSpecAuthzValues(t *testing.T, root string) (values map[string][]string, files []string, ops int) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "docs", "openapi-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	values = map[string][]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		v, n := specAuthzValuesInYAML(t, filepath.Base(p), b)
		ops += n
		for k, where := range v {
			values[k] = append(values[k], where...)
		}
		files = append(files, filepath.Base(p))
	}
	sort.Strings(files)
	return values, files, ops
}

// authzVocabularyViolations is the pure comparison (a)-(d); every input is a
// plain map so the mutation tests below can feed it synthetic vocabularies.
// classified is AuthzIdentitySources as word value -> source.
func authzVocabularyViolations(consts map[string]string, uses map[string]int, specValues map[string][]string, classified map[string]string) []string {
	var out []string
	declaredValues := map[string]string{}
	for name, v := range consts {
		declaredValues[v] = name
	}
	for _, name := range sortedKeys(consts) {
		if uses[name] == 0 {
			out = append(out, "(a) apispec."+name+" ("+strconv.Quote(consts[name])+") is used by no Route in non-test code — dead vocabulary")
		}
		if len(specValues[consts[name]]) == 0 {
			out = append(out, "(c) apispec."+name+" ("+strconv.Quote(consts[name])+") appears in no docs/openapi-*.yaml x-ctf-authz — dead vocabulary")
		}
		if _, ok := classified[consts[name]]; !ok {
			out = append(out, "(d) apispec."+name+" ("+strconv.Quote(consts[name])+") has no identity source in AuthzIdentitySources — classify it proven / claimed / none")
		}
	}
	for _, v := range sortedKeys(classified) {
		if _, ok := declaredValues[v]; !ok {
			out = append(out, "(d) AuthzIdentitySources classifies "+strconv.Quote(v)+", which is not a declared Authz constant")
		}
	}
	for _, name := range sortedKeys(uses) {
		if _, ok := consts[name]; !ok {
			out = append(out, "(a) a Route uses apispec."+name+", which is not a declared Authz constant")
		}
	}
	for _, v := range sortedKeys(specValues) {
		if _, ok := declaredValues[v]; !ok {
			out = append(out, "(b) x-ctf-authz: "+strconv.Quote(v)+" is not a declared Authz constant ("+strings.Join(specValues[v], "; ")+")")
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestAuthzVocabulary_ConstantsRoutesAndSpecsAgree runs (a)-(c) on the repo.
func TestAuthzVocabulary_ConstantsRoutesAndSpecsAgree(t *testing.T) {
	root := repoRoot(t)
	consts, uses, parsed, packages, bad := repoAuthzSources(t, root)
	specValues, files, ops := repoSpecAuthzValues(t, root)

	// Fail-closed: an empty scan is "nothing to compare", never "agreement".
	// No count is hard-coded; non-emptiness is the only requirement.
	if len(consts) == 0 {
		t.Fatal("no Authz constant found in internal/apispec — the declaration scan is broken")
	}
	if packages < 2 {
		t.Fatalf("the declaration scan type-checked %d packages — it never left internal/apispec, so it is broken", packages)
	}
	if parsed == 0 || len(uses) == 0 {
		t.Fatalf("parsed %d non-test Go files and found %d distinct Authz constants in Routes — the use scan is broken", parsed, len(uses))
	}
	if len(files) == 0 || ops == 0 || len(specValues) == 0 {
		t.Fatalf("spec scan saw %d files, %d operations, %d distinct x-ctf-authz values — the spec scan is broken", len(files), ops, len(specValues))
	}
	for _, b := range bad {
		t.Error(b)
	}
	classified := map[string]string{}
	for w, src := range AuthzIdentitySources() {
		classified[string(w)] = string(src)
	}
	for _, v := range authzVocabularyViolations(consts, uses, specValues, classified) {
		t.Error(v)
	}
}

// TestAuthzVocabulary_ClassificationReachesEveryServiceRoute pins the links
// that make the per-service wiring enough (app#393): (c) puts every constant
// in a spec; the scanned specs are exactly the mux owners' (the test below);
// every mux owner must run V1 and V3b (each spec operation is a live route
// with the same x-ctf-authz) and the identity-source property on its live
// Routes() (TestParityTestsExistForEverySpec). So every word is on a live
// route that specparity.ClaimedIdentityForwardViolations reads, and that
// property fails a word the table does not classify. Dropping any of the
// three from requiredParityTestFuncs breaks the chain, so it is red here.
func TestAuthzVocabulary_ClassificationReachesEveryServiceRoute(t *testing.T) {
	required := map[string]bool{}
	for _, fn := range requiredParityTestFuncs {
		required[fn] = true
	}
	for _, fn := range []string{
		"TestAPISpec_V1_RouteSetMatchesSpec",
		"TestAPISpec_V3b_StringExtParity",
		"TestAPISpec_ClaimedIdentityImpliesForwardOrInternal",
	} {
		if !required[fn] {
			t.Errorf("requiredParityTestFuncs lost %s: a service could skip it, and a word would no longer be forced through the identity-source table on that service's routes", fn)
		}
	}
}

// TestAuthzVocabulary_ScannedSpecsAreTheMuxOwnersSpecs: the spec set the
// vocabulary scan reads equals the set derived from "which cmd/* binary owns
// an http.ServeMux" (mux_ownership_test.go), so a spec cannot hide from the
// scan by being outside a hand-written list, and the scan is not run on a
// hard-coded number of files.
func TestAuthzVocabulary_ScannedSpecsAreTheMuxOwnersSpecs(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, e := range entries {
		if !e.IsDir() || !cmdOwnsServeMux(t, root, e.Name()) {
			continue
		}
		f, known := specNameForCmd[e.Name()]
		if !known {
			t.Fatalf("cmd/%s owns a ServeMux but has no entry in specNameForCmd", e.Name())
		}
		want = append(want, f)
	}
	sort.Strings(want)
	_, got, _ := repoSpecAuthzValues(t, root)
	if len(want) == 0 {
		t.Fatal("derived no mux-owning binary — the ownership walk is broken")
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("docs/openapi-*.yaml files %v != specs of the mux-owning binaries %v", got, want)
	}
}

// --- the detector is not vacuous: V8 mutations ------------------------------

func baselineVocabulary() (map[string]string, map[string]int, map[string][]string, map[string]string) {
	return map[string]string{"AuthzNone": "none", "AuthzAdmin": "admin"},
		map[string]int{"AuthzNone": 3, "AuthzAdmin": 1},
		map[string][]string{"none": {"s.yaml: GET /healthz"}, "admin": {"s.yaml: POST /api/admin/reset"}},
		map[string]string{"none": "none", "admin": "proven"}
}

func TestAuthzVocabularyDetector_CleanBaselineIsClean(t *testing.T) {
	c, u, s, cl := baselineVocabulary()
	if v := authzVocabularyViolations(c, u, s, cl); len(v) != 0 {
		t.Fatalf("clean baseline flagged: %v", v)
	}
}

// Each mutation must be red and the message must carry its rule letter, so a
// failure names which half of the vocabulary drifted.
func TestAuthzVocabularyDetector_CatchesMutations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(c map[string]string, u map[string]int, s map[string][]string, cl map[string]string)
		want   string
	}{
		{"fictional constant: declared, used by a Route, in no spec", func(c map[string]string, u map[string]int, s map[string][]string, cl map[string]string) {
			c["AuthzGhost"] = "ghost"
			u["AuthzGhost"] = 1
		}, "(c) apispec.AuthzGhost"},
		{"fictional spec value: a spec writes a word no constant declares (the self-or-admin-write shape)", func(c map[string]string, u map[string]int, s map[string][]string, cl map[string]string) {
			s["self-or-admin-write"] = []string{"s.yaml: POST /api/challenges/{cid}/submit-detect"}
		}, "(b) x-ctf-authz: \"self-or-admin-write\""},
		{"unused constant: declared and in a spec, no Route uses it", func(c map[string]string, u map[string]int, s map[string][]string, cl map[string]string) {
			c["AuthzOrphan"] = "orphan"
			s["orphan"] = []string{"s.yaml: GET /x"}
		}, "(a) apispec.AuthzOrphan"},
		{"a Route uses a constant that is not declared", func(c map[string]string, u map[string]int, s map[string][]string, cl map[string]string) {
			u["AuthzUndeclared"] = 1
		}, "(a) a Route uses apispec.AuthzUndeclared"},
		{"unclassified constant: declared, used, in a spec, absent from AuthzIdentitySources", func(c map[string]string, u map[string]int, s map[string][]string, cl map[string]string) {
			c["AuthzFresh"] = "fresh"
			u["AuthzFresh"] = 1
			s["fresh"] = []string{"s.yaml: POST /x"}
		}, "(d) apispec.AuthzFresh"},
		{"the table classifies a word no constant declares", func(c map[string]string, u map[string]int, s map[string][]string, cl map[string]string) {
			cl["phantom"] = "claimed"
		}, "(d) AuthzIdentitySources classifies \"phantom\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, u, s, cl := baselineVocabulary()
			tc.mutate(c, u, s, cl)
			v := authzVocabularyViolations(c, u, s, cl)
			if len(v) == 0 {
				t.Fatalf("mutation not detected")
			}
			if !strings.Contains(strings.Join(v, "\n"), tc.want) {
				t.Fatalf("violations %v do not name %q", v, tc.want)
			}
		})
	}
}

// The extractors themselves: planted source/spec text must be seen, so an
// extractor that silently returns nothing cannot hide behind the empty-scan
// guard alone.
// plantedApispec is a stand-in for internal/apispec that declares the Authz
// type and one word in every form the declaration scan must see.
const plantedApispec = `package apispec

type Authz string

const (
	AuthzA Authz = "a"         // typed, string literal
	AuthzB Authz = "b" + "c"   // computed, still a constant
	AuthzC       = Authz("c")  // conversion form, no declared type
	AuthzD Authz = "d"
	AuthzE                     // implicit repetition of "d"
)

const AuthzF, AuthzG = Authz("f"), Authz("g")

const notAWord = "plain" // an untyped string constant is not vocabulary

func f() {
	const authzLocal Authz = "l" // function-local
	_ = authzLocal
}

var AuthzVar = Authz("v") // a var is never a word

type Route struct {
	Method, Pattern string
	Authz           Authz
}
`

func TestAuthzVocabularyExtractors_SeePlantedForms(t *testing.T) {
	l := newSrcLoader(t, t.TempDir())
	home := l.check(apispecImportPath, []*ast.File{mustParse(t, l.fset, "apispec.go", plantedApispec)})
	authz := authzType(t, home)
	consts, bad := authzDeclsIn(home, l.fset, authz, true)
	want := map[string]string{"AuthzA": "a", "AuthzB": "bc", "AuthzC": "c", "AuthzD": "d", "AuthzE": "d", "AuthzF": "f", "AuthzG": "g", "authzLocal": "l"}
	if !reflect.DeepEqual(consts, want) {
		t.Fatalf("constants = %v, want %v (conversion, group repetition, computed and function-local forms must all be seen; the untyped notAWord must not)", consts, want)
	}
	if len(bad) != 1 || !strings.Contains(bad[0], "var AuthzVar") {
		t.Fatalf("bad = %v, want exactly the AuthzVar var", bad)
	}

	// The same forms OUTSIDE internal/apispec are all violations; a look-alike
	// type named Authz in another package, and plain strings, are not.
	outside := l.check(modulePrefix+"internal/planted", []*ast.File{mustParse(t, l.fset, "planted.go", `package planted

import ap "`+apispecImportPath+`"

type Authz string // not ours

const (
	X ap.Authz = "x"
	Y          = ap.Authz("y")
	A ap.Authz = "a"
	B
)

var V ap.Authz = "v"
var W = ap.Authz("w")

const Lookalike Authz = "l"
const Plain = "p"

func f() { const local ap.Authz = "z"; _ = local }
`)})
	if len(outside.errs) != 0 {
		t.Fatalf("planted package does not type-check: %v", outside.errs)
	}
	_, bad = authzDeclsIn(outside, l.fset, authz, false)
	sort.Strings(bad)
	names := []string{"Authz constant A", "Authz constant B", "Authz constant X", "Authz constant Y", "Authz constant local", "var V", "var W"}
	if len(bad) != len(names) {
		t.Fatalf("bad = %v, want one per %v (and none for Lookalike / Plain)", bad, names)
	}
	for _, n := range names {
		found := false
		for _, b := range bad {
			found = found || strings.Contains(b, n+" ")
		}
		if !found {
			t.Fatalf("no violation names %q in %v", n, bad)
		}
	}

	// The use scan counts Route literals only, by type (app#393 (4)). A
	// look-alike Route in another module package resolves and is not ours.
	route := namedType(t, home, "Route")
	l.check(modulePrefix+"internal/lookalike", []*ast.File{mustParse(t, l.fset, "lookalike.go", "package lookalike\n\ntype Route struct{ Authz string }\n")})
	used := l.check(modulePrefix+"internal/planteduse", []*ast.File{mustParse(t, l.fset, "use.go", `package p

import (
	ap "`+apispecImportPath+`"
	"`+modulePrefix+`internal/lookalike"
	foreign "example.com/other/apispec"
)

type row struct{ Authz ap.Authz } // has an Authz field, is not a Route
type R = ap.Route                 // an alias is the same type

var _ = []ap.Route{{Authz: ap.AuthzA}, {Authz: ap.AuthzA}, {Authz: "none"}}
var _ = []*R{{Authz: ap.AuthzB}}
var _ = []row{{Authz: ap.AuthzC}}
var _ = map[ap.Authz]int{ap.AuthzD: 1}
var _ = lookalike.Route{Authz: "x"}
var _ = ap.Route{"GET", "/p", ap.AuthzF}
var _ = foreign.Route{Authz: foreign.AuthzG}
`)})
	uses, bad := authzUsesIn(used, l.fset, route, authz)
	if !reflect.DeepEqual(uses, map[string]int{"AuthzA": 2, "AuthzB": 1}) {
		t.Fatalf("uses = %v, want AuthzA x2 (through the alias import) and AuthzB x1 (through the type alias); the row struct, the map key, the look-alike and the positional literal are not uses", uses)
	}
	sort.Strings(bad)
	if len(bad) != 3 || !strings.Contains(bad[0], "is not an apispec.Authz* constant") ||
		!strings.Contains(bad[1], "positional fields") || !strings.Contains(bad[2], "no type the checker could work out") {
		t.Fatalf("bad = %v, want the string-literal Authz, the positional Route and the unresolvable foreign literal", bad)
	}

	vals, ops := specAuthzValuesInYAML(t, "p.yaml", []byte(`paths:
  /a:
    parameters: []
    get:
      x-ctf-authz: none
    post:
      x-ctf-authz: admin
  /b:
    get:
      summary: no authz key
`))
	if ops != 3 || len(vals["none"]) != 1 || len(vals["admin"]) != 1 || len(vals) != 2 {
		t.Fatalf("ops=%d vals=%v: want 3 operations and none/admin once each", ops, vals)
	}
}

func mustParse(t *testing.T, fset *token.FileSet, name, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return f
}
