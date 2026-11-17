package scope_test

// ADR-0056 V56 (stage A4c-1), fixed by reading the sources (the same way as the
// one-door tests of internal/edition): the Hints and Free items of a scope have
// ONE definition, scope.Assemble, and the tests of internal/hintleak call it.
//
//   - TestScopeFunctionsHaveTheExpectedCallers: every call of scope.Assemble and
//     scope.PromptCountProblem in cmd/ and internal/ is one of the sites below.
//     The callers are the tests of internal/hintleak (content_test.go: the real
//     tree, V5 / V6; questionprompt_test.go: the in-memory V24 scopes, which must
//     use the same definition) and the event validator: ADR-0056 A4e-2's
//     internal/edition/checkevent.go (func hintInputs, which CheckEvent calls for
//     B5's Hints and Free) calls both functions, once each.
//   - TestNoSecondAssemblyInHintleakTests: no _test.go under internal/hintleak
//     builds Hints or Free from catalog values by itself (see assemblyProblems).
//     Only the _test.go files of internal/hintleak are scanned; extending the scan
//     to the non-test code of internal/edition and cmd/scoreboard is A4e's.
//   - TestHintleakCoreImportsNoCatalog: internal/hintleak stays a pure function
//     over text; it imports neither the catalog nor this package.
//
// A second definition of "what is free" would be a second place where the answer
// to a hint-leak question could differ from the one a seat's bundle is judged by.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	modulePath         = "github.com/Qfour/falco-ctf-app/"
	scopeImportPath    = modulePath + "internal/hintleak/scope"
	hintleakImportPath = modulePath + "internal/hintleak"
	catalogImportPath  = modulePath + "internal/catalog"
)

// repoRoot is the root of the module as seen from this package's directory
// (internal/hintleak/scope).
var repoRoot = filepath.Join("..", "..", "..")

// goSources reads the .go files under the given directories of the repo (slash
// path from the repo root -> source) that keep accepts. testdata directories are
// not part of the program and are skipped, as the go tool does.
func goSources(t *testing.T, dirs []string, keep func(rel string) bool) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if !keep(rel) {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[rel] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// importName returns the name a file refers to the package at path by ("" when it
// does not import it, or only for its side effects), and whether it is a dot
// import.
func importName(f *ast.File, path string) (name string, dot bool) {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != path {
			continue
		}
		switch {
		case imp.Name == nil:
			return path[strings.LastIndex(path, "/")+1:], false
		case imp.Name.Name == ".":
			return "", true
		case imp.Name.Name == "_":
			return "", false
		default:
			return imp.Name.Name, false
		}
	}
	return "", false
}

// --- callers of the scope functions ----------------------------------------

// scopeGuarded are the functions of this package that define a scope's inputs
// and its count check: only the sites in wantScopeCalls may call them.
var scopeGuarded = []string{"Assemble", "PromptCountProblem"}

// guardedSelector returns e as a selector local.<guarded name>, or nil.
func guardedSelector(e ast.Expr, local string) *ast.SelectorExpr {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != local || !slices.Contains(scopeGuarded, sel.Sel.Name) {
		return nil
	}
	return sel
}

// scopeCalls counts the calls of the guarded functions in the given files (slash
// path -> source) by "name@file (func enclosing function)". A reference that is
// not a call (a function value carried around), a dot import and a file that does
// not parse are problems: only a call expression is a caller.
func scopeCalls(files map[string]string) (counts map[string]int, problems []string) {
	counts = map[string]int{}
	for _, p := range slices.Sorted(maps.Keys(files)) {
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], parser.SkipObjectResolution)
		if err != nil {
			problems = append(problems, p+": does not parse: "+err.Error())
			continue
		}
		local, dot := importName(f, scopeImportPath)
		if dot {
			problems = append(problems, p+": dot import of the scope package")
			continue
		}
		if local == "" {
			continue
		}
		for _, d := range f.Decls {
			fn := ""
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			callee := map[*ast.SelectorExpr]bool{}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if sel := guardedSelector(x.Fun, local); sel != nil {
						callee[sel] = true
						counts[sel.Sel.Name+"@"+p+" (func "+fn+")"]++
					}
				case *ast.SelectorExpr:
					if guardedSelector(x, local) != nil && !callee[x] {
						problems = append(problems, p+" (func "+fn+"): scope."+x.Sel.Name+" is used as a value, not called")
					}
				}
				return true
			})
		}
	}
	return counts, problems
}

// wantScopeCalls is the whole of what may call the scope functions: see the
// header.
var wantScopeCalls = map[string]int{
	"Assemble@internal/edition/checkevent.go (func hintInputs)": 1,

	"PromptCountProblem@internal/edition/checkevent.go (func hintInputs)": 1,

	"Assemble@internal/hintleak/content_test.go (func loadScope)": 1,

	"PromptCountProblem@internal/hintleak/content_test.go (func promptCountProblem)": 1,

	"Assemble@internal/hintleak/questionprompt_test.go (func v24Scope)": 1,

	"Assemble@internal/hintleak/questionprompt_test.go (func TestQuestionPrompts_CountMustMatchTheQuestions)": 1,
}

func TestScopeFunctionsHaveTheExpectedCallers(t *testing.T) {
	files := goSources(t, []string{"cmd", "internal"}, func(string) bool { return true })
	if len(files) < 50 {
		t.Fatalf("read only %d .go files; the walk is not seeing the tree", len(files))
	}
	counts, problems := scopeCalls(files)
	for _, p := range problems {
		t.Error(p)
	}
	// Positive: content_test.go really calls both (V56: the test calls the
	// function of scope). A scan that finds nothing is not a pass.
	if !maps.Equal(counts, wantScopeCalls) {
		t.Errorf("calls of the scope functions = %v, want %v", counts, wantScopeCalls)
	}

	// The scan itself: the allowed shape passes, every other way to reach the
	// functions is seen.
	const imp = "package x\n\nimport \"" + scopeImportPath + "\"\n\n"
	good := map[string]string{
		"a/a.go": imp + "func f() { scope.Assemble() }\n",
		"a/b.go": imp + "func g() { _ = scope.PromptCountProblem() }\n",
	}
	wantGood := map[string]int{"Assemble@a/a.go (func f)": 1, "PromptCountProblem@a/b.go (func g)": 1}
	if c, p := scopeCalls(good); len(p) != 0 || !maps.Equal(c, wantGood) {
		t.Fatalf("the allowed shape: counts %v, problems %v, want %v and none", c, p, wantGood)
	}
	bad := []struct {
		name string
		path string
		src  string
	}{
		{"a call from a non-test file", "cmd/scoreboard/edition.go", imp + "func f() { scope.Assemble() }\n"},
		{"a call from another function of checkevent.go", "internal/edition/checkevent.go", imp + "func g() { scope.Assemble() }\n"},
		{"a second call in hintInputs", "internal/edition/checkevent.go", imp + "func hintInputs() { scope.Assemble(); scope.Assemble() }\n"},
		{"a call from another test", "internal/hintleak/other_test.go", imp + "func f() { scope.Assemble() }\n"},
		{"a call through an alias", "internal/hintleak/other_test.go", "package x\n\nimport sc \"" + scopeImportPath + "\"\n\nfunc f() { sc.Assemble() }\n"},
		{"a second call in a known function", "a/a.go", imp + "func f() { scope.Assemble(); scope.Assemble() }\n"},
		{"the function taken as a value", "a/a.go", imp + "var f = scope.Assemble\n"},
		{"the function taken as a value in a function", "a/a.go", imp + "func g() { f := scope.PromptCountProblem; _ = f }\n"},
		{"a dot import", "a/a.go", "package x\n\nimport . \"" + scopeImportPath + "\"\n"},
		{"a file that does not parse", "a/a.go", "package x\n\nfunc (\n"},
	}
	for _, c := range bad {
		files := maps.Clone(good)
		files[c.path] = c.src
		counts, problems := scopeCalls(files)
		if len(problems) == 0 && maps.Equal(counts, wantGood) {
			t.Errorf("%s: nothing was reported", c.name)
		}
	}
	// A function of the same name on another type is not a caller.
	other := "package x\n\nfunc f(s interface{ Assemble() }) { s.Assemble() }\n"
	if c, p := scopeCalls(map[string]string{"a/c.go": other}); len(p) != 0 || len(c) != 0 {
		t.Errorf("a method call on another type was reported: counts %v, problems %v", c, p)
	}
}

// --- no second definition of Hints / Free in the tests -----------------------

// assemblyProblems reports the places in one _test.go file that build the Hints
// or Free items of a scope from catalog values, which only scope.Assemble may do:
//
//   - R1: `x.Free = append(...)` or `x.Hints = append(...)` where something other
//     than a composite literal of a catalog type is appended (a hintleak.Item
//     literal, a spread of a helper's result, a variable). Appending a
//     catalog.JourneyHint to a journey's own Hints (a mutation helper) is not
//     building a scope.
//   - R2: a hintleak.Input literal whose Hints or Free value is anything but a
//     literal, nil or one(...) (the one-item helper of the synthetic cases): a
//     literal like Input{Free: someHelper(catalog...)} is an assembly too.
//   - R3: a function that returns a hintleak.Input or hintleak.Item and reads the
//     catalog: the shape of a helper that turns catalog values into items (what
//     ruleItems and questionPromptItems were before they moved here).
//
// What is not covered is a plain `x.Free = y` and the synthetic scopes of the
// mutation cases, which are inputs of Check and not an assembly from a catalog.
// The review of internal/hintleak (R1: security-engineer) covers the rest.
func assemblyProblems(file, src string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	hl, hlDot := importName(f, hintleakImportPath)
	cat, _ := importName(f, catalogImportPath)
	inPackage := f.Name.Name == "hintleak" || hlDot

	at := func(n ast.Node) string { return file + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) }

	// isHintleak: e is hintleak.<name> (or the bare name in package hintleak).
	isHintleak := func(e ast.Expr, name string) bool {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			return ok && hl != "" && id.Name == hl && x.Sel.Name == name
		case *ast.Ident:
			return inPackage && x.Name == name
		}
		return false
	}
	// catalogLiteral: e is a composite literal of a type of the catalog package.
	catalogLiteral := func(e ast.Expr) bool {
		cl, ok := e.(*ast.CompositeLit)
		if !ok || cat == "" {
			return false
		}
		sel, ok := cl.Type.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == cat
	}
	inputValueOK := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.CompositeLit:
			return true
		case *ast.Ident:
			return x.Name == "nil"
		case *ast.CallExpr:
			id, ok := x.Fun.(*ast.Ident)
			return ok && id.Name == "one"
		}
		return false
	}
	producesItems := func(ft *ast.FuncType) bool {
		if ft.Results == nil {
			return false
		}
		found := false
		for _, r := range ft.Results.List {
			ast.Inspect(r.Type, func(n ast.Node) bool {
				if e, ok := n.(ast.Expr); ok && (isHintleak(e, "Item") || isHintleak(e, "Input")) {
					found = true
				}
				return true
			})
		}
		return found
	}
	readsCatalog := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && cat != "" && id.Name == cat {
					found = true
				}
			}
			return true
		})
		return found
	}

	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) != 1 || len(x.Rhs) != 1 {
				break
			}
			sel, ok := x.Lhs[0].(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Free" && sel.Sel.Name != "Hints") {
				break
			}
			call, ok := x.Rhs[0].(*ast.CallExpr)
			if !ok {
				break
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "append" {
				break
			}
			clean := !call.Ellipsis.IsValid()
			for _, a := range call.Args[min(1, len(call.Args)):] {
				if !catalogLiteral(a) {
					clean = false
				}
			}
			if !clean {
				out = append(out, at(x)+": append to ."+sel.Sel.Name+" of something that is not a catalog literal (R1: Hints and Free are built by scope.Assemble only)")
			}
		case *ast.CompositeLit:
			if !isHintleak(x.Type, "Input") {
				break
			}
			for _, el := range x.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || (key.Name != "Hints" && key.Name != "Free") {
					continue
				}
				if !inputValueOK(kv.Value) {
					out = append(out, at(kv)+": hintleak.Input."+key.Name+" is set from something that is not a literal, nil or one(...) (R2: Hints and Free are built by scope.Assemble only)")
				}
			}
		case *ast.FuncDecl:
			if producesItems(x.Type) && readsCatalog(x) {
				out = append(out, at(x)+": func "+x.Name.Name+" builds hintleak items from catalog values (R3: that is scope.Assemble's job)")
			}
		case *ast.FuncLit:
			if producesItems(x.Type) && readsCatalog(x) {
				out = append(out, at(x)+": a function literal builds hintleak items from catalog values (R3: that is scope.Assemble's job)")
			}
		}
		return true
	})
	return out, nil
}

func TestNoSecondAssemblyInHintleakTests(t *testing.T) {
	files := goSources(t, []string{"internal/hintleak"}, func(rel string) bool { return strings.HasSuffix(rel, "_test.go") })
	for _, want := range []string{
		"internal/hintleak/content_test.go",
		"internal/hintleak/fixtures_test.go",
		"internal/hintleak/hintleak_test.go",
		"internal/hintleak/questionprompt_test.go",
	} {
		if _, ok := files[want]; !ok {
			t.Fatalf("%s was not scanned (files: %v): a scan that covers nothing is not a pass", want, slices.Sorted(maps.Keys(files)))
		}
	}
	for _, p := range slices.Sorted(maps.Keys(files)) {
		probs, err := assemblyProblems(p, files[p])
		if err != nil {
			t.Errorf("%s: does not parse: %v", p, err)
		}
		for _, v := range probs {
			t.Error(v)
		}
	}

	// The scan itself, against the real definition: scope.go copied into a
	// _test.go (a second definition) is reported by every rule that sees it.
	b, err := os.ReadFile("scope.go")
	if err != nil {
		t.Fatal(err)
	}
	probs, err := assemblyProblems("internal/hintleak/copy_test.go", string(b))
	if err != nil {
		t.Fatal(err)
	}
	var r1, r3 int
	for _, v := range probs {
		switch {
		case strings.Contains(v, "(R1:"):
			r1++
		case strings.Contains(v, "(R3:"):
			r3++
		}
	}
	if r1 == 0 || r3 == 0 {
		t.Errorf("scope.go copied into a _test.go: R1 %d, R3 %d report(s); want both > 0 (the scan does not see a second definition): %v", r1, r3, probs)
	}

	const hdr = "package hintleak_test\n\nimport (\n\t\"" + catalogImportPath + "\"\n\t\"" + hintleakImportPath + "\"\n)\n\n"
	allowed := []struct{ name, src string }{
		{"a mutation helper that appends a catalog hint to a journey", hdr + "func addHint(j *catalog.Journey) { j.Hints = append(j.Hints, catalog.JourneyHint{Kind: \"solution\"}) }\n"},
		{"the synthetic cases", hdr + "func f(fixtures []hintleak.Item) hintleak.Input {\n\treturn hintleak.Input{Hints: one(\"a\", \"b\"), Free: []hintleak.Item{{Source: \"x\"}}, Targets: fixtures}\n}\n"},
		{"nil for Free", hdr + "func f() hintleak.Input { return hintleak.Input{Free: nil} }\n"},
		{"a reader of fixtures (targets, no catalog)", hdr + "func readFixtures() []hintleak.Item {\n\tvar items []hintleak.Item\n\titems = append(items, hintleak.Item{Source: \"s\"})\n\treturn items\n}\n"},
		{"a plain assignment of a filtered Free", hdr + "func f(s *S, kept []hintleak.Item) { s.in.Free = kept }\n"},
		{"a function that reads the catalog and returns something else", hdr + "func f(c catalog.Catalog) []string { return nil }\n"},
	}
	for _, c := range allowed {
		if probs, err := assemblyProblems("internal/hintleak/x_test.go", c.src); err != nil || len(probs) != 0 {
			t.Errorf("%s: reported %v (err %v), want none", c.name, probs, err)
		}
	}
	denied := []struct{ name, src string }{
		{"Free appended with an Item literal", hdr + "func f(in *hintleak.Input, j catalog.Journey) {\n\tin.Free = append(in.Free, hintleak.Item{Source: \"b\", Text: j.Briefing})\n}\n"},
		{"Hints appended with an Item literal", hdr + "func f(in *hintleak.Input, j catalog.Journey) {\n\tin.Hints = append(in.Hints, hintleak.Item{Source: \"b\", Text: j.Title})\n}\n"},
		{"Free appended with the result of a helper", hdr + "func f(in *hintleak.Input) {\n\tin.Free = append(in.Free, helper()...)\n}\n"},
		{"Free appended with a variable", hdr + "func f(in *hintleak.Input, it hintleak.Item) {\n\tin.Free = append(in.Free, it)\n}\n"},
		{"an Input literal whose Free is a helper's result", hdr + "func f() hintleak.Input { return hintleak.Input{Free: ruleItems(\"a\")} }\n"},
		{"an Input literal whose Hints is a variable", hdr + "func f(hs []hintleak.Item) hintleak.Input { return hintleak.Input{Hints: hs} }\n"},
		{"an Input literal through an alias", "package hintleak_test\n\nimport hl \"" + hintleakImportPath + "\"\n\nfunc f(x []hl.Item) hl.Input { return hl.Input{Free: x} }\n"},
		{"an Input literal inside package hintleak", "package hintleak\n\nfunc f(x []Item) Input { return Input{Free: x} }\n"},
		{"a helper that turns catalog values into items", hdr + "func ruleItems(ex catalog.FalcoRuleExcerpt) []hintleak.Item { return nil }\n"},
		{"a function literal that does", hdr + "var g = func(j catalog.Journey) []hintleak.Item { return nil }\n"},
		{"a helper that returns an Input", hdr + "func scopeOf(c catalog.Catalog) hintleak.Input { return hintleak.Input{} }\n"},
	}
	for _, c := range denied {
		if probs, err := assemblyProblems("internal/hintleak/x_test.go", c.src); err != nil || len(probs) == 0 {
			t.Errorf("%s: nothing was reported (err %v)", c.name, err)
		}
	}
}

// --- internal/hintleak stays pure ----------------------------------------------

func TestHintleakCoreImportsNoCatalog(t *testing.T) {
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		n++
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if p == catalogImportPath || p == scopeImportPath || strings.HasPrefix(p, catalogImportPath+"/") {
				t.Errorf("internal/hintleak/%s imports %s: hintleak is a pure function over the text it is given; the assembly from the catalog is in internal/hintleak/scope, which imports hintleak and not the other way round", e.Name(), p)
			}
		}
	}
	if n == 0 {
		t.Fatal("read no non-test file of internal/hintleak: a scan that covers nothing is not a pass")
	}
}
