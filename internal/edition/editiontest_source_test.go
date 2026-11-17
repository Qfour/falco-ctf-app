package edition_test

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

// ADR-0056 D19 A4e-2d and V91, fixed by reading the sources (the way render_reach_test.go and
// load_source_test.go fix the doors): internal/edition/editiontest is the positive fixture of
// the event-edition commands, shared by the tests of internal/edition and of cmd/scoreboard
// (and, from A4e-3, by the round trip of `edition render`). The rules:
//
//   - no non-test Go file of the module imports it: it is a test support package, and a binary
//     that linked it would carry a fixture for nothing;
//   - the _test.go files that import it include one of cmd/scoreboard and one of
//     internal/edition (0 of either is red: a support package nobody shares is the copy this
//     step removed);
//   - no file of the package names anything the renderer declares (every function, type, constant
//     and variable the render files of internal/edition declare, exported or not: the set
//     render_reach_test.go's renderDeclarations reads from the source, so a name added to the
//     renderer is covered without an edit here), as a call or as a value; and it has no function
//     type except a declaration's own and a literal's, so no renderer function can be handed to it
//     as a value either (a parameter, a result, a field or a type of a function). The renderer
//     is called by the _test.go file of each test package, and that is all V78's closed list
//     (renderCallers, which this step does not change) is about.
//
// That a fixture built with it is accepted is not tested again here: the two accepting cases
// are TestCheckEvent_AcceptsAnEventThatEveryCheckAccepts (CheckEvent accepts the event) and
// cmd/scoreboard's TestEditionCheck_Accepts (`edition check` exits 0 with it), and both build
// their event with the package.

const (
	editiontestImportPath = editionImportPath + "/editiontest"
	editiontestDir        = "internal/edition/editiontest/"
)

// testSources reads every _test.go file of cmd/ and internal/ (slash path from the repo root ->
// source), except what is under a testdata directory (the go tool does not build it).
func testSources(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, root := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join("..", "..", root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(filepath.Join("..", ".."), path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 50 {
		t.Fatalf("read only %d test files; the walk is not seeing the tree", len(files))
	}
	return files
}

// editiontestImporters lists the files (slash path -> source) that import the support package,
// under any name (a dot import and a blank import too), and the files that do not parse.
func editiontestImporters(files map[string]string) (importers, problems []string) {
	for _, p := range slices.Sorted(maps.Keys(files)) {
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], parser.ImportsOnly)
		if err != nil {
			problems = append(problems, p+": does not parse: "+err.Error())
			continue
		}
		for _, imp := range f.Imports {
			if path, err := strconv.Unquote(imp.Path.Value); err == nil && path == editiontestImportPath {
				importers = append(importers, p)
				break
			}
		}
	}
	return importers, problems
}

// editiontestImportViolations judges who imports the support package: nonTest are the non-test
// files and tests the _test.go files (slash path -> source).
func editiontestImportViolations(nonTest, tests map[string]string) []string {
	var out []string
	imp, problems := editiontestImporters(nonTest)
	out = append(out, problems...)
	for _, p := range imp {
		out = append(out, p+": a non-test Go file imports editiontest, the test support package")
	}
	timp, tproblems := editiontestImporters(tests)
	out = append(out, tproblems...)
	inCmd, inEdition := 0, 0
	for _, p := range timp {
		switch {
		case strings.HasPrefix(p, "cmd/scoreboard/"):
			inCmd++
		case isEditionPackageFile(p):
			inEdition++
		}
	}
	if inCmd == 0 {
		out = append(out, "no _test.go file of cmd/scoreboard imports editiontest: a support package that one test package alone uses is not shared")
	}
	if inEdition == 0 {
		out = append(out, "no _test.go file of internal/edition imports editiontest: a support package that one test package alone uses is not shared")
	}
	return out
}

func TestEditiontestIsImportedFromTestFilesOfBothPackagesOnly(t *testing.T) {
	nonTest, tests := nonTestSources(t), testSources(t)
	for _, v := range editiontestImportViolations(nonTest, tests) {
		t.Error(v)
	}
	// Positive: the importers are there (the violations above already say so for the two
	// packages; this is the count itself), and the package's own files are read.
	if imp, _ := editiontestImporters(tests); len(imp) < 2 {
		t.Errorf("%d _test.go files import editiontest, want at least 2: %v", len(imp), imp)
	}
	n := 0
	for p := range nonTest {
		if strings.HasPrefix(p, editiontestDir) {
			n++
		}
	}
	if n == 0 {
		t.Errorf("no non-test file under %s: the scan does not see the package", editiontestDir)
	}

	// The scan itself: the allowed shape is clean, and every way to break a rule is seen.
	const imp = "package x\n\nimport \"" + editiontestImportPath + "\"\n"
	goodTests := map[string]string{"cmd/scoreboard/a_test.go": imp, "internal/edition/b_test.go": imp}
	goodNonTest := map[string]string{"cmd/scoreboard/main.go": "package main\n", editiontestDir + "editiontest.go": "package editiontest\n"}
	if v := editiontestImportViolations(goodNonTest, goodTests); len(v) != 0 {
		t.Fatalf("the allowed shape was reported: %v", v)
	}
	nonTestCases := []struct{ name, path, src string }{
		{"a binary", "cmd/scoreboard/main.go", imp},
		{"a package of the server", "internal/scoreboard/x.go", imp},
		{"an alias", "internal/scoreboard/x.go", "package x\n\nimport et \"" + editiontestImportPath + "\"\n"},
		{"a dot import", "internal/scoreboard/x.go", "package x\n\nimport . \"" + editiontestImportPath + "\"\n"},
		{"a blank import", "internal/scoreboard/x.go", "package x\n\nimport _ \"" + editiontestImportPath + "\"\n"},
		{"a grouped import", "internal/scoreboard/x.go", "package x\n\nimport (\n\t\"fmt\"\n\t\"" + editiontestImportPath + "\"\n)\n"},
		{"a file that does not parse", "internal/scoreboard/x.go", "package x\n\nimport (\n"},
	}
	for _, c := range nonTestCases {
		files := rdCopyFiles(goodNonTest)
		files[c.path] = c.src
		if v := editiontestImportViolations(files, goodTests); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	testCases := []struct {
		name  string
		tests map[string]string
	}{
		{"no test file imports it", map[string]string{"cmd/scoreboard/a_test.go": "package main\n"}},
		{"only a test of cmd/scoreboard", map[string]string{"cmd/scoreboard/a_test.go": imp}},
		{"only a test of internal/edition", map[string]string{"internal/edition/b_test.go": imp}},
		{"a test of another package and one of internal/edition", map[string]string{"internal/scoreboard/c_test.go": imp, "internal/edition/b_test.go": imp}},
		{"a test file of a subdirectory of internal/edition and one of cmd/scoreboard", map[string]string{"internal/edition/sub/b_test.go": imp, "cmd/scoreboard/a_test.go": imp}},
		{"a test file that does not parse", map[string]string{"cmd/scoreboard/a_test.go": imp, "internal/edition/b_test.go": imp, "internal/edition/c_test.go": "package x\n\nimport (\n"}},
	}
	for _, c := range testCases {
		if v := editiontestImportViolations(goodNonTest, c.tests); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
}

// editiontestBanned is every name the render files declare: the exported functions, types,
// constants and variables, and the unexported functions.
func editiontestBanned(t *testing.T, files map[string]string) map[string]bool {
	t.Helper()
	exported, unexported := renderDeclarations(t, files)
	banned := map[string]bool{}
	maps.Copy(banned, exported)
	maps.Copy(banned, unexported)
	return banned
}

// editiontestViolations lists, in the source of one file of the support package (path p), every
// identifier that is a name the renderer declares, and every function type that is neither the
// type of a function declaration nor of a function literal: a parameter, a result, a field, a
// variable or a type of a function type, through which a function value comes in. idents is how
// many identifiers the file has (the positive side: a scan that reads nothing is not a pass).
func editiontestViolations(p, src string, banned map[string]bool) (out []string, idents int) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, p, src, 0)
	if err != nil {
		return []string{p + ": does not parse: " + err.Error()}, 0
	}
	own := map[*ast.FuncType]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			own[x.Type] = true
		case *ast.FuncLit:
			own[x.Type] = true
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			idents++
			if banned[x.Name] {
				out = append(out, p+":"+strconv.Itoa(fset.Position(x.Pos()).Line)+": names "+x.Name+", which the renderer declares")
			}
		case *ast.FuncType:
			if !own[x] {
				out = append(out, p+":"+strconv.Itoa(fset.Position(x.Pos()).Line)+": a function type that is not a declaration's or a literal's: a function value (the renderer's) could be handed in through it")
			}
		}
		return true
	})
	return out, idents
}

func TestEditiontestNamesNothingTheRendererDeclaresAndTakesNoFunction(t *testing.T) {
	all := nonTestSources(t)
	banned := editiontestBanned(t, all)
	// Positive: the set is the renderer's. A set that holds nothing is not a pass.
	for _, name := range []string{"Render", "RenderPractice", "WriteAnswers", "WriteRenderRecord", "RenderInput", "NewMasterKey", "MasterKey", "render"} {
		if !banned[name] {
			t.Errorf("the render files do not declare %s: the scan does not see the renderer", name)
		}
	}
	// The package's files: the non-test files, and a _test.go file of the package if there ever
	// is one.
	files := map[string]string{}
	for p, src := range all {
		if strings.HasPrefix(p, editiontestDir) {
			files[p] = src
		}
	}
	for p, src := range testSources(t) {
		if strings.HasPrefix(p, editiontestDir) {
			files[p] = src
		}
	}
	if len(files) == 0 {
		t.Fatalf("no file under %s: the scan does not see the package", editiontestDir)
	}
	total := 0
	for _, p := range slices.Sorted(maps.Keys(files)) {
		v, n := editiontestViolations(p, files[p], banned)
		total += n
		for _, line := range v {
			t.Error(line)
		}
	}
	if total < 100 {
		t.Errorf("the package has %d identifiers, want at least 100: the scan does not read it", total)
	}

	// The scan itself: the allowed shape is clean, and every way to reach the renderer is seen.
	const head = "package editiontest\n\nimport \"" + editionImportPath + "\"\n\n"
	const allowed = head + "var _ = edition.SpecFileName\n\n// Render is a word in a comment.\nfunc Place(dir string) string {\n\tg := func(p string) string { return p }\n\treturn g(dir) + \"Render\"\n}\n"
	if v, n := editiontestViolations(editiontestDir+"x.go", allowed, banned); len(v) != 0 || n == 0 {
		t.Fatalf("the allowed shape: %v (%d identifiers)", v, n)
	}
	cases := []struct{ name, src string }{
		{"a call of the renderer", head + "func f() { edition.Render(edition.RenderInput{}) }\n"},
		{"a call through an alias", "package editiontest\n\nimport ed \"" + editionImportPath + "\"\n\nfunc f() { ed.RenderPractice() }\n"},
		{"the writer of the answers table", head + "func f() { edition.WriteAnswers(nil, \"\", nil) }\n"},
		{"the writer of the render record", head + "func f() { edition.WriteRenderRecord(nil, \"\", edition.MasterKey{}) }\n"},
		{"a renderer function as a value", head + "var f = edition.PracticeOutput\n"},
		{"a type the renderer declares", head + "var in edition.RenderInput\n"},
		{"the key's constructor", head + "func f() { _, _ = edition.NewMasterKey(nil) }\n"},
		{"a dot import and a bare call", "package editiontest\n\nimport . \"" + editionImportPath + "\"\n\nfunc f() { Render() }\n"},
		{"an unexported function of the renderer declared here", "package editiontest\n\nfunc render() {}\n"},
		{"an unexported function of the renderer called here", "package editiontest\n\nfunc f() { drawSeat() }\n"},
		{"a function as a parameter", "package editiontest\n\nfunc Place(run func() error) {}\n"},
		{"a function as a result", "package editiontest\n\nfunc Make() func() { return nil }\n"},
		{"a function as a field", "package editiontest\n\ntype T struct{ Run func() }\n"},
		{"a function type", "package editiontest\n\ntype Run func()\n"},
		{"a function as a variable", "package editiontest\n\nvar run func()\n"},
		{"a method in an interface", "package editiontest\n\ntype R interface{ Do() }\n"},
		{"a file that does not parse", "package editiontest\n\nfunc ("},
	}
	for _, c := range cases {
		if v, _ := editiontestViolations(editiontestDir+"x.go", c.src, banned); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
}
