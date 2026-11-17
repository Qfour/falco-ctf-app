package catalog_test

// ADR-0056 V89 (A4e-2c), fixed by reading the sources (the same way as the one-door tests of
// internal/edition and internal/hintleak/scope). The target is the code that applies the
// scenario's narrative overrides to the journeys, which the server shows and B5 checks: the
// read of the overrides (LoadNarrative) and their application (ApplyNarrativeOverrides).
//
//   - Both are called by catalog.LoadHintInputs (internal/catalog/hintinputs.go), once each,
//     and by nothing else in the module: no non-test file and no _test.go (cmd/ and internal/,
//     testdata skipped) has a second application. A reference that is not a call (a function
//     value carried around) and a dot import of the catalog are violations too.
//   - The one exception is the unit tests of the two functions themselves, in
//     internal/catalog/narrative_test.go: a test function named TestApplyNarrativeOverrides_*
//     may call ApplyNarrativeOverrides, and one named TestLoadNarrative_* may call
//     LoadNarrative. Neither may call the other function, so a test that reads a narrative and
//     applies it (a replay of the wiring) is a violation wherever it is.
//   - LoadHintInputs is called, among its callers, by the scoreboard's start-up
//     (cmd/scoreboard/main.go, func main), the validator (internal/edition/checkevent.go, func
//     hintInputs) and the hint-leak tests (internal/hintleak/content_test.go, func loadScope).
//     An extraction that finds none of them is red, and so is one that misses any.
//   - Those three files do not call LoadJourneys or LoadRuleExcerpts themselves: the journeys
//     and the rule excerpts they show or check are LoadHintInputs's result.
//
// Out of the target (ADR-0056 V89): the callers that use LoadJourneys or LoadRuleExcerpts alone,
// with no override, and build neither the display nor B5's inputs (internal/e2e/harness/seed.go,
// cmd/scoreboard/investigate_boot_test.go, internal/homefragments/manifest_verified_test.go,
// internal/scoreboard/journey_hint_gate_test.go). They are not scanned for LoadJourneys.

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

const hiCatalogImport = "github.com/Qfour/falco-ctf-app/internal/catalog"

const (
	hiReaderFile   = "internal/catalog/hintinputs.go"
	hiReaderFunc   = "LoadHintInputs"
	hiUnitTestFile = "internal/catalog/narrative_test.go"
)

// hiApplyNames are the two functions that read and apply the overrides.
var hiApplyNames = []string{"LoadNarrative", "ApplyNarrativeOverrides"}

// hiUnitTestPrefix is, for each of hiApplyNames, the prefix of the names of its own unit tests.
var hiUnitTestPrefix = map[string]string{
	"LoadNarrative":           "TestLoadNarrative_",
	"ApplyNarrativeOverrides": "TestApplyNarrativeOverrides_",
}

// hiRequiredCallers are the callers of LoadHintInputs that must be there (V89).
var hiRequiredCallers = []string{
	"cmd/scoreboard/main.go (func main)",
	"internal/edition/checkevent.go (func hintInputs)",
	"internal/hintleak/content_test.go (func loadScope)",
}

// hiShownFiles are the files whose journeys and rule excerpts must come from LoadHintInputs.
var hiShownFiles = []string{"cmd/scoreboard/main.go", "internal/edition/checkevent.go", "internal/hintleak/content_test.go"}

// hiSources reads every .go file (tests included) under cmd/ and internal/ of the module,
// slash path from the repo root -> source; testdata directories are skipped, as the go tool
// skips them.
func hiSources(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	files := map[string]string{}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
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
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
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
	if len(files) < 100 {
		t.Fatalf("read only %d .go files; the walk is not seeing the tree", len(files))
	}
	return files
}

// hiUse is one reference to a name of the catalog: the file, the enclosing function ("" outside
// any), the name, and whether it is the function of a call expression.
type hiUse struct {
	file string
	fn   string
	name string
	call bool
}

// hiUses lists the references in one file to the names given: qualified ones (through whatever
// name the file imports the catalog under) and, in a file of package catalog under
// internal/catalog/ (its non-test files and its internal tests), bare ones. A dot import of the
// catalog is reported as a use (not a call) of every name.
func hiUses(file, src string, names []string) ([]hiUse, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	inPackage := f.Name.Name == "catalog" && strings.HasPrefix(file, "internal/catalog/") && !strings.Contains(strings.TrimPrefix(file, "internal/catalog/"), "/")
	local := ""
	var uses []hiUse
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != hiCatalogImport {
			continue
		}
		switch {
		case imp.Name == nil:
			local = "catalog"
		case imp.Name.Name == ".":
			for _, n := range names {
				uses = append(uses, hiUse{file: file, name: n})
			}
		case imp.Name.Name != "_":
			local = imp.Name.Name
		}
	}
	fn := ""
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			name := ""
			switch fun := x.Fun.(type) {
			case *ast.SelectorExpr:
				if id, ok := fun.X.(*ast.Ident); ok && local != "" && id.Name == local && slices.Contains(names, fun.Sel.Name) {
					name = fun.Sel.Name
				}
			case *ast.Ident:
				if inPackage && slices.Contains(names, fun.Name) {
					name = fun.Name
				}
			}
			if name == "" {
				return true
			}
			uses = append(uses, hiUse{file: file, fn: fn, name: name, call: true})
			for _, a := range x.Args {
				ast.Inspect(a, visit)
			}
			return false
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && slices.Contains(names, x.Sel.Name) {
				uses = append(uses, hiUse{file: file, fn: fn, name: x.Sel.Name})
			}
			// The Sel of a selector is a field or a method, not a bare name of the package.
			ast.Inspect(x.X, visit)
			return false
		case *ast.Ident:
			if inPackage && slices.Contains(names, x.Name) {
				uses = append(uses, hiUse{file: file, fn: fn, name: x.Name})
			}
		}
		return true
	}
	for _, d := range f.Decls {
		fn = ""
		if fd, ok := d.(*ast.FuncDecl); ok {
			// The body only: the declared name (func LoadNarrative) is not a use of it.
			fn = fd.Name.Name
			if fd.Body != nil {
				ast.Inspect(fd.Body, visit)
			}
			continue
		}
		ast.Inspect(d, visit)
	}
	return uses, nil
}

// hiResult is what the scan found: the violations, the calls of the two applying functions by
// LoadHintInputs ("name@LoadHintInputs"), the calls by their unit tests, and the callers of
// LoadHintInputs ("file (func fn)").
type hiResult struct {
	violations []string
	reader     map[string]int
	unitTests  int
	callers    map[string]int
}

// hiScan judges the files (slash path -> source) against the rule of the header.
func hiScan(files map[string]string) hiResult {
	r := hiResult{reader: map[string]int{}, callers: map[string]int{}}
	names := append(slices.Clone(hiApplyNames), hiReaderFunc, "LoadJourneys", "LoadRuleExcerpts")
	for _, p := range slices.Sorted(maps.Keys(files)) {
		uses, err := hiUses(p, files[p], names)
		if err != nil {
			r.violations = append(r.violations, p+": does not parse: "+err.Error())
			continue
		}
		for _, u := range uses {
			where := p
			if u.fn != "" {
				where += " (func " + u.fn + ")"
			}
			switch u.name {
			case "LoadNarrative", "ApplyNarrativeOverrides":
				switch {
				case !u.call:
					r.violations = append(r.violations, where+": "+u.name+" is used as a value, not called (the overrides are applied by LoadHintInputs only)")
				case p == hiReaderFile && u.fn == hiReaderFunc:
					r.reader[u.name+"@"+hiReaderFunc]++
				case p == hiUnitTestFile && strings.HasPrefix(u.fn, hiUnitTestPrefix[u.name]):
					r.unitTests++
				default:
					r.violations = append(r.violations, where+": calls "+u.name+"; the narrative overrides are read and applied by catalog.LoadHintInputs only (ADR-0056 V89), and a unit test of one of the two may call that one only")
				}
			case hiReaderFunc:
				if !u.call {
					r.violations = append(r.violations, where+": LoadHintInputs is used as a value, not called")
					continue
				}
				r.callers[where]++
			case "LoadJourneys", "LoadRuleExcerpts":
				if slices.Contains(hiShownFiles, p) {
					r.violations = append(r.violations, where+": uses "+u.name+" itself; the journeys and the rule excerpts it shows or checks are LoadHintInputs's result (ADR-0056 V89)")
				}
			}
		}
	}
	for _, n := range hiApplyNames {
		if c := r.reader[n+"@"+hiReaderFunc]; c != 1 {
			r.violations = append(r.violations, hiReaderFile+": LoadHintInputs calls "+n+" "+strconv.Itoa(c)+" time(s), want exactly 1")
		}
	}
	if len(r.callers) == 0 {
		r.violations = append(r.violations, "no caller of LoadHintInputs was found: an extraction that finds nothing is not a pass")
	}
	for _, want := range hiRequiredCallers {
		if r.callers[want] == 0 {
			r.violations = append(r.violations, want+" does not call catalog.LoadHintInputs (V89: the start-up, the validator and the hint-leak tests read the hint inputs through it)")
		}
	}
	return r
}

func TestNarrativeOverridesAreAppliedByLoadHintInputsOnly(t *testing.T) {
	files := hiSources(t)
	r := hiScan(files)
	for _, v := range r.violations {
		t.Error(v)
	}
	// Positive: the reader applies, once, and the three callers are there (checked in hiScan);
	// the unit tests of narrative.go are seen too, so the exception is not empty by accident.
	if r.unitTests == 0 {
		t.Errorf("no unit test of LoadNarrative or ApplyNarrativeOverrides was found in %s: the scan does not see that file", hiUnitTestFile)
	}

	// The scan against copies of the real files, one change each.
	mutate := func(path, old, repl string) map[string]string {
		t.Helper()
		src, ok := files[path]
		if !ok {
			t.Fatalf("%s is not there", path)
		}
		if strings.Count(src, old) != 1 {
			t.Fatalf("%s: %q occurs %d time(s), want 1", path, old, strings.Count(src, old))
		}
		out := maps.Clone(files)
		out[path] = strings.Replace(src, old, repl, 1)
		return out
	}
	realCases := []struct{ name, path, old, repl string }{
		{"the validator reads the journeys itself", "internal/edition/checkevent.go", "catalog.LoadHintInputs(", "catalog.LoadJourneys("},
		{"the start-up reads the journeys itself", "cmd/scoreboard/main.go", "catalog.LoadHintInputs(", "catalog.LoadJourneys("},
		{"the hint-leak tests read the journeys themselves", "internal/hintleak/content_test.go", "catalog.LoadHintInputs(", "catalog.LoadJourneys("},
		{"the reader does not apply the overrides", hiReaderFile, "ApplyNarrativeOverrides(journeys, narrative)", "error(nil)"},
		{"the reader does not read the narrative", hiReaderFile, "LoadNarrative(out.NarrativeFile)", "Narrative{}, error(nil)"},
	}
	for _, c := range realCases {
		if v := hiScan(mutate(c.path, c.old, c.repl)).violations; len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	// The real reader copied into another file of the package: a second application.
	second := maps.Clone(files)
	second["internal/catalog/second.go"] = files[hiReaderFile]
	if v := hiScan(second).violations; len(v) == 0 {
		t.Error("the reader copied into another file: no violation was reported")
	}
}

// The scan itself on small sources: the allowed shape passes, and every other way to apply the
// overrides, or to show the journeys without the reader, is seen.
func TestNarrativeOverridesScan_SeesAViolation(t *testing.T) {
	const imp = "import \"" + hiCatalogImport + "\"\n\n"
	const readerSrc = "package catalog\n\n" +
		"func LoadHintInputs(dir, sc string, cat Catalog) (HintInputs, error) {\n" +
		"\tj, _ := LoadJourneys(dir, cat)\n\tn, _ := LoadNarrative(sc)\n\t_ = ApplyNarrativeOverrides(j, n)\n\t_, _ = LoadRuleExcerpts(dir, cat)\n\treturn HintInputs{}, nil\n}\n"
	const mainSrc = "package main\n\n" + imp + "func main() {\n\t_, _ = catalog.LoadHintInputs(\"\", \"\", nil)\n}\n"
	const eventSrc = "package edition\n\n" + imp + "func hintInputs() {\n\t_, _ = catalog.LoadHintInputs(\"\", \"\", nil)\n}\n"
	const contentSrc = "package hintleak_test\n\n" + imp + "func loadScope() {\n\t_, _ = catalog.LoadHintInputs(\"\", \"\", nil)\n}\n"
	const unitSrc = "package catalog_test\n\n" + imp +
		"func TestApplyNarrativeOverrides_X(t *T) { _ = catalog.ApplyNarrativeOverrides(nil, catalog.Narrative{}) }\n\n" +
		"func TestLoadNarrative_X(t *T) { _, _ = catalog.LoadNarrative(\"\") }\n"
	good := map[string]string{}
	good[hiReaderFile] = readerSrc
	good["cmd/scoreboard/main.go"] = mainSrc
	good["internal/edition/checkevent.go"] = eventSrc
	good["internal/hintleak/content_test.go"] = contentSrc
	good[hiUnitTestFile] = unitSrc
	// out of the target: a caller of LoadJourneys alone
	good["internal/e2e/harness/seed.go"] = "package harness\n\n" + imp + "func seed() { _, _ = catalog.LoadJourneys(\"\", nil) }\n"
	if r := hiScan(good); len(r.violations) != 0 || r.unitTests != 2 {
		t.Fatalf("the allowed shape: violations %v, unit tests %d; want none and 2", r.violations, r.unitTests)
	}

	cases := []struct{ name, path, src string }{
		{"the start-up applies the overrides itself (the old shape)", "cmd/scoreboard/main.go", "package main\n\n" + imp +
			"func main() {\n\t_, _ = catalog.LoadHintInputs(\"\", \"\", nil)\n\tn, _ := catalog.LoadNarrative(\"\")\n\t_ = catalog.ApplyNarrativeOverrides(nil, n)\n}\n"},
		{"the validator reads the narrative itself", "internal/edition/checkevent.go", "package edition\n\n" + imp +
			"func hintInputs() {\n\t_, _ = catalog.LoadHintInputs(\"\", \"\", nil)\n\t_, _ = catalog.LoadNarrative(\"\")\n}\n"},
		{"a test that replays the wiring", hiUnitTestFile, unitSrc +
			"\nfunc TestNimbus(t *T) {\n\tn, _ := catalog.LoadNarrative(\"\")\n\t_ = catalog.ApplyNarrativeOverrides(nil, n)\n}\n"},
		{"a unit test of ApplyNarrativeOverrides that also reads a narrative", hiUnitTestFile, unitSrc +
			"\nfunc TestApplyNarrativeOverrides_Y(t *T) {\n\tn, _ := catalog.LoadNarrative(\"\")\n\t_ = catalog.ApplyNarrativeOverrides(nil, n)\n}\n"},
		{"a unit test named for the function in another file", "internal/catalog/other_test.go", "package catalog_test\n\n" + imp +
			"func TestApplyNarrativeOverrides_Z(t *T) { _ = catalog.ApplyNarrativeOverrides(nil, catalog.Narrative{}) }\n"},
		{"a second applier in the package", "internal/catalog/other.go", "package catalog\n\nfunc other(j Journeys) { _ = ApplyNarrativeOverrides(j, Narrative{}) }\n"},
		{"an internal test of the package that applies", "internal/catalog/x_internal_test.go", "package catalog\n\nfunc TestFoo(t *T) { _ = ApplyNarrativeOverrides(nil, Narrative{}) }\n"},
		{"the reader defined in another file", "internal/catalog/other.go", "package catalog\n\nfunc LoadHintInputs() { _, _ = LoadNarrative(\"\") }\n"},
		{"the reader applies twice", hiReaderFile, strings.Replace(readerSrc, "\t_ = ApplyNarrativeOverrides(j, n)\n", "\t_ = ApplyNarrativeOverrides(j, n)\n\t_ = ApplyNarrativeOverrides(j, n)\n", 1)},
		{"the reader does not apply", hiReaderFile, strings.Replace(readerSrc, "\t_ = ApplyNarrativeOverrides(j, n)\n", "", 1)},
		{"the start-up does not call the reader", "cmd/scoreboard/main.go", "package main\n\n" + imp + "func main() { _, _ = catalog.LoadJourneys(\"\", nil) }\n"},
		{"the start-up shows rule excerpts it read itself", "cmd/scoreboard/main.go", "package main\n\n" + imp +
			"func main() {\n\t_, _ = catalog.LoadHintInputs(\"\", \"\", nil)\n\t_, _ = catalog.LoadRuleExcerpts(\"\", nil)\n}\n"},
		{"the hint-leak tests do not call the reader", "internal/hintleak/content_test.go", "package hintleak_test\n\nfunc loadScope() {}\n"},
		{"the validator calls the reader from another function", "internal/edition/checkevent.go", "package edition\n\n" + imp + "func other() { _, _ = catalog.LoadHintInputs(\"\", \"\", nil) }\n"},
		{"an applier through an alias", "internal/scoreboard/x.go", "package scoreboard\n\nimport c \"" + hiCatalogImport + "\"\n\nfunc f() { _ = c.ApplyNarrativeOverrides(nil, c.Narrative{}) }\n"},
		{"a dot import", "internal/scoreboard/x.go", "package scoreboard\n\nimport . \"" + hiCatalogImport + "\"\n"},
		{"the function taken as a value", "internal/scoreboard/x.go", "package scoreboard\n\n" + imp + "var f = catalog.ApplyNarrativeOverrides\n"},
		{"the reader taken as a value", "internal/scoreboard/x.go", "package scoreboard\n\n" + imp + "var f = catalog.LoadHintInputs\n"},
		{"a file that does not parse", "internal/scoreboard/x.go", "package scoreboard\n\nfunc (\n"},
	}
	for _, c := range cases {
		files := maps.Clone(good)
		files[c.path] = c.src
		if r := hiScan(files); len(r.violations) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	// No caller at all is red, not a pass.
	if r := hiScan(map[string]string{hiReaderFile: readerSrc}); len(r.violations) == 0 {
		t.Error("a tree with no caller of LoadHintInputs: no violation was reported")
	}
	// A method of the same name on another type is not the catalog's function.
	other := "package scoreboard\n\nfunc f(x interface{ ApplyNarrativeOverrides() }) { x.ApplyNarrativeOverrides() }\n"
	files := maps.Clone(good)
	files["internal/scoreboard/x.go"] = other
	if r := hiScan(files); len(r.violations) != 0 {
		t.Errorf("a method call on another type was reported: %v", r.violations)
	}
}
