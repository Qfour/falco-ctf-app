package edition_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ADR-0056 D9 (M2), D20 (the reach of the commands), V54 and V78, fixed by reading the sources (the way
// load_source_test.go fixes the door of the answers table): the validator's types and the
// signatures that carry them.
//
//   - a *CheckedTable is built only by LoadEventTable (internal/edition/load.go), and a
//     *CheckedBundles only by CheckBundles (internal/edition/bundlecheck.go): no other non-test
//     file has a composite literal, a new(...) or a `var x T` of either type. A test file may
//     (export_test.go does), because a _test.go file is not in a build of the program;
//   - the signatures are what the types are for: CheckBundles takes a *CheckedTable (and not a
//     *Table, which Parse alone makes) and gives a *CheckedBundles, BundleInput has no table,
//     WriteDigests takes a *CheckedBundles and nothing weaker, LoadEventTable gives a
//     *CheckedTable;
//   - the callers of LoadEventTable and of Check are load_source_test.go's (doorViolations).
//     `edition check` (A4e-2) adds the one caller of LoadEventTable and of CheckBundles; its pin
//     is added with it and is not placed before the caller exists;
//   - hintleak's `scope` package, which A4e-2 imports to assemble B5's input, is imported under
//     the name hlscope (edition.Scope is a type of this package): any import of it in this
//     package under another name is refused, so the name is settled before the first import.

// checkedMakers is where a value of each type may be made: the file and the function.
var checkedMakers = map[string]struct{ file, fn string }{
	"CheckedTable":   {"internal/edition/load.go", "LoadEventTable"},
	"CheckedBundles": {"internal/edition/bundlecheck.go", "CheckBundles"},
}

// checkedViolations judges every non-test file (slash path -> source): a CheckedTable or a
// CheckedBundles made anywhere but in its maker is a violation. counts is the positive side,
// by "type@function".
func checkedViolations(files map[string]string) (violations []string, counts map[string]int) {
	counts = map[string]int{}
	paths := slices.Sorted(maps.Keys(files))
	types := slices.Sorted(maps.Keys(checkedMakers))
	for _, p := range paths {
		for _, ty := range types {
			fns, err := typeMakes(p, files[p], ty)
			if err != nil {
				violations = append(violations, p+": does not parse: "+err.Error())
				break
			}
			mk := checkedMakers[ty]
			for _, fn := range fns {
				if p == mk.file && fn == mk.fn {
					counts[ty+"@"+fn]++
					continue
				}
				violations = append(violations, p+" (func "+fn+"): makes an edition."+ty+" outside "+mk.fn+" in "+mk.file)
			}
		}
	}
	return violations, counts
}

func TestCheckedValuesAreMadeOnlyByTheirDoors(t *testing.T) {
	violations, counts := checkedViolations(nonTestSources(t))
	for _, v := range violations {
		t.Error(v)
	}
	// Positive: each maker is there, once. A scan that finds nothing is not a pass.
	if want := map[string]int{"CheckedTable@LoadEventTable": 1, "CheckedBundles@CheckBundles": 1}; !maps.Equal(counts, want) {
		t.Errorf("makers found = %v, want %v", counts, want)
	}

	// The scan itself: the allowed shape passes, every other way to make a value is seen.
	const loadSrc = "package edition\n\nfunc LoadEventTable() *CheckedTable { return &CheckedTable{} }\n"
	const bundleSrc = "package edition\n\nfunc CheckBundles() *CheckedBundles { return &CheckedBundles{} }\n"
	base := map[string]string{"internal/edition/load.go": loadSrc, "internal/edition/bundlecheck.go": bundleSrc}
	if v, c := checkedViolations(base); len(v) != 0 || !maps.Equal(c, map[string]int{"CheckedTable@LoadEventTable": 1, "CheckedBundles@CheckBundles": 1}) {
		t.Fatalf("the allowed shape: violations %v, counts %v", v, c)
	}
	cases := []struct{ name, path, src string }{
		{"a CheckedTable literal in another function of load.go", "internal/edition/load.go", loadSrc + "\nfunc other() *CheckedTable { return &CheckedTable{} }\n"},
		{"a CheckedTable literal in bundlecheck.go", "internal/edition/bundlecheck.go", bundleSrc + "\nfunc other() *CheckedTable { return &CheckedTable{} }\n"},
		{"a CheckedBundles literal in load.go", "internal/edition/load.go", loadSrc + "\nfunc other() *CheckedBundles { return &CheckedBundles{} }\n"},
		{"a CheckedBundles literal in another function of bundlecheck.go", "internal/edition/bundlecheck.go", bundleSrc + "\nfunc other() *CheckedBundles { return &CheckedBundles{} }\n"},
		{"a CheckedTable value literal elsewhere in the package", "internal/edition/other.go", "package edition\n\nfunc f() { _ = CheckedTable{} }\n"},
		{"new(CheckedTable)", "internal/edition/other.go", "package edition\n\nfunc f() { _ = new(CheckedTable) }\n"},
		{"new(CheckedBundles)", "internal/edition/other.go", "package edition\n\nfunc f() { _ = new(CheckedBundles) }\n"},
		{"var t CheckedTable in a function", "internal/edition/other.go", "package edition\n\nfunc f() { var t CheckedTable; _ = t }\n"},
		{"a package-level var of CheckedBundles", "internal/edition/other.go", "package edition\n\nvar b CheckedBundles\n"},
		{"a qualified CheckedTable literal elsewhere", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _ = &edition.CheckedTable{} }\n"},
		{"a qualified CheckedBundles literal through an alias", "cmd/scoreboard/x.go", "package main\n\nimport ed \"" + editionImportPath + "\"\n\nfunc f() { _ = ed.CheckedBundles{} }\n"},
		{"a dot import", "cmd/scoreboard/x.go", "package main\n\nimport . \"" + editionImportPath + "\"\n"},
	}
	for _, c := range cases {
		files := rdCopyFiles(base)
		files[c.path] = c.src
		if v, _ := checkedViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	// A type of another package with the name, a pointer, a parameter and a receiver make none.
	for name, c := range map[string]struct{ path, src string }{
		"another package's type": {"internal/contracttable/x.go", "package contracttable\n\ntype CheckedTable struct{}\n\nfunc f() *CheckedTable { return &CheckedTable{} }\n"},
		"a pointer, a parameter and a receiver": {"internal/edition/other.go", "package edition\n\nfunc (t *CheckedTable) M() {}\n\nfunc g(b *CheckedBundles, t *CheckedTable) *CheckedBundles { var p *CheckedTable; _ = p; return b }\n"},
	} {
		files := rdCopyFiles(base)
		files[c.path] = c.src
		if v, _ := checkedViolations(files); len(v) != 0 {
			t.Errorf("%s was reported: %v", name, v)
		}
	}
}

// sigWant is the parameter and the result types of a function.
type sigWant struct{ params, results []string }

// wantValidatorSigs are the signatures of the validator's door and of what it hands on.
var wantValidatorSigs = []struct {
	file, fn string
	want     sigWant
}{
	{"internal/edition/digests.go", "WriteDigests", sigWant{[]string{"io.Writer", "*CheckedBundles"}, []string{"error"}}},
	{"internal/edition/bundlecheck.go", "CheckBundles", sigWant{[]string{"string", "*CheckedTable", "BundleInput"}, []string{"*CheckedBundles", "error"}}},
	{"internal/edition/load.go", "LoadEventTable", sigWant{[]string{"catalog.Scored", "string"}, []string{"*CheckedTable", "string", "error"}}},
}

// resultTypes is the result types of a function, one entry per result.
func resultTypes(ft *ast.FuncType) []string {
	var out []string
	if ft.Results == nil {
		return out
	}
	for _, fld := range ft.Results.List {
		ty := typeString(fld.Type)
		n := max(len(fld.Names), 1)
		for i := 0; i < n; i++ {
			out = append(out, ty)
		}
	}
	return out
}

// validatorSigViolations holds the three functions of wantValidatorSigs to their signatures
// and BundleInput to "no table of its own" (a field of type *Table or Table would be the old
// way to hand CheckBundles a table that only Parse read). files is slash path -> source.
func validatorSigViolations(files map[string]string) []string {
	var out []string
	for _, w := range wantValidatorSigs {
		src, ok := files[w.file]
		if !ok {
			out = append(out, w.file+": is not there")
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), w.file, src, 0)
		if err != nil {
			out = append(out, w.file+": does not parse: "+err.Error())
			continue
		}
		var fd *ast.FuncDecl
		for _, d := range f.Decls {
			if x, ok := d.(*ast.FuncDecl); ok && x.Recv == nil && x.Name.Name == w.fn {
				fd = x
			}
		}
		if fd == nil {
			out = append(out, w.file+": func "+w.fn+" not found")
			continue
		}
		if got := paramsOf(fd.Type).types; !slices.Equal(got, w.want.params) {
			out = append(out, w.file+" (func "+w.fn+"): parameters are ("+strings.Join(got, ", ")+"), want ("+strings.Join(w.want.params, ", ")+")")
		}
		if got := resultTypes(fd.Type); !slices.Equal(got, w.want.results) {
			out = append(out, w.file+" (func "+w.fn+"): results are ("+strings.Join(got, ", ")+"), want ("+strings.Join(w.want.results, ", ")+")")
		}
	}
	const bundleFile = "internal/edition/bundlecheck.go"
	src, ok := files[bundleFile]
	if !ok {
		return out
	}
	f, err := parser.ParseFile(token.NewFileSet(), bundleFile, src, 0)
	if err != nil {
		return out
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "BundleInput" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			out = append(out, bundleFile+": BundleInput is not a struct")
			return false
		}
		found = true
		for _, fld := range st.Fields.List {
			if ty := typeString(fld.Type); ty == "*Table" || ty == "Table" {
				out = append(out, bundleFile+": BundleInput has a field of type "+ty+": the answers table is CheckBundles's *CheckedTable parameter")
			}
		}
		return false
	})
	if !found {
		out = append(out, bundleFile+": type BundleInput not found")
	}
	return out
}

func TestValidatorSignaturesCarryTheCheckedTypes(t *testing.T) {
	all := nonTestSources(t)
	files := map[string]string{}
	for _, w := range wantValidatorSigs {
		src, ok := all[w.file]
		if !ok {
			t.Fatalf("%s is not there", w.file)
		}
		files[w.file] = src
	}
	for _, v := range validatorSigViolations(files) {
		t.Error(v)
	}

	// The scan itself, on copies of the real files with one change each: the form the ADR calls
	// "CheckBundles back to a *Table" is red, and so is each of the others.
	mutate := func(t *testing.T, file, old, repl string) map[string]string {
		t.Helper()
		if strings.Count(files[file], old) != 1 {
			t.Fatalf("%s does not hold %q once: the case does not test the real source", file, old)
		}
		c := rdCopyFiles(files)
		c[file] = strings.Replace(files[file], old, repl, 1)
		return c
	}
	const (
		digestsFile = "internal/edition/digests.go"
		bundleFile  = "internal/edition/bundlecheck.go"
		loadFile    = "internal/edition/load.go"
	)
	cases := []struct {
		name            string
		file, old, repl string
	}{
		{"CheckBundles taking a *Table again", bundleFile, "t *CheckedTable, in BundleInput) (*CheckedBundles", "t *Table, in BundleInput) (*CheckedBundles"},
		{"CheckBundles taking no table (it is in BundleInput)", bundleFile, "root string, t *CheckedTable, in BundleInput)", "root string, in BundleInput)"},
		{"CheckBundles giving rows", bundleFile, "in BundleInput) (*CheckedBundles, error)", "in BundleInput) ([]DigestRow, error)"},
		{"BundleInput with a *Table field", bundleFile, "type BundleInput struct {", "type BundleInput struct {\n\tTable *Table"},
		{"BundleInput with a Table field", bundleFile, "type BundleInput struct {", "type BundleInput struct {\n\tTable Table"},
		{"WriteDigests taking a run id and rows", digestsFile, "func WriteDigests(w io.Writer, cb *CheckedBundles) error", "func WriteDigests(w io.Writer, runID string, rows []DigestRow) error"},
		{"WriteDigests taking rows only", digestsFile, "func WriteDigests(w io.Writer, cb *CheckedBundles) error", "func WriteDigests(w io.Writer, rows []DigestRow) error"},
		{"LoadEventTable giving a *Table", loadFile, "(*CheckedTable, string, error) {\n\tif answersFile", "(*Table, string, error) {\n\tif answersFile"},
		{"LoadEventTable taking a third argument", loadFile, "func LoadEventTable(scored catalog.Scored, answersFile string)", "func LoadEventTable(scored catalog.Scored, answersFile string, eventMode bool)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if v := validatorSigViolations(mutate(t, c.file, c.old, c.repl)); len(v) == 0 {
				t.Error("no violation was reported")
			}
		})
	}
	// A file that is missing is reported, not skipped.
	missing := rdCopyFiles(files)
	delete(missing, bundleFile)
	if v := validatorSigViolations(missing); len(v) == 0 {
		t.Error("a missing bundlecheck.go was not reported")
	}
}

// hlscopeImportPath is hintleak's assembly of B5's input (ADR-0056 A4c-1).
const hlscopeImportPath = "github.com/Qfour/falco-ctf-app/internal/hintleak/scope"

// scopeImportViolations lists the imports of hintleak's scope package in the non-test files
// of package edition (slash path -> source) that are not under the name hlscope: an import
// with no name, a dot import, a blank import or another name. A file that does not parse is
// reported.
func scopeImportViolations(files map[string]string) []string {
	var out []string
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if !isEditionPackageFile(p) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], parser.ImportsOnly)
		if err != nil {
			out = append(out, p+": does not parse: "+err.Error())
			continue
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || path != hlscopeImportPath {
				continue
			}
			if imp.Name == nil || imp.Name.Name != "hlscope" {
				name := "no name"
				if imp.Name != nil {
					name = imp.Name.Name
				}
				out = append(out, fmt.Sprintf("%s: imports hintleak's scope package under %s; in package edition it is hlscope (edition.Scope is a type of this package)", p, name))
			}
		}
	}
	return out
}

func TestHintleakScopeIsImportedAsHlscope(t *testing.T) {
	files := nonTestSources(t)
	for _, v := range scopeImportViolations(files) {
		t.Error(v)
	}
	n := 0
	for p := range files {
		if isEditionPackageFile(p) {
			n++
		}
	}
	if n < 10 {
		t.Errorf("%d files of package edition were scanned, want at least 10: the scan does not see the package", n)
	}

	// The scan itself. Nothing imports the package yet, so the cases are the whole test: the
	// name is settled before A4e-2 adds the first import.
	imp := func(name string) string {
		return "package edition\n\nimport " + name + " \"" + hlscopeImportPath + "\"\n"
	}
	for name, src := range map[string]string{
		"an import with the alias hlscope": imp("hlscope"),
		"another package under its own name": "package edition\n\nimport \"github.com/Qfour/falco-ctf-app/internal/hintleak\"\n",
	} {
		if v := scopeImportViolations(map[string]string{"internal/edition/x.go": src}); len(v) != 0 {
			t.Errorf("%s was reported: %v", name, v)
		}
	}
	for name, src := range map[string]string{
		"an import with no name":     "package edition\n\nimport \"" + hlscopeImportPath + "\"\n",
		"an import named scope":      imp("scope"),
		"an import named hlScope":    imp("hlScope"),
		"an import named hintscope":  imp("hintscope"),
		"a dot import":               imp("."),
		"a blank import":             imp("_"),
		"a grouped import of it":     "package edition\n\nimport (\n\t\"fmt\"\n\t\"" + hlscopeImportPath + "\"\n)\n",
		"a file that does not parse": "package edition\n\nimport (\n",
	} {
		if v := scopeImportViolations(map[string]string{"internal/edition/x.go": src}); len(v) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
	// A file of another package is not this rule's.
	if v := scopeImportViolations(map[string]string{"internal/hintleak/x.go": "package hintleak\n\nimport \"" + hlscopeImportPath + "\"\n"}); len(v) != 0 {
		t.Errorf("a file of another package was reported: %v", v)
	}
}
