package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// ADR-0056 D20 (the reach of the commands) and V78, fixed by reading the sources (the way
// slotmark_source_test.go fixes the grammar of a mark): the names of an edition's directory
// (edition/, edition.yaml, template/, practice/, practice/answers.tsv, practice/digests.tsv,
// practice/evidence/) have ONE definition, practicelayout.go. No other non-test Go file of
// package edition has a string literal that is one of the names; they use the constants. A
// comment is not a spelling (the scan reads string literals of the syntax tree only), and a
// message that holds a name among other words (`"edition.yaml is empty"`) is not one either:
// the scan is of a literal that IS a name, which is what a path is built from.
//
// The one exception is render.go's practiceKeyText: the key of a practice render is the text
// "practice" (ADR-0056 D12), which is the name of a directory by coincidence. It is exempt BY
// NAME, in that file only, so that a second literal "practice" in render.go, or the same
// constant in another file, is still seen.

const layoutPath = "internal/edition/practicelayout.go"

// layoutNames are the names of the layout, from the package's own constants: a name changed
// in practicelayout.go is guarded under its new spelling without an edit here.
var layoutNames = []string{
	edition.EditionDirName,
	edition.SpecFileName,
	edition.TemplateDirName,
	edition.PracticeDirName,
	edition.PracticeEvidenceDirName,
	edition.PracticeAnswersFileName,
	edition.PracticeDigestsFileName,
}

// layoutExempt are the constants that may hold the text of a name: file -> constant names.
var layoutExempt = map[string][]string{"internal/edition/render.go": {"practiceKeyText"}}

// layoutLiteralsIn lists the string literals of the source (a Go file at slash path p) whose
// value is a name of the layout, as "path:line", except the exempt constants. A file that does
// not parse, and a literal that does not unquote, are reported too. n is how many literals
// of the layout the file has, exempt ones included (the positive side).
func layoutLiteralsIn(p, src string) (found []string, n int) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, p, src, 0)
	if err != nil {
		return []string{p + ": does not parse: " + err.Error()}, 0
	}
	skip := map[*ast.BasicLit]bool{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if !slices.Contains(layoutExempt[p], name.Name) {
					continue
				}
				for _, v := range vs.Values {
					ast.Inspect(v, func(n ast.Node) bool {
						if bl, ok := n.(*ast.BasicLit); ok {
							skip[bl] = true
						}
						return true
					})
				}
			}
		}
	}
	ast.Inspect(f, func(node ast.Node) bool {
		bl, ok := node.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(bl.Value)
		if err != nil {
			found = append(found, p+": a string literal that does not unquote")
			return true
		}
		if !slices.Contains(layoutNames, v) {
			return true
		}
		n++
		if !skip[bl] {
			found = append(found, p+":"+strconv.Itoa(fset.Position(bl.Pos()).Line)+": spells the layout name "+strconv.Quote(v))
		}
		return true
	})
	return found, n
}

// layoutSpellings lists, over the non-test files of package edition other than
// practicelayout.go (slash path -> source), every literal that spells a name of the layout.
func layoutSpellings(files map[string]string) []string {
	var out []string
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if !isEditionPackageFile(p) || p == layoutPath {
			continue
		}
		found, _ := layoutLiteralsIn(p, files[p])
		out = append(out, found...)
	}
	return out
}

func TestLayoutNamesAreDefinedOnlyInPracticelayout(t *testing.T) {
	files := nonTestSources(t)
	for _, v := range layoutSpellings(files) {
		t.Error(v)
	}

	// Positive: the definition holds every name once, and the scan reads the rest of the
	// package. A scan that finds nothing is not a pass.
	src, ok := files[layoutPath]
	if !ok {
		t.Fatalf("%s is not there", layoutPath)
	}
	if _, n := layoutLiteralsIn(layoutPath, src); n != len(layoutNames) {
		t.Errorf("practicelayout.go has %d literals of the layout, want %d (one per name)", n, len(layoutNames))
	}
	if got := len(slices.Compact(slices.Sorted(slices.Values(layoutNames)))); got != len(layoutNames) {
		t.Errorf("the layout names are not distinct (%d of %d): a literal could not be told to which constant it belongs", got, len(layoutNames))
	}
	n := 0
	for p := range files {
		if isEditionPackageFile(p) && p != layoutPath {
			n++
		}
	}
	if n < 10 {
		t.Errorf("%d other files of package edition were scanned, want at least 10: the scan does not see the package", n)
	}
	// The exemption is real: render.go has its practiceKeyText, which the scan counts and
	// does not report.
	renderSrc, ok := files["internal/edition/render.go"]
	if !ok {
		t.Fatal("internal/edition/render.go is not there")
	}
	if found, n := layoutLiteralsIn("internal/edition/render.go", renderSrc); len(found) != 0 || n != 1 {
		t.Errorf("render.go: %d literals of the layout, reported %v; want practiceKeyText only (counted, exempt)", n, found)
	}

	// The scan itself: a copy with a name spelled elsewhere is reported, and what is not a
	// spelling is not.
	const layoutSrc = "package edition\n\nconst (\n\tEditionDirName = \"edition\"\n\tSpecFileName = \"edition.yaml\"\n)\n"
	const otherSrc = "package edition\n\n// the directory \"practice\" in a comment\nfunc f() string { return EditionDirName + \" is the edition.yaml of it\" }\n"
	base := map[string]string{layoutPath: layoutSrc, "internal/edition/other.go": otherSrc, "internal/scoreboard/x.go": "package scoreboard\n\nconst c = \"practice\"\n"}
	if v := layoutSpellings(base); len(v) != 0 {
		t.Fatalf("the allowed shape was reported: %v", v)
	}
	cases := []struct{ name, src string }{}
	for _, name := range layoutNames {
		cases = append(cases,
			struct{ name, src string }{"the name " + name + " in a string", "package edition\n\nvar p = filepath.Join(dir, " + strconv.Quote(name) + ")\n"},
			struct{ name, src string }{"the name " + name + " in a raw string", "package edition\n\nvar p = `" + name + "`\n"},
		)
	}
	cases = append(cases,
		struct{ name, src string }{"a name with an escape", "package edition\n\nvar p = \"answers\\x2etsv\"\n"},
		struct{ name, src string }{"a name as a const of its own", "package edition\n\nconst practiceName = \"practice\"\n"},
		struct{ name, src string }{"a name in a composite literal", "package edition\n\nvar names = []string{\"a\", \"evidence\"}\n"},
		struct{ name, src string }{"a file that does not parse", "package edition\n\nvar p = (\n"},
	)
	for _, c := range cases {
		files := rdCopyFiles(base)
		files["internal/edition/copy.go"] = c.src
		if v := layoutSpellings(files); len(v) == 0 {
			t.Errorf("%s: no spelling was reported", c.name)
		}
		// The same text in practicelayout.go is the definition, and is not reported.
		defn := rdCopyFiles(base)
		defn[layoutPath] = c.src
		if c.name != "a file that does not parse" {
			if v := layoutSpellings(defn); len(v) != 0 {
				t.Errorf("%s: practicelayout.go was reported: %v", c.name, v)
			}
		}
	}
	// The exemption is narrow: practiceKeyText in render.go only.
	const keySrc = "package edition\n\nconst practiceKeyText = \"practice\"\n"
	if v := layoutSpellings(map[string]string{"internal/edition/render.go": keySrc}); len(v) != 0 {
		t.Errorf("practiceKeyText in render.go was reported: %v", v)
	}
	for name, c := range map[string]struct{ path, src string }{
		"practiceKeyText in another file": {"internal/edition/other.go", keySrc},
		"another constant in render.go":   {"internal/edition/render.go", "package edition\n\nconst otherKey = \"practice\"\n"},
		"a second literal in render.go":   {"internal/edition/render.go", keySrc + "\nvar dir = \"practice\"\n"},
	} {
		if v := layoutSpellings(map[string]string{c.path: c.src}); len(v) == 0 {
			t.Errorf("%s: no spelling was reported", name)
		}
	}
}
