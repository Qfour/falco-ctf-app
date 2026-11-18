package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// ADR-0056 V73 (D19 A4c-3), fixed by reading the sources (the way slotmark_source_test.go
// does): a shingle has ONE definition, hintleak.GramSet (the normalisation of ADR-0026 D5-2 and
// the window of hintleak.GramRunes, in one exported function that hintleak.Check also calls).
// B4 (practiceoverlap.go) builds its shingle sets by calling it. No non-test file of package
// edition cuts a window or normalises a text itself: none reaches for hintleak.Normalize or
// hintleak.GramRunes (the two pieces of a window), and B4 imports neither unicode nor
// unicode/utf8 and converts nothing to []rune. The same fact on hintleak's side (Check is the
// only caller, GramSet the only user of the pieces) is internal/hintleak/gramset_test.go.
// A comment is not a use (the scan reads the syntax tree).

const (
	shingleHintleakImport = "github.com/Qfour/falco-ctf-app/internal/hintleak"
	shingleOverlapPath    = "internal/edition/practiceoverlap.go"
)

// shingleProblems lists what the source (a Go file at slash path p of package edition) does that
// the one definition forbids, and, for practiceoverlap.go, a shingleSet that does not call
// hintleak.GramSet.
func shingleProblems(t *testing.T, p, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, p, src, 0)
	if err != nil {
		t.Fatalf("%s does not parse: %v", p, err)
	}
	isB4 := p == shingleOverlapPath
	local := "" // the name the file gives to the hintleak import ("" = it does not import it)
	var out []string
	for _, im := range f.Imports {
		path, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			t.Fatalf("%s: an import path that does not unquote: %v", p, err)
		}
		if path == shingleHintleakImport {
			local = "hintleak"
			if im.Name != nil {
				local = im.Name.Name
			}
		}
		if isB4 && (path == "unicode" || path == "unicode/utf8") {
			out = append(out, p+": imports "+path+": a shingle is cut by hintleak.GramSet, not by a normalisation of its own")
		}
	}

	// The pieces of a window, and a rune slice, anywhere in the file (a package-level
	// declaration is a use too).
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			if ok && local != "" && id.Name == local && (x.Sel.Name == "Normalize" || x.Sel.Name == "GramRunes") {
				out = append(out, p+":"+strconv.Itoa(fset.Position(x.Pos()).Line)+": uses hintleak."+x.Sel.Name+": the window is hintleak.GramSet's")
			}
		case *ast.ArrayType:
			if id, ok := x.Elt.(*ast.Ident); ok && isB4 && x.Len == nil && id.Name == "rune" {
				out = append(out, p+":"+strconv.Itoa(fset.Position(x.Pos()).Line)+": a []rune: the window is hintleak.GramSet's")
			}
		}
		return true
	})

	if isB4 {
		calls := false
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv != nil || fd.Name.Name != "shingleSet" {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && local != "" && id.Name == local && sel.Sel.Name == "GramSet" {
					calls = true
				}
				return true
			})
		}
		if !calls {
			out = append(out, p+": shingleSet does not call hintleak.GramSet")
		}
	}
	return out
}

func TestB4ShingleIsHintleaksGramSet(t *testing.T) {
	files := nonTestSources(t)
	n := 0
	for p, src := range files {
		if !isEditionPackageFile(p) {
			continue
		}
		n++
		for _, v := range shingleProblems(t, p, src) {
			t.Error(v)
		}
	}
	// Positive: the scan sees B4 and the rest of the package. A scan that reads nothing is not
	// a pass (shingleProblems reports a B4 without the call, so the file must be there).
	if _, ok := files[shingleOverlapPath]; !ok {
		t.Fatalf("%s is not there", shingleOverlapPath)
	}
	if n < 10 {
		t.Errorf("%d files of package edition were scanned, want at least 10: the scan does not see the package", n)
	}
}

// The scan itself: the allowed shape is not reported, and each way of keeping a second
// definition of a shingle is.
func TestB4ShingleScan_SeesASecondDefinition(t *testing.T) {
	const head = "package edition\n\nimport (\n\t\"github.com/Qfour/falco-ctf-app/internal/hintleak\"\n)\n\n"
	const clean = head + "func shingleSet(files []BundleFile, stripMarks bool) (map[string]struct{}, *markFault) {\n" +
		"\tset := make(map[string]struct{})\n" +
		"\tfor _, f := range files {\n" +
		"\t\tfor g := range hintleak.GramSet(string(f.Data)) {\n" +
		"\t\t\tset[g] = struct{}{}\n" +
		"\t\t}\n" +
		"\t}\n" +
		"\treturn set, nil\n" +
		"}\n"
	if v := shingleProblems(t, shingleOverlapPath, clean); len(v) != 0 {
		t.Fatalf("the allowed shape was reported: %v", v)
	}

	cases := []struct{ name, src string }{
		{"the old loop: Normalize and GramRunes in shingleSet", head +
			"func shingleSet(files []BundleFile, stripMarks bool) (map[string]struct{}, *markFault) {\n" +
			"\tset := make(map[string]struct{})\n" +
			"\tfor _, f := range files {\n" +
			"\t\truns := hintleak.Normalize(string(f.Data))\n" +
			"\t\tfor i := 0; i+hintleak.GramRunes <= len(runs); i++ {\n" +
			"\t\t\tset[string(runs[i:i+hintleak.GramRunes])] = struct{}{}\n" +
			"\t\t}\n" +
			"\t}\n" +
			"\treturn set, nil\n" +
			"}\n"},
		{"shingleSet that does not call GramSet", head +
			"func shingleSet(files []BundleFile, stripMarks bool) (map[string]struct{}, *markFault) {\n" +
			"\treturn make(map[string]struct{}), nil\n" +
			"}\n" +
			"var _ = hintleak.GramSet\n"},
		{"GramSet called in another function only", head +
			"func shingleSet(files []BundleFile, stripMarks bool) (map[string]struct{}, *markFault) {\n" +
			"\treturn make(map[string]struct{}), nil\n" +
			"}\n" +
			"func other(s string) { _ = hintleak.GramSet(s) }\n"},
		{"a normalisation of its own: unicode and []rune", "package edition\n\nimport \"unicode\"\n\n" +
			"func shingleSet(files []BundleFile, stripMarks bool) (map[string]struct{}, *markFault) {\n" +
			"\tvar r []rune\n" +
			"\tfor _, c := range string(files[0].Data) {\n" +
			"\t\tif !unicode.IsSpace(c) {\n" +
			"\t\t\tr = append(r, c)\n" +
			"\t\t}\n" +
			"\t}\n" +
			"\treturn nil, nil\n" +
			"}\n"},
		{"the window size as a package-level constant", head +
			"const window = hintleak.GramRunes\n" +
			"func shingleSet(files []BundleFile, stripMarks bool) (map[string]struct{}, *markFault) {\n" +
			"\tfor g := range hintleak.GramSet(\"\") {\n\t\t_ = g\n\t}\n" +
			"\treturn nil, nil\n" +
			"}\n"},
		{"the import under another name", "package edition\n\nimport hl \"github.com/Qfour/falco-ctf-app/internal/hintleak\"\n\n" +
			"func shingleSet(files []BundleFile, stripMarks bool) (map[string]struct{}, *markFault) {\n" +
			"\t_ = hl.Normalize(\"\")\n" +
			"\tfor g := range hl.GramSet(\"\") {\n\t\t_ = g\n\t}\n" +
			"\treturn nil, nil\n" +
			"}\n"},
	}
	for _, c := range cases {
		if v := shingleProblems(t, shingleOverlapPath, c.src); len(v) == 0 {
			t.Errorf("%s: no problem was reported", c.name)
		}
	}

	// The pieces are forbidden in every file of the package, not only in B4.
	other := head + "func f(s string) []rune { return hintleak.Normalize(s) }\n"
	if v := shingleProblems(t, "internal/edition/other.go", other); len(v) == 0 {
		t.Error("hintleak.Normalize in another file of the package was not reported")
	}
	// ... but GramSet is allowed in every file, and a []rune is only B4's concern.
	fine := head + "func f(s string) []rune { _ = hintleak.GramSet(s); return nil }\n"
	if v := shingleProblems(t, "internal/edition/other.go", fine); len(v) != 0 {
		t.Errorf("GramSet and a []rune in another file were reported: %v", v)
	}
}
