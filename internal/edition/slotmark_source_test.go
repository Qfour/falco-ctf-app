package edition_test

import (
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ADR-0056 D12 (amendment 10) and D19 A4d-2a, fixed by reading the sources (the way
// render_reach_test.go and load_source_test.go do): the grammar of a mark `{{ctf:<slot>}}`
// has ONE definition in the package, slotmark.go (the constants MarkOpen / MarkClose and the
// lexer ScanMarks). No other non-test file of package edition spells it: not as a regular
// expression, not as a string that holds the opening of a mark, not as the opening in pieces.
// Everything else (the renderer, B4) reads a template through ScanMarks and names the ends by
// the constants. A comment is not a spelling (the scan reads string tokens only).

const slotmarkPath = "internal/edition/slotmark.go"

// looksLikeMarkSpelling reports whether the value of a string literal is a spelling of the
// grammar of a mark: the opening, a pattern of it (the braces escaped for a regular
// expression, `ctf:` and a brace), or the two braces of the opening on their own (a literal
// that is the first half of an opening cut in pieces). No literal of this package holds two
// braces in a row other than slotmark.go's.
func looksLikeMarkSpelling(v string) bool {
	return strings.Contains(v, "{{") ||
		strings.Contains(v, `\{\{`) ||
		(strings.Contains(v, "ctf:") && strings.Contains(v, "{"))
}

// markSpellingsIn lists the string literals of the source (a Go file at slash path p) that
// spell the grammar of a mark, as "path:line". A file that does not scan is reported too.
func markSpellingsIn(p, src string) []string {
	var out []string
	fset := token.NewFileSet()
	file := fset.AddFile(p, fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, []byte(src), func(pos token.Position, msg string) {
		out = append(out, p+": does not scan: "+msg)
	}, 0) // mode 0: comments are skipped
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.STRING {
			continue
		}
		v, err := strconv.Unquote(lit)
		if err != nil {
			out = append(out, p+": a string literal that does not unquote")
			continue
		}
		if looksLikeMarkSpelling(v) {
			out = append(out, p+":"+strconv.Itoa(fset.Position(pos).Line)+": spells the grammar of a mark")
		}
	}
	return out
}

// markGrammarSpellings lists, over the non-test files of package edition other than
// slotmark.go (files: slash path from the repo root -> source), every literal that spells
// the grammar of a mark.
func markGrammarSpellings(files map[string]string) []string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	var out []string
	for _, p := range paths {
		if !isEditionPackageFile(p) || p == slotmarkPath {
			continue
		}
		out = append(out, markSpellingsIn(p, files[p])...)
	}
	return out
}

// refersToIdent reports whether the source has an identifier of that name.
func refersToIdent(t *testing.T, p, src, name string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		t.Fatalf("%s does not parse: %v", p, err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

func TestMarkGrammarIsDefinedOnlyInSlotmark(t *testing.T) {
	files := nonTestSources(t)
	for _, v := range markGrammarSpellings(files) {
		t.Error(v)
	}

	// Positive: the scan sees the definition (one literal in slotmark.go: the opening), and
	// reads the other files of the package. A scan that finds nothing is not a pass.
	src, ok := files[slotmarkPath]
	if !ok {
		t.Fatalf("%s is not there", slotmarkPath)
	}
	if got := markSpellingsIn(slotmarkPath, src); len(got) != 1 {
		t.Errorf("slotmark.go has %d literals that spell a mark (%v), want 1: the opening, MarkOpen", len(got), got)
	}
	n := 0
	for p := range files {
		if isEditionPackageFile(p) && p != slotmarkPath {
			n++
		}
	}
	if n < 10 {
		t.Errorf("%d other files of package edition were scanned, want at least 10: the scan does not see the package", n)
	}

	// The two readers of a template read it through the lexer: B4 (the marks it takes out
	// before it cuts the shingles) and the renderer (rendertemplate.go, and render.go which
	// holds no spelling).
	for _, p := range []string{"internal/edition/practiceoverlap.go", "internal/edition/rendertemplate.go"} {
		src, ok := files[p]
		if !ok {
			t.Fatalf("%s is not there", p)
		}
		if !refersToIdent(t, p, src, "ScanMarks") {
			t.Errorf("%s does not call ScanMarks: a template is read by the one lexer of the marks", p)
		}
	}
	if src, ok := files["internal/edition/render.go"]; !ok {
		t.Error("internal/edition/render.go is not there")
	} else if got := markSpellingsIn("internal/edition/render.go", src); len(got) != 0 {
		t.Errorf("render.go spells a mark: %v", got)
	}
}

// The scan itself: a copy with the grammar spelled elsewhere is reported, and what is not a
// spelling is not.
func TestMarkGrammarScan_SeesASpelling(t *testing.T) {
	const slotmarkSrc = "package edition\n\nconst MarkOpen = \"{{ctf:\"\n\nconst MarkClose = \"}}\"\n"
	const otherSrc = "package edition\n\n// a mark {{ctf:<slot>}} in a comment\nfunc f() string { return MarkOpen }\n"
	base := map[string]string{
		slotmarkPath:                 slotmarkSrc,
		"internal/edition/other.go":  otherSrc,
		"internal/scoreboard/x.go":   "package scoreboard\n\nconst c = \"{{ctf:\"\n",
		"internal/edition/b4like.go": "package edition\n\nfunc g() string { return \"a \" + MarkOpen + \" is not a mark\" }\n",
	}
	if v := markGrammarSpellings(base); len(v) != 0 {
		t.Fatalf("the allowed shape was reported: %v", v)
	}

	cases := []struct{ name, src string }{
		{"a regular expression of the mark", "package edition\n\nimport \"regexp\"\n\nvar re = regexp.MustCompile(`\\{\\{ctf:[^{}]*\\}\\}`)\n"},
		{"a regular expression in a quoted string", "package edition\n\nvar re = \"\\\\{\\\\{ctf:[a-z]+\\\\}\\\\}\"\n"},
		{"the opening as a string", "package edition\n\nconst open = \"{{ctf:\"\n"},
		{"a whole mark as a string", "package edition\n\nconst m = \"x={{ctf:who}}\"\n"},
		{"the opening in a raw string", "package edition\n\nconst open = `{{ctf:`\n"},
		{"the opening in pieces", "package edition\n\nconst open = \"{{\" + \"ctf:\"\n"},
		{"the opening with escapes", "package edition\n\nconst open = \"\\x7b\\x7bctf:\"\n"},
		{"ctf: and a brace in two literals of a pattern", "package edition\n\nconst p = \"ctf:[{]\"\n"},
	}
	for _, c := range cases {
		files := rdCopyFiles(base)
		files["internal/edition/copy.go"] = c.src
		if v := markGrammarSpellings(files); len(v) == 0 {
			t.Errorf("%s: no spelling was reported", c.name)
		}
		// The same text in slotmark.go is the definition, and is not reported.
		defn := rdCopyFiles(base)
		defn[slotmarkPath] = c.src
		if v := markGrammarSpellings(defn); len(v) != 0 {
			t.Errorf("%s: slotmark.go was reported: %v", c.name, v)
		}
	}

	// A file that does not scan is reported, not skipped.
	bad := rdCopyFiles(base)
	bad["internal/edition/copy.go"] = "package edition\n\nconst s = \"unterminated\n"
	if v := markGrammarSpellings(bad); len(v) == 0 {
		t.Error("a file that does not scan was not reported")
	}
}
