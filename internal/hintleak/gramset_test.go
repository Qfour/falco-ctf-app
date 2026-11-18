package hintleak_test

// gramset_test.go pins hintleak.GramSet, the one function that normalises a text and cuts the
// windows of GramRunes runes (ADR-0026 D5-2 / D5-3), and fixes by reading hintleak.go that
// nothing else in the package keeps a second definition (ADR-0056 V73, stage A4c-3). B4 of
// internal/edition calls GramSet; its side of V73 is internal/edition/shingle_source_test.go.
// It was an unexported function used by Check; exporting it must not change a byte of what the
// rule sees, which TestHintLeakChecker_Mutation (V6) shows from the other side. Every non-ASCII
// rune is built with u(0x....): this file carries no raw non-ASCII character.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// gramRunesOf is n distinct runes, the k-th being the code point 0x4E00+k.
func gramRunesOf(n int) string {
	r := make([]rune, n)
	for i := range r {
		r[i] = rune(0x4E00 + i)
	}
	return string(r)
}

func TestGramSet(t *testing.T) {
	n := hintleak.GramRunes
	tests := []struct {
		name string
		in   string
		want int // the number of distinct shingles
	}{
		{"empty", "", 0},
		{"one rune short of a window", gramRunesOf(n - 1), 0},
		{"exactly one window", gramRunesOf(n), 1},
		{"one rune more is a second window", gramRunesOf(n + 1), 2},
		{"windows are counted in runes, not bytes", gramRunesOf(n + 5), 6},
		{"whitespace is not a rune of a window: nine runes and a space are no window", "abcde fghi", 0},
		{"the same text with and without whitespace has the same windows", "abcde fghij\n", 1},
		{"a repeated run is one shingle (a set)", strings.Repeat("a", n+4), 1},
		{"a space inside a window is removed, so the window is one", "abcdefghi j", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hintleak.GramSet(tt.in)
			if got == nil {
				t.Fatalf("GramSet(%q) is nil, want a set (empty when there is no window)", tt.in)
			}
			if len(got) != tt.want {
				t.Fatalf("GramSet(%q) has %d shingles, want %d", tt.in, len(got), tt.want)
			}
		})
	}

	t.Run("a shingle is the normalised run", func(t *testing.T) {
		got := hintleak.GramSet("abcde fghij" + u(0x3000) + "k")
		want := map[string]struct{}{"abcdefghij": {}, "bcdefghijk": {}}
		if len(got) != len(want) {
			t.Fatalf("GramSet has %d shingles, want %d", len(got), len(want))
		}
		for g := range want {
			if _, ok := got[g]; !ok {
				t.Errorf("shingle %q is missing", g)
			}
		}
	})

	t.Run("it is Normalize, then windows of GramRunes runes", func(t *testing.T) {
		text := "ab cd" + u(0x3000) + "ef gh\tij kl" + u(0x65E5, 0x672C) + "mn\nop"
		runes := hintleak.Normalize(text)
		want := map[string]struct{}{}
		for i := 0; i+n <= len(runes); i++ {
			want[string(runes[i:i+n])] = struct{}{}
		}
		got := hintleak.GramSet(text)
		if len(want) == 0 || len(got) != len(want) {
			t.Fatalf("GramSet has %d shingles, the windows of Normalize have %d (want a non-empty, equal set)", len(got), len(want))
		}
		for g := range want {
			if _, ok := got[g]; !ok {
				t.Errorf("shingle %q is missing", g)
			}
		}
	})

	t.Run("the result is a new map", func(t *testing.T) {
		a := hintleak.GramSet(gramRunesOf(n))
		for g := range a {
			delete(a, g)
		}
		a["x"] = struct{}{}
		if b := hintleak.GramSet(gramRunesOf(n)); len(b) != 1 {
			t.Fatalf("a second call has %d shingles after the first result was modified, want 1", len(b))
		}
	})

	t.Run("Check reports exactly the shingles of GramSet", func(t *testing.T) {
		hint := gramRunesOf(n + 3)
		vs, err := hintleak.Check(hintleak.Input{Hints: one("h", hint), Targets: one("f", hint)})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		set := hintleak.GramSet(hint)
		if len(vs) != len(set) || len(vs) != 4 {
			t.Fatalf("Check reported %d violations, GramSet has %d shingles, want both 4", len(vs), len(set))
		}
		for _, v := range vs {
			if _, ok := set[v.Gram]; !ok {
				t.Errorf("Check reported a gram that is not in GramSet")
			}
		}
	})
}

// funcsWithIdent lists the functions of the source (the bodies; a function's own name is not a
// use of it) that mention an identifier called name, sorted.
func funcsWithIdent(t *testing.T, src, name string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "hintleak.go", src, 0)
	if err != nil {
		t.Fatalf("hintleak.go does not parse: %v", err)
	}
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == name {
				found = true
			}
			return !found
		})
		if found {
			out = append(out, fd.Name.Name)
		}
	}
	slices.Sort(out)
	return out
}

// callsIn counts the calls of the function callee inside the function fn.
func callsIn(t *testing.T, src, fn, callee string) int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "hintleak.go", src, 0)
	if err != nil {
		t.Fatalf("hintleak.go does not parse: %v", err)
	}
	n := 0
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Recv != nil || fd.Name.Name != fn {
			continue
		}
		ast.Inspect(fd.Body, func(x ast.Node) bool {
			if c, ok := x.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == callee {
					n++
				}
			}
			return true
		})
	}
	return n
}

// secondDefinition reports what hintleak.go does that the one definition forbids: a function
// other than GramSet that uses GramRunes (a window) or Normalize (the normalisation, which only
// GramSet calls), and a Check that does not take all three kinds of item through GramSet.
func secondDefinition(t *testing.T, src string) []string {
	t.Helper()
	var out []string
	if got := funcsWithIdent(t, src, "GramRunes"); !slices.Equal(got, []string{"GramSet"}) {
		out = append(out, "GramRunes is used by "+strings.Join(got, ", ")+", want GramSet only")
	}
	if got := funcsWithIdent(t, src, "Normalize"); !slices.Equal(got, []string{"GramSet"}) {
		out = append(out, "Normalize is called by "+strings.Join(got, ", ")+", want GramSet only")
	}
	if got := callsIn(t, src, "Check", "GramSet"); got != 3 {
		out = append(out, "Check calls GramSet "+strconv.Itoa(got)+" times, want 3 (hint, free and target items)")
	}
	return out
}

// V73, hintleak's side: the window and the normalisation are in GramSet and nowhere else of
// hintleak.go, and Check goes through it for every item.
func TestGramSetIsTheOneDefinitionOfAShingle(t *testing.T) {
	b, err := os.ReadFile("hintleak.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, v := range secondDefinition(t, src) {
		t.Error(v)
	}

	// Positive: the scan sees the function it is about.
	if got := funcsWithIdent(t, src, "GramRunes"); len(got) != 1 {
		t.Fatalf("the scan found %v, want GramSet: it does not see hintleak.go", got)
	}

	// The scan itself: a copy with a second loop, or with a call turned into one, is reported.
	// stub is a function that uses neither piece, so a case that turns a call of Check into a
	// call of it is reported by the count of Check's calls alone.
	const stub = "\nfunc ownSet(s string) map[string]struct{} { return nil }\n"
	const loop = "\nfunc ownSet(s string) map[string]struct{} {\n\tr := Normalize(s)\n\t_ = r[:GramRunes]\n\treturn nil\n}\n"
	cases := []struct{ name, from, to string }{
		{"Check cuts the windows of its targets itself", "for g := range GramSet(f.Text) {", "for g := range ownSet(f.Text) {"},
		{"Check cuts the windows of its hints itself", "for g := range GramSet(it.Text) {\n\t\t\thintGrams", "for g := range ownSet(it.Text) {\n\t\t\thintGrams"},
	}
	for _, c := range cases {
		if !strings.Contains(src, c.from) {
			t.Fatalf("%s: the text to replace is not in hintleak.go (the self-check is stale)", c.name)
		}
		mutated := strings.Replace(src, c.from, c.to, 1) + stub
		if v := secondDefinition(t, mutated); len(v) != 1 {
			t.Errorf("%s: %d problems were reported (%v), want 1: the count of Check's calls", c.name, len(v), v)
		}
	}
	if v := secondDefinition(t, src+loop); len(v) != 2 {
		t.Errorf("a second function that uses Normalize and GramRunes: %d problems were reported (%v), want 2", len(v), v)
	}
	if v := secondDefinition(t, src+"\nfunc ownNorm(s string) []rune { return Normalize(s) }\n"); len(v) != 1 {
		t.Errorf("a second caller of Normalize: %d problems were reported (%v), want 1", len(v), v)
	}
	if v := secondDefinition(t, src+"\nfunc ownWindow() int { return GramRunes }\n"); len(v) != 1 {
		t.Errorf("a second user of GramRunes: %d problems were reported (%v), want 1", len(v), v)
	}
}
