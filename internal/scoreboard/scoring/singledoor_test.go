package scoring_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The Grader is the only door to the four scoring tables (solved / evade_dirty /
// expected_rule_fire / exfil), and every public entry through it applies the seat
// grammar (app#479, ADR-0039 Signpost 3). Two static guards hold that without
// trusting a caller's promise:
//
//   - TestGrader_EntryTableIsComplete: the Grader entries a source has (the
//     exported methods that reach a store write) are exactly the rows of the
//     behavioural table in scoring_test.go (graderEntries) plus Sweep, so a new
//     entry cannot land without a negative test.
//   - TestScoringTables_OnlyTheGraderWrites: no non-test file outside
//     internal/store and internal/scoreboard/scoring calls a store write.

// storeWrites are the ScoreStore methods that write a scoring table.
var storeWrites = []string{"MarkSolved", "MarkDirty", "RecordExpectedRuleFire", "RecordExfil"}

// sweepEntry reads stored receipts rather than taking a `user`; its refusal is
// TestSweep_NonSlugUserReceiptIsSkipped, not a row of graderEntries.
const sweepEntry = "Sweep"

// graderWriteEntries returns the exported methods of *Grader in src that reach a
// store write: directly (g.store.<write>) or through other Grader methods
// (g.<method>), however deep. It sorts nothing out by name or by a `user`
// parameter, so an entry that takes its seat under another name is still found.
func graderWriteEntries(t *testing.T, src string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "scoring.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string][]string{} // method -> Grader methods it calls
	writes := map[string]bool{}    // method -> calls a store write itself
	var exported []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || fd.Body == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
			continue
		}
		if star, ok := fd.Recv.List[0].Type.(*ast.StarExpr); !ok || !isIdent(star.X, "Grader") {
			continue
		}
		recv := fd.Recv.List[0].Names[0].Name
		name := fd.Name.Name
		if fd.Name.IsExported() {
			exported = append(exported, name)
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
			switch x := sel.X.(type) {
			case *ast.Ident: // g.method(...)
				if x.Name == recv {
					calls[name] = append(calls[name], sel.Sel.Name)
				}
			case *ast.SelectorExpr: // g.store.write(...)
				if isIdent(x.X, recv) && x.Sel.Name == "store" && slices.Contains(storeWrites, sel.Sel.Name) {
					writes[name] = true
				}
			}
			return true
		})
	}
	reaches := func(from string) bool {
		seen := map[string]bool{}
		var walk func(string) bool
		walk = func(m string) bool {
			if seen[m] {
				return false
			}
			seen[m] = true
			if writes[m] {
				return true
			}
			for _, c := range calls[m] {
				if walk(c) {
					return true
				}
			}
			return false
		}
		return walk(from)
	}
	var out []string
	for _, m := range exported {
		if reaches(m) {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func tableMethods() []string {
	set := map[string]bool{sweepEntry: true}
	for _, e := range graderEntries {
		set[e.method] = true
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func TestGrader_EntryTableIsComplete(t *testing.T) {
	src, err := os.ReadFile("scoring.go")
	if err != nil {
		t.Fatal(err)
	}
	got := graderWriteEntries(t, string(src))
	if len(got) < 5 { // fail closed: an extractor that sees nothing proves nothing
		t.Fatalf("found only %v in scoring.go; the scan is not seeing the Grader", got)
	}
	if want := tableMethods(); !slices.Equal(got, want) {
		t.Fatalf("Grader entries that reach a store write = %v, but graderEntries (+ Sweep) = %v: "+
			"add a row to graderEntries for the new entry (a negative with a non-seat user and its positive) "+
			"or remove the stale one", got, want)
	}
}

// The scan itself, run on synthetic sources: a new entry, direct or through a
// helper, is found; a method that never reaches a write is not.
func TestGraderWriteEntries_Scan(t *testing.T) {
	const head = "package scoring\ntype Grader struct{ store ScoreStore }\n"
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"direct write", head + "func (g *Grader) A(user string) { g.store.MarkSolved(user, \"c\", \"t\") }", []string{"A"}},
		{"write through an unexported helper", head +
			"func (g *Grader) A(user string) { g.help(user) }\nfunc (g *Grader) help(user string) { g.store.RecordExfil(user, \"c\", \"f\", \"t\") }", []string{"A"}},
		{"write through two exported hops", head +
			"func (g *Grader) A(u string) { g.B(u) }\nfunc (g *Grader) B(u string) { g.store.MarkDirty(u, \"c\", \"r\", \"t\") }", []string{"A", "B"}},
		{"a seat under another name", head + "func (g *Grader) A(who string) { g.store.RecordExpectedRuleFire(who, \"c\", \"r\", \"t\") }", []string{"A"}},
		{"reads only", head + "func (g *Grader) A(user string) bool { return g.store.IsSolved(user, \"c\") }", nil},
		{"a cycle terminates", head + "func (g *Grader) A() { g.B() }\nfunc (g *Grader) B() { g.A() }", nil},
		{"unexported entry is not public", head + "func (g *Grader) a(user string) { g.store.MarkSolved(user, \"c\", \"t\") }", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := graderWriteEntries(t, c.src); !slices.Equal(got, c.want) {
				t.Fatalf("entries = %v, want %v", got, c.want)
			}
		})
	}
}

// storeWriteCalls returns "<line>: <call>" for each call in src of a store write
// that is not the Grader's own same-named RecordExfil (receiver `grader`).
func storeWriteCalls(t *testing.T, name, src string) (violations []string, writes int) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !slices.Contains(storeWrites, sel.Sel.Name) {
			return true
		}
		writes++
		if sel.Sel.Name == "RecordExfil" && lastName(sel.X) == "grader" {
			return true // Grader.RecordExfil, the entry itself
		}
		violations = append(violations, fset.Position(call.Pos()).String()+": "+sel.Sel.Name)
		return true
	})
	return violations, writes
}

// lastName is the right-most identifier of a receiver expression (h.grader -> "grader").
func lastName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

func TestScoringTables_OnlyTheGraderWrites(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var files, violations []string
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			slash := filepath.ToSlash(p)
			if d.IsDir() && (strings.HasSuffix(slash, "internal/store") || strings.HasSuffix(slash, "internal/scoreboard/scoring")) {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 50 { // fail closed: the walk must see the services
		t.Fatalf("scanned only %d files under cmd/ and internal/", len(files))
	}
	grader := 0
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		v, w := storeWriteCalls(t, p, string(b))
		violations = append(violations, v...)
		grader += w
	}
	if grader == 0 { // the api exfil handler calls Grader.RecordExfil: a scan that sees none is blind
		t.Fatal("the scan saw no Grader.RecordExfil call in api.go; it is not reading the handlers")
	}
	if len(violations) != 0 {
		t.Fatalf("a store write outside internal/store and internal/scoreboard/scoring (only the Grader may write the scoring tables):\n%s",
			strings.Join(violations, "\n"))
	}
}

func TestStoreWriteCalls_Scan(t *testing.T) {
	const head = "package x\nfunc f() {\n"
	cases := []struct {
		name string
		body string
		want int
	}{
		{"the Grader's RecordExfil is the door", "h.grader.RecordExfil(u, c, f)", 0},
		{"a store RecordExfil is not", "h.store.RecordExfil(u, c, f, t)", 1},
		{"MarkSolved", "st.MarkSolved(u, c, t)", 1},
		{"MarkDirty", "s.MarkDirty(u, c, r, t)", 1},
		{"RecordExpectedRuleFire", "s.RecordExpectedRuleFire(u, c, r, t)", 1},
		{"a read", "s.IsSolved(u, c)", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, _ := storeWriteCalls(t, "x.go", head+c.body+"\n}\n")
			if len(v) != c.want {
				t.Fatalf("violations = %v, want %d", v, c.want)
			}
		})
	}
}
