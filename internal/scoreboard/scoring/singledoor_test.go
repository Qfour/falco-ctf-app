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

// The Grader is the only door for ADDING to the four scoring tables (solved /
// evade_dirty / expected_rule_fire / exfil): the four insert / upsert methods
// below (MarkSolved, MarkDirty, RecordExpectedRuleFire, RecordExfil) are called
// from the Grader and nowhere else, and every public Grader entry that reaches
// one applies the seat grammar (app#479, ADR-0039 Signpost 3). Two static guards
// hold that without trusting a caller's promise:
//
//   - TestGrader_EntryTableIsComplete: the Grader entries the package has (the
//     exported methods, in ANY non-test file of package scoring, that reach a
//     store write) are exactly the rows of the behavioural table in
//     scoring_test.go (graderEntries) plus Sweep, so a new entry cannot land
//     without a negative test.
//   - TestScoringTables_OnlyTheGraderWrites: no non-test file outside
//     internal/store and internal/scoreboard/scoring calls a store write.
//
// What the claim does NOT cover, on purpose (review-5x 57 回目, VP 決定): writes
// that REMOVE or are not an adding write to a scoring table, which sit outside the
// Grader behind their route's gate, not behind the Grader's:
//   - Store.ResetDirty (a participant's reset-dirty, deletes from evade_dirty and
//     exfil) and Store.Reset (the admin reset, wipes the tables): gated by the
//     route's {user} seat check / the admin gate (and the origin guard);
//   - Store.RecordHintView (a hint reveal, a score INPUT through the penalty, not a
//     solve): gated by the route's {user} seat check and selfOrAdmin.
//
// They are not excluded by name from the scan; the scan simply looks for the four
// methods above. A new direct write belongs in the Grader, or in this list with
// its gate. Known limits of the scan: it follows `g.method` / `g.store.write`
// references (calls and method values) through the receiver by name; an alias of
// the receiver, or a Grader method reached through a function value or an
// interface, is not followed.

// storeWrites are the ScoreStore methods that write a scoring table.
var storeWrites = []string{"MarkSolved", "MarkDirty", "RecordExpectedRuleFire", "RecordExfil"}

// sweepEntry reads stored receipts rather than taking a `user`; its refusal is
// TestSweep_NonSlugUserReceiptIsSkipped, not a row of graderEntries.
const sweepEntry = "Sweep"

// graderWriteEntries returns the exported methods of *Grader in src that reach a
// store write: directly (g.store.<write>) or through other Grader methods
// (g.<method>), however deep. It sorts nothing out by name or by a `user`
// parameter, so an entry that takes its seat under another name is still found.
func graderWriteEntries(t *testing.T, srcs map[string]string) []string {
	t.Helper()
	calls := map[string][]string{} // method -> Grader methods it references
	writes := map[string]bool{}    // method -> references a store write itself
	var exported []string
	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}
	sort.Strings(names)
	var decls []ast.Decl
	for _, n := range names {
		f, err := parser.ParseFile(token.NewFileSet(), n, srcs[n], 0)
		if err != nil {
			t.Fatal(err)
		}
		decls = append(decls, f.Decls...)
	}
	for _, d := range decls {
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
		// Every selector, not only a CallExpr.Fun: a method value (`f := g.store.MarkSolved`,
		// `go g.help`) reaches the same method.
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch x := sel.X.(type) {
			case *ast.Ident: // g.method
				if x.Name == recv {
					calls[name] = append(calls[name], sel.Sel.Name)
				}
			case *ast.SelectorExpr: // g.store.write
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

// packageSources reads every non-test .go file of this package.
func packageSources(t *testing.T) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string]string{}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		srcs[n] = string(b)
	}
	return srcs
}

func TestGrader_EntryTableIsComplete(t *testing.T) {
	srcs := packageSources(t)
	got := graderWriteEntries(t, srcs)
	if len(srcs) < 2 || len(got) < 5 { // fail closed: an extractor that sees nothing proves nothing
		t.Fatalf("found %v in %d files of package scoring; the scan is not seeing the Grader", got, len(srcs))
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
		{"write as a method value", head + "func (g *Grader) A(user string) { f := g.store.MarkSolved; f(user, \"c\", \"t\") }", []string{"A"}},
		{"helper reached as a method value", head +
			"func (g *Grader) A(user string) { f := g.help; f(user) }\nfunc (g *Grader) help(user string) { g.store.MarkDirty(user, \"c\", \"r\", \"t\") }", []string{"A"}},
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
			if got := graderWriteEntries(t, map[string]string{"scoring.go": c.src}); !slices.Equal(got, c.want) {
				t.Fatalf("entries = %v, want %v", got, c.want)
			}
		})
	}
}

// An entry defined in ANOTHER file of the package, or reaching its write through a
// helper defined there, is found: the guard does not read scoring.go alone.
func TestGraderWriteEntries_Scan_AcrossFiles(t *testing.T) {
	const head = "package scoring\n"
	srcs := map[string]string{
		"scoring.go": head + "type Grader struct{ store ScoreStore }\nfunc (g *Grader) Old(user string) { g.store.MarkSolved(user, \"c\", \"t\") }",
		"replay.go":  head + "func (g *Grader) Replay(who string) { g.write(who) }",
		"helper.go":  head + "func (g *Grader) write(who string) { g.store.RecordExfil(who, \"c\", \"f\", \"t\") }",
		"reads.go":   head + "func (g *Grader) Peek(user string) bool { return g.store.IsSolved(user, \"c\") }",
	}
	if got, want := graderWriteEntries(t, srcs), []string{"Old", "Replay"}; !slices.Equal(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
}

// storeWriteCalls returns "<line>: <call>" for each reference in src to a store
// write (a call, or a method value such as `f := st.MarkSolved`) that is not the
// Grader's own same-named RecordExfil (receiver `grader`). A method value counts
// because the api handler holds Grader.RecordExfil / SubmitEvade as fields, test
// seams (app#486), and `recordExfil: grader.RecordExfil` is no call.
func storeWriteCalls(t *testing.T, name, src string) (violations []string, writes int) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || !slices.Contains(storeWrites, sel.Sel.Name) {
			return true
		}
		writes++
		if sel.Sel.Name == "RecordExfil" && lastName(sel.X) == "grader" {
			return true // Grader.RecordExfil, the entry itself
		}
		violations = append(violations, fset.Position(sel.Pos()).String()+": "+sel.Sel.Name)
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
		{"the Grader's RecordExfil as a method value is the door", "h.recordExfil = grader.RecordExfil", 0},
		{"a store write as a method value is not", "w := h.store.MarkSolved", 1},
		{"a store RecordExfil as a method value is not", "h.recordExfil = store.RecordExfil", 1},
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
