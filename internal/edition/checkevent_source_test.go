package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// ADR-0056 D20 and amendment 12 (V78, V86), fixed by reading the source of checkevent.go: a
// *CheckedEvent is the proof that every check of D20 passed, so CheckEvent may make it only
// after the last of them, and every way out before that gives no event.
//
//   - every gate of the list below is called in the body of CheckEvent, once, in the order D20
//     gives (the usage errors first, then steps 1 to 8: B4, B7 / B8 (b) and B10 last);
//   - the composite literal of CheckedEvent is in CheckEvent once, after the last gate (the
//     scan that no other file makes one is validator_door_source_test.go's);
//   - every return before that literal has the untyped nil as its first result, and the
//     return after it has the literal.
//
// The calls are matched by name (a selector's last name or an identifier): there is no type
// information in a parse, and none of these names is another function's in the file.

const checkEventPath = "internal/edition/checkevent.go"

// checkEventGates are the calls of CheckEvent's body, in the order they must come in.
var checkEventGates = []string{
	"validate",
	"readSeatsFile",
	"readPreviousDigests",
	"LoadScored",
	"readRenderRecord",
	"ScopeDigest",
	"LoadEventTable",
	"readEditions",
	"checkEditions",
	"hintInputs",
	"ReadCorpus",
	"CheckBundles",
	"checkPracticeOverlap",
	"checkSpreads",
	"checkCrossChallenges",
	"checkRowRules",
	"checkPracticeClues",
	"checkContinuity",
}

// checkEventViolations judges the source of checkevent.go (path p).
func checkEventViolations(p, src string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		return []string{p + ": does not parse: " + err.Error()}
	}
	var fd *ast.FuncDecl
	for _, d := range f.Decls {
		if x, ok := d.(*ast.FuncDecl); ok && x.Recv == nil && x.Name.Name == "CheckEvent" {
			fd = x
		}
	}
	if fd == nil || fd.Body == nil {
		return []string{p + ": func CheckEvent is not found"}
	}
	calls := map[string][]token.Pos{}
	var literals []token.Pos
	var returns []*ast.ReturnStmt
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false // a closure's return is not CheckEvent's
		case *ast.CallExpr:
			switch fun := x.Fun.(type) {
			case *ast.Ident:
				calls[fun.Name] = append(calls[fun.Name], x.Pos())
			case *ast.SelectorExpr:
				calls[fun.Sel.Name] = append(calls[fun.Sel.Name], x.Pos())
			}
		case *ast.CompositeLit:
			if id, ok := x.Type.(*ast.Ident); ok && id.Name == "CheckedEvent" {
				literals = append(literals, x.Pos())
			}
		case *ast.ReturnStmt:
			returns = append(returns, x)
		}
		return true
	})

	var out []string
	last := token.NoPos
	prev := token.NoPos
	for _, g := range checkEventGates {
		pos := calls[g]
		switch {
		case len(pos) != 1:
			out = append(out, p+": CheckEvent calls "+g+" "+strconv.Itoa(len(pos))+" time(s), want exactly 1")
			continue
		case pos[0] < prev:
			out = append(out, p+": CheckEvent calls "+g+" before an earlier gate of D20's order")
		}
		prev = pos[0]
		if pos[0] > last {
			last = pos[0]
		}
	}
	if len(literals) != 1 {
		return append(out, p+": CheckEvent makes "+strconv.Itoa(len(literals))+" CheckedEvent literal(s), want exactly 1")
	}
	if literals[0] < last {
		out = append(out, p+": CheckEvent makes the CheckedEvent before its last gate")
	}
	finals := 0
	for _, r := range returns {
		first := ""
		if len(r.Results) > 0 {
			switch x := r.Results[0].(type) {
			case *ast.Ident:
				first = x.Name
			case *ast.UnaryExpr:
				first = "&literal"
			}
		}
		switch {
		case r.Pos() <= literals[0] && literals[0] <= r.End():
			// the return that carries the literal: the only way out with an event
			if first != "&literal" {
				out = append(out, p+": the return that holds the CheckedEvent does not give it as the event")
			}
			finals++
		case r.End() < literals[0] && first != "nil":
			out = append(out, p+": a return of CheckEvent before the CheckedEvent is made gives something other than nil as the event")
		case r.Pos() > literals[0]:
			out = append(out, p+": CheckEvent returns after the CheckedEvent was made, other than by giving it")
		}
	}
	if finals != 1 {
		out = append(out, p+": CheckEvent has "+strconv.Itoa(finals)+" return(s) that give the CheckedEvent after it is made, want exactly 1")
	}
	if len(returns) < 2 {
		out = append(out, p+": CheckEvent has fewer than two returns: the scan does not see its exits")
	}
	return out
}

func TestCheckEventRunsEveryGateBeforeItMakesTheEvent(t *testing.T) {
	src, ok := nonTestSources(t)[checkEventPath]
	if !ok {
		t.Fatalf("%s is not there", checkEventPath)
	}
	for _, v := range checkEventViolations(checkEventPath, src) {
		t.Error(v)
	}

	// The scan itself: copies of the real file with one change each.
	cases := []struct{ name, old, repl string }{
		{"the continuity (B10) is not run", "\trefusals = append(refusals, checkContinuity(bundles.rows, previous, !in.NoPrevious))\n", ""},
		{"B4 is not run", "\treport.Overlap = checkPracticeOverlap(", "\treport.Overlap = OverlapReport{}\n\t_ = checkPracticeOverlap_removed("},
		{"B13 to B16 are not run", "\trefusals = append(refusals, checkCrossChallenges(scope, scored.Catalog, editions, bundles.bundles, table))\n", ""},
		{"B13 to B16 are run after B10", "\trefusals = append(refusals, checkCrossChallenges(scope, scored.Catalog, editions, bundles.bundles, table))\n\trefusals = append(refusals, checkRowRules(scope, editions))\n\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n\trefusals = append(refusals, checkContinuity(bundles.rows, previous, !in.NoPrevious))\n", "\trefusals = append(refusals, checkRowRules(scope, editions))\n\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n\trefusals = append(refusals, checkContinuity(bundles.rows, previous, !in.NoPrevious))\n\trefusals = append(refusals, checkCrossChallenges(scope, scored.Catalog, editions, bundles.bundles, table))\n"},
		{"B17 and B19 are not run", "\trefusals = append(refusals, checkRowRules(scope, editions))\n", ""},
		{"B17 and B19 are run after B10", "\trefusals = append(refusals, checkRowRules(scope, editions))\n\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n\trefusals = append(refusals, checkContinuity(bundles.rows, previous, !in.NoPrevious))\n", "\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n\trefusals = append(refusals, checkContinuity(bundles.rows, previous, !in.NoPrevious))\n\trefusals = append(refusals, checkRowRules(scope, editions))\n"},
		{"B18 is not run", "\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n", ""},
		{"B18 is run twice", "\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n", "\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n"},
		{"B18 is run after B10", "\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n\trefusals = append(refusals, checkContinuity(bundles.rows, previous, !in.NoPrevious))\n", "\trefusals = append(refusals, checkContinuity(bundles.rows, previous, !in.NoPrevious))\n\trefusals = append(refusals, checkPracticeClues(scope, editions, table))\n"},
		{"B7 and B8 (b) are run twice", "\trefusals = append(refusals, checkSpreads(scope, editions, bundles.bundles, table))\n", "\trefusals = append(refusals, checkSpreads(scope, editions, bundles.bundles, table))\n\trefusals = append(refusals, checkSpreads(scope, editions, bundles.bundles, table))\n"},
		{"the render record is not read", "\trecord, err := readRenderRecord(in.RenderRecordFile)\n", "\trecord, err := renderRecord{}, error(nil)\n"},
		{"B12 is not run", "\tif record.scope != ScopeDigest(scored.Order) {\n", "\tif record.scope == \"\" {\n"},
		{"the render record is read after the table", "\t// 2. The answers table.\n\ttable, runID, err := LoadEventTable(scored, in.AnswersFile)\n", "\t// 2. The answers table.\n\ttable, runID, err := LoadEventTable(scored, in.AnswersFile)\n\t_, _ = readRenderRecord(in.RenderRecordFile)\n"},
		{"the event is made before the last gate", "\tvar refusals []error\n", "\t_ = &CheckedEvent{}\n\tvar refusals []error\n"},
		{"an exit gives an event", "\tscope := ScopeOf(scored.Catalog)\n", "\tscope := ScopeOf(scored.Catalog)\n\tif len(seats) > 0 {\n\t\treturn ev, report, nil\n\t}\n"},
		{"the final return gives no event", "\treturn &CheckedEvent{runID: bundles.runID", "\treturn nil, report, nil\n\t_ = &CheckedEvent{runID: bundles.runID"},
	}
	for _, c := range cases {
		mutated := replaceOnce(t, src, c.old, c.repl)
		if v := checkEventViolations(checkEventPath, mutated); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	if v := checkEventViolations(checkEventPath, "package edition\n\nfunc other() {}\n"); len(v) == 0 {
		t.Error("a file with no CheckEvent was not reported")
	}
	if v := checkEventViolations(checkEventPath, "package edition\n\nfunc ("); len(v) == 0 {
		t.Error("a file that does not parse was not reported")
	}
}
