package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"strings"
	"testing"
)

// ADR-0056 D10 B7 / B8 (b), D19 A4d-2c, fixed by reading the sources (the way
// render_reach_test.go fixes the renderer): the output half of B7 and B8 (b) is spread.go, and it
// is NOT a render file. It holds no key, draws no answer and opens no answers table, and the
// validator does not trust the renderer, so it must not be able to reach the renderer's door
// either:
//
//   - spread.go is not named render*.go, so render_reach_test.go does not count it as a file of
//     the renderer, and TestRenderIsNotReachableFromTheScoreboard holds it to the rule of a file
//     outside the renderer: it refers to no exported name a render file declares (MasterKey,
//     Render, RenderInput, ...) and calls no unexported function a render file declares (the
//     random source, the template fill). This test adds that the file is there and is not a
//     render file, and that the scan would see a reach from it.
//   - CheckDecoySpread is given the plaintext answers of a challenge (SeatAnswers, for a group in
//     a block: amendment 28 as revised, A7-x PR 2), so who may call it is fixed: the two checks
//     that hold the answers already, the self check of `edition render` (RenderEvent, the rows it
//     is about to write) and `edition check` (checkSpreads, the answers table of LoadEventTable).
//     A third reference to it anywhere outside test files (a call or a function value) is red.
//     CheckOutputSpace takes no answer, and its callers are not fixed (ADR-0056 asks for no
//     such pin).

const spreadPath = "internal/edition/spread.go"

func TestSpreadIsNotARenderFileAndDoesNotReachTheRenderer(t *testing.T) {
	files := nonTestSources(t)
	src, ok := files[spreadPath]
	if !ok {
		t.Fatalf("%s is not there", spreadPath)
	}
	if isRenderFile(spreadPath) {
		t.Errorf("%s is counted as a file of the renderer: B7 and B8 (b) hold no key and draw no answer, and must not be named render*.go", spreadPath)
	}
	exported, unexported := renderDeclarations(t, files)
	for _, name := range []string{"CheckDecoySpread", "CheckOutputSpace", "RuleDecoySpread", "CandidateFactor"} {
		if exported[name] {
			t.Errorf("a render file declares %s, which is B7 / B8 (b)'s", name)
		}
	}
	for _, name := range []string{"prepareSpread", "templateLayout", "fitsFormat", "fileTokens"} {
		if unexported[name] {
			t.Errorf("a render file declares %s, which spread.go declares", name)
		}
	}
	// The scan covers the file: nothing in spread.go reaches the renderer.
	for _, v := range renderReaches(t, files, nil) {
		if strings.HasPrefix(v, spreadPath) {
			t.Error(v)
		}
	}

	// The scan itself: a copy of spread.go with one reach into the renderer is reported (a
	// reach is reported for a file that is not a render file whatever it is called).
	base := map[string]string{
		"internal/edition/render.go": "package edition\n\nfunc Render() {}\n\nfunc render() {}\n\ntype MasterKey struct{}\n",
		spreadPath:                   src,
	}
	if v := renderReaches(t, base, nil); len(v) != 0 {
		t.Fatalf("the real spread.go reaches the renderer: %v", v)
	}
	for name, add := range map[string]string{
		"the key":              "\nvar planted MasterKey\n",
		"a call of Render":     "\nfunc planted() { Render() }\n",
		"a call of the render": "\nfunc planted2() { render() }\n",
	} {
		files := rdCopyFiles(base)
		files[spreadPath] = src + add
		if v := renderReaches(t, files, nil); len(v) == 0 {
			t.Errorf("%s: a reach from spread.go was not reported", name)
		}
	}
}

// decoySpreadCallers are the places of the non-test files that refer to CheckDecoySpread, as
// "path@function", and how many times each: the two checks that hold the answers already.
var decoySpreadCallers = map[string]int{
	"internal/edition/eventrender.go@RenderEvent": 1,
	"internal/edition/checkevent.go@checkSpreads": 1,
}

// decoySpreadRefs is every reference to the name CheckDecoySpread in the files (a call, a
// function value, a selector's name), by "path@function" (the function that holds it, "" at
// the package level), its declaration left out.
func decoySpreadRefs(t *testing.T, files map[string]string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for p, src := range files {
		f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
		if err != nil {
			t.Fatalf("%s does not parse: %v", p, err)
		}
		for _, d := range f.Decls {
			fn := ""
			var decl *ast.Ident
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn, decl = fd.Name.Name, fd.Name
			}
			ast.Inspect(d, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id != decl && id.Name == "CheckDecoySpread" {
					out[p+"@"+fn]++
				}
				return true
			})
		}
	}
	return out
}

// CheckDecoySpread takes the plaintext answers (SeatAnswers), so its callers are fixed: the self
// check of `edition render` and `edition check`, once each. A third caller, a function value of
// it, or one of the two calls taken out is red.
func TestCheckDecoySpreadIsCalledOnlyByTheTwoChecks(t *testing.T) {
	files := nonTestSources(t)
	if got := decoySpreadRefs(t, files); !maps.Equal(got, decoySpreadCallers) {
		t.Fatalf("the references to CheckDecoySpread are %v, want %v", got, decoySpreadCallers)
	}
	const checkCall = "CheckDecoySpread(cid, ed.spec, scope[cid], ed.template, ofChallenge, seatAnswersOf(table.table, cid))"
	src, ok := files["internal/edition/checkevent.go"]
	if !ok || strings.Count(src, checkCall) != 1 {
		t.Fatalf("checkevent.go does not hold the call %q once: the case below does not test what it says", checkCall)
	}
	for _, c := range []struct{ name, path, src string }{
		{"a third caller in the package", "internal/edition/other.go", "package edition\n\nfunc f() error { return CheckDecoySpread(\"\", nil, nil, nil, nil, nil) }\n"},
		{"a function value of it in cmd", "cmd/scoreboard/x.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.CheckDecoySpread\n"},
		{"the call of edition check taken out", "internal/edition/checkevent.go", strings.Replace(src, checkCall, "error(nil)", 1)},
	} {
		mutated := rdCopyFiles(files)
		mutated[c.path] = c.src
		if maps.Equal(decoySpreadRefs(t, mutated), decoySpreadCallers) {
			t.Errorf("%s: not reported", c.name)
		}
	}
}
