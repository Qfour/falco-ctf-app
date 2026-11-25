package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"strings"
	"testing"
)

// ADR-0056 D10 B13 to B16 (amendment 26, A7-x PR 3), fixed by reading the sources (the way
// spread_source_test.go fixes B7): CheckCrossChallenge is given the plaintext answers of every
// investigate challenge of a scope (CrossChallenge.Answers, a SeatAnswers), so who may call it is
// fixed: `edition check` (checkCrossChallenges in checkevent.go, with the answers table of
// LoadEventTable), once. A second reference to it anywhere outside test files (a call or a function
// value) is red. crosschallenge.go is not a render file (it holds no key and draws no answer), so
// render_reach_test.go holds it to the rule of a file outside the renderer; this test adds that the
// scan sees it.

const crossPath = "internal/edition/crosschallenge.go"

// crossCallers are the places of the non-test files that refer to CheckCrossChallenge.
var crossCallers = map[string]int{
	"internal/edition/checkevent.go@checkCrossChallenges": 1,
}

// identRefs is every reference to the identifier name in the files (a call, a function value, a
// selector's name), by "path@function" (the function that holds it, "" at the package level),
// the declaration of a function of that name left out.
func identRefs(t *testing.T, files map[string]string, name string) map[string]int {
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
				if id, ok := n.(*ast.Ident); ok && id != decl && id.Name == name {
					out[p+"@"+fn]++
				}
				return true
			})
		}
	}
	return out
}

func TestCheckCrossChallengeIsCalledOnlyByEditionCheck(t *testing.T) {
	files := nonTestSources(t)
	if got := identRefs(t, files, "CheckCrossChallenge"); !maps.Equal(got, crossCallers) {
		t.Fatalf("the references to CheckCrossChallenge are %v, want %v", got, crossCallers)
	}
	const call = "CheckCrossChallenge(chs)"
	src, ok := files["internal/edition/checkevent.go"]
	if !ok || strings.Count(src, call) != 1 {
		t.Fatalf("checkevent.go does not hold the call %q once: the case below does not test what it says", call)
	}
	for _, c := range []struct{ name, path, src string }{
		{"a second caller in the package", "internal/edition/other.go", "package edition\n\nfunc f() { _, _ = CheckCrossChallenge(nil) }\n"},
		{"a function value of it in cmd", "cmd/scoreboard/x.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.CheckCrossChallenge\n"},
		{"the call of edition check taken out", "internal/edition/checkevent.go", strings.Replace(src, call, "CrossReport{}, error(nil)", 1)},
	} {
		mutated := rdCopyFiles(files)
		mutated[c.path] = c.src
		if maps.Equal(identRefs(t, mutated, "CheckCrossChallenge"), crossCallers) {
			t.Errorf("%s: not reported", c.name)
		}
	}
}

func TestCrossChallengeIsNotARenderFileAndDoesNotReachTheRenderer(t *testing.T) {
	files := nonTestSources(t)
	src, ok := files[crossPath]
	if !ok {
		t.Fatalf("%s is not there", crossPath)
	}
	if isRenderFile(crossPath) {
		t.Errorf("%s is counted as a file of the renderer: B13 to B16 hold no key and draw no answer", crossPath)
	}
	for _, v := range renderReaches(t, files, nil) {
		if strings.HasPrefix(v, crossPath) {
			t.Error(v)
		}
	}
	// The scan sees a reach from the file.
	base := map[string]string{
		"internal/edition/render.go": "package edition\n\nfunc Render() {}\n\ntype MasterKey struct{}\n",
		crossPath:                    src,
	}
	if v := renderReaches(t, base, nil); len(v) != 0 {
		t.Fatalf("the real crosschallenge.go reaches the renderer: %v", v)
	}
	planted := rdCopyFiles(base)
	planted[crossPath] = src + "\nfunc planted() { Render() }\n"
	if v := renderReaches(t, planted, nil); len(v) == 0 {
		t.Error("a call of Render from crosschallenge.go was not reported")
	}
}
