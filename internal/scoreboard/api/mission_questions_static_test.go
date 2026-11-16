package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// ADR-0056 D4 (review #615 R4#3): the journey is polled about every 2 seconds, and
// MissionDetail.questions reads the attempt budget from the store. One MissionDetail
// is ONE read of it: the package has exactly one call of AnswerAttempts, in
// missionQuestions (not in a loop, so not one per question), and missionDetail
// calls missionQuestions exactly once (not in a loop). A second read, or a read
// per question, would multiply a query that runs for every participant every
// 2 seconds.

type callSite struct {
	fn     string
	inLoop bool
}

// callSites lists every call of a function or method named name in src, with the
// declaration it is in and whether a for / range statement encloses it.
func callSites(t *testing.T, src, name string) []callSite {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var out []callSite
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		var stack []ast.Node
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var called string
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				called = fun.Sel.Name
			case *ast.Ident:
				called = fun.Name
			}
			if called != name {
				return true
			}
			loop := false
			for _, s := range stack {
				switch s.(type) {
				case *ast.ForStmt, *ast.RangeStmt:
					loop = true
				}
			}
			out = append(out, callSite{fn: fd.Name.Name, inLoop: loop})
			return true
		})
	}
	return out
}

// checkOneCall is the rule: exactly one call of name in srcs, in wantFn, not in a loop.
func checkOneCall(t *testing.T, srcs map[string]string, name, wantFn string) error {
	t.Helper()
	var all []string
	for file, src := range srcs {
		for _, s := range callSites(t, src, name) {
			if s.fn != wantFn || s.inLoop {
				return fmt.Errorf("%s: a call of %s in %s (in a loop: %v), want one call in %s, not in a loop", file, name, s.fn, s.inLoop, wantFn)
			}
			all = append(all, file)
		}
	}
	if len(all) != 1 {
		return fmt.Errorf("%d call(s) of %s (%v), want exactly 1 in %s", len(all), name, all, wantFn)
	}
	return nil
}

func TestCallSiteRule_Scan(t *testing.T) {
	const head = "package x\n"
	cases := []struct {
		name string
		srcs map[string]string
		want bool // true = the rule holds
	}{
		{"one read in the function", map[string]string{"a.go": head + "func missionQuestions() { st.AnswerAttempts(u, c) }"}, true},
		{"a read per question", map[string]string{"a.go": head + "func missionQuestions() { for range qs { st.AnswerAttempts(u, c) } }"}, false},
		{"a read in a closure in a loop", map[string]string{"a.go": head + "func missionQuestions() { for range qs { func() { st.AnswerAttempts(u, c) }() } }"}, false},
		{"a second read in the same function", map[string]string{"a.go": head + "func missionQuestions() { st.AnswerAttempts(u, c); st.AnswerAttempts(u, c) }"}, false},
		{"a read in another function", map[string]string{"a.go": head + "func missionQuestions() { st.AnswerAttempts(u, c) }\nfunc missionDetail() { st.AnswerAttempts(u, c) }"}, false},
		{"a read in another file", map[string]string{"a.go": head + "func missionQuestions() { st.AnswerAttempts(u, c) }", "b.go": head + "func g() { s.AnswerAttempts(u, c) }"}, false},
		{"no read at all", map[string]string{"a.go": head + "func missionQuestions() {}"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkOneCall(t, c.srcs, "AnswerAttempts", "missionQuestions")
			if (err == nil) != c.want {
				t.Fatalf("rule holds = %v, want %v (err=%v)", err == nil, c.want, err)
			}
		})
	}
}

func TestMissionDetail_OneStoreReadOfTheAnswerBudgetPerCall(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string]string{}
	for _, e := range entries {
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
	if _, ok := srcs["api.go"]; !ok || len(srcs) < 3 {
		t.Fatalf("the scan read %d source file(s) and not api.go: it is not looking at the package", len(srcs))
	}
	if err := checkOneCall(t, srcs, "AnswerAttempts", "missionQuestions"); err != nil {
		t.Error(err)
	}
	if err := checkOneCall(t, srcs, "missionQuestions", "missionDetail"); err != nil {
		t.Error(err)
	}
}
