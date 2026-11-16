package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ADR-0056 D5 and D19 A3a, fixed by reading the sources (the same way
// load_source_test.go fixes the answers table's door): the comparison has ONE
// caller. Judge.Match (the four-argument method: seat, cid, qid, input) and
// Judge.OtherSeat are called by the Grader's SubmitAnswer
// (internal/scoreboard/scoring/answers.go, func SubmitAnswer) and by nothing else in
// a non-test file. A second caller would be a second place where an answer is
// compared without the count having been committed first, or where "which seat's
// value is this" is asked.
//
// Match is matched by name and by arity (four arguments): there is no type
// information in a parse, and a one-argument Match (regexp, the e2e harness) is
// another method. A Match or OtherSeat that is not called (a method value
// `f := j.Match`, passed on) would hide the call, so it is a violation wherever it
// is, the Grader included.

const (
	judgeDoorFile = "internal/scoreboard/scoring/answers.go"
	judgeDoorFunc = "SubmitAnswer"
	judgeMatchArg = 4
)

type judgeUse struct {
	file string
	fn   string
	name string
	call bool
}

// judgeUses lists the references to Match (four-argument calls, and any
// non-call reference) and OtherSeat in one non-test file.
func judgeUses(file, src string) ([]judgeUse, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, 0)
	if err != nil {
		return nil, err
	}
	var uses []judgeUse
	fn := ""
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if name := sel.Sel.Name; name == "OtherSeat" || (name == "Match" && len(x.Args) == judgeMatchArg) {
				uses = append(uses, judgeUse{file: file, fn: fn, name: name, call: true})
			}
			// Whatever the name and arity, the selector of a call is that call's own
			// (a one-argument Match is another method): look into its operand and its
			// arguments only.
			ast.Inspect(sel.X, visit)
			for _, a := range x.Args {
				ast.Inspect(a, visit)
			}
			return false
		case *ast.SelectorExpr:
			// Reached only for a selector that is not the function of a call: a method
			// value, which would hide the call.
			if x.Sel.Name == "OtherSeat" || x.Sel.Name == "Match" {
				uses = append(uses, judgeUse{file: file, fn: fn, name: x.Sel.Name})
			}
		}
		return true
	}
	for _, d := range f.Decls {
		fn = ""
		if fd, ok := d.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
			if fd.Body != nil {
				ast.Inspect(fd.Body, visit)
			}
			continue
		}
		ast.Inspect(d, visit)
	}
	return uses, nil
}

// judgeViolations judges the uses of every non-test file (slash path -> source) and
// returns what it found, with the number of Match and OtherSeat calls in the door.
func judgeViolations(files map[string]string) (violations []string, match, other int) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		uses, err := judgeUses(p, files[p])
		if err != nil {
			violations = append(violations, p+": does not parse: "+err.Error())
			continue
		}
		for _, u := range uses {
			where := p
			if u.fn != "" {
				where += " (func " + u.fn + ")"
			}
			if !u.call {
				violations = append(violations, where+": "+u.name+" is referenced without being called (a method value hides the call)")
				continue
			}
			if p != judgeDoorFile || u.fn != judgeDoorFunc {
				violations = append(violations, where+": "+u.name+" is called outside "+judgeDoorFunc+" in "+judgeDoorFile)
				continue
			}
			if u.name == "Match" {
				match++
			} else {
				other++
			}
		}
	}
	return violations, match, other
}

func TestJudgeComparisonHasOneCaller(t *testing.T) {
	files := map[string]string{}
	for _, root := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join("..", "..", root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(filepath.Join("..", ".."), path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 50 {
		t.Fatalf("read only %d non-test files; the walk is not seeing the tree", len(files))
	}
	if _, ok := files[judgeDoorFile]; !ok {
		t.Fatalf("%s is not in the tree: the door moved, and this test has to move with it", judgeDoorFile)
	}
	violations, match, other := judgeViolations(files)
	for _, v := range violations {
		t.Error(v)
	}
	// Positive: the door is there, once each. A scan that finds nothing is not a pass.
	if match != 1 || other != 1 {
		t.Errorf("%s (func %s) calls Match %d time(s) and OtherSeat %d time(s), want 1 and 1", judgeDoorFile, judgeDoorFunc, match, other)
	}
}

// The scanner itself: a copy with one deliberate violation is reported, and the
// allowed shape is not.
func TestJudgeDoorScan_SeesAViolation(t *testing.T) {
	const doorSrc = "package scoring\n\nfunc (g *Grader) SubmitAnswer() {\n\tg.judge.Match(\"s\", \"c\", \"q\", \"x\")\n\tg.judge.OtherSeat(\"s\", \"c\", \"q\", \"x\")\n}\n"
	good := map[string]string{judgeDoorFile: doorSrc}
	if v, m, o := judgeViolations(good); len(v) != 0 || m != 1 || o != 1 {
		t.Fatalf("the allowed shape: violations %v, match %d, other %d", v, m, o)
	}

	cases := []struct {
		name string
		path string
		src  string
	}{
		{"Match called in another package", "internal/scoreboard/api/x.go", "package api\n\nfunc f(j J) { j.Match(\"s\", \"c\", \"q\", \"x\") }\n"},
		{"OtherSeat called in another package", "internal/scoreboard/api/x.go", "package api\n\nfunc f(j J) { j.OtherSeat(\"s\", \"c\", \"q\", \"x\") }\n"},
		{"Match called by another function of the door's file", judgeDoorFile, doorSrc + "\nfunc (g *Grader) other() { g.judge.Match(\"s\", \"c\", \"q\", \"x\") }\n"},
		{"Match called a second time in SubmitAnswer's file by a helper", judgeDoorFile, doorSrc + "\nfunc helper(j J) { _, _ = j.Match(\"s\", \"c\", \"q\", \"x\") }\n"},
		{"Match taken as a method value", "internal/scoreboard/api/x.go", "package api\n\nfunc f(j J) { m := j.Match; m(\"s\", \"c\", \"q\", \"x\") }\n"},
		{"OtherSeat taken as a method value in the door", judgeDoorFile, "package scoring\n\nfunc (g *Grader) SubmitAnswer() { f := g.judge.OtherSeat; f(\"s\", \"c\", \"q\", \"x\") }\n"},
		{"Match reached through a call chain", "internal/scoreboard/api/x.go", "package api\n\nfunc f(j J) bool { ok, _ := h().Match(\"s\", \"c\", \"q\", \"x\"); return ok }\n"},
	}
	for _, c := range cases {
		files := map[string]string{judgeDoorFile: doorSrc, c.path: c.src}
		if c.path == judgeDoorFile {
			files = map[string]string{judgeDoorFile: c.src}
		}
		if v, _, _ := judgeViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}

	// A Match of another arity (regexp.Regexp.Match, the e2e harness) is not the
	// Judge's.
	other := "package x\n\nfunc f(re R, m M) { re.Match([]byte(\"a\")); m.Match(1) }\n"
	if v, m, o := judgeViolations(map[string]string{"internal/x/x.go": other}); len(v) != 0 || m != 0 || o != 0 {
		t.Errorf("a one-argument Match was reported: %v (%d, %d)", v, m, o)
	}
}
