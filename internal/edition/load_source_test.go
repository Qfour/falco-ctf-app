package edition_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ADR-0056 D8 (iii) and D19 A2b, fixed by reading the sources (ADR-0033 D6 does the
// same for the flags file): the answers table has ONE door.
//
//   - edition.NewJudge is called by edition.Load (internal/edition/load.go, func
//     Load) and by practiceJudge (the practice mode's Judge, A4a-2, same file), and by
//     nothing else in a non-test file;
//   - practiceJudge is called by edition.Load and by nothing else, and only inside the
//     body of an `if` whose condition has `!eventMode` (TestPracticeJudgeIsOnlyReached
//     OutsideTheEventMode): in the event mode no Judge is made from the practice
//     answers (D8 (iii), V36);
//   - edition.Parse is called by edition.Load and by loadPractice, the unexported
//     reader of the practice answers (A4a-1), in the same file; loadPractice is called
//     by edition.Load (T6 in the event mode) and by practiceJudge and by nothing else,
//     so the practice answers have one reader and it has two callers;
//   - edition.Load is called by cmd/scoreboard, exactly once, and by nothing else;
//   - load.go holds no PracticeSet literal (TestLoadHasNoPracticeLiteral).
//
// A second reader of the table would be a second place where the practice answers
// could be read in the event mode, or where a value is parsed without Check.

const editionImportPath = "github.com/Qfour/falco-ctf-app/internal/edition"

// doorGuarded are the names of this package that only the door may use.
var doorGuarded = []string{"Parse", "NewJudge", "Load", "loadPractice", "practiceJudge"}

// doorUse is one reference to a guarded name: the file (slash path from the repo
// root), the enclosing function ("" outside any function), the name, and whether
// the reference is the function of a call expression (call) or something else, such
// as `var f = edition.Load`: a value carried around would make the door a name that
// can be used anywhere, so only a call expression is the door.
type doorUse struct {
	file string
	fn   string
	name string
	call bool
}

// doorUses lists the references to Parse, NewJudge and Load in one non-test file.
// A reference is a qualified one (edition.X, through whatever name the file imports
// the package under), or, in a file of the package itself, a bare name. A dot import
// of the package is reported as a (non-call) use of every guarded name.
func doorUses(file, src string) ([]doorUse, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		return nil, err
	}
	inPackage := f.Name.Name == "edition" && strings.HasPrefix(file, "internal/edition/")
	local := ""
	var uses []doorUse
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != editionImportPath {
			continue
		}
		switch {
		case imp.Name == nil:
			local = "edition"
		case imp.Name.Name == ".":
			for _, n := range doorGuarded {
				uses = append(uses, doorUse{file: file, name: n})
			}
		case imp.Name.Name != "_":
			local = imp.Name.Name
		}
	}
	fn := ""
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			// A call whose function is a guarded name is recorded as a call; every
			// other reference (below) is not.
			name := ""
			switch fun := x.Fun.(type) {
			case *ast.SelectorExpr:
				if id, ok := fun.X.(*ast.Ident); ok && local != "" && id.Name == local && slices.Contains(doorGuarded, fun.Sel.Name) {
					name = fun.Sel.Name
				}
			case *ast.Ident:
				if inPackage && slices.Contains(doorGuarded, fun.Name) {
					name = fun.Name
				}
			}
			if name == "" {
				return true
			}
			uses = append(uses, doorUse{file: file, fn: fn, name: name, call: true})
			for _, a := range x.Args {
				ast.Inspect(a, visit)
			}
			return false
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && slices.Contains(doorGuarded, x.Sel.Name) {
				uses = append(uses, doorUse{file: file, fn: fn, name: x.Sel.Name})
			}
			// A selector's own Sel is a field or method name, not a bare identifier of
			// this package: look into X only.
			ast.Inspect(x.X, visit)
			return false
		case *ast.Ident:
			if inPackage && slices.Contains(doorGuarded, x.Name) {
				uses = append(uses, doorUse{file: file, fn: fn, name: x.Name})
			}
		}
		return true
	}
	for _, d := range f.Decls {
		fn = ""
		if fd, ok := d.(*ast.FuncDecl); ok {
			// The body only: the declared name (func Load) is not a use of it.
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

// doorViolations judges the uses of every non-test file of the program (the map is
// slash path -> source) against the rule above, and reports what it found: the
// violations, and how many allowed calls there were, by "name@enclosing function"
// (the positive side of the check: a scan that finds nothing is not a pass).
func doorViolations(files map[string]string) (violations []string, counts map[string]int) {
	counts = map[string]int{}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		uses, err := doorUses(p, files[p])
		if err != nil {
			violations = append(violations, p+": does not parse: "+err.Error())
			continue
		}
		for _, u := range uses {
			where := p
			if u.fn != "" {
				where += " (func " + u.fn + ")"
			}
			switch u.name {
			case "Parse":
				// Load, and loadPractice (the practice answers, A4a-1), which only Load calls.
				if p != "internal/edition/load.go" || (u.fn != "Load" && u.fn != "loadPractice") || !u.call {
					violations = append(violations, where+": Parse is used outside a call in edition.Load or loadPractice")
					continue
				}
				counts["Parse@"+u.fn]++
			case "NewJudge":
				// A Judge is made from the event table (Load) or, outside the event mode,
				// from the practice answers of the scope (practiceJudge): never from
				// loadPractice, the reader.
				if p != "internal/edition/load.go" || (u.fn != "Load" && u.fn != "practiceJudge") || !u.call {
					violations = append(violations, where+": NewJudge is used outside a call in edition.Load or practiceJudge")
					continue
				}
				counts["NewJudge@"+u.fn]++
			case "loadPractice":
				if p != "internal/edition/load.go" || (u.fn != "Load" && u.fn != "practiceJudge") || !u.call {
					violations = append(violations, where+": loadPractice is used outside a call in edition.Load or practiceJudge (it is the one reader of the practice answers)")
					continue
				}
				counts["loadPractice@"+u.fn]++
			case "practiceJudge":
				// The practice mode's Judge: Load is its only caller (and the branch it is
				// called in is checked by practiceJudgeBranch).
				if p != "internal/edition/load.go" || u.fn != "Load" || !u.call {
					violations = append(violations, where+": practiceJudge is used outside a call in edition.Load")
					continue
				}
				counts["practiceJudge@Load"]++
			case "Load":
				if !strings.HasPrefix(p, "cmd/scoreboard/") {
					violations = append(violations, where+": edition.Load is used outside cmd/scoreboard")
					continue
				}
				if !u.call {
					violations = append(violations, where+": edition.Load is taken as a value; only a call expression is the door")
					continue
				}
				counts["Load@cmd/scoreboard"]++
			}
		}
	}
	if counts["Load@cmd/scoreboard"] > 1 {
		violations = append(violations, "cmd/scoreboard calls edition.Load more than once; the door is one call")
	}
	return violations, counts
}

func TestAnswersTableHasOneDoor(t *testing.T) {
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
	violations, counts := doorViolations(files)
	for _, v := range violations {
		t.Error(v)
	}
	// Positive: the door is there, once, and so is the practice reader. A scan that
	// finds nothing is not a pass.
	if !maps.Equal(counts, wantDoorCounts) {
		t.Errorf("calls found = %v, want %v", counts, wantDoorCounts)
	}
}

// wantDoorCounts is the whole of what the program may call: see the header.
// A4a-2 added NewJudge@practiceJudge, loadPractice@practiceJudge and
// practiceJudge@Load (the practice mode's Judge); the other five are as before.
var wantDoorCounts = map[string]int{
	"Parse@Load":                 1,
	"Parse@loadPractice":         1,
	"NewJudge@Load":              1,
	"NewJudge@practiceJudge":     1,
	"loadPractice@Load":          1,
	"loadPractice@practiceJudge": 1,
	"practiceJudge@Load":         1,
	"Load@cmd/scoreboard":        1,
}

// ADR-0056 D19 A4a-1 / V34: the Options that Load hands to Check carry the practice
// answers loadPractice read, never a literal PracticeSet (which would be "no practice
// answers" written by hand: the T6 that never refuses). The check is on the syntax of
// load.go: no composite literal of type PracticeSet anywhere in it.
func practiceLiterals(file, src string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, 0)
	if err != nil {
		return nil, err
	}
	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		switch ty := cl.Type.(type) {
		case *ast.Ident:
			if ty.Name == "PracticeSet" {
				found = append(found, "PracticeSet{...}")
			}
		case *ast.SelectorExpr:
			if ty.Sel.Name == "PracticeSet" {
				found = append(found, "edition.PracticeSet{...}")
			}
		}
		return true
	})
	return found, nil
}

func TestLoadHasNoPracticeLiteral(t *testing.T) {
	b, err := os.ReadFile("load.go")
	if err != nil {
		t.Fatal(err)
	}
	got, err := practiceLiterals("internal/edition/load.go", string(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("load.go holds a PracticeSet literal %v; the set comes from loadPractice", got)
	}
	// The scan itself: the old shape, and a qualified one, are seen; make() is not a literal.
	for name, src := range map[string]string{
		"the old shape":   "package edition\n\nvar o = Options{Practice: PracticeSet{}}\n",
		"a qualified one": "package x\n\nvar o = edition.Options{Practice: edition.PracticeSet{}}\n",
	} {
		if got, err := practiceLiterals("x.go", src); err != nil || len(got) != 1 {
			t.Errorf("%s: found %v (err %v), want one literal", name, got, err)
		}
	}
	if got, err := practiceLiterals("x.go", "package edition\n\nvar s = make(PracticeSet)\n"); err != nil || len(got) != 0 {
		t.Errorf("make(PracticeSet) was reported: %v (err %v)", got, err)
	}
}

// The scanner itself: a copy with one deliberate violation is reported, and the
// shape that is allowed is not.
func TestAnswersTableDoorScan_SeesAViolation(t *testing.T) {
	const loadSrc = "package edition\n\nfunc Load(eventMode bool) {\n\t_, _ = Parse(nil)\n\t_, _ = NewJudge(nil)\n\t_, _ = loadPractice(\"\")\n\tif !eventMode {\n\t\t_, _ = practiceJudge()\n\t}\n}\n\nfunc loadPractice(string) (int, error) {\n\t_, _ = Parse(nil)\n\treturn 0, nil\n}\n\nfunc practiceJudge() (int, error) {\n\t_, _ = NewJudge(nil)\n\t_, _ = loadPractice(\"\")\n\treturn 0, nil\n}\n"
	const mainSrc = "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc main() {\n\tedition.Load()\n}\n"
	good := map[string]string{"internal/edition/load.go": loadSrc, "cmd/scoreboard/edition.go": mainSrc}
	if v, c := doorViolations(good); len(v) != 0 || !maps.Equal(c, wantDoorCounts) {
		t.Fatalf("the allowed shape: violations %v, calls %v, want none and %v", v, c, wantDoorCounts)
	}

	cases := []struct {
		name string
		path string
		src  string
	}{
		{"Parse called by a package that imports edition", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { edition.Parse(nil) }\n"},
		{"NewJudge called through an alias", "internal/scoreboard/x.go", "package scoreboard\n\nimport ed \"" + editionImportPath + "\"\n\nfunc f() { ed.NewJudge(nil) }\n"},
		{"Load called outside cmd/scoreboard", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { edition.Load() }\n"},
		{"Load taken as a value in cmd/scoreboard", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.Load\n"},
		{"Load taken as a value elsewhere", "internal/scoreboard/y.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.Load\n"},
		{"Load called a second time in cmd/scoreboard", "cmd/scoreboard/y.go", mainSrc},
		{"Parse taken as a value in Load", "internal/edition/other.go", "package edition\n\nfunc Load() { f := Parse; _ = f }\n"},
		{"a dot import", "cmd/scoreboard/y.go", "package main\n\nimport . \"" + editionImportPath + "\"\n"},
		{"Parse called by another function of the package", "internal/edition/other.go", "package edition\n\nfunc other() { Parse(nil) }\n"},
		{"Parse called by Load in another file", "internal/edition/other.go", "package edition\n\nfunc Load() { Parse(nil) }\n"},
		{"Parse reached through a call chain", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _ = edition.Parse(nil).Seats() }\n"},
		// The practice reader (A4a-1): it may Parse, and nothing else may call it or make a Judge in it.
		{"NewJudge called by loadPractice", "internal/edition/load.go", "package edition\n\nfunc Load() {\n\t_, _ = loadPractice(\"\")\n}\n\nfunc loadPractice(string) (int, error) {\n\t_, _ = NewJudge(nil)\n\treturn 0, nil\n}\n"},
		{"loadPractice called by another function", "internal/edition/other.go", "package edition\n\nfunc other() { _, _ = loadPractice(\"\") }\n"},
		{"loadPractice taken as a value in Load", "internal/edition/other.go", "package edition\n\nfunc Load() { f := loadPractice; _ = f }\n"},
		{"Parse called by loadPractice in another file", "internal/edition/other.go", "package edition\n\nfunc loadPractice(string) { Parse(nil) }\n"},
		{"Parse called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _ = Parse(nil) }\n"},
		// The practice mode's Judge (A4a-2): Load alone calls practiceJudge; the Judge is
		// made in practiceJudge and in Load, in no third function; the reader has two callers.
		{"practiceJudge called by another function", "internal/edition/other.go", "package edition\n\nfunc other() { _, _ = practiceJudge() }\n"},
		{"practiceJudge called by Load in another file", "internal/edition/other.go", "package edition\n\nfunc Load() { _, _ = practiceJudge() }\n"},
		{"practiceJudge taken as a value in Load", "internal/edition/other.go", "package edition\n\nfunc Load() { f := practiceJudge; _ = f }\n"},
		{"NewJudge called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _ = NewJudge(nil) }\n"},
		{"loadPractice called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _ = loadPractice(\"\") }\n"},
		{"practiceJudge called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _ = practiceJudge() }\n"},
	}
	for _, c := range cases {
		files := map[string]string{"internal/edition/load.go": loadSrc, "cmd/scoreboard/edition.go": mainSrc, c.path: c.src}
		if v, _ := doorViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}

	// A method that is named Load or Parse on something else is not the door.
	other := "package scoreboard\n\nfunc f(x interface{ Load(); Parse() }) { x.Load(); x.Parse() }\n"
	if v, _ := doorViolations(map[string]string{"internal/scoreboard/x.go": other}); len(v) != 0 {
		t.Errorf("a method call on another type was reported: %v", v)
	}
}

// ADR-0056 D8 (iii) and D19 A4a-2 / V36: in the event mode no Judge is made from the
// practice answers. practiceJudge is the one function that does, so it may be reached
// from edition.Load only inside the body of an `if` whose condition cannot hold
// unless eventMode is false.

// impliesNotEventMode reports whether e cannot be true while eventMode is true:
// `!eventMode`, in parentheses or as an operand of &&. A condition that lets the
// branch be taken another way (an ||, a bare eventMode) does not count.
func impliesNotEventMode(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return impliesNotEventMode(x.X)
	case *ast.UnaryExpr:
		id, ok := x.X.(*ast.Ident)
		return x.Op == token.NOT && ok && id.Name == "eventMode"
	case *ast.BinaryExpr:
		return x.Op == token.LAND && (impliesNotEventMode(x.X) || impliesNotEventMode(x.Y))
	}
	return false
}

// practiceJudgeCalls counts the calls to practiceJudge in the body of func Load of
// src, and how many of them are not in the Body of an if that impliesNotEventMode
// (the Else of such an if is the event mode's side, so it is not guarded).
func practiceJudgeCalls(file, src string) (total, unguarded int, err error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, 0)
	if err != nil {
		return 0, 0, err
	}
	var load *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "Load" {
			load = fd
		}
	}
	if load == nil || load.Body == nil {
		return 0, 0, errors.New("func Load not found")
	}
	var walk func(n ast.Node, guarded bool)
	walk = func(n ast.Node, guarded bool) {
		ast.Inspect(n, func(x ast.Node) bool {
			switch x := x.(type) {
			case *ast.IfStmt:
				if x.Init != nil {
					walk(x.Init, guarded)
				}
				walk(x.Cond, guarded)
				walk(x.Body, guarded || impliesNotEventMode(x.Cond))
				if x.Else != nil {
					walk(x.Else, guarded)
				}
				return false
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "practiceJudge" {
					total++
					if !guarded {
						unguarded++
					}
				}
			}
			return true
		})
	}
	walk(load.Body, false)
	return total, unguarded, nil
}

func TestPracticeJudgeIsOnlyReachedOutsideTheEventMode(t *testing.T) {
	b, err := os.ReadFile("load.go")
	if err != nil {
		t.Fatal(err)
	}
	total, unguarded, err := practiceJudgeCalls("load.go", string(b))
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("func Load calls practiceJudge %d time(s), want exactly 1 (a scan that finds nothing is not a pass)", total)
	}
	if unguarded != 0 {
		t.Errorf("func Load calls practiceJudge %d time(s) outside an `if !eventMode` branch: in the event mode no Judge is made from the practice answers (D8 (iii))", unguarded)
	}

	// The scan itself: the allowed shapes pass, every other way to reach the call is seen.
	cases := []struct {
		name      string
		body      string
		total     int
		unguarded int
	}{
		{"the branch", "if !eventMode {\n\t\t_, _ = practiceJudge()\n\t}", 1, 0},
		{"the branch with another operand", "if !eventMode && x {\n\t\t_, _ = practiceJudge()\n\t}", 1, 0},
		{"the branch in parentheses", "if (!eventMode) {\n\t\t_, _ = practiceJudge()\n\t}", 1, 0},
		{"a nested if inside the branch", "if !eventMode {\n\t\tif x {\n\t\t\t_, _ = practiceJudge()\n\t\t}\n\t}", 1, 0},
		{"no condition", "_, _ = practiceJudge()", 1, 1},
		{"the else of the branch (the event mode)", "if !eventMode {\n\t\t_ = 1\n\t} else {\n\t\t_, _ = practiceJudge()\n\t}", 1, 1},
		{"the condition without the negation", "if eventMode {\n\t\t_, _ = practiceJudge()\n\t}", 1, 1},
		{"an or, which the event mode can satisfy", "if !eventMode || x {\n\t\t_, _ = practiceJudge()\n\t}", 1, 1},
		{"another variable", "if !x {\n\t\t_, _ = practiceJudge()\n\t}", 1, 1},
		{"no call at all", "_ = x", 0, 0},
	}
	for _, c := range cases {
		src := "package edition\n\nfunc Load(eventMode, x bool) {\n\t" + c.body + "\n}\n"
		gotTotal, gotUnguarded, err := practiceJudgeCalls("x.go", src)
		if err != nil || gotTotal != c.total || gotUnguarded != c.unguarded {
			t.Errorf("%s: total %d, unguarded %d, err %v; want %d and %d", c.name, gotTotal, gotUnguarded, err, c.total, c.unguarded)
		}
	}
	if _, _, err := practiceJudgeCalls("x.go", "package edition\n\nfunc other() {}\n"); err == nil {
		t.Error("a file with no func Load was not reported")
	}
}
