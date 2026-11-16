package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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
//   - edition.Parse and edition.NewJudge are called by edition.Load (internal/edition/
//     load.go, func Load) and by nothing else in a non-test file;
//   - edition.Load is called by cmd/scoreboard, exactly once, and by nothing else.
//
// A second reader of the table would be a second place where the practice answers
// could be read in the event mode, or where a value is parsed without Check.

const editionImportPath = "github.com/Qfour/falco-ctf-app/internal/edition"

// doorGuarded are the names of this package that only the door may use.
var doorGuarded = []string{"Parse", "NewJudge", "Load"}

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
// slash path -> source) against the rule above, and reports what it found.
func doorViolations(files map[string]string) (violations []string, parse, newJudge, load int) {
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
			case "Parse", "NewJudge":
				if p != "internal/edition/load.go" || u.fn != "Load" || !u.call {
					violations = append(violations, where+": "+u.name+" is used outside a call in edition.Load")
					continue
				}
				if u.name == "Parse" {
					parse++
				} else {
					newJudge++
				}
			case "Load":
				if !strings.HasPrefix(p, "cmd/scoreboard/") {
					violations = append(violations, where+": edition.Load is used outside cmd/scoreboard")
					continue
				}
				if !u.call {
					violations = append(violations, where+": edition.Load is taken as a value; only a call expression is the door")
					continue
				}
				load++
			}
		}
	}
	if load > 1 {
		violations = append(violations, "cmd/scoreboard calls edition.Load more than once; the door is one call")
	}
	return violations, parse, newJudge, load
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
	violations, parse, newJudge, load := doorViolations(files)
	for _, v := range violations {
		t.Error(v)
	}
	// Positive: the door is there, once. A scan that finds nothing is not a pass.
	if parse != 1 || newJudge != 1 {
		t.Errorf("edition.Load calls Parse %d time(s) and NewJudge %d time(s), want 1 and 1", parse, newJudge)
	}
	if load != 1 {
		t.Errorf("cmd/scoreboard calls edition.Load %d time(s), want exactly 1", load)
	}
}

// The scanner itself: a copy with one deliberate violation is reported, and the
// shape that is allowed is not.
func TestAnswersTableDoorScan_SeesAViolation(t *testing.T) {
	const loadSrc = "package edition\n\nfunc Load() {\n\t_, _ = Parse(nil)\n\t_, _ = NewJudge(nil)\n}\n"
	const mainSrc = "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc main() {\n\tedition.Load()\n}\n"
	good := map[string]string{"internal/edition/load.go": loadSrc, "cmd/scoreboard/edition.go": mainSrc}
	if v, p, n, l := doorViolations(good); len(v) != 0 || p != 1 || n != 1 || l != 1 {
		t.Fatalf("the allowed shape: violations %v, parse %d, newJudge %d, load %d", v, p, n, l)
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
	}
	for _, c := range cases {
		files := map[string]string{"internal/edition/load.go": loadSrc, "cmd/scoreboard/edition.go": mainSrc, c.path: c.src}
		if v, _, _, _ := doorViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}

	// A method that is named Load or Parse on something else is not the door.
	other := "package scoreboard\n\nfunc f(x interface{ Load(); Parse() }) { x.Load(); x.Parse() }\n"
	if v, _, _, _ := doorViolations(map[string]string{"internal/scoreboard/x.go": other}); len(v) != 0 {
		t.Errorf("a method call on another type was reported: %v", v)
	}
}
