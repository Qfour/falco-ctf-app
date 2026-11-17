package main

// ADR-0056 D20 (the reach of the commands) and V78, fixed by reading the sources (the way
// main_test.go fixes the catalog's wiring and internal/edition's source tests fix the doors):
//
//   - the types of the check's surface (CheckInput, CheckReport, InputError) are named by
//     editioncmd.go only. (Who calls edition.CheckEvent and edition.WriteDigestsFile, where and
//     how many times, is internal/edition/load_source_test.go's doorViolations, the one place
//     that holds it: runEditionCheck, once each);
//   - `scoreboard edition ...` is a subcommand that never starts the server: the first statement
//     of main() is `if len(os.Args) > 1 && os.Args[1] == "edition" { os.Exit(runEdition(...)) }`,
//     and runEdition is called there and nowhere else, so the server's path (everything after
//     that statement: the handler, the wiring, the listener) cannot reach the subcommand;
//   - nothing the subcommand file declares is named by another non-test file of cmd/scoreboard
//     (runEdition, by main's first statement only), so the server's code cannot reach it;
//   - the command opens and writes no file: editioncmd.go imports `errors`, `fmt`, `io`,
//     `strings` and internal/edition and nothing else (no `os`, no `io/fs`, no `path/filepath`,
//     no catalog), because the readers and the writers are internal/edition's (D20: the layers).
//
// A reference in a test file is not a use (only non-test files are read).

import (
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

const (
	cmdEditionImport = "github.com/Qfour/falco-ctf-app/internal/edition"
	cmdFile          = "cmd/scoreboard/editioncmd.go"
	cmdMainFile      = "cmd/scoreboard/main.go"
)

// checkSurface is the types of the check that only the `edition check` command may name. (The
// callers of CheckEvent and WriteDigestsFile are held by internal/edition's doorViolations.)
var checkSurface = []string{"CheckInput", "CheckReport", "InputError"}

// readNonTest reads the non-test .go files under cmd/ and internal/ (slash path from the repo
// root -> source).
func readNonTest(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, root := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join("..", "..", root), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(filepath.Join("..", ".."), p)
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
	return files
}

// importLocal is the name a file refers to package path by ("" when it does not import it, or
// only for effect), and whether it is a dot import.
func importLocal(f *ast.File, path string) (name string, dot bool) {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != path {
			continue
		}
		switch {
		case imp.Name == nil:
			return path[strings.LastIndex(path, "/")+1:], false
		case imp.Name.Name == ".":
			return "", true
		case imp.Name.Name == "_":
			return "", false
		}
		return imp.Name.Name, false
	}
	return "", false
}

// surfaceRefs counts every reference to a name of `names` of package edition, by
// "Name@file (func enclosing)", in the files given (slash path -> source). A reference is a
// selector through the import (a call or not), and a dot import is a problem of its own. The
// files of internal/edition itself are not scanned: they are the package.
func surfaceRefs(files map[string]string, names []string) (refs map[string]int, problems []string) {
	refs = map[string]int{}
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if strings.HasPrefix(p, "internal/edition/") && !strings.Contains(strings.TrimPrefix(p, "internal/edition/"), "/") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], 0)
		if err != nil {
			problems = append(problems, p+": does not parse: "+err.Error())
			continue
		}
		local, dot := importLocal(f, cmdEditionImport)
		if dot {
			problems = append(problems, p+": dot import of package edition (a name of the check could be used unseen)")
			continue
		}
		if local == "" {
			continue
		}
		for _, d := range f.Decls {
			fn := ""
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			ast.Inspect(d, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && slices.Contains(names, sel.Sel.Name) {
					refs[sel.Sel.Name+"@"+p+" (func "+fn+")"]++
				}
				return true
			})
		}
	}
	return refs, problems
}

// surfaceViolations is the rule of the test below: the types of the check's surface are named by
// the command's file and by no other non-test file of cmd/ and internal/ outside package edition
// (a dot import is a problem of its own, and a file that does not parse is reported).
func surfaceViolations(files map[string]string) []string {
	refs, problems := surfaceRefs(files, checkSurface)
	out := slices.Clone(problems)
	for _, key := range slices.Sorted(maps.Keys(refs)) {
		if !strings.Contains(key, "@"+cmdFile+" (func ") {
			out = append(out, key+": the surface of `edition check` is named outside the command")
		}
	}
	return out
}

// The place and the number of the callers of CheckEvent and WriteDigestsFile are held by ONE
// test, internal/edition's doorViolations (load_source_test.go). This one holds the types of
// the check's surface (CheckInput, CheckReport, InputError): only the command names them.
func TestOnlyTheCommandNamesTheSurfaceOfEditionCheck(t *testing.T) {
	files := readNonTest(t)
	for _, v := range surfaceViolations(files) {
		t.Error(v)
	}
	// Positive: the command names each type. A scan that finds nothing is not a pass.
	refs, _ := surfaceRefs(files, checkSurface)
	for _, name := range checkSurface {
		found := false
		for key := range refs {
			if strings.HasPrefix(key, name+"@"+cmdFile+" (func ") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not named by %s: the scan does not see the command", name, cmdFile)
		}
	}

	// The scan itself: the same function, on copies.
	const imp = "package main\n\nimport \"" + cmdEditionImport + "\"\n\n"
	base := map[string]string{cmdFile: imp + "func parse() (edition.CheckInput, error) { return edition.CheckInput{}, nil }\n\nfunc print(r edition.CheckReport, e *edition.InputError) {}\n"}
	if v := surfaceViolations(base); len(v) != 0 {
		t.Fatalf("the allowed shape: %v", v)
	}
	cases := []struct{ name, path, src string }{
		{"the input type in the server's wiring", "cmd/scoreboard/server.go", imp + "var in edition.CheckInput\n"},
		{"the report type in the handler", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + cmdEditionImport + "\"\n\nvar r edition.CheckReport\n"},
		{"the error type through an alias", "internal/scoreboard/x.go", "package scoreboard\n\nimport ed \"" + cmdEditionImport + "\"\n\nvar e *ed.InputError\n"},
		{"a dot import", "cmd/scoreboard/server.go", "package main\n\nimport . \"" + cmdEditionImport + "\"\n"},
		{"a file that does not parse", "cmd/scoreboard/x.go", "package main\n\nfunc ("},
	}
	for _, c := range cases {
		files := maps.Clone(base)
		files[c.path] = c.src
		if v := surfaceViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
}

// mainEditionBranchViolations judges the source of main.go (path p): the first statement of
// func main is the `edition` branch, which calls runEdition with the arguments after `edition`
// and the two streams, and ends the process with its result; and runEdition is called nowhere
// else in the file.
func mainEditionBranchViolations(p, src string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		return []string{p + ": does not parse: " + err.Error()}
	}
	var fd *ast.FuncDecl
	for _, d := range f.Decls {
		if x, ok := d.(*ast.FuncDecl); ok && x.Recv == nil && x.Name.Name == "main" {
			fd = x
		}
	}
	if fd == nil || fd.Body == nil || len(fd.Body.List) == 0 {
		return []string{p + ": func main is not found"}
	}
	var out []string
	first, ok := fd.Body.List[0].(*ast.IfStmt)
	if !ok || first.Init != nil || first.Else != nil {
		return append(out, p+": the first statement of main is not the plain `if` of the edition branch")
	}
	// condition: len(os.Args) > 1 && os.Args[1] == "edition"
	and, ok := first.Cond.(*ast.BinaryExpr)
	if !ok || and.Op != token.LAND {
		out = append(out, p+": the condition of the edition branch is not `a && b`")
	} else {
		if gt, ok := and.X.(*ast.BinaryExpr); !ok || gt.Op != token.GTR || !isLit(gt.Y, token.INT, "1") || !isCallTo(gt.X, "len") {
			out = append(out, p+": the first operand of the edition branch is not `len(os.Args) > 1`")
		}
		eq, ok := and.Y.(*ast.BinaryExpr)
		if !ok || eq.Op != token.EQL || !isLit(eq.Y, token.STRING, `"edition"`) || !isIndexOfOSArgs(eq.X, "1") {
			out = append(out, p+": the second operand of the edition branch is not `os.Args[1] == \"edition\"`")
		}
	}
	// body: exactly os.Exit(runEdition(os.Args[2:], os.Stdout, os.Stderr))
	if len(first.Body.List) != 1 {
		return append(out, p+": the edition branch does more than end the process")
	}
	es, ok := first.Body.List[0].(*ast.ExprStmt)
	exit, isCall := ast.Expr(nil), false
	if ok {
		exit, isCall = es.X, true
	}
	call, ok := exit.(*ast.CallExpr)
	if !isCall || !ok || !isSelector(call.Fun, "os", "Exit") || len(call.Args) != 1 {
		return append(out, p+": the edition branch does not end with os.Exit(runEdition(...))")
	}
	inner, ok := call.Args[0].(*ast.CallExpr)
	if !ok || !isIdent(inner.Fun, "runEdition") || len(inner.Args) != 3 {
		return append(out, p+": os.Exit in the edition branch is not given runEdition(args, stdout, stderr)")
	}
	if sl, ok := inner.Args[0].(*ast.SliceExpr); !ok || sl.High != nil || !isLit(sl.Low, token.INT, "2") {
		out = append(out, p+": runEdition is not given os.Args[2:]")
	}
	// runEdition is called here and nowhere else in the file
	n := 0
	ast.Inspect(f, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && id.Name == "runEdition" {
			n++
		}
		return true
	})
	if n != 1 {
		out = append(out, p+": runEdition is named "+strconv.Itoa(n)+" times in main.go, want exactly 1")
	}
	return out
}

func isLit(e ast.Expr, kind token.Token, value string) bool {
	bl, ok := e.(*ast.BasicLit)
	return ok && bl.Kind == kind && bl.Value == value
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && isIdent(sel.X, pkg) && sel.Sel.Name == name
}

func isCallTo(e ast.Expr, fn string) bool {
	c, ok := e.(*ast.CallExpr)
	return ok && isIdent(c.Fun, fn) && len(c.Args) == 1 && isSelector(c.Args[0], "os", "Args")
}

func isIndexOfOSArgs(e ast.Expr, idx string) bool {
	ix, ok := e.(*ast.IndexExpr)
	return ok && isSelector(ix.X, "os", "Args") && isLit(ix.Index, token.INT, idx)
}

func replaceOnceSrc(t *testing.T, src, old, repl string) string {
	t.Helper()
	if strings.Count(src, old) != 1 {
		t.Fatalf("the source does not hold %q exactly once: the case does not test what it says", old)
	}
	return strings.Replace(src, old, repl, 1)
}

func TestMainBranchesToTheSubcommandFirstAndNeverStartsTheServerForIt(t *testing.T) {
	src := readNonTest(t)[cmdMainFile]
	for _, v := range mainEditionBranchViolations(cmdMainFile, src) {
		t.Error(v)
	}

	// The scan itself: copies of the real main.go with one change each.
	const branch = "\tif len(os.Args) > 1 && os.Args[1] == \"edition\" {\n\t\tos.Exit(runEdition(os.Args[2:], os.Stdout, os.Stderr))\n\t}\n"
	cases := []struct{ name, old, repl string }{
		{"another word", `os.Args[1] == "edition"`, `os.Args[1] == "Edition"`},
		{"an or: the server's argv would branch", `len(os.Args) > 1 && os.Args[1]`, `len(os.Args) > 1 || os.Args[1]`},
		{"no length guard", `len(os.Args) > 1 && os.Args[1]`, `len(os.Args) > 0 && os.Args[1]`},
		{"the branch does not end the process", "os.Exit(runEdition(os.Args[2:], os.Stdout, os.Stderr))", "runEdition(os.Args[2:], os.Stdout, os.Stderr)"},
		{"the branch gives the subcommand its own word too", "runEdition(os.Args[2:]", "runEdition(os.Args[1:]"},
		{"the branch is not first", branch + "\n\tlogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))\n", "\tlogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))\n\n" + branch},
		{"the branch does more", "\t\tos.Exit(runEdition(os.Args[2:], os.Stdout, os.Stderr))\n", "\t\tlogger := 1\n\t\t_ = logger\n\t\tos.Exit(runEdition(os.Args[2:], os.Stdout, os.Stderr))\n"},
		{"runEdition called a second time", "\tlogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))\n", "\tlogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))\n\tdefer runEdition(nil, os.Stdout, os.Stderr)\n"},
	}
	for _, c := range cases {
		mutated := replaceOnceSrc(t, src, c.old, c.repl)
		if v := mainEditionBranchViolations(cmdMainFile, mutated); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	if v := mainEditionBranchViolations(cmdMainFile, "package main\n\nfunc other() {}\n"); len(v) == 0 {
		t.Error("a file with no main was not reported")
	}
}

// topLevelNames are the names a file declares at its top level: functions (not methods), and the
// names of consts, vars and types.
func topLevelNames(f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				out = append(out, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.ValueSpec:
					for _, n := range s.Names {
						out = append(out, n.Name)
					}
				case *ast.TypeSpec:
					out = append(out, s.Name.Name)
				}
			}
		}
	}
	return out
}

// subcommandLeaks lists the identifiers of another non-test file of cmd/scoreboard (slash path
// -> source) that are a name editioncmd.go declares, other than runEdition in main.go.
func subcommandLeaks(files map[string]string) (leaks []string, declared int) {
	cf, err := parser.ParseFile(token.NewFileSet(), cmdFile, files[cmdFile], 0)
	if err != nil {
		return []string{cmdFile + ": does not parse: " + err.Error()}, 0
	}
	names := topLevelNames(cf)
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if !strings.HasPrefix(p, "cmd/scoreboard/") || p == cmdFile {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], 0)
		if err != nil {
			leaks = append(leaks, p+": does not parse: "+err.Error())
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if ok && slices.Contains(names, id.Name) && !(p == cmdMainFile && id.Name == "runEdition") {
				leaks = append(leaks, p+": names "+id.Name+", which the subcommand's file declares")
			}
			return true
		})
	}
	return leaks, len(names)
}

func TestTheServersFilesDoNotNameTheSubcommand(t *testing.T) {
	files := readNonTest(t)
	leaks, declared := subcommandLeaks(files)
	for _, l := range leaks {
		t.Error(l)
	}
	if declared < 10 {
		t.Errorf("editioncmd.go declares %d top-level names, want at least 10: the scan does not see the file", declared)
	}

	// The scan itself.
	base := map[string]string{
		cmdFile:                     "package main\n\nfunc runEdition() {}\n\nfunc helper() {}\n",
		cmdMainFile:                 "package main\n\nfunc main() { runEdition() }\n",
		"cmd/scoreboard/catalog.go": "package main\n\nfunc scoredFromEnv() {}\n",
	}
	if l, _ := subcommandLeaks(base); len(l) != 0 {
		t.Fatalf("the allowed shape: %v", l)
	}
	for name, add := range map[string]string{
		"the helper in the server's wiring":      "package main\n\nfunc f() { helper() }\n",
		"runEdition outside main.go":             "package main\n\nfunc f() { runEdition() }\n",
		"the helper taken as a value":            "package main\n\nvar g = helper\n",
		"a file of the server that is not parse": "package main\n\nfunc (",
	} {
		files := maps.Clone(base)
		files["cmd/scoreboard/server.go"] = add
		if l, _ := subcommandLeaks(files); len(l) == 0 {
			t.Errorf("%s: no leak was reported", name)
		}
	}
	// runEdition in main.go is the one allowed use; the same call in another function of main.go
	// is still the allowed name (TestMainBranches... counts it).
}

// commandImportViolations judges the imports of editioncmd.go (path p, source src): only the
// packages that format and print, and internal/edition. A file's import of `os` or of anything
// that opens a file would let the command touch a file itself, which the layers forbid.
func commandImportViolations(p, src string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, parser.ImportsOnly)
	if err != nil {
		return []string{p + ": does not parse: " + err.Error()}
	}
	allowed := []string{"errors", "fmt", "io", "strings", cmdEditionImport}
	var out []string
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !slices.Contains(allowed, path) {
			out = append(out, p+": imports "+imp.Path.Value+"; the command reads and writes no file (D20), so it imports "+strings.Join(allowed, ", ")+" only")
		}
		if imp.Name != nil && imp.Name.Name == "." {
			out = append(out, p+": dot import of "+imp.Path.Value)
		}
	}
	if len(f.Imports) == 0 {
		out = append(out, p+": has no import: the scan does not see the file")
	}
	return out
}

func TestTheCommandOpensAndWritesNoFile(t *testing.T) {
	src := readNonTest(t)[cmdFile]
	for _, v := range commandImportViolations(cmdFile, src) {
		t.Error(v)
	}
	const head = "package main\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n\t\"io\"\n\t\"strings\"\n\n\t\"" + cmdEditionImport + "\"\n)\n"
	if v := commandImportViolations(cmdFile, head); len(v) != 0 {
		t.Fatalf("the allowed shape: %v", v)
	}
	for name, imp := range map[string]string{
		"os":            "os",
		"io/ioutil":     "io/ioutil",
		"io/fs":         "io/fs",
		"path/filepath": "path/filepath",
		"bufio":         "bufio",
		"the catalog":   "github.com/Qfour/falco-ctf-app/internal/catalog",
	} {
		mutated := strings.Replace(head, "\t\"io\"\n", "\t\"io\"\n\t\""+imp+"\"\n", 1)
		if v := commandImportViolations(cmdFile, mutated); len(v) == 0 {
			t.Errorf("an import of %s: no violation was reported", name)
		}
	}
	if v := commandImportViolations(cmdFile, "package main\n\nimport . \"fmt\"\n"); len(v) == 0 {
		t.Error("a dot import was not reported")
	}
	if v := commandImportViolations(cmdFile, "package main\n"); len(v) == 0 {
		t.Error("a file with no import was not reported")
	}
}
