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

	"github.com/Qfour/falco-ctf-app/internal/edition"
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

// declNamed is the function or method of f named name (the first one), or nil.
func declNamed(f *ast.File, name string) *ast.FuncDecl {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name && fd.Body != nil {
			return fd
		}
	}
	return nil
}

// within reports whether n is inside the block b.
func within(n ast.Node, b *ast.BlockStmt) bool {
	return b != nil && n.Pos() >= b.Pos() && n.End() <= b.End()
}

// returnsFinishRefusal reports whether the block has `return finishRefusal(_, name)`.
func returnsFinishRefusal(b *ast.BlockStmt, name string) bool {
	for _, s := range b.List {
		r, ok := s.(*ast.ReturnStmt)
		if !ok || len(r.Results) != 1 {
			continue
		}
		if c, ok := r.Results[0].(*ast.CallExpr); ok && isIdent(c.Fun, "finishRefusal") && len(c.Args) == 2 && isIdent(c.Args[1], name) {
			return true
		}
	}
	return false
}

// writeWiringViolations judges the source of editioncmd.go (path p) for the wiring of the write
// of --digests-out (ADR-0056 D20 exit 3 and the commit point, V92), which the tests of the
// command cannot reach through the library's seam:
//
//   - in runEditionCheck, both results of edition.WriteDigestsFile are named (left, err), once;
//   - after it, an `if err != nil` whose body returns finishRefusal(_, err): a failure before the
//     commit point goes to the exit code and to the names left;
//   - after it, outside that if (on the way to success), printLeftWarning(_, _, left): the names
//     left after the commit point are printed, and the exit is 0;
//   - finishRefusal hands its error to leftNamesOf (the names printed) and returns
//     editionExitCode of it (exit 3 for an *edition.OutputError).
func writeWiringViolations(p, src string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		return []string{p + ": does not parse: " + err.Error()}
	}
	run := declNamed(f, "runEditionCheck")
	if run == nil {
		return []string{p + ": func runEditionCheck is not found"}
	}
	var out []string
	var assign *ast.AssignStmt
	writes := 0
	ast.Inspect(run.Body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || len(a.Rhs) != 1 {
			return true
		}
		if c, ok := a.Rhs[0].(*ast.CallExpr); ok && isSelector(c.Fun, "edition", "WriteDigestsFile") {
			writes++
			assign = a
		}
		return true
	})
	if writes != 1 || len(assign.Lhs) != 2 {
		return append(out, p+": runEditionCheck does not take the two results of edition.WriteDigestsFile once")
	}
	left, _ := assign.Lhs[0].(*ast.Ident)
	errID, _ := assign.Lhs[1].(*ast.Ident)
	if left == nil || left.Name == "_" || errID == nil || errID.Name == "_" {
		return append(out, p+": a result of edition.WriteDigestsFile is dropped (want the names left and the error)")
	}
	var guard *ast.IfStmt
	ast.Inspect(run.Body, func(n ast.Node) bool {
		s, ok := n.(*ast.IfStmt)
		if !ok || guard != nil || s.Pos() < assign.End() {
			return true
		}
		if b, ok := s.Cond.(*ast.BinaryExpr); ok && b.Op == token.NEQ && isIdent(b.X, errID.Name) && isIdent(b.Y, "nil") && returnsFinishRefusal(s.Body, errID.Name) {
			guard = s
		}
		return true
	})
	if guard == nil {
		out = append(out, p+": the error of edition.WriteDigestsFile does not reach `return finishRefusal(..., "+errID.Name+")` in an `if "+errID.Name+" != nil`")
	}
	warned := false
	ast.Inspect(run.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if ok && isIdent(c.Fun, "printLeftWarning") && len(c.Args) == 3 && isIdent(c.Args[2], left.Name) && c.Pos() > assign.End() && (guard == nil || !within(c, guard.Body)) {
			warned = true
		}
		return true
	})
	if !warned {
		out = append(out, p+": the names left by edition.WriteDigestsFile ("+left.Name+") are not given to printLeftWarning on the way to success")
	}
	fin := declNamed(f, "finishRefusal")
	if fin == nil || fin.Type.Params == nil || len(fin.Type.Params.List) == 0 || len(fin.Type.Params.List[len(fin.Type.Params.List)-1].Names) != 1 {
		return append(out, p+": func finishRefusal(w, err) is not found")
	}
	param := fin.Type.Params.List[len(fin.Type.Params.List)-1].Names[0].Name
	names, exits := false, false
	ast.Inspect(fin.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if isIdent(x.Fun, "leftNamesOf") && len(x.Args) == 1 && isIdent(x.Args[0], param) {
				names = true
			}
		case *ast.ReturnStmt:
			if len(x.Results) == 1 {
				if c, ok := x.Results[0].(*ast.CallExpr); ok && isIdent(c.Fun, "editionExitCode") && len(c.Args) == 1 && isIdent(c.Args[0], param) {
					exits = true
				}
			}
		}
		return true
	})
	if !names {
		out = append(out, p+": finishRefusal does not print the names left (leftNamesOf of its error)")
	}
	if !exits {
		out = append(out, p+": finishRefusal does not return editionExitCode of its error")
	}
	return out
}

// V92 (ADR-0056 D20, amendment 13 as revised): the command's part of exit 3 and of the warning
// after the commit point. The library's failures are caused through its seam, which this
// package cannot reach (and no seam is added to the command), so the wiring is held by reading
// the source: a copy with each link of it cut is red.
func TestTheWriteOfTheDigestsFileIsWiredToTheExitAndTheWarning(t *testing.T) {
	src := readNonTest(t)[cmdFile]
	for _, v := range writeWiringViolations(cmdFile, src) {
		t.Error(v)
	}
	const (
		warnLine = "\tprintLeftWarning(stderr, \"edition check\", left)\n"
		failLine = "\t\tfmt.Fprintln(stderr, \"edition check: the digests file was not written\")\n"
	)
	cases := []struct {
		name string
		edit func(src string) string
	}{
		{"no warning", func(s string) string { return replaceOnceSrc(t, s, warnLine, "\t_ = left\n") }},
		{"a warning of nothing", func(s string) string {
			return replaceOnceSrc(t, s, warnLine, "\tprintLeftWarning(stderr, \"edition check\", nil)\n")
		}},
		{"the names left dropped", func(s string) string {
			return replaceOnceSrc(t, s, "left, err := edition.WriteDigestsFile(", "_, err := edition.WriteDigestsFile(")
		}},
		{"the warning on the failure only", func(s string) string {
			return replaceOnceSrc(t, replaceOnceSrc(t, s, warnLine, "\t_ = left\n"), failLine, failLine+"\t\tprintLeftWarning(stderr, \"edition check\", left)\n")
		}},
		{"the failure not through finishRefusal", func(s string) string {
			return replaceOnceSrc(t, s, failLine+"\t\treturn finishRefusal(stderr, err)\n", failLine+"\t\treturn exitUsage\n")
		}},
		{"the failure not tested", func(s string) string {
			return replaceOnceSrc(t, s, "edition.WriteDigestsFile(in.DigestsOut, ev)\n\tif err != nil {", "edition.WriteDigestsFile(in.DigestsOut, ev)\n\tif err == nil {")
		}},
		{"finishRefusal prints no name", func(s string) string { return replaceOnceSrc(t, s, "leftNamesOf(err)", "leftNamesOf(nil)") }},
		{"finishRefusal gives no exit code of the error", func(s string) string {
			return replaceOnceSrc(t, s, "\treturn editionExitCode(err)\n", "\treturn exitUsage\n")
		}},
	}
	for _, c := range cases {
		if v := writeWiringViolations(cmdFile, c.edit(src)); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	if v := writeWiringViolations(cmdFile, "package main\n\nfunc other() {}\n"); len(v) == 0 {
		t.Error("a file with no runEditionCheck was not reported")
	}
}

// renderWiringViolations judges the source of editioncmd.go (path p) for the wiring of
// `edition render` (ADR-0056 D20, V92), the same way as writeWiringViolations does for the write
// of --digests-out: in runEditionRender, both results of edition.RenderEvent are named, once;
// after it, an `if err != nil` whose body returns finishRefusal(_, err) (the exit code, and the
// temporary names an *edition.OutputError lists as left: finishRefusal's own wiring is held by
// writeWiringViolations); and no `return exitAccepted` comes before that if. A render has no
// warning after its commit point (the rename leaves no name), so there is no left to wire.
func renderWiringViolations(p, src string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		return []string{p + ": does not parse: " + err.Error()}
	}
	run := declNamed(f, "runEditionRender")
	if run == nil {
		return []string{p + ": func runEditionRender is not found"}
	}
	var assign *ast.AssignStmt
	renders := 0
	ast.Inspect(run.Body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || len(a.Rhs) != 1 {
			return true
		}
		if c, ok := a.Rhs[0].(*ast.CallExpr); ok && isSelector(c.Fun, "edition", "RenderEvent") {
			renders++
			assign = a
		}
		return true
	})
	if renders != 1 || len(assign.Lhs) != 2 {
		return []string{p + ": runEditionRender does not take the two results of edition.RenderEvent once"}
	}
	ev, _ := assign.Lhs[0].(*ast.Ident)
	errID, _ := assign.Lhs[1].(*ast.Ident)
	if ev == nil || ev.Name == "_" || errID == nil || errID.Name == "_" {
		return []string{p + ": a result of edition.RenderEvent is dropped (want the event and the error)"}
	}
	var out []string
	var guard *ast.IfStmt
	ast.Inspect(run.Body, func(n ast.Node) bool {
		s, ok := n.(*ast.IfStmt)
		if !ok || guard != nil || s.Pos() < assign.End() {
			return true
		}
		if b, ok := s.Cond.(*ast.BinaryExpr); ok && b.Op == token.NEQ && isIdent(b.X, errID.Name) && isIdent(b.Y, "nil") && returnsFinishRefusal(s.Body, errID.Name) {
			guard = s
		}
		return true
	})
	if guard == nil {
		return append(out, p+": the error of edition.RenderEvent does not reach `return finishRefusal(..., "+errID.Name+")` in an `if "+errID.Name+" != nil`")
	}
	accepted := 0
	ast.Inspect(run.Body, func(n ast.Node) bool {
		r, ok := n.(*ast.ReturnStmt)
		if !ok || len(r.Results) != 1 || !isIdent(r.Results[0], "exitAccepted") {
			return true
		}
		accepted++
		if r.Pos() < guard.End() {
			out = append(out, p+": runEditionRender returns exitAccepted before the error of edition.RenderEvent is tested")
		}
		return true
	})
	if accepted == 0 {
		out = append(out, p+": runEditionRender never returns exitAccepted: the scan does not see its success")
	}
	return out
}

// V92 for `edition render`: the error of RenderEvent goes to finishRefusal (exit 3 and the names
// left for an *edition.OutputError, exit 1 and 2 for the others), and nothing is accepted before
// it is tested. A copy with each link cut is red.
func TestTheRenderIsWiredToTheExit(t *testing.T) {
	src := readNonTest(t)[cmdFile]
	for _, v := range renderWiringViolations(cmdFile, src) {
		t.Error(v)
	}
	const failLine = "\t\tfmt.Fprintln(stderr, \"edition render: nothing was put at --out\")\n"
	cases := []struct {
		name string
		edit func(src string) string
	}{
		{"the error not through finishRefusal", func(s string) string {
			return replaceOnceSrc(t, s, failLine+"\t\treturn finishRefusal(stderr, err)\n", failLine+"\t\treturn exitUsage\n")
		}},
		{"the error not tested", func(s string) string {
			return replaceOnceSrc(t, s, "edition.RenderEvent(in)\n\tif err != nil {", "edition.RenderEvent(in)\n\tif err == nil {")
		}},
		{"the error dropped", func(s string) string {
			return replaceOnceSrc(t, s, "ev, err := edition.RenderEvent(in)", "ev, _ := edition.RenderEvent(in)")
		}},
		{"accepted before the error is tested", func(s string) string {
			return replaceOnceSrc(t, s, "ev, err := edition.RenderEvent(in)\n", "ev, err := edition.RenderEvent(in)\n\tif ev != nil {\n\t\treturn exitAccepted\n\t}\n")
		}},
	}
	for _, c := range cases {
		if v := renderWiringViolations(cmdFile, c.edit(src)); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	if v := renderWiringViolations(cmdFile, "package main\n\nfunc other() {}\n"); len(v) == 0 {
		t.Error("a file with no runEditionRender was not reported")
	}
}

// practiceWiringViolations judges the source of editioncmd.go (path p) for the wiring of
// `edition render --practice` (ADR-0056 D20, V81, V92, A4e-3b), as writeWiringViolations does for
// the write of --digests-out:
//
//   - runEditionRender hands every invocation with --practice to runEditionRenderPractice before
//     it reads the event's arguments: its first statement is `if hasPracticeArg(args) { return
//     runEditionRenderPractice(args, ...) }`;
//   - in runEditionRenderPractice, both results of edition.RenderPracticeEdition are named
//     (left, err), once;
//   - after it, an `if err != nil` whose body returns finishRefusal(_, err): a failure goes to the
//     exit code and to the names left (exit 3 for an *edition.OutputError);
//   - after it, outside that if, printLeftWarning(_, _, left): the earlier practice/ moved aside
//     that could not be removed after the commit point is printed, and the exit is 0;
//   - no `return exitAccepted` comes before that if.
func practiceWiringViolations(p, src string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		return []string{p + ": does not parse: " + err.Error()}
	}
	var out []string
	render := declNamed(f, "runEditionRender")
	dispatched := false
	if render != nil && len(render.Body.List) > 0 {
		if s, ok := render.Body.List[0].(*ast.IfStmt); ok && s.Init == nil {
			if c, ok := s.Cond.(*ast.CallExpr); ok && isIdent(c.Fun, "hasPracticeArg") && len(c.Args) == 1 && isIdent(c.Args[0], "args") &&
				len(s.Body.List) == 1 {
				if r, ok := s.Body.List[0].(*ast.ReturnStmt); ok && len(r.Results) == 1 {
					if rc, ok := r.Results[0].(*ast.CallExpr); ok && isIdent(rc.Fun, "runEditionRenderPractice") && len(rc.Args) == 3 && isIdent(rc.Args[0], "args") {
						dispatched = true
					}
				}
			}
		}
	}
	if !dispatched {
		out = append(out, p+": the first statement of runEditionRender is not `if hasPracticeArg(args) { return runEditionRenderPractice(args, ...) }`")
	}
	run := declNamed(f, "runEditionRenderPractice")
	if run == nil {
		return append(out, p+": func runEditionRenderPractice is not found")
	}
	var assign *ast.AssignStmt
	renders := 0
	ast.Inspect(run.Body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || len(a.Rhs) != 1 {
			return true
		}
		if c, ok := a.Rhs[0].(*ast.CallExpr); ok && isSelector(c.Fun, "edition", "RenderPracticeEdition") {
			renders++
			assign = a
		}
		return true
	})
	if renders != 1 || len(assign.Lhs) != 2 {
		return append(out, p+": runEditionRenderPractice does not take the two results of edition.RenderPracticeEdition once")
	}
	left, _ := assign.Lhs[0].(*ast.Ident)
	errID, _ := assign.Lhs[1].(*ast.Ident)
	if left == nil || left.Name == "_" || errID == nil || errID.Name == "_" {
		return append(out, p+": a result of edition.RenderPracticeEdition is dropped (want the names left and the error)")
	}
	var guard *ast.IfStmt
	ast.Inspect(run.Body, func(n ast.Node) bool {
		s, ok := n.(*ast.IfStmt)
		if !ok || guard != nil || s.Pos() < assign.End() {
			return true
		}
		if b, ok := s.Cond.(*ast.BinaryExpr); ok && b.Op == token.NEQ && isIdent(b.X, errID.Name) && isIdent(b.Y, "nil") && returnsFinishRefusal(s.Body, errID.Name) {
			guard = s
		}
		return true
	})
	if guard == nil {
		return append(out, p+": the error of edition.RenderPracticeEdition does not reach `return finishRefusal(..., "+errID.Name+")` in an `if "+errID.Name+" != nil`")
	}
	warned := false
	accepted := 0
	ast.Inspect(run.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if isIdent(x.Fun, "printLeftWarning") && len(x.Args) == 3 && isIdent(x.Args[2], left.Name) && x.Pos() > guard.End() {
				warned = true
			}
		case *ast.ReturnStmt:
			if len(x.Results) == 1 && isIdent(x.Results[0], "exitAccepted") {
				accepted++
				if x.Pos() < guard.End() {
					out = append(out, p+": runEditionRenderPractice returns exitAccepted before the error of edition.RenderPracticeEdition is tested")
				}
			}
		}
		return true
	})
	if !warned {
		out = append(out, p+": the names left by edition.RenderPracticeEdition ("+left.Name+") are not given to printLeftWarning on the way to success")
	}
	if accepted == 0 {
		out = append(out, p+": runEditionRenderPractice never returns exitAccepted: the scan does not see its success")
	}
	return out
}

// V81 / V92 for `edition render --practice`: the dispatch from `edition render`, the error of
// RenderPracticeEdition to finishRefusal (exit 3 and the names left for an *edition.OutputError,
// exit 1 and 2 for the others), the warning after the commit point, and nothing accepted before
// the error is tested. A copy with each link cut is red.
func TestThePracticeRenderIsWiredToTheExitAndTheWarning(t *testing.T) {
	src := readNonTest(t)[cmdFile]
	for _, v := range practiceWiringViolations(cmdFile, src) {
		t.Error(v)
	}
	const (
		warnLine = "\tprintLeftWarning(stderr, \"edition render --practice\", left)\n"
		call     = "left, err := edition.RenderPracticeEdition(challenges, cid)\n"
	)
	cases := []struct {
		name string
		edit func(src string) string
	}{
		{"no dispatch", func(s string) string {
			return replaceOnceSrc(t, s, "\tif hasPracticeArg(args) {\n\t\treturn runEditionRenderPractice(args, stdout, stderr)\n\t}\n", "")
		}},
		{"the dispatch after the event's arguments are read", func(s string) string {
			s = replaceOnceSrc(t, s, "\tif hasPracticeArg(args) {\n\t\treturn runEditionRenderPractice(args, stdout, stderr)\n\t}\n\tin, err := parseRenderArgs(args)\n", "\tin, err := parseRenderArgs(args)\n\tif hasPracticeArg(args) {\n\t\treturn runEditionRenderPractice(args, stdout, stderr)\n\t}\n")
			return s
		}},
		{"no warning", func(s string) string { return replaceOnceSrc(t, s, warnLine, "\t_ = left\n") }},
		{"the names left dropped", func(s string) string {
			return replaceOnceSrc(t, s, call, "_, err := edition.RenderPracticeEdition(challenges, cid)\n")
		}},
		{"the error dropped", func(s string) string {
			return replaceOnceSrc(t, s, call, "left, _ := edition.RenderPracticeEdition(challenges, cid)\n")
		}},
		{"the error not tested", func(s string) string {
			return replaceOnceSrc(t, s, call+"\tif err != nil {", call+"\tif err == nil {")
		}},
		{"the error not through finishRefusal", func(s string) string {
			return replaceOnceSrc(t, s, "\t\treturn finishRefusal(stderr, err)\n\t}\n"+warnLine, "\t\treturn exitUsage\n\t}\n"+warnLine)
		}},
		{"accepted before the error is tested", func(s string) string {
			return replaceOnceSrc(t, s, call, call+"\tif left == nil {\n\t\treturn exitAccepted\n\t}\n")
		}},
	}
	for _, c := range cases {
		if v := practiceWiringViolations(cmdFile, c.edit(src)); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	if v := practiceWiringViolations(cmdFile, "package main\n\nfunc other() {}\n"); len(v) == 0 {
		t.Error("a file with no runEditionRenderPractice was not reported")
	}
}

// switchKinds is the types (`*edition.X` as X) of the cases of the first type switch of the
// function or method name of the source.
func switchKinds(p, src, name string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		return nil, err
	}
	fd := declNamed(f, name)
	if fd == nil {
		return nil, errors.New("func " + name + " is not found")
	}
	var out []string
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSwitchStmt)
		if !ok || found {
			return true
		}
		found = true
		for _, s := range ts.Body.List {
			for _, e := range s.(*ast.CaseClause).List {
				if st, ok := e.(*ast.StarExpr); ok && isSelectorOf(st.X, "edition") {
					out = append(out, st.X.(*ast.SelectorExpr).Sel.Name)
				}
			}
		}
		return false
	})
	slices.Sort(out)
	return out, nil
}

// isSelectorOf reports whether e is pkg.<anything>.
func isSelectorOf(e ast.Expr, pkg string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && isIdent(sel.X, pkg)
}

// The two walks of the library's error tree in editioncmd.go (leafKinds.count for the exit code,
// collectLeaves for what is printed) each have a type switch of the library's kinds; a kind
// added to one of them and not to the other would print one thing and exit by another. The
// probe table holds every kind with the exit code it gives: each probe (with a cause that is a
// join, so that a kind the walks did not stop at would be taken apart) is one leaf of its kind for
// both walks; and the cases of the two switches are the probe table's kinds (collectLeaves needs
// no case for a kind that wraps nothing: it is a leaf anyway).
func TestTheTwoWalksOfTheErrorTreeKnowTheSameKinds(t *testing.T) {
	cause := errors.Join(errors.New("first cause"), errors.New("second cause"))
	probes := []struct {
		kind string
		err  error
		exit int
	}{
		{"Violation", &edition.Violation{Rule: "B7", Msg: "a rule"}, exitRefused},
		{"MoreViolations", &edition.MoreViolations{N: 2}, exitRefused},
		{"InputError", &edition.InputError{Msg: "an input", Err: cause}, exitUsage},
		{"OutputError", &edition.OutputError{Err: cause}, exitWriteFailed},
	}
	var all, wrapping []string
	for _, p := range probes {
		all = append(all, p.kind)
		if _, ok := p.err.(interface{ Unwrap() error }); ok {
			wrapping = append(wrapping, p.kind)
		}
		var leaves []error
		collectLeaves(p.err, &leaves)
		if len(leaves) != 1 || leaves[0] != p.err {
			t.Errorf("%s: collectLeaves gives %v, want the probe as one leaf", p.kind, leaves)
		}
		var k leafKinds
		k.count(p.err)
		if k.violation+k.output+k.other != 1 {
			t.Errorf("%s: leafKinds counts %+v, want one leaf", p.kind, k)
		}
		if got := editionExitCode(p.err); got != p.exit {
			t.Errorf("%s: exit %d, want %d", p.kind, got, p.exit)
		}
	}
	slices.Sort(all)
	slices.Sort(wrapping)

	src := readNonTest(t)[cmdFile]
	check := func(src string) []string {
		var v []string
		if got, err := switchKinds(cmdFile, src, "count"); err != nil || !slices.Equal(got, all) {
			v = append(v, "the switch of leafKinds.count has "+strings.Join(got, ",")+", want the probes' "+strings.Join(all, ","))
		}
		if got, err := switchKinds(cmdFile, src, "collectLeaves"); err != nil || !slices.Equal(got, wrapping) {
			v = append(v, "the switch of collectLeaves has "+strings.Join(got, ",")+", want the probes' that wrap "+strings.Join(wrapping, ","))
		}
		return v
	}
	for _, v := range check(src) {
		t.Error(v)
	}
	// The scan itself: a kind added to one switch only, or taken out of one, is red.
	for name, mutated := range map[string]string{
		"a kind added to the exit's switch only": replaceOnceSrc(t, src, "case *edition.Violation, *edition.MoreViolations:", "case *edition.Violation, *edition.MoreViolations, *edition.CheckedEvent:"),
		"a kind taken out of the printing's":     replaceOnceSrc(t, src, "case *edition.Violation, *edition.InputError, *edition.OutputError:", "case *edition.Violation, *edition.InputError:"),
	} {
		if len(check(mutated)) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
}
