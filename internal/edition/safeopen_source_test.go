package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ADR-0056 D20 (the form of the files), V57 and V78, fixed by reading the sources (the way
// load_source_test.go fixes the door of the answers table): how the validator opens a file and
// writes an output.
//
//   - the two doors that read the answers file pass the opener that is theirs to loadChecked:
//     Load (the scoreboard's start-up) passes openFollowing, because the answers Secret is a
//     directory volume and its files are links; LoadEventTable (the validator) passes
//     openRegular (O_NOFOLLOW and a Stat of the open descriptor held to the Lstat); loadChecked
//     passes the one it was given to readTable, and loadPractice reads the practice answers
//     through openRegular. openFollowing is named nowhere else: a validator that took it would
//     follow a link, and nothing else of the program has a use for it;
//   - no non-test file of package edition opens, reads, creates or renames a file by itself:
//     os.Open, os.OpenFile, os.ReadFile, os.Create, os.WriteFile, os.CreateTemp, os.Mkdir,
//     os.MkdirAll, os.MkdirTemp, os.Rename, os.Remove, os.RemoveAll, os.Symlink and os.Link are
//     called in safeopen.go (the reader) and atomicwrite.go (the writer) only, so a reader of
//     A4e-2 or A4e-3 (the key, the seats, the previous list, the digests) has to go through
//     them;
//   - safeopen.go's seam for the tests, afterLstat, is assigned by no non-test file and named
//     by none but safeopen.go itself, so it is nil in every build of the program.

const (
	loadFilePath     = "internal/edition/load.go"
	safeopenFilePath = "internal/edition/safeopen.go"
)

// The opener each function of load.go passes: the last argument of the call to loadChecked in
// the two doors, the second argument of the call to readTable in loadChecked (the one it was
// given) and in loadPractice.
var (
	loadCheckedOpener = map[string]string{"Load": "openFollowing", "LoadEventTable": "openRegular"}
	readTableOpener   = map[string]string{"loadChecked": "open", "loadPractice": "openRegular"}
)

// openerViolations judges the calls of loadChecked and readTable in load.go and the uses of
// openFollowing in every non-test file of package edition (slash path -> source). counts is
// the positive side, by "callee@function" and "openFollowing@function".
func openerViolations(files map[string]string) (violations []string, counts map[string]int) {
	counts = map[string]int{}
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if !isEditionPackageFile(p) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], 0)
		if err != nil {
			violations = append(violations, p+": does not parse: "+err.Error())
			continue
		}
		for _, d := range f.Decls {
			fn, root := "", ast.Node(d)
			if fd, ok := d.(*ast.FuncDecl); ok {
				// The body only: the declared name (func openFollowing) is not a use of it.
				if fd.Body == nil {
					continue
				}
				fn, root = fd.Name.Name, fd.Body
			}
			where := p
			if fn != "" {
				where += " (func " + fn + ")"
			}
			ast.Inspect(root, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if x.Name != "openFollowing" {
						return true
					}
					if p == loadFilePath && fn == "Load" {
						counts["openFollowing@Load"]++
					} else {
						violations = append(violations, where+": names openFollowing; only Load (the start-up) opens the answers file through links")
					}
				case *ast.CallExpr:
					id, ok := x.Fun.(*ast.Ident)
					if !ok || (id.Name != "loadChecked" && id.Name != "readTable") {
						return true
					}
					// The opener is argument 4 of loadChecked and argument 2 of readTable.
					want, arg := loadCheckedOpener[fn], 3
					if id.Name == "readTable" {
						want, arg = readTableOpener[fn], 1
					}
					switch {
					case p != loadFilePath || want == "":
						violations = append(violations, where+": calls "+id.Name+"; only the functions of load.go that are named for it may")
					case len(x.Args) != arg+1:
						violations = append(violations, where+": calls "+id.Name+" with "+strconv.Itoa(len(x.Args))+" arguments, the opener is argument "+strconv.Itoa(arg+1))
					default:
						got := ""
						if a, ok := x.Args[arg].(*ast.Ident); ok {
							got = a.Name
						}
						if got != want {
							violations = append(violations, where+": passes "+strconv.Quote(got)+" to "+id.Name+", want "+want)
						} else {
							counts[id.Name+"@"+fn]++
						}
					}
				}
				return true
			})
		}
	}
	return violations, counts
}

// replaceOnce is src with its one occurrence of old replaced by repl (a case that changes
// nothing, or changes the wrong place, tests nothing).
func replaceOnce(t *testing.T, src, old, repl string) string {
	t.Helper()
	if strings.Count(src, old) != 1 {
		t.Fatalf("the source does not hold %q exactly once: the case does not test what it says", old)
	}
	return strings.Replace(src, old, repl, 1)
}

func TestTheOpenersAreTheDoorsOwn(t *testing.T) {
	want := map[string]int{
		"openFollowing@Load":         1,
		"loadChecked@Load":           1,
		"loadChecked@LoadEventTable": 1,
		"readTable@loadChecked":      1,
		"readTable@loadPractice":     1,
	}
	violations, counts := openerViolations(nonTestSources(t))
	for _, v := range violations {
		t.Error(v)
	}
	if !maps.Equal(counts, want) {
		t.Errorf("calls found = %v, want %v", counts, want)
	}

	// The scan itself: the allowed shape passes, every other way is seen.
	const loadSrc = "package edition\n\n" +
		"func Load() {\n\t_, _, _, _ = loadChecked(s, f, e, openFollowing)\n}\n\n" +
		"func LoadEventTable() {\n\t_, _, _, _ = loadChecked(s, f, true, openRegular)\n}\n\n" +
		"func loadChecked() {\n\t_, _ = readTable(f, open)\n}\n\n" +
		"func loadPractice() {\n\t_, _ = readTable(p, openRegular)\n}\n"
	const safeSrc = "package edition\n\nfunc openFollowing(path string) {}\n\nfunc openRegular(path string) {}\n"
	base := map[string]string{loadFilePath: loadSrc, safeopenFilePath: safeSrc}
	if v, c := openerViolations(base); len(v) != 0 || !maps.Equal(c, want) {
		t.Fatalf("the allowed shape: violations %v, counts %v, want none and %v", v, c, want)
	}
	cases := []struct{ name, path, src string }{
		{"the validator's door opens through links", loadFilePath, replaceOnce(t, loadSrc, "loadChecked(s, f, true, openRegular)", "loadChecked(s, f, true, openFollowing)")},
		{"the start-up's door opens with the validator's opener", loadFilePath, replaceOnce(t, loadSrc, "loadChecked(s, f, e, openFollowing)", "loadChecked(s, f, e, openRegular)")},
		{"loadChecked passes openFollowing to readTable", loadFilePath, replaceOnce(t, loadSrc, "readTable(f, open)", "readTable(f, openFollowing)")},
		{"loadChecked passes openRegular to readTable (it would refuse a Secret's link)", loadFilePath, replaceOnce(t, loadSrc, "readTable(f, open)", "readTable(f, openRegular)")},
		{"loadPractice passes openFollowing", loadFilePath, replaceOnce(t, loadSrc, "readTable(p, openRegular)", "readTable(p, openFollowing)")},
		{"a door without the opener", loadFilePath, replaceOnce(t, loadSrc, "loadChecked(s, f, true, openRegular)", "loadChecked(s, f, true)")},
		{"readTable without the opener", loadFilePath, replaceOnce(t, loadSrc, "readTable(p, openRegular)", "readTable(p)")},
		{"a third caller of readTable", loadFilePath, loadSrc + "\nfunc other() {\n\t_, _ = readTable(p, openRegular)\n}\n"},
		{"a third caller of loadChecked", loadFilePath, loadSrc + "\nfunc other() {\n\t_, _, _, _ = loadChecked(s, f, true, openRegular)\n}\n"},
		{"openFollowing named by another function of load.go", loadFilePath, loadSrc + "\nfunc other() {\n\tf := openFollowing\n\t_ = f\n}\n"},
		{"openFollowing named by another file", "internal/edition/other.go", "package edition\n\nfunc other() {\n\t_ = openFollowing\n}\n"},
		{"readTable called by another file", "internal/edition/other.go", "package edition\n\nfunc loadChecked() {\n\t_, _ = readTable(f, open)\n}\n"},
		{"a file that does not parse", "internal/edition/other.go", "package edition\n\nfunc ("},
	}
	for _, c := range cases {
		files := rdCopyFiles(base)
		files[c.path] = c.src
		if v, _ := openerViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
}

// rawIOFiles are the files that may call the functions of rawIONames: safeopen.go (the reader)
// and atomicwrite.go (the writer).
var rawIOFiles = []string{safeopenFilePath, "internal/edition/atomicwrite.go"}

// rawIONames are the functions of package os that open, read, create or move a file.
var rawIONames = []string{"Open", "OpenFile", "ReadFile", "Create", "WriteFile", "CreateTemp", "Mkdir", "MkdirAll", "MkdirTemp", "Rename", "Remove", "RemoveAll", "Symlink", "Link"}

// rawIOViolations lists the calls of os.<name> for the names of rawIONames, and of ioutil's
// ReadFile and WriteFile, in the non-test files of package edition (slash path -> source)
// other than rawIOFiles. counts is how many of them rawIOFiles hold, by file (the positive
// side: the scan sees the two files that are allowed).
func rawIOViolations(files map[string]string) (violations []string, counts map[string]int) {
	counts = map[string]int{}
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if !isEditionPackageFile(p) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], 0)
		if err != nil {
			violations = append(violations, p+": does not parse: "+err.Error())
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			hit := (pkg.Name == "os" && slices.Contains(rawIONames, sel.Sel.Name)) ||
				(pkg.Name == "ioutil" && (sel.Sel.Name == "ReadFile" || sel.Sel.Name == "WriteFile"))
			switch {
			case !hit:
			case slices.Contains(rawIOFiles, p):
				counts[p]++
			default:
				violations = append(violations, p+": uses "+pkg.Name+"."+sel.Sel.Name+"; a file is opened, written and moved in safeopen.go and atomicwrite.go only")
			}
			return true
		})
	}
	return violations, counts
}

func TestNoFileIsOpenedOrWrittenOutsideTheHelpers(t *testing.T) {
	violations, counts := rawIOViolations(nonTestSources(t))
	for _, v := range violations {
		t.Error(v)
	}
	for _, p := range rawIOFiles {
		if counts[p] == 0 {
			t.Errorf("%s has no call that the scan counts: the scan does not see the helpers", p)
		}
	}

	// The scan itself: the helpers' own calls and the calls that do not open or move a file
	// (Stat, Lstat, ReadDir) pass; every function of the list is seen in another file.
	base := map[string]string{
		safeopenFilePath:                  "package edition\n\nfunc a() { _, _ = os.OpenFile(\"x\", 0, 0) }\n",
		"internal/edition/atomicwrite.go": "package edition\n\nfunc b() { _ = os.Rename(\"a\", \"b\") }\n",
		"internal/edition/bundle.go":      "package edition\n\nfunc c() { _, _ = os.ReadDir(\"x\"); _, _ = os.Stat(\"x\"); _, _ = os.Lstat(\"x\") }\n",
	}
	if v, c := rawIOViolations(base); len(v) != 0 || c[safeopenFilePath] != 1 || c["internal/edition/atomicwrite.go"] != 1 {
		t.Fatalf("the allowed shape: violations %v, counts %v", v, c)
	}
	for _, name := range rawIONames {
		files := rdCopyFiles(base)
		files["internal/edition/other.go"] = "package edition\n\nfunc f() { _ = os." + name + "(x) }\n"
		if v, _ := rawIOViolations(files); len(v) == 0 {
			t.Errorf("os.%s in another file: no violation was reported", name)
		}
	}
	for _, name := range []string{"ReadFile", "WriteFile"} {
		files := rdCopyFiles(base)
		files["internal/edition/other.go"] = "package edition\n\nfunc f() { _ = ioutil." + name + "(x) }\n"
		if v, _ := rawIOViolations(files); len(v) == 0 {
			t.Errorf("ioutil.%s in another file: no violation was reported", name)
		}
	}
	bad := rdCopyFiles(base)
	bad["internal/edition/other.go"] = "package edition\n\nfunc ("
	if v, _ := rawIOViolations(bad); len(v) == 0 {
		t.Error("a file that does not parse was not reported")
	}
}

// afterLstatViolations lists, in the non-test files of package edition (slash path -> source),
// each use of the name afterLstat outside safeopen.go and each assignment to it in safeopen.go.
// names is how many times safeopen.go names it (the declaration, the nil test and the call:
// the positive side).
func afterLstatViolations(files map[string]string) (violations []string, names int) {
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if !isEditionPackageFile(p) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], 0)
		if err != nil {
			violations = append(violations, p+": does not parse: "+err.Error())
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				switch {
				case x.Name != "afterLstat":
				case p == safeopenFilePath:
					names++
				default:
					violations = append(violations, p+": names afterLstat, the test seam of safeopen.go; no other non-test code may")
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == "afterLstat" && p == safeopenFilePath {
						violations = append(violations, p+": assigns afterLstat; only a test file does")
					}
				}
			}
			return true
		})
	}
	return violations, names
}

func TestTheAfterLstatSeamIsAssignedByTestsOnly(t *testing.T) {
	violations, names := afterLstatViolations(nonTestSources(t))
	for _, v := range violations {
		t.Error(v)
	}
	if names != 3 {
		t.Errorf("safeopen.go names afterLstat %d times, want 3 (its declaration, the nil test and the call): the scan does not see the seam", names)
	}

	const safeSrc = "package edition\n\nvar afterLstat func(string)\n\nfunc open() {\n\tif afterLstat != nil {\n\t\tafterLstat(\"x\")\n\t}\n}\n"
	base := map[string]string{safeopenFilePath: safeSrc}
	if v, n := afterLstatViolations(base); len(v) != 0 || n != 3 {
		t.Fatalf("the allowed shape: violations %v, names %d, want none and 3", v, n)
	}
	for name, c := range map[string]struct{ path, src string }{
		"an assignment in another file":       {"internal/edition/other.go", "package edition\n\nfunc f() { afterLstat = nil }\n"},
		"a read in another file":              {"internal/edition/other.go", "package edition\n\nfunc f() { _ = afterLstat }\n"},
		"a declaration of its own elsewhere":  {"internal/edition/other.go", "package edition\n\nvar afterLstat func(string)\n"},
		"an assignment in safeopen.go":        {safeopenFilePath, safeSrc + "\nfunc g() { afterLstat = func(string) {} }\n"},
		"an assignment inside a literal":      {safeopenFilePath, safeSrc + "\nvar _ = func() int { afterLstat = nil; return 0 }()\n"},
		"a file that does not parse":          {"internal/edition/other.go", "package edition\n\nfunc ("},
	} {
		files := rdCopyFiles(base)
		files[c.path] = c.src
		if v, _ := afterLstatViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
}
