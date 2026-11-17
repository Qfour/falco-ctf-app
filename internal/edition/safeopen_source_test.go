package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	pathpkg "path"
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
//     them. The scan reads the identifiers `os` and `ioutil`, so no non-test file imports
//     either under another name (an alias, a dot, a blank);
//   - safeopen.go's seam for the tests, afterLstat, and atomicwrite.go's, beforeLink and
//     writeFault (the failures of exit 3, A4e-3a), are assigned by no non-test file and named by
//     none but their own file, so they are nil in every build of the program;
//   - writeFileAtomic and writeNewFile call Sync on the file after its last write, in their
//     own bodies: the data of every output file is synced before the output is put in place.

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
		// The scan below knows the packages by their identifiers: os under another name, or
		// dot-imported, would pass it. So they are imported under their own names only.
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || (path != "os" && path != "io/ioutil") || imp.Name == nil {
				continue
			}
			if want := pathpkg.Base(path); imp.Name.Name != want {
				violations = append(violations, p+": imports "+path+" as "+imp.Name.Name+"; os and io/ioutil are imported under their own names only, so that the scan for raw file I/O sees every call")
			}
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

	// os and io/ioutil under their own names pass; under another name, dot-imported or imported
	// for effect only, they are reported (the scan reads the identifiers `os` and `ioutil`).
	plain := rdCopyFiles(base)
	plain["internal/edition/imports.go"] = "package edition\n\nimport (\n\t\"io/ioutil\"\n\t\"os\"\n)\n\nfunc f() { _, _ = os.Stat(\"x\"); _ = ioutil.Discard }\n"
	if v, _ := rawIOViolations(plain); len(v) != 0 {
		t.Errorf("os and io/ioutil under their own names were reported: %v", v)
	}
	for name, src := range map[string]string{
		"os under another name":        "package edition\n\nimport o \"os\"\n\nfunc f() { _ = o.Open }\n",
		"os dot-imported":              "package edition\n\nimport . \"os\"\n\nfunc f() { _ = Open }\n",
		"os imported for effect":       "package edition\n\nimport _ \"os\"\n",
		"io/ioutil under another name": "package edition\n\nimport iu \"io/ioutil\"\n\nfunc f() { _ = iu.ReadFile }\n",
		"os in a grouped import":       "package edition\n\nimport (\n\t\"fmt\"\n\tfsx \"os\"\n)\n\nvar _ = fmt.Sprint\n",
	} {
		files := rdCopyFiles(base)
		files["internal/edition/other.go"] = src
		if v, _ := rawIOViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
	// The same in a helper's own file: the helpers are held to it too.
	aliased := rdCopyFiles(base)
	aliased[safeopenFilePath] = "package edition\n\nimport o \"os\"\n\nfunc a() { _, _ = o.OpenFile(\"x\", 0, 0) }\n"
	if v, _ := rawIOViolations(aliased); len(v) == 0 {
		t.Error("os under another name in safeopen.go was not reported")
	}
}

// atomicwriteFilePath is the writer, which owns the seam beforeLink.
const atomicwriteFilePath = "internal/edition/atomicwrite.go"

// afterLstatViolations lists, in the non-test files of package edition (slash path -> source),
// each use of the name afterLstat outside safeopen.go and each assignment to it in safeopen.go.
// names is how many times safeopen.go names it (the declaration, the nil test and the call:
// the positive side).
func afterLstatViolations(files map[string]string) (violations []string, names int) {
	return seamViolations(files, "afterLstat", safeopenFilePath)
}

// beforeLinkViolations is the same for the seam beforeLink of atomicwrite.go.
func beforeLinkViolations(files map[string]string) (violations []string, names int) {
	return seamViolations(files, "beforeLink", atomicwriteFilePath)
}

// writeFaultViolations is the same for the seam writeFault of atomicwrite.go (A4e-3a).
func writeFaultViolations(files map[string]string) (violations []string, names int) {
	return seamViolations(files, "writeFault", atomicwriteFilePath)
}

// seamViolations lists, in the non-test files of package edition (slash path -> source), each
// use of the name `seam` outside home and each assignment to it in home. names is how many
// times home names it.
func seamViolations(files map[string]string, seam, home string) (violations []string, names int) {
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
				case x.Name != seam:
				case p == home:
					names++
				default:
					violations = append(violations, p+": names "+seam+", the test seam of "+home+"; no other non-test code may")
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == seam && p == home {
						violations = append(violations, p+": assigns "+seam+"; only a test file does")
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
		"an assignment in another file":      {"internal/edition/other.go", "package edition\n\nfunc f() { afterLstat = nil }\n"},
		"a read in another file":             {"internal/edition/other.go", "package edition\n\nfunc f() { _ = afterLstat }\n"},
		"a declaration of its own elsewhere": {"internal/edition/other.go", "package edition\n\nvar afterLstat func(string)\n"},
		"an assignment in safeopen.go":       {safeopenFilePath, safeSrc + "\nfunc g() { afterLstat = func(string) {} }\n"},
		"an assignment inside a literal":     {safeopenFilePath, safeSrc + "\nvar _ = func() int { afterLstat = nil; return 0 }()\n"},
		"a file that does not parse":         {"internal/edition/other.go", "package edition\n\nfunc ("},
	} {
		files := rdCopyFiles(base)
		files[c.path] = c.src
		if v, _ := afterLstatViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
}

// syncedWriters are the functions of atomicwrite.go that write the data of an output file: the
// single file's writeFileAtomic and, for every file of a tree, writeNewFile. Each must sync the
// file after its last write, in its own body (not in a deferred function literal, which would
// run after the return): atomicwrite.go's header says the data is synced before the output is
// put in place.
var syncedWriters = []string{"writeFileAtomic", "writeNewFile"}

// syncViolations judges the sources (slash path -> source) for the rule of syncedWriters.
func syncViolations(files map[string]string) []string {
	src, ok := files[atomicwriteFilePath]
	if !ok {
		return []string{atomicwriteFilePath + ": is not among the sources"}
	}
	f, err := parser.ParseFile(token.NewFileSet(), atomicwriteFilePath, src, 0)
	if err != nil {
		return []string{atomicwriteFilePath + ": does not parse: " + err.Error()}
	}
	var violations []string
	for _, name := range syncedWriters {
		var fd *ast.FuncDecl
		for _, d := range f.Decls {
			if x, ok := d.(*ast.FuncDecl); ok && x.Recv == nil && x.Name.Name == name {
				fd = x
			}
		}
		if fd == nil || fd.Body == nil {
			violations = append(violations, atomicwriteFilePath+": func "+name+" is not found")
			continue
		}
		var lastWrite, firstSync token.Pos
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "Write":
					if x.Pos() > lastWrite {
						lastWrite = x.Pos()
					}
				case "Sync":
					if firstSync == token.NoPos {
						firstSync = x.Pos()
					}
				}
			}
			return true
		})
		switch {
		case firstSync == token.NoPos:
			violations = append(violations, atomicwriteFilePath+": func "+name+" does not call Sync: its data is not on disk before the output is put in place")
		case lastWrite == token.NoPos:
			violations = append(violations, atomicwriteFilePath+": func "+name+" does not call Write: the scan does not see its write")
		case firstSync < lastWrite:
			violations = append(violations, atomicwriteFilePath+": func "+name+" syncs before its last write")
		}
	}
	return violations
}

func TestTheOutputFilesAreSyncedBeforeTheyArePutInPlace(t *testing.T) {
	sources := nonTestSources(t)
	for _, v := range syncViolations(sources) {
		t.Error(v)
	}

	// The scan itself: the allowed shape passes, every other one is seen.
	const good = "package edition\n\nfunc writeFileAtomic() {\n\t_, _ = f.Write(d)\n\t_ = f.Sync()\n\t_ = f.Close()\n}\n\n" +
		"func writeNewFile() {\n\tdefer func() { _ = f.Close() }()\n\t_, _ = f.Write(d)\n\t_ = f.Sync()\n}\n"
	if v := syncViolations(map[string]string{atomicwriteFilePath: good}); len(v) != 0 {
		t.Fatalf("the allowed shape: %v", v)
	}
	actual := sources[atomicwriteFilePath]
	for name, src := range map[string]string{
		"the single file is not synced":      replaceOnce(t, actual, "if err = f.Sync(); err != nil {", "if err = f.Close(); err != nil {"),
		"a file of a tree is not synced":     replaceOnce(t, actual, "if err := f.Sync(); err != nil {", "if err := f.Close(); err != nil {"),
		"the single file syncs before write": replaceOnce(t, good, "\t_, _ = f.Write(d)\n\t_ = f.Sync()\n\t_ = f.Close()\n", "\t_ = f.Sync()\n\t_, _ = f.Write(d)\n\t_ = f.Close()\n"),
		"the sync is in a deferred function": replaceOnce(t, good, "\tdefer func() { _ = f.Close() }()\n\t_, _ = f.Write(d)\n\t_ = f.Sync()\n", "\tdefer func() { _ = f.Sync() }()\n\t_, _ = f.Write(d)\n"),
		"a writer is missing":                "package edition\n\nfunc writeFileAtomic() {\n\t_, _ = f.Write(d)\n\t_ = f.Sync()\n}\n",
		"a writer does not write":            "package edition\n\nfunc writeFileAtomic() {\n\t_ = f.Sync()\n}\n\nfunc writeNewFile() {\n\t_, _ = f.Write(d)\n\t_ = f.Sync()\n}\n",
	} {
		if v := syncViolations(map[string]string{atomicwriteFilePath: src}); len(v) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
	if v := syncViolations(map[string]string{}); len(v) == 0 {
		t.Error("a source set without atomicwrite.go was not reported")
	}
}

// beforeLink, the seam of atomicwrite.go's put-in-place, is held the same way: assigned by test
// files only, named by no other non-test file. atomicwrite.go names it three times (the
// declaration, the nil test and the call).
func TestTheBeforeLinkSeamIsAssignedByTestsOnly(t *testing.T) {
	violations, names := beforeLinkViolations(nonTestSources(t))
	for _, v := range violations {
		t.Error(v)
	}
	if names != 3 {
		t.Errorf("atomicwrite.go names beforeLink %d times, want 3 (its declaration, the nil test and the call): the scan does not see the seam", names)
	}

	const writeSrc = "package edition\n\nvar beforeLink func(string)\n\nfunc put() {\n\tif beforeLink != nil {\n\t\tbeforeLink(\"x\")\n\t}\n}\n"
	base := map[string]string{atomicwriteFilePath: writeSrc}
	if v, n := beforeLinkViolations(base); len(v) != 0 || n != 3 {
		t.Fatalf("the allowed shape: violations %v, names %d, want none and 3", v, n)
	}
	for name, c := range map[string]struct{ path, src string }{
		"an assignment in another file":   {"internal/edition/other.go", "package edition\n\nfunc f() { beforeLink = nil }\n"},
		"a read in another file":          {"internal/edition/other.go", "package edition\n\nfunc f() { _ = beforeLink }\n"},
		"a call in safeopen.go":           {safeopenFilePath, "package edition\n\nfunc f() { beforeLink(\"x\") }\n"},
		"an assignment in atomicwrite.go": {atomicwriteFilePath, writeSrc + "\nfunc g() { beforeLink = func(string) {} }\n"},
		"an assignment inside a literal":  {atomicwriteFilePath, writeSrc + "\nvar _ = func() int { beforeLink = nil; return 0 }()\n"},
		"a file that does not parse":      {"internal/edition/other.go", "package edition\n\nfunc ("},
	} {
		files := rdCopyFiles(base)
		files[c.path] = c.src
		if v, _ := beforeLinkViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
}

// writeFault, the seam of atomicwrite.go's failures (ADR-0056 V87, V92: exit 3 is made to
// happen in the tests without a permission, which a test that runs as root would not feel), is
// held the same way: assigned by test files only, named by no other non-test file. atomicwrite.go
// names it three times (the declaration, the nil test in injected and the call).
func TestTheWriteFaultSeamIsAssignedByTestsOnly(t *testing.T) {
	violations, names := writeFaultViolations(nonTestSources(t))
	for _, v := range violations {
		t.Error(v)
	}
	if names != 3 {
		t.Errorf("atomicwrite.go names writeFault %d times, want 3 (its declaration, the nil test and the call): the scan does not see the seam", names)
	}

	const writeSrc = "package edition\n\nvar writeFault func(string) error\n\nfunc injected(step string) error {\n\tif writeFault == nil {\n\t\treturn nil\n\t}\n\treturn writeFault(step)\n}\n"
	base := map[string]string{atomicwriteFilePath: writeSrc}
	if v, n := writeFaultViolations(base); len(v) != 0 || n != 3 {
		t.Fatalf("the allowed shape: violations %v, names %d, want none and 3", v, n)
	}
	for name, c := range map[string]struct{ path, src string }{
		"an assignment in another file":   {"internal/edition/other.go", "package edition\n\nfunc f() { writeFault = nil }\n"},
		"a read in another file":          {"internal/edition/other.go", "package edition\n\nfunc f() { _ = writeFault }\n"},
		"a call in safeopen.go":           {safeopenFilePath, "package edition\n\nfunc f() { _ = writeFault(\"x\") }\n"},
		"a call in the renderer's file":   {"internal/edition/eventrender.go", "package edition\n\nfunc f() { _ = writeFault(\"x\") }\n"},
		"an assignment in atomicwrite.go": {atomicwriteFilePath, writeSrc + "\nfunc g() { writeFault = func(string) error { return nil } }\n"},
		"an assignment inside a literal":  {atomicwriteFilePath, writeSrc + "\nvar _ = func() int { writeFault = nil; return 0 }()\n"},
		"a file that does not parse":      {"internal/edition/other.go", "package edition\n\nfunc ("},
	} {
		files := rdCopyFiles(base)
		files[c.path] = c.src
		if v, _ := writeFaultViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
}
