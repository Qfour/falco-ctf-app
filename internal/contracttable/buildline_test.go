package contracttable

// ADR-0054 V1: the form of the Makefile's build lines and the rule for their
// `-f` / context paths are a cross-repo contract. platform's release reads them
// (scripts/lib/release-scan.sh, rs_build_args_checked) and builds nothing when one
// is outside the rule, so a Makefile that breaks it is red here first.
//
//	(a) the real Makefile: one line per image of IMAGES, both values pass D2, and in
//	    the test build context the Dockerfile is a regular file without an execute
//	    bit, the context is a directory and no path element is a symlink;
//	(b) the shared case table (testdata/build-path-cases.tsv, read by platform's
//	    test too): every row's verdict, and the table itself is held to a shape;
//	(c) D1 negatives (a Go table of Makefile texts);
//	(d) file system negatives (fixtures in t.TempDir());
//	(e) the contract table row exists and names the table and platform's script;
//	(f) dropping any one rule of the judgement turns a row of (b) red.
//
// A missing file or row FAILS, never skips (the Makefile, the conventions file and
// the table are in the Docker test context: Dockerfile.test copies the tree and
// .dockerignore keeps them).

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const caseTablePath = "testdata/build-path-cases.tsv"

const caseTableHeader = "dockerfile\tcontext\tverdict"

// minCaseRows is the floor on the table's rows: a table emptied down to a few rows
// must not still pass.
const minCaseRows = 20

type pathCase struct {
	dockerfile string
	context    string
	ok         bool
	line       int
}

// parseCaseTable reads the shared case table: the header, then one row per line with
// exactly three TAB-separated columns whose verdict is OK or REJECT. It is an error
// for the table to have too few rows or to lack either verdict.
func parseCaseTable(text string) ([]pathCase, error) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if lines[0] != caseTableHeader {
		return nil, fmt.Errorf("header is %q, want %q", lines[0], caseTableHeader)
	}
	var cases []pathCase
	nOK, nReject := 0, 0
	for i, ln := range lines[1:] {
		lineNo := i + 2
		cols := strings.Split(ln, "\t")
		if len(cols) != 3 {
			return nil, fmt.Errorf("line %d has %d columns, want 3: %q", lineNo, len(cols), ln)
		}
		ok := false
		switch cols[2] {
		case "OK":
			ok = true
			nOK++
		case "REJECT":
			nReject++
		default:
			return nil, fmt.Errorf("line %d: verdict %q is neither OK nor REJECT", lineNo, cols[2])
		}
		cases = append(cases, pathCase{dockerfile: cols[0], context: cols[1], ok: ok, line: lineNo})
	}
	if len(cases) < minCaseRows {
		return nil, fmt.Errorf("%d rows, want at least %d", len(cases), minCaseRows)
	}
	if nOK == 0 || nReject == 0 {
		return nil, fmt.Errorf("the table needs both verdicts (OK rows: %d, REJECT rows: %d)", nOK, nReject)
	}
	return cases, nil
}

func loadCaseTable(path string) ([]pathCase, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCaseTable(string(b))
}

func mustLoadCaseTable(t *testing.T) []pathCase {
	t.Helper()
	cases, err := loadCaseTable(caseTablePath)
	if err != nil {
		t.Fatalf("%s: %v (is it in the test build context?)", caseTablePath, err)
	}
	return cases
}

// tableMismatches returns the rows whose verdict differs from the judgement with
// the rule named skip left out ("" = the production judgement).
func tableMismatches(cases []pathCase, skip string) []pathCase {
	var bad []pathCase
	for _, c := range cases {
		if (checkBuildPaths(skip, c.dockerfile, c.context) == nil) != c.ok {
			bad = append(bad, c)
		}
	}
	return bad
}

// checkedBuildLines is the whole D1 + D2 judgement on a Makefile text.
func checkedBuildLines(makefile string) (map[string]BuildArgs, error) {
	lines, err := MakefileBuildLines(makefile)
	if err != nil {
		return nil, err
	}
	for name, a := range lines {
		if err := CheckBuildPaths(a.Dockerfile, a.Context); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return lines, nil
}

// noSymlinkElements fails when any element of rel, walked from root, is a symlink
// (or cannot be examined).
func noSymlinkElements(root, rel string) error {
	acc := ""
	for _, e := range strings.Split(rel, "/") {
		acc = filepath.Join(acc, e)
		fi, err := os.Lstat(filepath.Join(root, acc))
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%q is a symlink (the element of %q)", acc, rel)
		}
	}
	return nil
}

// checkBuildFiles is D2's file system half for one build line, under root: no
// symlink element in either path, the context is a directory, and the Dockerfile is
// a regular file without an execute bit (mode 0644 in the repository).
func checkBuildFiles(root string, a BuildArgs) error {
	for _, p := range []string{a.Context, a.Dockerfile} {
		if p == "." {
			continue
		}
		if err := noSymlinkElements(root, p); err != nil {
			return err
		}
	}
	ci, err := os.Lstat(filepath.Join(root, a.Context))
	if err != nil {
		return err
	}
	if !ci.IsDir() {
		return fmt.Errorf("context %q is not a directory", a.Context)
	}
	di, err := os.Lstat(filepath.Join(root, a.Dockerfile))
	if err != nil {
		return err
	}
	if !di.Mode().IsRegular() {
		return fmt.Errorf("Dockerfile %q is not a regular file (mode %v)", a.Dockerfile, di.Mode())
	}
	if di.Mode().Perm()&0o111 != 0 {
		return fmt.Errorf("Dockerfile %q has an execute bit (mode %v)", a.Dockerfile, di.Mode())
	}
	return nil
}

// (a)
func TestBuildLines_RealMakefile(t *testing.T) {
	makefile := readRepoFile(t, MakefilePath)
	images, err := MakefileImages(makefile)
	if err != nil {
		t.Fatalf("Makefile IMAGES: %v", err)
	}
	lines, err := MakefileBuildLines(makefile)
	if err != nil {
		t.Fatalf("Makefile build lines: %v", err)
	}
	if len(images) == 0 || len(lines) != len(images) {
		t.Fatalf("read %d build lines for %d images (%q): want one line per image and no other, and at least one", len(lines), len(images), images)
	}
	root := filepath.Join("..", "..")
	for _, name := range images {
		a, ok := lines[name]
		if !ok {
			t.Errorf("%s: no build line", name)
			continue
		}
		if err := CheckBuildPaths(a.Dockerfile, a.Context); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if err := checkBuildFiles(root, a); err != nil {
			t.Errorf("%s (-f %s, context %s): %v", name, a.Dockerfile, a.Context, err)
		}
	}
}

// (b)
func TestBuildPathCases_SharedTable(t *testing.T) {
	cases := mustLoadCaseTable(t)
	for _, c := range tableMismatches(cases, "") {
		t.Errorf("table line %d (-f %q, context %q): the table says ok=%v, the judgement says %v", c.line, c.dockerfile, c.context, c.ok, !c.ok)
	}
}

// The table must keep the rows the ADR names, so that emptying it of its sharp cases
// is red even when the row count and both verdicts are still there.
func TestBuildPathCases_TableKeepsTheNamedRows(t *testing.T) {
	cases := mustLoadCaseTable(t)
	has := func(dockerfile, context string, ok bool) bool {
		return slices.ContainsFunc(cases, func(c pathCase) bool {
			return c.dockerfile == dockerfile && c.context == context && c.ok == ok
		})
	}
	for _, w := range []struct {
		dockerfile string
		context    string
		ok         bool
		why        string
	}{
		{"images/ttyd/Dockerfile", "images", true, "a Dockerfile deeper than the context"},
		{"images/ttyd/Dockerfile", "images/ttyd", true, "the shape of the real ttyd line"},
		{".hidden/Dockerfile", ".", true, "a leading dot is not an element `.`"},
		{"/etc/hosts", ".", false, "an absolute path"},
		{"../falco-ctf-app/images/docs/Dockerfile", ".", false, "a `..` element"},
		{"$(HOME)/Dockerfile", ".", false, "a make variable"},
		{"~/Dockerfile", ".", false, "a tilde"},
		{"./images/docs/Dockerfile", ".", false, "a `./` prefix"},
		{"images//docs/Dockerfile", ".", false, "an empty element"},
		{"images/docs/Dockerfile/", ".", false, "a trailing slash"},
		{"scoreboard/Dockerfile", "images/ttyd", false, "a Dockerfile outside the context"},
		{"images/ttyd-proxy/Dockerfile", "images/ttyd", false, "a prefix of the context's name is not inside"},
		{"images/ttyd", "images/ttyd", false, "the Dockerfile is the context"},
	} {
		if !has(w.dockerfile, w.context, w.ok) {
			t.Errorf("the table has no row (-f %q, context %q, ok=%v): %s", w.dockerfile, w.context, w.ok, w.why)
		}
	}
}

// Strings the shared table has no row for (it holds paths a Makefile could carry;
// these are the characters a path grammar must refuse), judged by the same rules.
func TestCheckBuildPaths_ExtraRejects(t *testing.T) {
	for _, c := range []struct {
		name       string
		dockerfile string
		context    string
	}{
		{"a space in the Dockerfile", "a b/Dockerfile", "."},
		{"a tab in the context", "a/Dockerfile", "a\t"},
		{"a double quote", "a\"b/Dockerfile", "."},
		{"a single quote", "a'b/Dockerfile", "."},
		{"a backslash", "a\\b/Dockerfile", "."},
		{"a leading dash would be read as a flag", "-x/Dockerfile", "."},
		{"an empty Dockerfile", "", "."},
		{"an empty context", "a/Dockerfile", ""},
		{"a glob character", "a*/Dockerfile", "."},
		{"a colon", "a:b/Dockerfile", "."},
	} {
		if err := CheckBuildPaths(c.dockerfile, c.context); err == nil {
			t.Errorf("%s: (-f %q, context %q) passed", c.name, c.dockerfile, c.context)
		}
	}
}

// The table's own shape is held: a missing table, a different header, a row of a
// different width, an unknown verdict, too few rows or one verdict only are all
// errors (a loader that skipped them would turn (b) into a pass over nothing).
func TestParseCaseTable_Shape(t *testing.T) {
	row := func(i int, verdict string) string {
		return fmt.Sprintf("d%d/Dockerfile\t.\t%s\n", i, verdict)
	}
	rows := func(nOK, nReject int) string {
		s := caseTableHeader + "\n"
		for i := 0; i < nOK; i++ {
			s += row(i, "OK")
		}
		for i := 0; i < nReject; i++ {
			s += row(nOK+i, "REJECT")
		}
		return s
	}
	good := rows(10, 10)
	cases := []struct {
		name    string
		text    string
		wantErr bool
	}{
		{"a table of the minimum rows with both verdicts", good, false},
		{"without the final newline", strings.TrimSuffix(good, "\n"), false},
		{"empty", "", true},
		{"a different header", strings.Replace(good, "verdict", "result", 1), true},
		{"a header with the columns swapped", strings.Replace(good, "dockerfile\tcontext", "context\tdockerfile", 1), true},
		{"a row with two columns", good + "a/Dockerfile\tOK\n", true},
		{"a row with four columns", good + "a/Dockerfile\t.\tOK\textra\n", true},
		{"an unknown verdict", good + "a/Dockerfile\t.\tMAYBE\n", true},
		{"a verdict with a carriage return", good + "a/Dockerfile\t.\tOK\r\n", true},
		{"a blank line in the middle", good + "\n" + row(99, "OK"), true},
		{"one row too few", rows(10, 9), true},
		{"OK rows only", rows(20, 0), true},
		{"REJECT rows only", rows(0, 20), true},
	}
	for _, c := range cases {
		_, err := parseCaseTable(c.text)
		switch {
		case c.wantErr && err == nil:
			t.Errorf("%s: want an error, got none", c.name)
		case !c.wantErr && err != nil:
			t.Errorf("%s: unexpected error: %v", c.name, err)
		}
	}
	if _, err := loadCaseTable(filepath.Join(t.TempDir(), "no-such-table.tsv")); err == nil {
		t.Error("a table that does not exist loaded without an error")
	}
}

const (
	lineA = "\tdocker build -t $(REGISTRY)/a:$(TAG) -f a/Dockerfile ."
	lineB = "\tdocker build -t $(REGISTRY)/b:$(TAG)   -f images/b/Dockerfile   images/b"
)

func mkfile(images string, lines ...string) string {
	return "IMAGES := " + images + "\nbuild:\n" + strings.Join(lines, "\n") + "\n"
}

// A Makefile of the accepted form is read, whatever else it has around the lines.
func TestBuildLines_AcceptedForm(t *testing.T) {
	want := map[string]BuildArgs{
		"a": {Dockerfile: "a/Dockerfile", Context: "."},
		"b": {Dockerfile: "images/b/Dockerfile", Context: "images/b"},
	}
	noise := []string{
		"# docker build -t $(REGISTRY)/zzz:$(TAG) -f x/Dockerfile .",
		"\tdocker build -f Dockerfile.test --progress=plain -t falco-ctf/gotest:local .",
		"\tdocker push $(REGISTRY)/a:$(TAG)",
		"\t@for img in $(IMAGES); do docker push $(REGISTRY)/$$img:$(TAG); done",
		"\t./scripts/check-image-hygiene.sh $(REGISTRY)/a:$(TAG)",
		"\t@echo \"  build - docker build all images ($(REGISTRY)/<name>:$(TAG))\"",
		"\t$(MAKE) check-image-hygiene",
	}
	around := slices.Concat(noise[:2], []string{lineA, lineB}, noise[2:])
	cases := []struct {
		name     string
		makefile string
	}{
		{"the two lines", mkfile("a b", lineA, lineB)},
		{"the two lines in the other order", mkfile("b a", lineB, lineA)},
		{"spaces for the recipe TAB", mkfile("a b", strings.Replace(lineA, "\t", "    ", 1), lineB)},
		{"other docker lines around them", mkfile("a b", around...)},
	}
	for _, c := range cases {
		got, err := checkedBuildLines(c.makefile)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
			continue
		}
		if !maps.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", c.name, got, want)
		}
	}
}

// (c)
func TestBuildLines_FormNegatives(t *testing.T) {
	cases := []struct {
		name     string
		makefile string
	}{
		{"an argument before -f", mkfile("a b", strings.Replace(lineA, " -f ", " --no-cache -f ", 1), lineB)},
		{"an argument after the context", mkfile("a b", lineA+" --pull", lineB)},
		{"a second line for the same name", mkfile("a b", lineA, lineB, lineA)},
		{"a second line for the same name with other paths", mkfile("a b", lineA, lineB, strings.Replace(lineA, "a/Dockerfile", "evil/Dockerfile", 1))},
		{"a line for a name IMAGES does not name", mkfile("a b", lineA, lineB, strings.Replace(lineA, "/a:", "/c:", 1))},
		{"an IMAGES name without a line", mkfile("a b", lineA)},
		{"no build line at all", mkfile("a b")},
		{"no IMAGES line", "build:\n" + lineA + "\n" + lineB + "\n"},
		{"an empty Makefile", ""},
		{"a make variable as the Dockerfile", mkfile("a b", strings.Replace(lineA, "a/Dockerfile", "$(DF)", 1), lineB)},
		{"a make variable as the context", mkfile("a b", strings.Replace(lineA, " .", " $(CTX)", 1), lineB)},
		{"a make variable as the whole -f value and context", mkfile("a b", strings.Replace(lineA, "-f a/Dockerfile .", "$(ARGS)", 1), lineB)},
		{"an absolute Dockerfile", mkfile("a b", strings.Replace(lineA, "a/Dockerfile", "/etc/passwd", 1), lineB)},
		{"a Dockerfile outside the context", mkfile("a b", lineA, strings.Replace(lineB, "images/b/Dockerfile", "a/Dockerfile", 1))},
		{"two spaces between docker and build", mkfile("a b", strings.Replace(lineA, "docker build", "docker  build", 1), lineB)},
		{"two spaces before -t", mkfile("a b", strings.Replace(lineA, " -t ", "  -t ", 1), lineB)},
		{"two spaces after -t", mkfile("a b", strings.Replace(lineA, "-t $(REGISTRY)", "-t  $(REGISTRY)", 1), lineB)},
		{"a recipe prefix @", mkfile("a b", strings.Replace(lineA, "\tdocker", "\t@docker", 1), lineB)},
		{"no leading whitespace", mkfile("a b", strings.TrimPrefix(lineA, "\t"), lineB)},
		{"a trailing space (platform's form has nothing after the context)", mkfile("a b", lineA+" ", lineB)},
		{"a carriage return (CRLF)", mkfile("a b", lineA+"\r", lineB)},
		{"a continuation after a space", mkfile("a b", lineA+" \\", lineB)},
		{"a continuation glued to the context", mkfile("a b", lineA+"\\", lineB)},
		{"an upper-case name", mkfile("a b", strings.Replace(lineA, "/a:", "/A:", 1), lineB)},
		{"the ${} spelling is no build line, so the image has none", mkfile("a b", strings.Replace(lineA, "$(REGISTRY)", "${REGISTRY}", 1), lineB)},
		{"a second IMAGES line", mkfile("a b", lineA, lineB) + "IMAGES += c\n"},
	}
	for _, c := range cases {
		if got, err := checkedBuildLines(c.makefile); err == nil {
			t.Errorf("%s: want an error, got %v", c.name, got)
		}
	}
}

// (d)
func TestBuildFiles_FileSystemNegatives(t *testing.T) {
	put := func(t *testing.T, path string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("FROM scratch\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	link := func(t *testing.T, target, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		build   func(t *testing.T, root string) BuildArgs
		wantErr bool
	}{
		{"a regular 0644 Dockerfile in a directory context", func(t *testing.T, root string) BuildArgs {
			put(t, filepath.Join(root, "images", "x", "Dockerfile"), 0o644)
			return BuildArgs{Dockerfile: "images/x/Dockerfile", Context: "images/x"}
		}, false},
		{"a regular Dockerfile with the repository as the context", func(t *testing.T, root string) BuildArgs {
			put(t, filepath.Join(root, "x", "Dockerfile"), 0o644)
			return BuildArgs{Dockerfile: "x/Dockerfile", Context: "."}
		}, false},
		{"a symlink Dockerfile", func(t *testing.T, root string) BuildArgs {
			put(t, filepath.Join(root, "images", "x", "real"), 0o644)
			link(t, "real", filepath.Join(root, "images", "x", "Dockerfile"))
			return BuildArgs{Dockerfile: "images/x/Dockerfile", Context: "images/x"}
		}, true},
		{"a symlink element in the context", func(t *testing.T, root string) BuildArgs {
			put(t, filepath.Join(root, "real", "Dockerfile"), 0o644)
			link(t, filepath.Join("..", "real"), filepath.Join(root, "images", "x"))
			return BuildArgs{Dockerfile: "images/x/Dockerfile", Context: "images/x"}
		}, true},
		{"a symlink as the whole context", func(t *testing.T, root string) BuildArgs {
			put(t, filepath.Join(root, "real", "Dockerfile"), 0o644)
			link(t, "real", filepath.Join(root, "link"))
			return BuildArgs{Dockerfile: "link/Dockerfile", Context: "link"}
		}, true},
		{"a symlink element in the Dockerfile's path under the context .", func(t *testing.T, root string) BuildArgs {
			put(t, filepath.Join(root, "real", "Dockerfile"), 0o644)
			link(t, "real", filepath.Join(root, "link"))
			return BuildArgs{Dockerfile: "link/Dockerfile", Context: "."}
		}, true},
		{"a Dockerfile with an execute bit", func(t *testing.T, root string) BuildArgs {
			put(t, filepath.Join(root, "images", "x", "Dockerfile"), 0o755)
			return BuildArgs{Dockerfile: "images/x/Dockerfile", Context: "images/x"}
		}, true},
		{"a directory as the Dockerfile", func(t *testing.T, root string) BuildArgs {
			if err := os.MkdirAll(filepath.Join(root, "images", "x", "Dockerfile"), 0o755); err != nil {
				t.Fatal(err)
			}
			return BuildArgs{Dockerfile: "images/x/Dockerfile", Context: "images/x"}
		}, true},
		{"a file as the context", func(t *testing.T, root string) BuildArgs {
			put(t, filepath.Join(root, "images", "x"), 0o644)
			return BuildArgs{Dockerfile: "images/x/Dockerfile", Context: "images/x"}
		}, true},
		{"a Dockerfile that is not there", func(t *testing.T, root string) BuildArgs {
			if err := os.MkdirAll(filepath.Join(root, "images", "x"), 0o755); err != nil {
				t.Fatal(err)
			}
			return BuildArgs{Dockerfile: "images/x/Dockerfile", Context: "images/x"}
		}, true},
	}
	for _, c := range cases {
		root := t.TempDir()
		a := c.build(t, root)
		err := checkBuildFiles(root, a)
		switch {
		case c.wantErr && err == nil:
			t.Errorf("%s: want an error, got none", c.name)
		case !c.wantErr && err != nil:
			t.Errorf("%s: unexpected error: %v", c.name, err)
		}
	}
}

// (e)
func TestContractTable_HasTheBuildLineRow(t *testing.T) {
	conventions := readRepoFile(t, Path)
	row := RowWhere(conventions, func(r string) bool { return strings.HasPrefix(r, "| release build の build 行") })
	if row == "" {
		t.Fatal("the contract table has no `| release build の build 行` row (ADR-0054)")
	}
	for _, want := range []string{"ADR-0054", "build-path-cases.tsv", "release-scan.sh"} {
		if !strings.Contains(row, want) {
			t.Errorf("the build line row no longer names %q: %.200s", want, row)
		}
	}
}

// (f) Each rule of the judgement is load-bearing: with any one rule left out, at
// least one row of the shared table gets a verdict it must not have. A rule that no
// row needs would be a rule whose removal nobody notices.
func TestPathRules_EachRuleDecidesARow(t *testing.T) {
	cases := mustLoadCaseTable(t)
	if bad := tableMismatches(cases, ""); len(bad) != 0 {
		t.Fatalf("the production judgement already disagrees with the table on %d rows (first: line %d)", len(bad), bad[0].line)
	}
	var names []string
	for _, r := range pathRules {
		names = append(names, r.name)
	}
	want := []string{"grammar", "no-dotdot-element", "no-dot-element", "no-empty-element", "dockerfile-inside-context"}
	if !slices.Equal(names, want) {
		t.Fatalf("the rules are %q, this test expects %q (a rule added or removed must be reflected here and in ADR-0054 D2)", names, want)
	}
	for _, skip := range names {
		if bad := tableMismatches(cases, skip); len(bad) == 0 {
			t.Errorf("leaving the rule %q out changes no verdict of the shared table: no row needs it", skip)
		}
	}
}
