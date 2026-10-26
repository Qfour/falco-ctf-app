package sourcehygiene

// app#537 (ADR-0045 D4): the readers' and the walk's negative examples are DATA, one
// directory each under testdata/negatives/, and both implementations read the same
// directories: this test, and `scripts/sourcehygiene-scan.py --selftest`. Before this a
// hand-written copy lived on each side and the two had already drifted.
//
// A directory holds expect.txt and exactly one input:
//
//	cases.tsv        lines for the cases reader (hidden-cases.tsv rows)       -> parseSharedCases
//	binary-ext.tsv   lines for the binary-ext reader (ext, reason, signature) -> parseBinaryExt
//	plant.tsv        a tree to walk: <path><TAB><content>, one file per row   -> checkTree
//	                 (allowlist.txt, optional, only beside plant.tsv: the invisible allowlist)
//
// Paths and contents are written with the placeholders of hidden-cases.tsv ({U+XXXX}, {xHH}),
// so a name with an LF or a non-ASCII character, a NUL and a raw byte need no such file in
// git. A content may be empty. expect.txt: `exit:0` or `exit:1` (once), then any number of
// `out:<text>` (the output must contain it) and `not:<text>` (it must not). exit:1 is
// "the reader refused it" for a reader and "a problem was found, or the walk failed" for a
// tree; the output is the reader's error or the problems. Only text both implementations
// print may be in an out: line (a path:line:col prefix, a sentence both share). A file that
// is not in that set is an error, so a typo cannot turn a negative into nothing.
//
// What is NOT shared (the scanner's --selftest holds it alone): the ranges reader (Go
// compares the file with the Go tables instead of reading it), a tree that is only binary
// files (Go's walk does not require a text file; the canaries do), the bidi allowlist, git
// mode, --also-untracked, symlinks, an unlistable directory and the command line.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	negativesDir = "internal/sourcehygiene/testdata/negatives"
	// minNegatives is a floor: a directory emptied out is not a pass.
	minNegatives = 50
)

type negExpect struct {
	exit     int
	out, not []string
}

func parseExpect(lines []string, label string) (negExpect, error) {
	e := negExpect{exit: -1}
	for i, l := range lines {
		if !isDataRow(l) {
			continue
		}
		k, v, _ := strings.Cut(l, ":")
		switch {
		case (l == "exit:0" || l == "exit:1") && e.exit < 0:
			e.exit = int(l[len(l)-1] - '0')
		case k == "out" && v != "":
			e.out = append(e.out, v)
		case k == "not" && v != "":
			e.not = append(e.not, v)
		default:
			return e, fmt.Errorf("%s:%d: want one exit:0|exit:1, out:<text> or not:<text>, got %q", label, i+1, l)
		}
	}
	if e.exit < 0 {
		return e, fmt.Errorf("%s: no exit:0|exit:1 line", label)
	}
	return e, nil
}

// runPlant plants the rows of plant.tsv, applies allow (the text of allowlist.txt, or "") and
// walks the tree the way the gate does. It returns the exit status and the output.
func runPlant(t *testing.T, rows []string, allow string) (int, string) {
	t.Helper()
	files := map[string]string{}
	for _, l := range rows {
		if !isDataRow(l) {
			continue
		}
		cols := strings.Split(l, "\t")
		if len(cols) != 2 {
			t.Fatalf("plant.tsv: want <path><TAB><content>, got %q", l)
		}
		path, err := decodeCaseInput(cols[0])
		if err != nil {
			t.Fatalf("plant.tsv path %q: %v", cols[0], err)
		}
		var body []byte
		if cols[1] != "" {
			if body, err = decodeCaseInput(cols[1]); err != nil {
				t.Fatalf("plant.tsv content %q: %v", cols[1], err)
			}
		}
		files[string(path)] = string(body)
	}
	inv, err := parseInvisibleAllowlist(allow)
	if err != nil {
		return 1, err.Error()
	}
	r, err := checkTree(plant(t, files), nil, newInvisibleScanner(inv))
	if err != nil {
		return 1, err.Error()
	}
	if len(r.problems) > 0 {
		return 1, strings.Join(r.problems, "\n")
	}
	return 0, ""
}

func TestSharedNegatives(t *testing.T) {
	dir := filepath.Join(repoRoot(t), filepath.FromSlash(negativesDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("%s is unreadable: %v", negativesDir, err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			t.Errorf("%s/%s: only directories (one negative each)", negativesDir, e.Name())
			continue
		}
		n++
		t.Run(e.Name(), func(t *testing.T) {
			read := func(name string) ([]string, bool) {
				b, err := os.ReadFile(filepath.Join(dir, e.Name(), name))
				if os.IsNotExist(err) {
					return nil, false
				}
				if err != nil {
					t.Fatal(err)
				}
				lines, err := dataLines(b, e.Name()+"/"+name)
				if err != nil {
					t.Fatal(err)
				}
				return lines, true
			}
			var names []string
			sub, _ := os.ReadDir(filepath.Join(dir, e.Name()))
			for _, f := range sub {
				names = append(names, f.Name())
			}
			sort.Strings(names)
			var kind string
			for _, k := range []string{"cases.tsv", "binary-ext.tsv", "plant.tsv"} {
				if _, ok := read(k); ok {
					kind = k
				}
			}
			wantFiles := map[string]string{"cases.tsv": "cases.tsv expect.txt", "binary-ext.tsv": "binary-ext.tsv expect.txt", "plant.tsv": "expect.txt plant.tsv"}[kind]
			if _, hasAllow := read("allowlist.txt"); hasAllow && kind == "plant.tsv" {
				wantFiles = "allowlist.txt expect.txt plant.tsv"
			}
			if got := strings.Join(names, " "); kind == "" || got != wantFiles {
				t.Fatalf("the files are %q, want %q (expect.txt and exactly one input; allowlist.txt only beside plant.tsv)", got, wantFiles)
			}
			expLines, _ := read("expect.txt")
			exp, err := parseExpect(expLines, e.Name()+"/expect.txt")
			if err != nil {
				t.Fatal(err)
			}
			lines, _ := read(kind)
			var code int
			var out string
			switch kind {
			case "cases.tsv":
				_, err = parseSharedCases(lines)
			case "binary-ext.tsv":
				_, err = parseBinaryExt(lines, "binary-ext.tsv")
			default:
				allow, _ := read("allowlist.txt")
				code, out = runPlant(t, lines, strings.Join(allow, "\n"))
			}
			if kind != "plant.tsv" {
				if err != nil {
					code, out = 1, err.Error()
				}
			}
			if code != exp.exit {
				t.Errorf("exit %d, want %d; output:\n%s", code, exp.exit, out)
			}
			for _, w := range exp.out {
				if !strings.Contains(out, w) {
					t.Errorf("the output has no %q; output:\n%s", w, out)
				}
			}
			for _, w := range exp.not {
				if strings.Contains(out, w) {
					t.Errorf("the output has %q; output:\n%s", w, out)
				}
			}
		})
	}
	if n < minNegatives {
		t.Errorf("%s holds %d negatives, fewer than the floor %d", negativesDir, n, minNegatives)
	}
	t.Logf("%d shared negatives", n)
}
