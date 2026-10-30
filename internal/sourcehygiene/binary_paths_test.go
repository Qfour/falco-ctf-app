package sourcehygiene

// app#542 (ADR-0045 D1 (f), D4): the closed set of PATHS where a binary file may live.
//
// A file is skipped as binary when its extension is in binaryExt and it starts with that
// extension's signature (bidi_test.go isBinary). A signature is printable ASCII ("%PDF-",
// "wOF2") or two bytes (gzip), so a text file that starts with one passes the test: the
// signature guards against a wrong name, not a forgery. What stops the forgery is the PLACE:
// binary-paths.tsv lists, per extension, the directories binary files of that kind live in,
// and a file that is binary by the test above but is not under one of them is a problem. It is
// not scanned as text instead, so a forgery has no place to hide. The reference scanner
// (scripts/sourcehygiene-scan.py --binary-paths <file>) reads the same file and applies the
// same rule; a consumer passes the closed set of its own repo.
//
// binary-paths.tsv is not an input of the scanner's default run: with no --binary-paths (and
// with a nil scanner here) every binary file is trusted wherever it is, as before. app's gate
// and app's flag-guard pass the file.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const binaryPathsFile = "internal/sourcehygiene/testdata/binary-paths.tsv"

// binaryPathRow is one row of binary-paths.tsv: files with this extension may be binary under
// the directory prefix segs ("*" is exactly one segment).
type binaryPathRow struct {
	ext    string
	prefix string
	segs   []string
}

var (
	binaryPathExt    = regexp.MustCompile(`^\.[a-z0-9]+$`)
	binaryPathPrefix = regexp.MustCompile(`^(([A-Za-z0-9._+@-]+|\*)/)+$`)
)

// parseBinaryPaths reads the rows. A row is <.ext><TAB><prefix>: the extension in lower case,
// the prefix a slash-terminated run of segments, each a literal name (not "." or "..") or a lone
// "*". Rows are strictly ascending (by extension, then prefix). A file with no row is fine: it
// is the closed set of nothing, the strictest one.
func parseBinaryPaths(lines []string, label string) ([]binaryPathRow, error) {
	var rows []binaryPathRow
	var prev string
	for i, l := range lines {
		if !isDataRow(l) {
			continue
		}
		cols := strings.Split(l, "\t")
		if len(cols) != 2 {
			return nil, fmt.Errorf("%s:%d: want <.ext><TAB><directory prefix>, got %q", label, i+1, l)
		}
		ext, prefix := cols[0], cols[1]
		if !binaryPathExt.MatchString(ext) {
			return nil, fmt.Errorf("%s:%d: %q is not an extension (.[a-z0-9]+, lower case)", label, i+1, ext)
		}
		if !binaryPathPrefix.MatchString(prefix) {
			return nil, fmt.Errorf("%s:%d: %q is not a directory prefix (slash-terminated segments of [A-Za-z0-9._+@-] or a lone *)", label, i+1, prefix)
		}
		segs := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
		for _, s := range segs {
			if s == "." || s == ".." {
				return nil, fmt.Errorf("%s:%d: %q has a %q segment: not a directory prefix", label, i+1, prefix, s)
			}
		}
		key := ext + "\t" + prefix
		if key <= prev {
			return nil, fmt.Errorf("%s:%d: rows must be ascending and not repeat (%q after %q)", label, i+1, key, prev)
		}
		prev = key
		rows = append(rows, binaryPathRow{ext, prefix, segs})
	}
	return rows, nil
}

// covers: the file rel (slash-separated, extension ext) is below this row's prefix, at any depth.
func (r binaryPathRow) covers(rel string) bool {
	segs := strings.Split(rel, "/")
	if len(segs) <= len(r.segs) {
		return false
	}
	for i, s := range r.segs {
		if segs[i] == "" || (s != "*" && s != segs[i]) {
			return false
		}
	}
	return true
}

// binaryPathScanner is a fileScanner: after the walk, every file the walk took for binary must be
// under a row of its own extension.
type binaryPathScanner struct{ rows []binaryPathRow }

// newBinaryPathScanner refuses a row whose extension is not in binaryExt: such a row could never
// match a binary file, so it is a typo or a dead line.
func newBinaryPathScanner(rows []binaryPathRow) (*binaryPathScanner, error) {
	for _, r := range rows {
		if _, ok := binaryExt[r.ext]; !ok {
			return nil, fmt.Errorf("binary-paths.tsv: %s is not in binary-ext.tsv, so no file of it is ever binary", r.ext)
		}
	}
	return &binaryPathScanner{rows}, nil
}

func (s *binaryPathScanner) path(string) []string         { return nil }
func (s *binaryPathScanner) file(string, []byte) []string { return nil }

func (s *binaryPathScanner) finish(r *report) []string {
	var out []string
	for _, rel := range r.binary {
		ext := extOf(rel)
		ok := false
		for _, row := range s.rows {
			if row.ext == ext && row.covers(rel) {
				ok = true
				break
			}
		}
		if ok {
			continue
		}
		shown := rel
		if !printablePath.MatchString(rel) {
			shown = strconv.QuoteToASCII(rel)
		}
		out = append(out, fmt.Sprintf("%s: binary file (%s) outside the closed set of binary paths: a signature is printable ASCII or two bytes and proves nothing about the rest, so a file with it is trusted only under a directory listed in binary-paths.tsv (put it there, or list its directory: a reviewed line)", shown, ext))
	}
	return out
}

// appBinaryPaths is the closed set app ships: written here too so that a PR that changes
// binary-paths.tsv changes this list in the same diff (the file is what the scanner reads).
var appBinaryPaths = []string{
	".tgz\tcharts/*/charts/",
	".woff2\tinternal/scoreboard/view/vendor/fonts/",
}

func TestBinaryPaths_FileIsTheClosedSetAppShips(t *testing.T) {
	lines := readData(t, binaryPathsFile)
	rows, err := parseBinaryPaths(lines, binaryPathsFile)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.ext+"\t"+r.prefix)
	}
	if strings.Join(got, "\n") != strings.Join(appBinaryPaths, "\n") {
		t.Errorf("%s holds %q, the closed set app ships is %q (a new binary path is a reviewed change in both)", binaryPathsFile, got, appBinaryPaths)
	}
	if _, err := newBinaryPathScanner(rows); err != nil {
		t.Error(err)
	}
	for _, r := range rows {
		if r.ext == ".pdf" {
			t.Errorf("app tracks no .pdf (ADR-0045: .pdf is in binary-ext.tsv for platform's decks); a row for it here is a place for a forged one")
		}
	}
}

func TestBinaryPathRow_Covers(t *testing.T) {
	fonts := binaryPathRow{".woff2", "internal/fonts/", []string{"internal", "fonts"}}
	charts := binaryPathRow{".tgz", "charts/*/charts/", []string{"charts", "*", "charts"}}
	tests := []struct {
		row  binaryPathRow
		rel  string
		want bool
	}{
		{fonts, "internal/fonts/a.woff2", true},
		{fonts, "internal/fonts/sub/a.woff2", true},
		{fonts, "internal/fonts", false},
		{fonts, "internal/fontsx/a.woff2", false},
		{fonts, "xinternal/fonts/a.woff2", false},
		{fonts, "a.woff2", false},
		{charts, "charts/ctf-user/charts/x.tgz", true},
		{charts, "charts/charts/x.tgz", false},
		{charts, "charts/a/b/charts/x.tgz", false},
		{charts, "charts//charts/x.tgz", false},
		{charts, "charts/a/charts", false},
	}
	for _, tc := range tests {
		if got := tc.row.covers(tc.rel); got != tc.want {
			t.Errorf("%s covers %q = %v, want %v", tc.row.prefix, tc.rel, got, tc.want)
		}
	}
}

// TestRealGate_RejectsABinaryOutsideTheClosedSet runs checkRealTree (what the gate runs) on a
// planted tree that holds the real binary-paths.tsv: it proves the gate is wired to the closed
// set, which the real tree (no forgery in it) cannot.
func TestRealGate_RejectsABinaryOutsideTheClosedSet(t *testing.T) {
	shipped, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(binaryPathsFile)))
	if err != nil {
		t.Fatal(err)
	}
	pdf := "%PDF-1.7\n"
	woff := "wOF2\x00\x01"
	tests := []struct {
		name  string
		files map[string]string
		want  []string // each must be in some problem; none: no problem at all
	}{
		{"a real-signature .pdf is outside the closed set (app tracks no .pdf)",
			map[string]string{"docs/a.pdf": pdf}, []string{"docs/a.pdf: binary file (.pdf) outside the closed set of binary paths"}},
		{"a .woff2 outside the font directory is outside the closed set",
			map[string]string{"static/a.woff2": woff}, []string{"static/a.woff2: binary file (.woff2) outside"}},
		{"a .woff2 in the font directory is skipped",
			map[string]string{"internal/scoreboard/view/vendor/fonts/a.woff2": woff}, nil},
		{"a .tgz below charts/<name>/charts/ is skipped",
			map[string]string{"charts/scoreboard/charts/dep-1.0.0.tgz": "\x1f\x8b\x08\x00"}, nil},
		{"a .tgz directly under charts/<name>/ is outside",
			map[string]string{"charts/scoreboard/dep-1.0.0.tgz": "\x1f\x8b\x08\x00"}, []string{"charts/scoreboard/dep-1.0.0.tgz: binary file (.tgz) outside"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				invisibleAllowlistFile: "# none\n",
				binaryPathsFile:        string(shipped),
				"README.md":            "text\n",
			}
			for p, b := range tc.files {
				files[p] = b
			}
			r, _ := checkRealTree(t, plant(t, files), nil)
			joined := strings.Join(r.problems, "\n")
			if len(tc.want) == 0 && len(r.problems) != 0 {
				t.Fatalf("want no problem, got:\n%s", joined)
			}
			for _, w := range tc.want {
				if !strings.Contains(joined, w) {
					t.Errorf("want a problem containing %q, got:\n%s", w, joined)
				}
			}
		})
	}
}
