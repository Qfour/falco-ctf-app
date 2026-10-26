package sourcehygiene

// app#511: no tracked text file may hold a raw invisible character, and no tracked
// path may hold anything but printable ASCII. The table, the scanner and the context
// rules are in invisible.go (so hintleak can import them); this file is the gate that
// applies them to the tree, the closed allowlist, and the selftests.
//
// The gate itself is TestTrackedFilesHoldNoRawBidiOrInvisibleCharacter (bidi_test.go):
// one walk, one file set, one canary list, two rules. This file adds the second rule
// to that walk (invisibleScanner) and proves it can fail.
//
// This file holds no raw invisible character: every one is built at run time with
// string(rune) (the helper cps), and every escape form is built from a backslash that
// is never next to its letter in the source.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

const invisibleAllowlistFile = "internal/sourcehygiene/testdata/invisible-allowlist.txt"

// printablePath is the one rule for a tracked path: U+0021-007E, no space.
var printablePath = regexp.MustCompile(`^[!-~]+$`)

// cps builds a string from code points (the only way this file writes one).
func cps(cp ...rune) string {
	var b strings.Builder
	for _, r := range cp {
		b.WriteRune(r)
	}
	return b.String()
}

// bs is a backslash. Escape forms are bs + "u200b" etc.: never written as one token.
const bs = "\\"

// escapeHint is the way to write cp without the raw character, for the message.
func escapeHint(cp rune) string {
	if cp > 0xFFFF {
		return fmt.Sprintf("%sU%08X", bs, cp)
	}
	return fmt.Sprintf("%su%04X", bs, cp)
}

// invEntry is one allowlist line: the code points that may appear raw in one file.
type invEntry struct {
	cps    []rune
	reason string
}

func (e invEntry) has(cp rune) bool {
	for _, c := range e.cps {
		if c == cp {
			return true
		}
	}
	return false
}

var cpToken = regexp.MustCompile(`^U\+[0-9A-F]{4,6}$`)

// parseInvisibleAllowlist reads <path><TAB><U+XXXX[,U+XXXX...]><TAB><reason>. The path
// rules are those of parseAllowlist. The code points are upper-case hex, strictly
// ascending, each a row of invisibleRanges (not a bidi control, not U+0000: NUL has
// its own rule).
func parseInvisibleAllowlist(text string) (map[string]invEntry, error) {
	allow := map[string]invEntry{}
	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		where := fmt.Sprintf("%s:%d", invisibleAllowlistFile, n+1)
		cols := strings.SplitN(line, "\t", 3)
		if len(cols) != 3 {
			return nil, fmt.Errorf("%s: want <path><TAB><U+XXXX[,...]><TAB><reason>, got %q", where, line)
		}
		p, list, reason := cols[0], cols[1], cols[2]
		switch {
		case strings.TrimSpace(reason) == "":
			return nil, fmt.Errorf("%s: %q has no reason", where, p)
		case p == "" || p != strings.TrimSpace(p) || strings.ContainsAny(p, `*?[]{}\`) ||
			filepath.ToSlash(filepath.Clean(p)) != p || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "../") || p == ".":
			return nil, fmt.Errorf("%s: %q is not an exact, clean, slash-separated file path (no glob, no directory)", where, p)
		}
		var list2 []rune
		for _, tok := range strings.Split(list, ",") {
			if !cpToken.MatchString(tok) {
				return nil, fmt.Errorf("%s: %q is not a code point written U+ and 4-6 upper-case hex digits", where, tok)
			}
			v, err := strconv.ParseUint(tok[2:], 16, 32)
			if err != nil || v > unicode.MaxRune {
				return nil, fmt.Errorf("%s: %q is not a code point", where, tok)
			}
			cp := rune(v)
			if _, bidi := bidiControls[cp]; bidi {
				return nil, fmt.Errorf("%s: %s is a bidi control: its exception goes in %s", where, tok, allowlistFile)
			}
			if cp == 0 {
				return nil, fmt.Errorf("%s: U+0000 is the NUL rule, not an invisible-character exception", where)
			}
			if _, _, in := lookup(cp); !in {
				return nil, fmt.Errorf("%s: %s is not in invisibleRanges, so there is nothing to allow", where, tok)
			}
			if len(list2) > 0 && cp <= list2[len(list2)-1] {
				return nil, fmt.Errorf("%s: code points must be strictly ascending (%s after U+%04X)", where, tok, list2[len(list2)-1])
			}
			list2 = append(list2, cp)
		}
		if _, dup := allow[p]; dup {
			return nil, fmt.Errorf("%s: %q is listed twice", where, p)
		}
		allow[p] = invEntry{cps: list2, reason: strings.TrimSpace(reason)}
	}
	return allow, nil
}

// invisibleScanner is the second rule of the walk (fileScanner).
type invisibleScanner struct {
	allow map[string]invEntry
	seen  map[string]map[rune]bool // allowlisted file -> code points that did appear raw
}

func newInvisibleScanner(allow map[string]invEntry) *invisibleScanner {
	return &invisibleScanner{allow: allow, seen: map[string]map[rune]bool{}}
}

func (s *invisibleScanner) path(rel string) []string {
	if printablePath.MatchString(rel) {
		return nil
	}
	return []string{fmt.Sprintf("%s: path name is not printable ASCII (U+0021-007E, no space)", strconv.QuoteToASCII(rel))}
}

func (s *invisibleScanner) file(rel string, data []byte) []string {
	var out []string
	e, listed := s.allow[rel]
	for _, f := range Invisible(data) {
		if f.CP == 0 {
			continue // a NUL byte is reported once, by the walk
		}
		if listed && e.has(f.CP) {
			if s.seen[rel] == nil {
				s.seen[rel] = map[rune]bool{}
			}
			s.seen[rel][f.CP] = true
			continue
		}
		msg := fmt.Sprintf("%s:%d:%d U+%04X %s: raw invisible character (write it as an escape such as %s; an exception needs a reviewed line in %s)",
			rel, f.Line, f.Col, f.CP, f.Name, escapeHint(f.CP), invisibleAllowlistFile)
		if f.Why != "" {
			msg += "; " + f.Why
		}
		out = append(out, msg)
	}
	return out
}

func (s *invisibleScanner) finish(r *report) []string {
	var out []string
	paths := make([]string, 0, len(s.allow))
	for p := range s.allow {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if len(s.seen[p]) == 0 {
			why := "the file holds none of the listed raw characters"
			switch {
			case r.scannedBinary(p):
				why = "the file has a binaryExt extension and is not scanned"
			case !r.scanned[p]:
				why = "the file is not a tracked regular file"
			}
			out = append(out, fmt.Sprintf("%s: dead allowlist entry %q: %s; delete the line", invisibleAllowlistFile, p, why))
			continue
		}
		for _, cp := range s.allow[p].cps {
			if !s.seen[p][cp] {
				out = append(out, fmt.Sprintf("%s: dead allowlist code point U+%04X for %q: the file does not hold it raw; remove it from the line", invisibleAllowlistFile, cp, p))
			}
		}
	}
	return out
}

func (r *report) scannedBinary(p string) bool {
	for _, b := range r.binary {
		if b == p {
			return true
		}
	}
	return false
}

// checkRealTree runs the walk on root with the shipped invisible allowlist and returns
// the report and that allowlist. bidiAllow is the bidi list.
func checkRealTree(t *testing.T, root string, bidiAllow map[string]string) (*report, map[string]invEntry) {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(invisibleAllowlistFile)))
	if err != nil {
		t.Fatalf("the invisible allowlist is unreadable (it must exist): %v", err)
	}
	allow, err := parseInvisibleAllowlist(string(text))
	if err != nil {
		t.Fatal(err)
	}
	r, err := checkTree(root, bidiAllow, newInvisibleScanner(allow))
	if err != nil {
		t.Fatal(err)
	}
	return r, allow
}

// ---- the table -----------------------------------------------------------

func TestInvisibleTable_Shape(t *testing.T) {
	for i, row := range invisibleRanges {
		if row.lo > row.hi || row.name == "" {
			t.Errorf("row %d (U+%04X-%04X %q) is malformed", i, row.lo, row.hi, row.name)
		}
		if i > 0 && row.lo <= invisibleRanges[i-1].hi {
			t.Errorf("row %d (U+%04X) is not ascending or overlaps the row before (U+%04X)", i, row.lo, invisibleRanges[i-1].hi)
		}
		for cp := row.lo; cp <= row.hi; cp++ {
			want := always
			switch cp {
			case 0x000D:
				want = loneCR
			case 0x200D:
				want = zwjInEmoji
			case 0xFE0E, 0xFE0F:
				want = vsAfterSymbol
			case 0xFEFF:
				want = bomAtStart
			}
			if row.rule != want {
				t.Errorf("U+%04X has rule %d, want %d (a context rule belongs to exactly its own rune)", cp, row.rule, want)
			}
		}
	}
}

// TestInvisibleTable_CoversCfAndDICP is the meta test: every rune that Unicode says a
// renderer may draw as nothing is forbidden raw, by this table or by bidiControls.
// It goes red when a Go upgrade brings a new Unicode version with a new Cf or
// Default_Ignorable rune: the table is then updated, with review.
func TestInvisibleTable_CoversCfAndDICP(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		_, _, inInv := lookup(r)
		_, inBidi := bidiControls[r]
		if inInv && inBidi {
			t.Errorf("U+%04X is in both invisibleRanges and bidiControls: it would be reported twice", r)
		}
		invisible := unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
		if invisible && !inInv && !inBidi {
			t.Errorf("U+%04X is Cf / Variation_Selector / Other_Default_Ignorable but in neither invisibleRanges nor bidiControls", r)
		}
	}
	for _, r := range []rune{'\t', '\n', ' ', 0xA0, 0x2000, 0x3000, 'a', '~', '!', 0x2800, 0x3042} {
		if _, _, in := lookup(r); in {
			t.Errorf("U+%04X is visible or ordinary whitespace and must not be in the table", r)
		}
	}
}

// TestInvisible_EveryRuneAndOnlyThose: "a" + r + "b" has exactly one finding at column 2
// if r is a row of the table (the context rules are all red here: nothing visible
// before r, or no pictographic symbol around it), and none otherwise.
func TestInvisible_EveryRuneAndOnlyThose(t *testing.T) {
	hits := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // not a code point a string can hold
		}
		_, _, forbidden := lookup(r)
		got := Invisible([]byte("a" + string(r) + "b"))
		switch {
		case forbidden && (len(got) != 1 || got[0].CP != r || got[0].Col != 2 || got[0].Line != 1):
			t.Errorf("U+%04X is in the table but Invisible gave %v", r, got)
		case !forbidden && len(got) != 0:
			t.Errorf("U+%04X is not in the table but Invisible gave %v", r, got)
		}
		if forbidden {
			hits++
		}
	}
	t.Logf("%d runes are forbidden in the middle of a word", hits)
}

// ---- the scanner ----------------------------------------------------------

func at(f Finding) string { return fmt.Sprintf("%d:%d U+%04X", f.Line, f.Col, f.CP) }

// TestInvisible_Table moved to testdata/hidden-cases.tsv (ADR-0045): the same inputs, the
// same expected findings and the same names, now shared with scripts/sourcehygiene-scan.py.
// TestHidden_SharedCases (exported_table_test.go) runs every row against Hidden AND
// against Invisible (= Hidden without the bidi controls), so no coverage is lost.

// ---- the walk, the allowlist, the path rule --------------------------------

func TestCheckTree_Invisible(t *testing.T) {
	zwsp := cps(0x200B)
	ps := cps(0x2029)
	warn := cps(0x26A0, 0xFE0F)
	tests := []struct {
		name  string
		files map[string]string
		allow string // allowlist text
		want  []string
		none  bool // no problem at all
	}{
		{name: "a ZWSP in a file that is not listed is red with path, line, column, name and an escape hint",
			files: map[string]string{"a/b.md": "x\nab" + zwsp + "\n"},
			want:  []string{"a/b.md:2:3 U+200B ZERO WIDTH SPACE: raw invisible character (write it as an escape such as " + bs + "u200B;"}},
		{name: "a Tag character names its escape with eight digits",
			files: map[string]string{".claude/agents/x.md": "go" + cps(0xE0041)},
			want:  []string{".claude/agents/x.md:1:3 U+E0041", bs + "U000E0041"}},
		{name: "the code point listed for the file is green",
			files: map[string]string{"a/b.md": "x" + zwsp},
			allow: "a/b.md\tU+200B\tattack fixture\n", none: true},
		{name: "a code point that is not in the file's list is red even if another is listed",
			files: map[string]string{"a/b.md": "x" + zwsp + ps},
			allow: "a/b.md\tU+200B\tattack fixture\n",
			want:  []string{"a/b.md:1:3 U+2029"}},
		{name: "a listed code point that the file does not hold is a dead code point",
			files: map[string]string{"a/b.md": "x" + zwsp},
			allow: "a/b.md\tU+200B,U+2029\tattack fixture\n",
			want:  []string{`dead allowlist code point U+2029 for "a/b.md"`}},
		{name: "a listed file with no hit at all is a dead entry",
			files: map[string]string{"a/b.md": "clean\n"},
			allow: "a/b.md\tU+200B\tattack fixture\n",
			want:  []string{`dead allowlist entry "a/b.md": the file holds none of the listed raw characters`}},
		{name: "a listed file that is not in the tree is a dead entry",
			files: map[string]string{"ok.md": "clean\n"},
			allow: "gone.md\tU+200B\tattack fixture\n",
			want:  []string{`dead allowlist entry "gone.md": the file is not a tracked regular file`}},
		{name: "a listed binaryExt file is a dead entry",
			files: map[string]string{"f.woff2": "\x00" + zwsp},
			allow: "f.woff2\tU+200B\tattack fixture\n",
			want:  []string{`dead allowlist entry "f.woff2": the file has a binaryExt extension`}},
		{name: "a context-green occurrence is not a hit: listing it makes the entry dead",
			files: map[string]string{"a.md": warn + " careful\n"},
			allow: "a.md\tU+FE0F\tthe warning sign\n",
			want:  []string{`dead allowlist entry "a.md"`}},
		{name: "a context-green VS16 is green without a list, a bad one beside it is red",
			files: map[string]string{"a.md": warn + " a" + cps(0xFE0F) + "\n"},
			want:  []string{"a.md:1:5 U+FE0F", "not directly after a non-ASCII symbol (So)"}},
		{name: "a listed code point also allows a context-bad use of it (the grant is per code point)",
			files: map[string]string{"a.md": "a" + cps(0xFE0F)},
			allow: "a.md\tU+FE0F\tfixture\n", none: true},
		{name: "a ZWSP in a word of a journey.yaml hint is red",
			files: map[string]string{"challenges/00-tutorial/journey.yaml": "hints:\n  - text: \"cat /etc/pa" + zwsp + "sswd\"\n"},
			want:  []string{"challenges/00-tutorial/journey.yaml:2:23 U+200B"}},
		{name: "a ZWSP in a path name is red, and the path is shown escaped",
			files: map[string]string{"agents/rev" + zwsp + "iew.md": "x\n"},
			want:  []string{`"agents/rev` + bs + `u200biew.md": path name is not printable ASCII`}},
		{name: "a path name that ends in LF is red (an end-anchored regexp that lets a final LF through would miss it)",
			files: map[string]string{"docs/a.md\n": "x\n"},
			want:  []string{"path name is not printable ASCII"}},
		{name: "a non-ASCII path name is red",
			files: map[string]string{"docs/" + cps(0x3042) + ".md": "x\n"},
			want:  []string{"path name is not printable ASCII"}},
		{name: "a non-ASCII name of a binaryExt file is red too (the path rule runs before the binary skip)",
			files: map[string]string{"fonts/" + cps(0x3042) + ".woff2": "\x00\x01"},
			want:  []string{"path name is not printable ASCII"}},
		{name: "a path with a space is red",
			files: map[string]string{"docs/a b.md": "x\n"},
			want:  []string{"path name is not printable ASCII"}},
		{name: "a NUL byte is one NUL problem and no U+0000 line",
			files: map[string]string{"n.md": "a\x00b\n"},
			want:  []string{"n.md: holds a NUL byte"}},
		{name: "a raw RLO is the bidi rule's finding only (reported once)",
			files: map[string]string{"r.md": "a" + cps(0x202E) + "b\n"},
			want:  []string{"r.md:1:2 U+202E RIGHT-TO-LEFT OVERRIDE"}},
		{name: "escapes of every kind are green",
			files: map[string]string{"e.md": bs + "U0000200B " + bs + "u200b " + bs + "U000E0041 {U+200B} &#x200B; &#8203;\n"}, none: true},
		{name: "a binaryExt file is not scanned",
			files: map[string]string{"f.woff2": "\x00" + zwsp}, none: true},
		{name: "invalid UTF-8 earlier in the file does not hide a later ZWSP",
			files: map[string]string{"bad.txt": "\xff\xfe broken\nab" + zwsp},
			want:  []string{"bad.txt:2:3 U+200B"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allow, err := parseInvisibleAllowlist(tc.allow)
			if err != nil {
				t.Fatal(err)
			}
			r, err := checkTree(plant(t, tc.files), nil, newInvisibleScanner(allow))
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(r.problems, "\n")
			if tc.none && len(r.problems) != 0 {
				t.Fatalf("want no problem, got:\n%s", joined)
			}
			for _, w := range tc.want {
				if !strings.Contains(joined, w) {
					t.Errorf("want a problem containing %q, got:\n%s", w, joined)
				}
			}
			if strings.Contains(joined, "U+0000") {
				t.Errorf("a NUL must be reported by the NUL rule only, got:\n%s", joined)
			}
		})
	}
}

func TestCheckTree_Invisible_ANonASCIISymlinkNameIsRed(t *testing.T) {
	root := plant(t, map[string]string{"real.txt": "x\n"})
	link := "link-" + cps(0x3042) + ".txt"
	if err := os.Symlink(filepath.Join(root, "real.txt"), filepath.Join(root, link)); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	r, err := checkTree(root, nil, newInvisibleScanner(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.problems) != 1 || !strings.Contains(r.problems[0], "path name is not printable ASCII") {
		t.Errorf("the symlink's name must be the one problem, got %v", r.problems)
	}
	if len(r.skipped) != 1 || r.skipped[0] != link {
		t.Errorf("the symlink is skipped (not followed) but its name is still checked, got skipped=%v", r.skipped)
	}
}

// TestHidden_CoversBothSets: Hidden is Invisible plus the nine bidi controls, in order;
// Invisible alone never reports a bidi control (the gate reports those by its own rule).
func TestHidden_CoversBothSets(t *testing.T) {
	text := []byte("a" + cps(0x202E) + "b" + cps(0x200B) + "c" + cps(0x2069))
	var inv, all []string
	for _, f := range Invisible(text) {
		inv = append(inv, at(f))
	}
	for _, f := range Hidden(text) {
		all = append(all, at(f))
	}
	if strings.Join(inv, ",") != "1:4 U+200B" {
		t.Errorf("Invisible = %v, want only the ZWSP", inv)
	}
	if strings.Join(all, ",") != "1:2 U+202E,1:4 U+200B,1:6 U+2069" {
		t.Errorf("Hidden = %v, want RLO, ZWSP, PDI in order", all)
	}
	for cp := range bidiControls {
		if got := Hidden([]byte("a" + string(cp) + "b")); len(got) != 1 || got[0].CP != cp || got[0].Name != bidiControls[cp] {
			t.Errorf("Hidden of U+%04X = %v", cp, got)
		}
	}
}

// TestCheckTree_Invisible_BidiAndInvisibleShareOneWalk: one file with a bidi control, an
// invisible character and a NUL gives one finding of each rule and one NUL problem.
func TestCheckTree_Invisible_BidiAndInvisibleShareOneWalk(t *testing.T) {
	body := "a" + cps(0x202E) + "b" + cps(0x200B) + "c\x00\n"
	r, err := checkTree(plant(t, map[string]string{"m.md": body}), nil, newInvisibleScanner(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"m.md: holds a NUL byte", "m.md:1:4 U+200B", "m.md:1:2 U+202E"}
	if len(r.problems) != len(want) {
		t.Fatalf("want %d problems, got %d:\n%s", len(want), len(r.problems), strings.Join(r.problems, "\n"))
	}
	for i, w := range want {
		if !strings.Contains(r.problems[i], w) {
			t.Errorf("problem %d = %q, want it to contain %q", i, r.problems[i], w)
		}
	}
}

func TestParseInvisibleAllowlist(t *testing.T) {
	good, err := parseInvisibleAllowlist("# c\n\na/b.txt\tU+2028\tfixture: the raw LS is the input\nc.go\tU+200B,U+2029\tx\nd.md\tU+E0041\ty\n")
	if err != nil || len(good) != 3 || len(good["c.go"].cps) != 2 || good["d.md"].cps[0] != 0xE0041 {
		t.Fatalf("good list: %v %v", good, err)
	}
	bad := map[string]string{
		"two columns":          "a.txt\treason\n",
		"no code point":        "a.txt\t\treason\n",
		"empty reason":         "a.txt\tU+200B\t \n",
		"glob":                 "a/*.txt\tU+200B\treason\n",
		"directory":            "a/\tU+200B\treason\n",
		"absolute":             "/a.txt\tU+200B\treason\n",
		"parent":               "../a.txt\tU+200B\treason\n",
		"dot-slash":            "./a.txt\tU+200B\treason\n",
		"backslash":            "a" + bs + "b.txt\tU+200B\treason\n",
		"leading space":        " a.txt\tU+200B\treason\n",
		"duplicate path":       "a.txt\tU+200B\tr\na.txt\tU+2029\tr\n",
		"lower-case hex":       "a.txt\tU+200b\treason\n",
		"two digits":           "a.txt\tU+41\treason\n",
		"seven digits":         "a.txt\tU+0200B00\treason\n",
		"no U+ prefix":         "a.txt\t200B\treason\n",
		"not ascending":        "a.txt\tU+2029,U+200B\treason\n",
		"duplicate code point": "a.txt\tU+200B,U+200B\treason\n",
		"trailing comma":       "a.txt\tU+200B,\treason\n",
		"space in the list":    "a.txt\tU+200B, U+2029\treason\n",
		"outside the table":    "a.txt\tU+0041\treason\n",
		"a bidi control":       "a.txt\tU+202E\treason\n",
		"NUL":                  "a.txt\tU+0000\treason\n",
		"beyond Unicode":       "a.txt\tU+110000\treason\n",
	}
	for name, text := range bad {
		if _, err := parseInvisibleAllowlist(text); err == nil {
			t.Errorf("%s: %q must be rejected", name, text)
		}
	}
}

// TestShippedInvisibleAllowlist: the real file parses, and each line carries the reason
// its shape asks for (a flags-parity case whose raw byte is the validators' input).
func TestShippedInvisibleAllowlist(t *testing.T) {
	text, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(invisibleAllowlistFile)))
	if err != nil {
		t.Fatal(err)
	}
	allow, err := parseInvisibleAllowlist(string(text))
	if err != nil {
		t.Fatal(err)
	}
	for p, e := range allow {
		if !strings.HasPrefix(p, "internal/catalog/testdata/flags-parity/") {
			t.Errorf("%s: only the flags-parity corpus is allowed raw invisible characters", p)
		}
		if !strings.HasPrefix(e.reason, "flags-parity shared case (cases.tsv: ") || !strings.Contains(e.reason, "an escape would be a different input") {
			t.Errorf("%s: the reason must say which cases.tsv case the raw character is the input of, and why an escape cannot: %q", p, e.reason)
		}
	}
}
