package sourcehygiene

// ADR-0045 (app#511 F2): the table and the context rules as DATA, for the consumers that
// cannot import this Go package (the platform repo, the workspace repo, a host with no
// go). Three files under testdata/ are the export:
//
//   - hidden-ranges.tsv: three header lines (the Unicode version, the skin-tone range and
//     the variation-selector ranges that invisible.go holds as constants), then one row
//     per range of invisibleRanges and per bidi control: U+LLLL TAB U+HHHH TAB rule TAB name;
//   - hidden-cases.tsv: name TAB input TAB expected, the findings Hidden must give;
//   - binary-ext.tsv: ext TAB reason TAB hex signature, binaryExt (bidi_test.go): what is not
//     scanned, and only when the file starts with the signature (app#537).
//
// scripts/sourcehygiene-scan.py reads exactly these three files and re-implements the
// context rules; its --selftest runs every row of the cases. The tests here keep the files
// and this package one definition (V1 of the ADR):
//
//	(a) TestExportedRanges_EqualGoTables      hidden-ranges.tsv = the Go tables
//	(b) TestExportedBinaryExt_EqualsBinaryExt binary-ext.tsv = binaryExt
//	(c) TestHidden_SharedCases                every case row = Hidden (and Invisible)
//	(d) TestSharedCaseReader_RejectsMalformed the reader of (c) refuses what the contract refuses
//	(e) TestNonTestFiles_ArePredicateOnly     nothing was added to the non-test package
//
// (e) is the tripwire of ADR-0043 Signpost 3: a walker, an allowlist reader or a CLI in
// the non-test files would widen the import closure of hintleak. The accessors here are
// test-only. This file is ASCII: every character the data holds is a placeholder.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const (
	hiddenRangesFile = "internal/sourcehygiene/testdata/hidden-ranges.tsv"
	hiddenCasesFile  = "internal/sourcehygiene/testdata/hidden-cases.tsv"
	binaryExtFile    = "internal/sourcehygiene/testdata/binary-ext.tsv"
	// minCaseRows is a floor under hidden-cases.tsv: a file cut down is still too small to mean anything.
	minCaseRows = 45

	headerSkinTone = "# skin-tone: U+1F3FB-U+1F3FF"
	headerVS       = "# variation-selector: U+FE00-U+FE0F,U+E0100-U+E01EF"
)

// ruleIdent is the rule column's vocabulary (ADR-0045 D2): the identifiers of ruleKind, and
// ruleBidi for a row of bidiControls. There is no alias map: a word is its Go identifier.
var ruleIdent = map[ruleKind]string{
	always:        "always",
	vsAfterSymbol: "vsAfterSymbol",
	zwjInEmoji:    "zwjInEmoji",
	bomAtStart:    "bomAtStart",
	loneCR:        "loneCR",
}

const ruleBidi = "bidi"

type exportedRow struct {
	lo, hi     rune
	rule, name string
}

func (r exportedRow) line() string {
	return fmt.Sprintf("U+%04X\tU+%04X\t%s\t%s", r.lo, r.hi, r.rule, r.name)
}

// goRows is invisibleRanges and bidiControls as one list, ascending by the first rune.
func goRows() []exportedRow {
	var rows []exportedRow
	for _, r := range invisibleRanges {
		rows = append(rows, exportedRow{r.lo, r.hi, ruleIdent[r.rule], r.name})
	}
	for cp, name := range bidiControls {
		rows = append(rows, exportedRow{cp, cp, ruleBidi, name})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].lo < rows[j].lo })
	return rows
}

// dataLines splits a data file: printable ASCII, TAB and LF only (a CR is a failure), a final newline.
func dataLines(b []byte, label string) ([]string, error) {
	for i, c := range b {
		if c >= 0x80 || c == '\r' || (c < 0x20 && c != '\n' && c != '\t') {
			return nil, fmt.Errorf("%s: byte %d (0x%02X) is not printable ASCII, TAB or LF", label, i, c)
		}
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return nil, fmt.Errorf("%s: no final newline", label)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"), nil
}

func readData(t *testing.T, rel string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("%s is unreadable (it is part of the ADR-0045 export): %v", rel, err)
	}
	lines, err := dataLines(b, rel)
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

// isDataRow: not a blank line and not a comment. A comment is "#" or "# " and a text, so a
// line like "#n" is a row (and a row whose name starts with # is refused).
func isDataRow(l string) bool { return l != "" && l != "#" && !strings.HasPrefix(l, "# ") }

// ---- (a) hidden-ranges.tsv = invisibleRanges + bidiControls -----------------

// parseHeaderRanges reads "U+LLLL-U+HHHH[,...]".
func parseHeaderRanges(s string) ([][2]rune, error) {
	var out [][2]rune
	for _, part := range strings.Split(s, ",") {
		lo, hi, ok := strings.Cut(part, "-")
		var r [2]rune
		for i, tok := range []string{lo, hi} {
			if !ok || !regexp.MustCompile(`^U\+[0-9A-F]{4,6}$`).MatchString(tok) {
				return nil, fmt.Errorf("%q is not U+LLLL-U+HHHH", part)
			}
			v, _ := strconv.ParseUint(tok[2:], 16, 32)
			r[i] = rune(v)
		}
		out = append(out, r)
	}
	return out, nil
}

func inHeaderRanges(rs [][2]rune, r rune) bool {
	for _, x := range rs {
		if x[0] <= r && r <= x[1] {
			return true
		}
	}
	return false
}

// checkRanges compares the lines of hidden-ranges.tsv with the Go tables and returns every
// difference (none = equal). version is unicode.Version.
func checkRanges(lines []string, version string) []string {
	var p []string
	if len(lines) < 3 {
		return []string{"fewer than the three header lines"}
	}
	if want := "# unicode: " + version; lines[0] != want {
		p = append(p, fmt.Sprintf("line 1 = %q, want %q (the Unicode version this Go toolchain ships; a toolchain upgrade that changes it is a change of the table: ADR-0043 Signpost 2)", lines[0], want))
	}
	for i, h := range []struct {
		line   string
		prefix string
		in     func(rune) bool
	}{{headerSkinTone, "# skin-tone: ", isSkinTone}, {headerVS, "# variation-selector: ", isVS}} {
		got := lines[i+1]
		if got != h.line {
			p = append(p, fmt.Sprintf("line %d = %q, want %q", i+2, got, h.line))
			continue
		}
		rs, err := parseHeaderRanges(strings.TrimPrefix(got, h.prefix))
		if err != nil {
			p = append(p, fmt.Sprintf("line %d: %v", i+2, err))
			continue
		}
		for r := rune(0); r <= unicode.MaxRune; r++ {
			if inHeaderRanges(rs, r) != h.in(r) {
				p = append(p, fmt.Sprintf("line %d disagrees with the Go constant at U+%04X", i+2, r))
				break
			}
		}
	}
	var got []string
	for _, l := range lines[3:] {
		if isDataRow(l) {
			got = append(got, l)
		}
	}
	rows := goRows()
	want := make([]string, len(rows))
	for i, r := range rows {
		want[i] = r.line()
	}
	for i := 0; i < len(got) || i < len(want); i++ {
		switch {
		case i >= len(got):
			p = append(p, fmt.Sprintf("no row for %q (in the Go tables, not in the file)", want[i]))
		case i >= len(want):
			p = append(p, fmt.Sprintf("an extra row %q (not in invisibleRanges or bidiControls)", got[i]))
		case got[i] != want[i]:
			p = append(p, fmt.Sprintf("row %d = %q, want %q", i+1, got[i], want[i]))
		}
	}
	return p
}

func TestExportedRanges_EqualGoTables(t *testing.T) {
	lines := readData(t, hiddenRangesFile)
	for _, p := range checkRanges(lines, unicode.Version) {
		t.Errorf("%s: %s", hiddenRangesFile, p)
	}
	if len(ruleIdent) != int(loneCR)+1 {
		t.Errorf("ruleIdent names %d ruleKind values but there are %d: a new ruleKind needs a word here, in the scanner and in the ADR", len(ruleIdent), int(loneCR)+1)
	}
	if len(bidiControls) != 9 {
		t.Errorf("bidiControls has %d entries; the nine controls of app#501 are the contract", len(bidiControls))
	}
	used := map[string]int{}
	for _, r := range goRows() {
		used[r.rule]++
	}
	for _, v := range append(vocabulary(), ruleBidi) {
		if used[v] == 0 {
			t.Errorf("no row has rule %q: the vocabulary of ADR-0045 D2 is closed and every word is used", v)
		}
	}

	// The comparison can fail: a copy with a row dropped, a rule changed, a header changed.
	first := 3
	for !isDataRow(lines[first]) {
		first++
	}
	drop := append(append([]string{}, lines[:first]...), lines[first+1:]...)
	rule := append([]string{}, lines...)
	for i := 3; i < len(rule); i++ {
		if strings.Contains(rule[i], "\talways\t") {
			rule[i] = strings.Replace(rule[i], "\talways\t", "\tloneCR\t", 1)
			break
		}
	}
	header := append([]string{"# unicode: 1.0.0"}, lines[1:]...)
	skin := append([]string{lines[0], "# skin-tone: U+1F3FB-U+1F3FE"}, lines[2:]...)
	for what, mutated := range map[string][]string{
		"a row dropped": drop, "a rule changed": rule, "the Unicode header changed": header, "the skin-tone header changed": skin,
	} {
		if len(checkRanges(mutated, unicode.Version)) == 0 {
			t.Errorf("checkRanges accepted a copy with %s: the comparison cannot fail", what)
		}
	}
}

func vocabulary() []string {
	var v []string
	for _, w := range ruleIdent {
		v = append(v, w)
	}
	sort.Strings(v)
	return v
}

// ---- (b) binary-ext.tsv = binaryExt ----------------------------------------

var binaryExtRow = regexp.MustCompile(`^\.[a-z0-9]+$`)
var signatureHex = regexp.MustCompile(`^([0-9A-F]{2}){2,}$`)

// parseBinaryExt reads the lines of binary-ext.tsv: <.ext><TAB><reason><TAB><hex signature>.
// The extension is lower case, ascending, no repeat; the signature is upper-case hex of at
// least two bytes (app#537, ADR-0045 D1 (c)). It stops at the first row that is not that.
func parseBinaryExt(lines []string, label string) (map[string]binaryKind, error) {
	var prev string
	got := map[string]binaryKind{}
	for i, l := range lines {
		if !isDataRow(l) {
			continue
		}
		cols := strings.Split(l, "\t")
		if len(cols) != 3 || !binaryExtRow.MatchString(cols[0]) || cols[1] == "" || !signatureHex.MatchString(cols[2]) {
			return nil, fmt.Errorf("%s:%d: want <.ext><TAB><reason><TAB><signature: upper-case hex, 2 bytes or more> (ext in lower case), got %q", label, i+1, l)
		}
		if cols[0] <= prev {
			return nil, fmt.Errorf("%s:%d: %q is not after %q: ascending, no repeat", label, i+1, cols[0], prev)
		}
		prev = cols[0]
		sig, _ := hex.DecodeString(cols[2])
		got[cols[0]] = binaryKind{cols[1], sig}
	}
	if len(got) == 0 {
		return nil, fmt.Errorf("%s: no extension", label)
	}
	return got, nil
}

func TestExportedBinaryExt_EqualsBinaryExt(t *testing.T) {
	got, err := parseBinaryExt(readData(t, binaryExtFile), binaryExtFile)
	if err != nil {
		t.Fatal(err)
	}
	for ext, want := range binaryExt {
		if g, ok := got[ext]; !ok {
			t.Errorf("%s has no row for %s (in binaryExt)", binaryExtFile, ext)
		} else if g.reason != want.reason {
			t.Errorf("%s: the reason of %s is %q, binaryExt says %q", binaryExtFile, ext, g.reason, want.reason)
		} else if !bytes.Equal(g.sig, want.sig) {
			t.Errorf("%s: the signature of %s is %X, binaryExt says %X", binaryExtFile, ext, g.sig, want.sig)
		}
	}
	for ext := range got {
		if _, ok := binaryExt[ext]; !ok {
			t.Errorf("%s has a row for %s that binaryExt does not have", binaryExtFile, ext)
		}
	}
}

// ---- (c) / (d) hidden-cases.tsv = what Hidden says -------------------------

var (
	casePlaceholder = regexp.MustCompile(`\{(U\+[0-9A-F]{4,6}|x[89A-F][0-9A-F])\}`)
	caseExpected    = regexp.MustCompile(`^[0-9]+:[0-9]+ U\+[0-9A-F]{4,6}(,[0-9]+:[0-9]+ U\+[0-9A-F]{4,6})*$`)
)

// decodeCaseInput turns an input into the bytes it stands for: a printable ASCII byte as it
// is, {U+XXXX} the UTF-8 of that code point, {xHH} (80-FF) one raw byte. Anything else is an
// error of the reader (D1 (d)), never a verdict.
func decodeCaseInput(s string) ([]byte, error) {
	var out []byte
	lit := func(part string) error {
		if strings.ContainsAny(part, "{}") {
			return fmt.Errorf("a brace is left after the placeholders ('{' is {U+007B}): %q", part)
		}
		out = append(out, part...)
		return nil
	}
	pos := 0
	for _, m := range casePlaceholder.FindAllStringSubmatchIndex(s, -1) {
		if err := lit(s[pos:m[0]]); err != nil {
			return nil, err
		}
		tok := s[m[2]:m[3]]
		if tok[0] == 'x' {
			v, _ := strconv.ParseUint(tok[1:], 16, 8)
			out = append(out, byte(v))
		} else {
			v, _ := strconv.ParseUint(tok[2:], 16, 32)
			switch {
			case v > unicode.MaxRune || (v >= 0xD800 && v <= 0xDFFF):
				return nil, fmt.Errorf("{%s} is not a code point a string can hold", tok)
			case v >= 0x21 && v <= 0x7E && v != '{' && v != '}':
				return nil, fmt.Errorf("{%s} writes a printable ASCII character as a placeholder: write it as it is", tok)
			}
			out = utf8.AppendRune(out, rune(v))
		}
		pos = m[1]
	}
	if err := lit(s[pos:]); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the input decodes to nothing")
	}
	return out, nil
}

type sharedCase struct {
	line     int // 1-based line of the file
	name     string
	raw      string
	input    []byte
	expected string
}

// parseSharedCases reads the lines of hidden-cases.tsv (rows only; a # line and a blank
// line are skipped).
func parseSharedCases(lines []string) ([]sharedCase, error) {
	var rows []sharedCase
	names := map[string]bool{}
	for i, l := range lines {
		if !isDataRow(l) {
			continue
		}
		cols := strings.Split(l, "\t")
		where := fmt.Sprintf("%s:%d", hiddenCasesFile, i+1)
		if len(cols) != 3 {
			return nil, fmt.Errorf("%s: want <name><TAB><input><TAB><expected>, got %d columns", where, len(cols))
		}
		name, raw, exp := cols[0], cols[1], cols[2]
		if name == "" || strings.HasPrefix(name, "#") || names[name] {
			return nil, fmt.Errorf("%s: the name %q is empty, starts with # or is used twice", where, name)
		}
		names[name] = true
		in, err := decodeCaseInput(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %v (a reader error, not a verdict)", where, err)
		}
		if exp != "none" && !caseExpected.MatchString(exp) {
			return nil, fmt.Errorf("%s: expected must be none or <line>:<col> U+XXXX joined by commas, got %q", where, exp)
		}
		rows = append(rows, sharedCase{i + 1, name, raw, in, exp})
	}
	return rows, nil
}

func formatFindings(fs []Finding) string {
	if len(fs) == 0 {
		return "none"
	}
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = at(f)
	}
	return strings.Join(parts, ",")
}

// TestSharedCaseReader_RejectsMalformed: the cases reader's negatives (and the one list it
// must keep accepting) are the dirs reader-cases-* of testdata/negatives, which the
// reference scanner's --selftest reads too (negatives_test.go). What stays here is the file
// level: a CR, a byte above 7F and a missing final newline cannot be written in a data file.
func TestSharedCaseReader_RejectsMalformed(t *testing.T) {
	for what, b := range map[string][]byte{"a CR": []byte("n\ta\tnone\r\n"), "a non-ASCII byte": []byte("n\ta\xc3\xa9\tnone\n"), "no final newline": []byte("n\ta\tnone")} {
		if _, err := dataLines(b, "x"); err == nil {
			t.Errorf("%s: dataLines must reject the file", what)
		}
	}
}

func TestHidden_SharedCases(t *testing.T) {
	rows, err := parseSharedCases(readData(t, hiddenCasesFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < minCaseRows {
		t.Fatalf("%s holds %d rows, fewer than the floor %d", hiddenCasesFile, len(rows), minCaseRows)
	}
	flagged := map[rune]bool{}
	green := map[rune]bool{}
	rawByte := false
	for _, c := range rows {
		found := Hidden(c.input)
		if got := formatFindings(found); got != c.expected {
			t.Errorf("%s:%d %q: Hidden gives %s, the file says %s", hiddenCasesFile, c.line, c.name, got, c.expected)
		}
		// Invisible is Hidden without the bidi controls: the same findings, in order.
		var noBidi []Finding
		for _, f := range found {
			if _, isBidi := bidiControls[f.CP]; !isBidi {
				noBidi = append(noBidi, f)
			}
		}
		if got, want := formatFindings(Invisible(c.input)), formatFindings(noBidi); got != want {
			t.Errorf("%s:%d %q: Invisible gives %s, Hidden minus the bidi controls gives %s", hiddenCasesFile, c.line, c.name, got, want)
		}
		hit := map[rune]bool{}
		for _, f := range found {
			flagged[f.CP], hit[f.CP] = true, true
		}
		for _, r := range []rune{0xFE0F, 0x200D, 0xFEFF, 0x0D} {
			if strings.ContainsRune(string(c.input), r) && !hit[r] {
				green[r] = true
			}
		}
		rawByte = rawByte || strings.Contains(c.raw, "{x")
	}
	// The four context rules each have a row where the rune is allowed and a row where it is a finding.
	for _, r := range []rune{0xFE0F, 0x200D, 0xFEFF, 0x0D} {
		if !green[r] {
			t.Errorf("no case holds U+%04X where it is allowed", r)
		}
		if !flagged[r] {
			t.Errorf("no case holds U+%04X where it is a finding", r)
		}
	}
	bidiRed := false
	for cp := range bidiControls {
		bidiRed = bidiRed || flagged[cp]
	}
	if !bidiRed {
		t.Error("no case has a bidi control as a finding")
	}
	if !rawByte {
		t.Error("no case has a raw byte ({xHH})")
	}
	// Every row of the table is exercised at both edges: a reader that drops the last row,
	// reads a range as half-open or stops at the first rune is caught by the cases alone.
	// The rune just outside each row is not hidden: "a<rune>b" with the expected none.
	inputs := map[string]string{}
	for _, c := range rows {
		inputs[string(c.input)] = c.expected
	}
	for _, r := range goRows() {
		for _, cp := range []rune{r.lo, r.hi} {
			if !flagged[cp] {
				t.Errorf("no case has a finding at U+%04X (an edge of %q)", cp, r.name)
			}
		}
		for _, cp := range []rune{r.lo - 1, r.hi + 1} {
			if cp < 0x20 || cp > unicode.MaxRune || (cp >= 0xD800 && cp <= 0xDFFF) {
				continue
			}
			if _, _, in := lookup(cp); in {
				continue
			}
			if _, isBidi := bidiControls[cp]; isBidi {
				continue
			}
			if inputs["a"+string(cp)+"b"] != "none" {
				t.Errorf("no case \"a<U+%04X>b\" with the expected none (the rune next to %q)", cp, r.name)
			}
		}
	}
}

// ---- (e) the non-test package is predicates only ---------------------------

func TestNonTestFiles_ArePredicateOnly(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "sourcehygiene")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	if got, want := strings.Join(files, ","), "chars.go,invisible.go"; got != want {
		t.Errorf("the non-test files are %s, want %s. If the new file is still predicates only (a table, a rule, a decision about a rune), add it to this list and keep the import set below. If it walks files, reads an allowlist or is a CLI, it does not belong in this package: split the predicate into a leaf package first (ADR-0043 Signpost 3, ADR-0045 D3)", got, want)
	}
	allowed := map[string]bool{"fmt": true, "sort": true, "unicode": true, "unicode/utf8": true}
	for _, f := range files {
		af, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, f), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || !allowed[path] {
				t.Errorf("%s imports %s. The imports of this package's non-test files are the leaves of hintleak's import closure ({fmt, sort, unicode, unicode/utf8}; ADR-0043 / ADR-0045 D3). If the new import is another standard-library leaf that decides nothing about files or I/O, add it to the set here and in ADR-0045; if it reaches the file system or a process, the code belongs outside this package (ADR-0043 Signpost 3)", f, imp.Path.Value)
			}
		}
	}
}
