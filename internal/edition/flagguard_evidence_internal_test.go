package edition

// ADR-0056 V93 (A4e-3c): the flag-guard's script scripts/check-edition-headers.sh also refuses
// a tracked PATH with the layout of an event's evidence bundles, evidence/<seat>/<cid>/<file>
// at any depth, each of the three a whole segment. The script cannot import the three parts of
// that rule, so it holds copies, and this test holds the copies to the Go definitions (the same
// way as flagguard_headers_internal_test.go holds the header constants, V84):
//
//	EVIDENCE_DIR          EventEvidenceDirName (practicelayout.go: the event's --out layout)
//	SEAT_PATTERN          identity.SeatPattern (the seat grammar of ADR-0042)
//	CHALLENGE_ID_PATTERN  challengeid.Pattern
//
// The two patterns are copied as their text (they are EREs as they stand; the script's comment
// says why), so the comparison is string equality. A part changed, removed or doubled in a copy
// of the script is red.
//
// The test also reads how scan_evidence joins the parts (its evidence_ere line) and the way it
// takes the anchors off a pattern (grammar_body, mirrored here), builds the same expression,
// compiles it with Go's regexp in place of the shell's ERE, and holds its verdict on a table of
// edge paths, and on every row of the seat and challenge id case tables, to the rule written in
// Go's own terms (evidenceLeak: split at `/`, then the Go definitions). The shell is not run from
// here: the script's --selftest (run by check-flags.sh, which the V84 test holds) runs the same
// kinds of path through bash.
//
// Two pins as for V84: EVIDENCE_ALLOWED_PATHS is empty (an entry added is a path taken out of
// the scan, reviewed as a change of this test), and the script's main runs scan_evidence with it
// and exits with the larger status of the two checks.

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/casetable"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
)

// evidenceGuardParts are the script's three parts of the path rule and the definitions they copy.
func evidenceGuardParts() map[string]string {
	return map[string]string{
		"EVIDENCE_DIR":         EventEvidenceDirName,
		"SEAT_PATTERN":         identity.SeatPattern,
		"CHALLENGE_ID_PATTERN": challengeid.Pattern,
	}
}

// evidenceGuardPartMismatches lists how the script's source differs from the definitions: a part
// that is not assigned exactly once (as `NAME='value'` on a line of its own), and a value that is
// not the definition's.
func evidenceGuardPartMismatches(src string) []string {
	parts := evidenceGuardParts()
	var out []string
	for _, name := range slices.Sorted(maps.Keys(parts)) {
		got, ok := casetable.ShellAssign(src, name)
		switch {
		case !ok:
			out = append(out, name+" is not assigned exactly once in the script (as NAME='...' on a line of its own)")
		case got != parts[name]:
			out = append(out, name+" in the script is "+strconv.Quote(got)+", not the Go definition "+strconv.Quote(parts[name]))
		}
	}
	return out
}

func readFlagGuardScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(flagGuardScript)
	if err != nil {
		t.Fatalf("the flag-guard's script %s cannot be read: %v", flagGuardScript, err)
	}
	return string(data)
}

func TestEvidenceGuardPartsAreTheGoDefinitions(t *testing.T) {
	src := readFlagGuardScript(t)
	for _, m := range evidenceGuardPartMismatches(src) {
		t.Error(m)
	}

	// The comparison itself: a copy with one part changed, removed or doubled is red, and a
	// copy with none of the three (nothing extracted) is red three times.
	none := src
	for name, want := range evidenceGuardParts() {
		line := name + "='" + want + "'\n"
		if strings.Count(src, line) != 1 {
			t.Fatalf("the script does not hold %q exactly once: the cases below do not test what they say", line)
		}
		for what, mutated := range map[string]string{
			"changed at the end":   strings.Replace(src, line, name+"='"+want+"x'\n", 1),
			"its first byte gone":  strings.Replace(src, line, name+"='"+want[1:]+"'\n", 1),
			"removed":              strings.Replace(src, line, "", 1),
			"assigned twice":       strings.Replace(src, line, line+line, 1),
			"indented (not found)": strings.Replace(src, line, "  "+line, 1),
		} {
			if len(evidenceGuardPartMismatches(mutated)) == 0 {
				t.Errorf("%s %s in a copy of the script: no mismatch was reported", name, what)
			}
		}
		none = strings.Replace(none, line, "", 1)
	}
	if got := evidenceGuardPartMismatches(none); len(got) != len(evidenceGuardParts()) {
		t.Errorf("a copy with none of the parts: %d mismatches (%v), want one a part", len(got), got)
	}
}

// evidenceAllowedOf is the entries of the script's EVIDENCE_ALLOWED_PATHS block (one quoted path
// a line, or none), or nil and false when there is not exactly one such block or a line of it is
// not one single-quoted entry.
func evidenceAllowedOf(src string) ([]string, bool) {
	blocks := regexp.MustCompile(`(?ms)^EVIDENCE_ALLOWED_PATHS=\(\n(.*?)^\)$`).FindAllStringSubmatch(src, -1)
	if len(blocks) != 1 {
		return nil, false
	}
	out := []string{}
	if blocks[0][1] == "" {
		return out, true
	}
	entry := regexp.MustCompile(`^  '([^']+)'$`)
	for _, ln := range strings.Split(strings.TrimSuffix(blocks[0][1], "\n"), "\n") {
		m := entry.FindStringSubmatch(ln)
		if m == nil {
			return nil, false
		}
		out = append(out, m[1])
	}
	return out, true
}

// evidenceGuardAllowed is the whole of EVIDENCE_ALLOWED_PATHS: no tracked path of the repository
// has the layout today (A4e-3c checked the tracked files of main; the practice goldens are flat).
var evidenceGuardAllowed = []string{}

func TestEvidenceGuardAllowedPathsAreNone(t *testing.T) {
	src := readFlagGuardScript(t)
	got, ok := evidenceAllowedOf(src)
	if !ok || !slices.Equal(got, evidenceGuardAllowed) {
		t.Errorf("EVIDENCE_ALLOWED_PATHS of the script is %v (read: %v), want %v: an entry is a path taken out of the scan", got, ok, evidenceGuardAllowed)
	}
	// The reading itself: an entry added, a line that is not an entry, and no block, are seen.
	block := "EVIDENCE_ALLOWED_PATHS=(\n)\n"
	if strings.Count(src, block) != 1 {
		t.Fatalf("the script does not hold %q exactly once: the cases below do not test what they say", block)
	}
	for name, mutated := range map[string]string{
		"an entry added":    strings.Replace(src, block, "EVIDENCE_ALLOWED_PATHS=(\n  'x/evidence/user1/01-demo/f'\n)\n", 1),
		"a line not entry":  strings.Replace(src, block, "EVIDENCE_ALLOWED_PATHS=(\n  x/evidence\n)\n", 1),
		"no block":          strings.Replace(src, block, "EVIDENCE_ALLOWED=(\n)\n", 1),
		"the block doubled": strings.Replace(src, block, block+block, 1),
	} {
		if got, ok := evidenceAllowedOf(mutated); ok && slices.Equal(got, evidenceGuardAllowed) {
			t.Errorf("%s: the copy still reads as %v", name, got)
		}
	}
}

// evidenceEREAssign is the one line of scan_evidence that joins the three parts.
var evidenceEREAssign = regexp.MustCompile(`(?m)^  evidence_ere="([^"\n]*)"$`)

// grammarBody mirrors the script's grammar_body: the pattern without its one leading `^` and one
// trailing `$`, refused when it is not anchored at both ends, or its body is empty or holds `^`,
// `$`, `/`, `.` or a backslash.
func grammarBody(p string) (string, bool) {
	if len(p) < 2 || p[0] != '^' || p[len(p)-1] != '$' {
		return "", false
	}
	b := p[1 : len(p)-1]
	if b == "" || strings.ContainsAny(b, "^$/.\\") {
		return "", false
	}
	return b, true
}

// evidenceRuleOf builds the path rule the way scan_evidence does, from the script's own text:
// its evidence_ere line with the three expansions put in (the parts as the script assigns them,
// the patterns through grammarBody). The script matches it against "/" + the path.
func evidenceRuleOf(src string) (*regexp.Regexp, error) {
	m := evidenceEREAssign.FindAllStringSubmatch(src, -1)
	if len(m) != 1 {
		return nil, fmt.Errorf("the evidence_ere line of scan_evidence is found %d times, want once", len(m))
	}
	ere := m[0][1]
	part := func(name string) (string, error) {
		v, ok := casetable.ShellAssign(src, name)
		if !ok {
			return "", errors.New(name + " is not assigned exactly once")
		}
		return v, nil
	}
	dir, err := part("EVIDENCE_DIR")
	if err != nil {
		return nil, err
	}
	subst := map[string]string{"${EVIDENCE_DIR}": dir}
	for ph, name := range map[string]string{"${seat_body}": "SEAT_PATTERN", "${cid_body}": "CHALLENGE_ID_PATTERN"} {
		v, err := part(name)
		if err != nil {
			return nil, err
		}
		b, ok := grammarBody(v)
		if !ok {
			return nil, errors.New(name + " has no body grammar_body takes")
		}
		subst[ph] = b
	}
	for _, ph := range slices.Sorted(maps.Keys(subst)) {
		if strings.Count(ere, ph) != 1 {
			return nil, fmt.Errorf("the evidence_ere line holds %s %d times, want once", ph, strings.Count(ere, ph))
		}
		ere = strings.Replace(ere, ph, subst[ph], 1)
	}
	if strings.ContainsAny(ere, "$`\\\"") {
		return nil, fmt.Errorf("the evidence_ere line expands or escapes something this test does not: %q", ere)
	}
	return regexp.Compile(ere)
}

// evidenceLeak is the rule of V93 in Go's own terms: some segment is the event's evidence
// directory name, the next is a seat, the one after it a challenge id, and a non-empty segment
// follows.
func evidenceLeak(path string) bool {
	segs := strings.Split(path, "/")
	for i := 0; i+3 < len(segs); i++ {
		if segs[i] == EventEvidenceDirName && identity.ValidSeat(segs[i+1]) && challengeid.Valid(segs[i+2]) && segs[i+3] != "" {
			return true
		}
	}
	return false
}

// evidenceRuleCases are the edges of the rule (the selftest of the script has the same kinds).
func evidenceRuleCases() []struct {
	path string
	leak bool
} {
	seat53 := "a" + strings.Repeat("0", 51) + "b"
	seat54 := "a" + strings.Repeat("0", 52) + "b"
	slug60 := strings.Repeat("0", 60)
	slug61 := strings.Repeat("0", 61)
	return []struct {
		path string
		leak bool
	}{
		// refused
		{"evidence/user1/01-demo/answer.txt", true},
		{"x/evidence/user1/01-demo/answer.txt", true},
		{"evidence/user1/01-demo/a/b", true},
		{"challenges/01-demo/edition/practice/evidence/user1/01-demo/answer.txt", true},
		{"out/evidence/0/00-a/f", true},
		{"evidence/" + seat53 + "/01-" + slug60 + "/f", true},
		{"evidence/a-b/01-x-/f", true},
		{"out dir/evidence/user1/01-demo/my file.txt", true},
		{"line\nbreak/evidence/user1/01-demo/f", true},
		{"evidence/evidence/user1/01-demo/f", true},
		{"evidence/user1/01-demo/evidence", true},
		{"evidence/x/evidence/user1/01-demo/f", true},
		// passed
		{"challenges/01-demo/edition/practice/evidence/a.txt", false},
		{"challenges/01-demo/edition/practice/evidence/Sub_Dir/01-demo/f", false},
		{"challenges/01-demo/edition/practice/evidence/notes/readme.txt", false},
		{"myevidence/user1/01-demo/f", false},
		{"evidence-x/user1/01-demo/f", false},
		{"Evidence/user1/01-demo/f", false},
		{"evidence/User1/01-demo/f", false},
		{"evidence/user1-/01-demo/f", false},
		{"evidence/-user1/01-demo/f", false},
		{"evidence/user.1/01-demo/f", false},
		{"evidence/" + seat54 + "/01-demo/f", false},
		{"evidence/user1/1-demo/f", false},
		{"evidence/user1/01-/f", false},
		{"evidence/user1/01-Demo/f", false},
		{"evidence/user1/01-" + slug61 + "/f", false},
		{"evidence/user1/01-demo", false},
		{"evidence/user1/01-demo/", false},
		{"evidence//user1/01-demo/f", false},
		{"evidence/user1\n/01-demo/f", false},
		{"evidence/user1/01-demo\n/f", false},
		{"evidence/user1/01-demo.tar", false},
		{"user1/01-demo/f", false},
	}
}

// evidenceRuleDisagreements lists where the rule the script builds differs from evidenceLeak (and
// from the table's verdict), on the edge table and on every row of the two shared grammar case
// tables put in the seat or the challenge id segment; or why the rule could not be built.
func evidenceRuleDisagreements(t *testing.T, src string) []string {
	t.Helper()
	re, err := evidenceRuleOf(src)
	if err != nil {
		return []string{"the path rule cannot be built from the script: " + err.Error()}
	}
	var out []string
	judge := func(path string, want bool, from string) {
		if got := re.MatchString("/" + path); got != want {
			out = append(out, fmt.Sprintf("%s: the script's rule says %v for %q, want %v", from, got, path, want))
		}
	}
	for _, c := range evidenceRuleCases() {
		judge(c.path, c.leak, "edge table")
	}
	for _, tbl := range []struct {
		file string
		path func(in string) string
	}{
		{filepath.Join("..", "identity", "testdata", "seat-cases.tsv"), func(in string) string { return "x/evidence/" + in + "/01-demo/f" }},
		{filepath.Join("..", "catalog", "challengeid", "testdata", "challenge-id-cases.tsv"), func(in string) string { return "evidence/user1/" + in + "/f/g" }},
	} {
		rows, err := casetable.Read(tbl.file)
		if err != nil {
			t.Fatalf("%s: %v", tbl.file, err)
		}
		if len(rows) < 10 {
			t.Fatalf("%s has %d rows: the table was read as (nearly) empty and tests nothing", tbl.file, len(rows))
		}
		for _, r := range rows {
			p := tbl.path(r.Input)
			from := tbl.file + ":" + strconv.Itoa(r.Line)
			judge(p, evidenceLeak(p), from)
			if !strings.Contains(r.Input, "/") {
				judge(p, r.Accept, from+" (the table's verdict)")
			}
		}
	}
	return out
}

func TestEvidenceGuardRuleIsTheSegmentRule(t *testing.T) {
	// The reference itself agrees with the edge table, so the table is a statement of the rule.
	for _, c := range evidenceRuleCases() {
		if got := evidenceLeak(c.path); got != c.leak {
			t.Errorf("evidenceLeak(%q) = %v, want %v: the edge table and the Go statement of the rule differ", c.path, got, c.leak)
		}
	}
	src := readFlagGuardScript(t)
	for _, d := range evidenceRuleDisagreements(t, src) {
		t.Error(d)
	}

	// The comparison itself: a copy whose evidence_ere loses the leading `/` or the segment after
	// <cid>, or whose seat or challenge id part is any segment, or that has no such line, is red.
	line := `  evidence_ere="/${EVIDENCE_DIR}/(${seat_body})/(${cid_body})/[^/]"`
	if strings.Count(src, line+"\n") != 1 {
		t.Fatalf("the script does not hold %q exactly once: the cases below do not test what they say", line)
	}
	for name, repl := range map[string]string{
		"no leading slash":       `  evidence_ere="${EVIDENCE_DIR}/(${seat_body})/(${cid_body})/[^/]"`,
		"no segment after <cid>": `  evidence_ere="/${EVIDENCE_DIR}/(${seat_body})/(${cid_body})"`,
		"any seat segment":       `  evidence_ere="/${EVIDENCE_DIR}/[^/]+/(${cid_body})/[^/]"`,
		"any cid segment":        `  evidence_ere="/${EVIDENCE_DIR}/(${seat_body})/[^/]+/[^/]"`,
		"no such line":           `  evidence="/${EVIDENCE_DIR}/(${seat_body})/(${cid_body})/[^/]"`,
	} {
		if len(evidenceRuleDisagreements(t, strings.Replace(src, line+"\n", repl+"\n", 1))) == 0 {
			t.Errorf("a copy with %s: no disagreement was reported", name)
		}
	}
	// grammar_body's refusals, mirrored: a copy whose seat pattern lost an anchor, or whose body
	// holds a `.`, cannot be built.
	seatLine := "SEAT_PATTERN='" + identity.SeatPattern + "'\n"
	for name, repl := range map[string]string{
		"no leading ^": "SEAT_PATTERN='" + strings.TrimPrefix(identity.SeatPattern, "^") + "'\n",
		"a . in it":    "SEAT_PATTERN='^.+$'\n",
	} {
		if _, err := evidenceRuleOf(strings.Replace(src, seatLine, repl, 1)); err == nil {
			t.Errorf("a copy whose seat pattern has %s: the rule was built", name)
		}
	}
}

// evidenceMainLines are the lines of the script's main that run the evidence check after the
// header check and exit with the larger status.
var evidenceMainLines = []string{
	`scan "$root" || rc=$?`,
	`scan_evidence "$root" ${EVIDENCE_ALLOWED_PATHS[@]+"${EVIDENCE_ALLOWED_PATHS[@]}"} || erc=$?`,
	`if [ "$erc" -gt "$rc" ]; then`,
	`  rc="$erc"`,
	`exit "$rc"`,
}

// evidenceMainViolations judges the text of the script: each line of evidenceMainLines is a line
// of its own exactly once, in that order.
func evidenceMainViolations(src string) []string {
	lines := strings.Split(src, "\n")
	var out []string
	last := -1
	for _, want := range evidenceMainLines {
		at, n := -1, 0
		for i, ln := range lines {
			if ln == want {
				at, n = i, n+1
			}
		}
		switch {
		case n != 1:
			out = append(out, "the script has the line `"+want+"` "+strconv.Itoa(n)+" times, want once")
		case at < last:
			out = append(out, "the line `"+want+"` comes before the one it must follow")
		default:
			last = at
		}
	}
	return out
}

func TestHeaderGuardMainRunsTheEvidenceScan(t *testing.T) {
	src := readFlagGuardScript(t)
	for _, v := range evidenceMainViolations(src) {
		t.Error(v)
	}
	// The judgement itself: a copy without each line, and one whose evidence scan cannot fail
	// the exit, is red.
	for _, want := range evidenceMainLines {
		if strings.Count(src, "\n"+want+"\n") != 1 {
			t.Fatalf("the script does not hold the line %q exactly once", want)
		}
		if len(evidenceMainViolations(strings.Replace(src, "\n"+want+"\n", "\n:\n", 1))) == 0 {
			t.Errorf("a copy without `%s`: no violation was reported", want)
		}
	}
	softened := strings.Replace(src, `|| erc=$?`, `|| true`, 1)
	if len(evidenceMainViolations(softened)) == 0 {
		t.Error("a copy whose evidence scan cannot set erc: no violation was reported")
	}
}
