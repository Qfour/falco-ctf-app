package edition

// ADR-0056 V84 (D20, A4e-3b): the flag-guard's check of the public repository,
// scripts/check-edition-headers.sh, refuses a tracked file that begins with the header of an
// event's answers table, digests file or render record. Its constants are copies of this
// package's definitions (a shell script cannot import them), so this test holds the copies to
// the definitions: the answers table's header (table.go), the digests file's (digests.go), the
// render record's (renderrecord.go) and the practice run id (table.go). A header that changed on
// one side only would leave the guard looking for a header no file has: it is red here.
//
// Two more pins (#657 review): the script's ALLOWED_PATHS is exactly the list below (an entry
// added is a file taken out of the scan, so it is a change of this test too, and reviewed as
// one), and scripts/check-flags.sh (the CI flag-guard) runs the script's scan and its selftest
// and sets its failure on either (a copy without one of them is red here).

import (
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	flagGuardScript = "../../scripts/check-edition-headers.sh"
	checkFlagsPath  = "../../scripts/check-flags.sh"
)

// flagGuardAllowed is the whole of ALLOWED_PATHS: the golden of WriteDigests, which holds an
// event's digests header on purpose.
var flagGuardAllowed = []string{"internal/edition/testdata/digests-golden/digests.tsv"}

// allowedPathsOf is the entries of the script's ALLOWED_PATHS=( ... ) block, one quoted path a
// line, or nil and false when there is not exactly one such block or a line of it is not one
// single-quoted entry.
func allowedPathsOf(src string) ([]string, bool) {
	blocks := regexp.MustCompile(`(?ms)^ALLOWED_PATHS=\(\n(.*?)^\)$`).FindAllStringSubmatch(src, -1)
	if len(blocks) != 1 {
		return nil, false
	}
	entry := regexp.MustCompile(`^  '([^']+)'$`)
	var out []string
	for _, ln := range strings.Split(strings.TrimSuffix(blocks[0][1], "\n"), "\n") {
		m := entry.FindStringSubmatch(ln)
		if m == nil {
			return nil, false
		}
		out = append(out, m[1])
	}
	return out, true
}

// checkFlagsCalls are the two calls of the script that check-flags.sh must make, each as the
// condition of an `if !` whose block sets rc=1.
var checkFlagsCalls = []string{
	"if ! bash ./scripts/check-edition-headers.sh; then",
	"if ! bash ./scripts/check-edition-headers.sh --selftest; then",
}

// checkFlagsViolations judges the text of check-flags.sh: each call of checkFlagsCalls is a
// line of its own exactly once, the lines of its block up to the `fi` hold `rc=1`, and the
// script ends by `exit "$rc"`.
func checkFlagsViolations(src string) []string {
	lines := strings.Split(src, "\n")
	var out []string
	for _, call := range checkFlagsCalls {
		at := -1
		n := 0
		for i, ln := range lines {
			if ln == call {
				at, n = i, n+1
			}
		}
		if n != 1 {
			out = append(out, "check-flags.sh has the line `"+call+"` "+strconv.Itoa(n)+" times, want once")
			continue
		}
		sets := false
		for _, ln := range lines[at+1:] {
			if ln == "fi" {
				break
			}
			if strings.TrimSpace(ln) == "rc=1" {
				sets = true
			}
		}
		if !sets {
			out = append(out, "check-flags.sh does not set rc=1 when `"+call+"` fails")
		}
	}
	if !slices.Contains(lines, `exit "$rc"`) {
		out = append(out, "check-flags.sh does not end with `exit \"$rc\"`: a failure that sets rc is not its exit")
	}
	return out
}

func TestFlagGuardAllowedPathsAreTheOneFixture(t *testing.T) {
	data, err := os.ReadFile(flagGuardScript)
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	got, ok := allowedPathsOf(src)
	if !ok || !slices.Equal(got, flagGuardAllowed) {
		t.Errorf("ALLOWED_PATHS of the script is %v (read: %v), want %v: an entry is a file taken out of the scan", got, ok, flagGuardAllowed)
	}
	// The reading itself: an entry added, changed or taken out, and no block, are seen.
	line := "  '" + flagGuardAllowed[0] + "'\n"
	if strings.Count(src, line) != 1 {
		t.Fatalf("the script does not hold %q exactly once: the cases below do not test what they say", line)
	}
	for name, mutated := range map[string]string{
		"an entry added":   strings.Replace(src, line, line+"  'internal/edition/testdata'\n", 1),
		"an entry changed": strings.Replace(src, line, "  'internal/edition/testdata'\n", 1),
		"no entry":         strings.Replace(src, line, "", 1),
		"no block":         strings.Replace(src, "ALLOWED_PATHS=(", "ALLOWED=(", 1),
	} {
		if got, ok := allowedPathsOf(mutated); ok && slices.Equal(got, flagGuardAllowed) {
			t.Errorf("%s: the copy still reads as %v", name, got)
		}
	}
}

func TestCheckFlagsRunsTheHeaderGuardAndItsSelftest(t *testing.T) {
	data, err := os.ReadFile(checkFlagsPath)
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	for _, v := range checkFlagsViolations(src) {
		t.Error(v)
	}
	// The judgement itself: a copy without each call, without its rc=1, and with the call
	// turned into one that cannot fail, is red.
	for _, call := range checkFlagsCalls {
		block := call + "\n"
		if strings.Count(src, block) != 1 {
			t.Fatalf("check-flags.sh does not hold %q exactly once", call)
		}
		removed := strings.Replace(src, block, "if false; then\n", 1)
		if len(checkFlagsViolations(removed)) == 0 {
			t.Errorf("a copy without `%s`: no violation was reported", call)
		}
		softened := strings.Replace(src, block, strings.Replace(call, "; then", " || true; then", 1)+"\n", 1)
		if len(checkFlagsViolations(softened)) == 0 {
			t.Errorf("a copy with `%s` that cannot fail: no violation was reported", call)
		}
		at := strings.Index(src, block)
		rest := src[at+len(block):]
		end := strings.Index(rest, "\nfi\n")
		if end < 0 || !strings.Contains(rest[:end], "rc=1") {
			t.Fatalf("the block of %q has no rc=1 before its fi: the case below does not test what it says", call)
		}
		noRC := src[:at+len(block)] + strings.Replace(rest[:end], "rc=1", ":", -1) + rest[end:]
		if len(checkFlagsViolations(noRC)) == 0 {
			t.Errorf("a copy whose block of `%s` does not set rc=1: no violation was reported", call)
		}
	}
	if v := checkFlagsViolations(strings.Replace(src, `exit "$rc"`, "exit 0", 1)); len(v) == 0 {
		t.Error("a copy that exits 0 whatever rc is: no violation was reported")
	}
}

// flagGuardConstants are the script's constants and the definitions they copy.
func flagGuardConstants() map[string]string {
	return map[string]string{
		"ANSWERS_PREFIX":  headerPrefix,
		"DIGESTS_PREFIX":  digestsHeaderPrefix,
		"RECORD_HEADER":   renderRecordHeader,
		"PRACTICE_RUN_ID": PracticeRunID,
	}
}

// flagGuardMismatches lists how the script's source differs from the definitions: a constant
// that is not assigned exactly once (as `NAME='value'` at the start of a line), and a value that
// is not the definition's.
func flagGuardMismatches(src string) []string {
	var out []string
	for name, want := range flagGuardConstants() {
		re := regexp.MustCompile(`(?m)^` + name + `='([^']*)'$`)
		found := re.FindAllStringSubmatch(src, -1)
		switch {
		case len(found) != 1:
			out = append(out, name+" is assigned "+strconv.Itoa(len(found))+" times in the script, want once")
		case found[0][1] != want:
			out = append(out, name+" in the script is not the definition of package edition")
		}
	}
	return out
}

func TestFlagGuardHeadersAreThePackagesDefinitions(t *testing.T) {
	data, err := os.ReadFile(flagGuardScript)
	if err != nil {
		t.Fatalf("the flag-guard's script %s cannot be read: %v", flagGuardScript, err)
	}
	src := string(data)
	for _, m := range flagGuardMismatches(src) {
		t.Error(m)
	}

	// The comparison itself: a copy with one constant changed, and a copy without it, are red.
	for name, want := range flagGuardConstants() {
		line := name + "='" + want + "'"
		if strings.Count(src, line) != 1 {
			t.Fatalf("the script does not hold %s exactly once: the cases below do not test what they say", line)
		}
		changed := strings.Replace(src, line, name+"='"+want+"x'", 1)
		if len(flagGuardMismatches(changed)) == 0 {
			t.Errorf("%s changed in a copy of the script: no mismatch was reported", name)
		}
		removed := strings.Replace(src, line+"\n", "", 1)
		if len(flagGuardMismatches(removed)) == 0 {
			t.Errorf("%s removed from a copy of the script: no mismatch was reported", name)
		}
		doubled := strings.Replace(src, line+"\n", line+"\n"+line+"\n", 1)
		if len(flagGuardMismatches(doubled)) == 0 {
			t.Errorf("%s assigned twice in a copy of the script: no mismatch was reported", name)
		}
	}
}
