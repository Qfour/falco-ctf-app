package edition

// ADR-0056 V84 (D20, A4e-3b): the flag-guard's check of the public repository,
// scripts/check-edition-headers.sh, refuses a tracked file that begins with the header of an
// event's answers table, digests file or render record. Its constants are copies of this
// package's definitions (a shell script cannot import them), so this test holds the copies to
// the definitions: the answers table's header (table.go), the digests file's (digests.go), the
// render record's (renderrecord.go) and the practice run id (table.go). A header that changed on
// one side only would leave the guard looking for a header no file has: it is red here.

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const flagGuardScript = "../../scripts/check-edition-headers.sh"

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
