package edition_test

// ADR-0056 V85 (A5d): scripts/check-flag-isolation.sh renders a real scope (values-all, a
// scenario) that holds an investigate challenge with the names of that challenge's public
// practice bundle, <cid>/edition/practice/evidence/ (the same bundle deploy-user.sh's
// practice path deploys; answers.tsv and digests.tsv beside it are not part of it). Its
// fixture also writes the two files beside the bundle, to show that they are left out. The
// script cannot import practicelayout.go, so it holds five literals, one top-level
// assignment each, and this test holds them to the Go definitions, in the style of
// practice_deploy_layout_test.go (deploy-user.sh's copy): a literal that is missing, doubled,
// moved out of the top level or changed is red, the path of the bundle must be built from
// them (the line below, exactly once), and no other line of the script that is not a
// comment may spell one of the layout's names next to a `/`.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

var flagIsolationScriptPath = filepath.Join("..", "..", "scripts", "check-flag-isolation.sh")

// flagIsolationLiterals are the script's five literals and the definitions they copy.
var flagIsolationLiterals = []struct{ name, want string }{
	{"EVIDENCE_EDITION_DIR", edition.EditionDirName},
	{"EVIDENCE_PRACTICE_DIR", edition.PracticeDirName},
	{"EVIDENCE_PRACTICE_EVIDENCE_DIR", edition.PracticeEvidenceDirName},
	{"EVIDENCE_PRACTICE_ANSWERS", edition.PracticeAnswersFileName},
	{"EVIDENCE_PRACTICE_DIGESTS", edition.PracticeDigestsFileName},
}

// flagIsolationUseLines are the lines that build the bundle's path (scope_practice_evidence)
// and the practice directory of the fixture from the literals.
var flagIsolationUseLines = []string{
	`    bundle="${root}/${cid}/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}"`,
	`  pd="${2}/${1}/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}"`,
}

// flagIsolationLayoutError is the whole rule; it returns the first difference.
func flagIsolationLayoutError(script string) error {
	exempt := map[string]bool{}
	for _, l := range flagIsolationLiterals {
		got, err := shellLiteral(script, l.name)
		if err != nil {
			return fmt.Errorf("check-flag-isolation.sh (the extractor's message names deploy-user.sh): %w", err)
		}
		if got != l.want {
			return fmt.Errorf("check-flag-isolation.sh: %s = %q, the Go definition is %q", l.name, got, l.want)
		}
		exempt[l.name+"='"+l.want+"'"] = true
	}
	lines := strings.Split(script, "\n")
	for _, want := range flagIsolationUseLines {
		n := 0
		for _, ln := range lines {
			if ln == want {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("check-flag-isolation.sh has the line %q %d times, want once: the practice path is not built from the literals", want, n)
		}
	}
	for i, ln := range lines {
		if exempt[ln] || strings.HasPrefix(strings.TrimLeft(ln, " \t"), "#") {
			continue
		}
		if m := practiceLayoutSpelling.FindString(ln); m != "" {
			return fmt.Errorf("check-flag-isolation.sh:%d spells a name of the practice layout as a path (%q): use the EVIDENCE_* literals", i+1, m)
		}
	}
	return nil
}

func readFlagIsolationScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(flagIsolationScriptPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPracticeLayout_CheckFlagIsolationMatchesGo(t *testing.T) {
	if err := flagIsolationLayoutError(readFlagIsolationScript(t)); err != nil {
		t.Error(err)
	}
}

// The check must be able to fail: one literal changed, doubled, indented or removed, a use
// line gone, and a name written out in a path, are each red.
func TestPracticeLayout_CheckFlagIsolationFailsOnADriftedCopy(t *testing.T) {
	script := readFlagIsolationScript(t)
	if err := flagIsolationLayoutError(script); err != nil {
		t.Fatalf("the real script is not equal to the Go definitions, so the negative cases below prove nothing: %v", err)
	}
	replaceOnce := func(t *testing.T, src, old, repl string) string {
		t.Helper()
		if n := strings.Count(src, old); n != 1 {
			t.Fatalf("the negative case's text %q must occur exactly once (%d times): rewording the line makes this check vacuous, update it", old, n)
		}
		return strings.Replace(src, old, repl, 1)
	}
	for _, l := range flagIsolationLiterals {
		line := l.name + "='" + l.want + "'\n"
		for what, mutated := range map[string]string{
			"changed":  replaceOnce(t, script, line, l.name+"='"+l.want+"x'\n"),
			"doubled":  replaceOnce(t, script, line, line+line),
			"indented": replaceOnce(t, script, line, "  "+line),
			"removed":  replaceOnce(t, script, line, ""),
		} {
			if flagIsolationLayoutError(mutated) == nil {
				t.Errorf("%s %s in a copy of the script: no difference was reported", l.name, what)
			}
		}
	}
	for _, want := range flagIsolationUseLines {
		if flagIsolationLayoutError(replaceOnce(t, script, want+"\n", "")) == nil {
			t.Errorf("a copy without the line %q: no difference was reported", want)
		}
	}
	anchor := flagIsolationUseLines[0] + "\n"
	for name, extra := range map[string]string{
		"the evidence dir by hand":    `    b="${root}/${cid}/edition/practice/evidence"`,
		"the answers file by hand":    `    a="${pd}/answers.tsv"`,
		"the digests file by hand":    `    d="${pd}/digests.tsv"`,
		"a name at the end of a line": `    r=${root}/${cid}/edition`,
	} {
		if flagIsolationLayoutError(replaceOnce(t, script, anchor, anchor+extra+"\n")) == nil {
			t.Errorf("a copy with %s: no difference was reported", name)
		}
	}
	// The same text in a comment is not a spelling.
	if err := flagIsolationLayoutError(replaceOnce(t, script, anchor, anchor+"    # ${root}/<cid>/edition/practice/evidence/\n")); err != nil {
		t.Errorf("a comment was read as a spelling: %v", err)
	}
	if flagIsolationLayoutError("") == nil {
		t.Error("an empty check-flag-isolation.sh was accepted")
	}
}
