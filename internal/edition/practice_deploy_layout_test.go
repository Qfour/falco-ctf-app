package edition_test

// ADR-0056 V85 (A5c-2): the practice edition's path of charts/ctf-user/deploy-user.sh reads
// <cid>/edition/practice/evidence/ (the bundle) and <cid>/edition/practice/digests.tsv (its
// digests file, the seat *). The script cannot import practicelayout.go, so it holds five
// literals, one top-level assignment each, and this test holds them to the Go definitions
// (EditionDirName, PracticeDirName, PracticeEvidenceDirName, PracticeDigestsFileName and the
// practice seat AnySeat), in the style of evidence_limits_test.go (V58): a literal that is
// missing, doubled, moved out of the top level or changed is red.
//
// The literals prove nothing unless the path is built from them, so the test also holds the
// lines that build it (each a line of its own, exactly once), and that no other line of the
// script that is not a comment spells one of the layout's names next to a `/` (a path written
// out by hand, which a rename in practicelayout.go would not reach). A copy of the script with
// one of these changed is red.

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// practiceDeployLiterals are the script's five literals and the definitions they copy.
var practiceDeployLiterals = []struct{ name, want string }{
	{"EVIDENCE_EDITION_DIR", edition.EditionDirName},
	{"EVIDENCE_PRACTICE_DIR", edition.PracticeDirName},
	{"EVIDENCE_PRACTICE_EVIDENCE_DIR", edition.PracticeEvidenceDirName},
	{"EVIDENCE_PRACTICE_DIGESTS", edition.PracticeDigestsFileName},
	{"EVIDENCE_PRACTICE_SEAT", edition.AnySeat},
}

// practiceDeployUseLines are the lines of evidence_verify_practice that build the paths and
// pass the seat from the literals.
var practiceDeployUseLines = []string{
	`    root="${CHALLENGES_DIR}/${cid}/${EVIDENCE_EDITION_DIR}/${EVIDENCE_PRACTICE_DIR}"`,
	`    digests="${root}/${EVIDENCE_PRACTICE_DIGESTS}"`,
	`    EVIDENCE_BUNDLE_DIRS+=("${root}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}")`,
	`    evidence_check_digests "${EVIDENCE_PRACTICE_DIGESTS_FILES[idx]}" "the practice digests file of ${cid}" "${EVIDENCE_PRACTICE_SEAT}" "${cid}"`,
}

// practiceLayoutSpelling matches a name of the practice layout written next to a `/`: after
// one (followed by a `/`, a quote, a space or the end) or before one (not part of a longer
// word). `/evidence-bundle.sh` and `falco-ctf/evidence-of` are longer words, not the name.
var practiceLayoutSpelling = func() *regexp.Regexp {
	var alts []string
	for _, n := range []string{
		edition.EditionDirName, edition.PracticeDirName, edition.PracticeEvidenceDirName,
		edition.PracticeDigestsFileName, edition.PracticeAnswersFileName,
	} {
		alts = append(alts, regexp.QuoteMeta(n))
	}
	names := "(?:" + strings.Join(alts, "|") + ")"
	return regexp.MustCompile(`/` + names + `(?:[/"'\s]|$)|(?:^|[^A-Za-z0-9_.-])` + names + `/`)
}()

// practiceDeployLayoutError is the whole rule; it returns the first difference.
func practiceDeployLayoutError(deploy string) error {
	exempt := map[string]bool{}
	for _, l := range practiceDeployLiterals {
		got, err := shellLiteral(deploy, l.name)
		if err != nil {
			return err
		}
		if got != l.want {
			return fmt.Errorf("deploy-user.sh: %s = %q, the Go definition is %q", l.name, got, l.want)
		}
		exempt[l.name+"='"+l.want+"'"] = true
	}
	lines := strings.Split(deploy, "\n")
	for _, want := range practiceDeployUseLines {
		n := 0
		for _, ln := range lines {
			if ln == want {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("deploy-user.sh has the line %q %d times, want once: the practice path is not built from the literals", want, n)
		}
	}
	for i, ln := range lines {
		if exempt[ln] || strings.HasPrefix(strings.TrimLeft(ln, " \t"), "#") {
			continue
		}
		if m := practiceLayoutSpelling.FindString(ln); m != "" {
			return fmt.Errorf("deploy-user.sh:%d spells a name of the practice layout as a path (%q): use the EVIDENCE_* literals", i+1, m)
		}
	}
	return nil
}

func TestPracticeDeployLayout_DeployUserMatchesGo(t *testing.T) {
	deploy, _ := readLimitCopies(t)
	if err := practiceDeployLayoutError(deploy); err != nil {
		t.Error(err)
	}
}

// The check must be able to fail: one literal changed, doubled, indented or removed, a use
// line gone, and a name written out in a path, are each red.
func TestPracticeDeployLayout_CheckFailsOnADriftedCopy(t *testing.T) {
	deploy, _ := readLimitCopies(t)
	if err := practiceDeployLayoutError(deploy); err != nil {
		t.Fatalf("the real script is not equal to the Go definitions, so the negative cases below prove nothing: %v", err)
	}
	replaceOnce := func(t *testing.T, src, old, repl string) string {
		t.Helper()
		if n := strings.Count(src, old); n != 1 {
			t.Fatalf("the negative case's text %q must occur exactly once (%d times): rewording the line makes this check vacuous, update it", old, n)
		}
		return strings.Replace(src, old, repl, 1)
	}
	for _, l := range practiceDeployLiterals {
		line := l.name + "='" + l.want + "'\n"
		for what, mutated := range map[string]string{
			"changed":  replaceOnce(t, deploy, line, l.name+"='"+l.want+"x'\n"),
			"doubled":  replaceOnce(t, deploy, line, line+line),
			"indented": replaceOnce(t, deploy, line, "  "+line),
			"removed":  replaceOnce(t, deploy, line, ""),
		} {
			if practiceDeployLayoutError(mutated) == nil {
				t.Errorf("%s %s in a copy of the script: no difference was reported", l.name, what)
			}
		}
	}
	for _, want := range practiceDeployUseLines {
		if practiceDeployLayoutError(replaceOnce(t, deploy, want+"\n", "")) == nil {
			t.Errorf("a copy without the line %q: no difference was reported", want)
		}
	}
	anchor := practiceDeployUseLines[1] + "\n"
	for name, extra := range map[string]string{
		"the evidence dir by hand":    `    p="${root}/evidence/${name}"`,
		"the digests file by hand":    `    d="${root}/digests.tsv"`,
		"the answers file by hand":    `    a="${root}/answers.tsv"`,
		"the practice dir by hand":    `    r="${CHALLENGES_DIR}/${cid}/edition/practice"`,
		"a relative path by hand":     `    r="edition/${x}"`,
		"a name at the end of a line": `    r=${CHALLENGES_DIR}/${cid}/edition`,
	} {
		if practiceDeployLayoutError(replaceOnce(t, deploy, anchor, anchor+extra+"\n")) == nil {
			t.Errorf("a copy with %s: no difference was reported", name)
		}
	}
	// The same text in a comment is not a spelling.
	if err := practiceDeployLayoutError(replaceOnce(t, deploy, anchor, anchor+"    # ${root}/evidence/ and digests.tsv\n")); err != nil {
		t.Errorf("a comment was read as a spelling: %v", err)
	}
	if practiceDeployLayoutError("") == nil {
		t.Error("an empty deploy-user.sh was accepted")
	}
}
