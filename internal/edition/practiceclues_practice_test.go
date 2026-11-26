package edition_test

// ADR-0056 V112 on the REAL tree (A7-x PR 4c, the review's LOW): B18's reading of the practice
// side, by the one function `edition check` calls (CheckPracticeClues), given the practice edition
// of every investigate challenge of the catalog as the practice (its edition.yaml's bytes and its
// template/, the catalog's questions) and, as the event, the same edition (an event that holds to
// E2, so that the practice side is what is looked at).
//
// The practice editions of 50 and 51 hold to E2 (they declare no block, so E2's clue lines ask
// nothing of them) and declare no clue, so the practice's clue words of every answer slot are
// empty, and an empty set is held by every event: B18 refuses each answer slot once (fail-closed:
// such a practice edition does not say what leads to its answer). That is the known state, pinned
// as exactly that set (pcKnownB18): a violation that is not in the table is red, and so is an
// entry of the table that is no longer reported. The check has no exception for them. The rewrite
// of the two challenges (PR 5, PR 6: their practice editions declare blocks and clues) turns it:
// the table is then emptied, and this test is where the rewritten practice editions are held to
// B18's reading of the practice side.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// pcKnown is one known violation of B18 on the real tree: the question of challenge cid whose
// practice answer has no clue word.
type pcKnown struct {
	cid, qid string
}

// pcKnownB18 are the violations of B18 that the real tree is known to have, and the only ones it
// may have (ADR-0056, the row of A7-x): one per answer slot of 50 and 51.
var pcKnownB18 = []pcKnown{
	{cid: crossIRA, qid: "first-shell"},
	{cid: crossIRA, qid: "cred-file"},
	{cid: crossIRA, qid: "bundle-file"},
	{cid: crossIRA, qid: "survey-file"},
	{cid: crossIRB, qid: "dest-host"},
	{cid: crossIRB, qid: "lookup-name"},
}

func (k pcKnown) matches(v *edition.Violation) bool {
	return v.Rule == edition.RulePracticeClues && v.CID == k.cid && v.QID == k.qid &&
		strings.Contains(v.Msg, "a practice answer with no clue word is held by every event")
}

func TestPracticeClues_TheRealTreeHasExactlyTheKnownViolations(t *testing.T) {
	cat, err := catalog.Load(goldenRealDir)
	if err != nil {
		t.Fatalf("catalog.Load(%s): %v", goldenRealDir, err)
	}
	var b18 []*edition.Violation
	seen := map[string]bool{}
	for _, id := range cat.IDs() {
		ch := cat[id]
		if ch.Type != catalog.TypeInvestigate || ch.Investigate == nil {
			continue
		}
		seen[id] = true
		spec, tmpl := goldenInputs(t, goldenRealDir, ch)
		raw, err := os.ReadFile(filepath.Join(goldenRealDir, ch.Dir(), goldenEditionDir, edition.SpecFileName))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		err = spec.CheckPracticeClues(id, ch.Investigate.Questions, tmpl, raw, tmpl)
		b18 = append(b18, crossViolationList(t, err, edition.RulePracticeClues)...)
	}
	if !seen[crossIRA] || !seen[crossIRB] {
		t.Fatalf("the catalog does not hold %s and %s: V112 pins that their answer slots are looked at", crossIRA, crossIRB)
	}
	if len(b18) == 0 {
		t.Fatal("B18 reported nothing on the real tree, whose practice editions declare no clue: a reading of nothing is not a pass")
	}
	matched := make([]bool, len(pcKnownB18))
	for _, v := range b18 {
		found := false
		for i, k := range pcKnownB18 {
			if !matched[i] && k.matches(v) {
				matched[i], found = true, true
				break
			}
		}
		if !found {
			t.Errorf("a violation of B18 that is not a known one (pcKnownB18): %v", v)
		}
	}
	for i, k := range pcKnownB18 {
		if !matched[i] {
			t.Errorf("the known violation of B18 (%s %s, a practice answer with no clue word) is no longer reported: it is fixed, so remove it from pcKnownB18 (ADR-0056 A7-x, PR 5 / PR 6)", k.cid, k.qid)
		}
	}
}
