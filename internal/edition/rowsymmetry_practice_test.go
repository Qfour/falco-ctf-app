package edition_test

// ADR-0056 V111 and V114 (1) (A7-x PR 4): B17 and B19 on the REAL tree, by the one function `edition
// check` calls (CheckRowRules), given the practice edition of every investigate challenge of the
// catalog (its edition.yaml, template/ and the catalog's questions). Every answer slot is looked at,
// and none at all is a failure; 50-nimbus-desk-triage and 51-nimbus-desk-egress must be among them.
//
// The real tree has known violations of B17: the practice editions of 50 and 51 declare no block
// (and no clue), so the lines of every answer slot are in no block (B17 asks for one). They are
// pinned as exactly that set, one per answer slot (rowKnownB17): a violation that is not in the
// table is red, and so is an entry of the table that is no longer reported. The check has no
// exception for them: an event edition of these templates is refused by `edition check`. B19 has
// nothing to say of a slot with no clue, so it must report nothing. PR 5 and PR 6 (the rewrite of
// the two challenges) make the table empty.

import (
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// rowKnown is one known violation of B17 on the real tree: the answer slot of challenge cid whose
// lines are in no block, the first of them in file.
type rowKnown struct {
	cid, slot, file string
}

// rowKnownB17 are the violations of B17 that the real tree is known to have, and the only ones it
// may have (ADR-0056, the row of A7-x): one per answer slot of 50 and 51, none of which is in a block.
var rowKnownB17 = []rowKnown{
	{cid: crossIRA, slot: "first", file: "falco-events.jsonl"},
	{cid: crossIRA, slot: "cred", file: "falco-events.jsonl"},
	{cid: crossIRA, slot: "bundle", file: "fs-inventory.tsv"},
	{cid: crossIRA, slot: "survey", file: "fs-inventory.tsv"},
	{cid: crossIRB, slot: "dest", file: "cluster-dns.log"},
	{cid: crossIRB, slot: "peer", file: "cluster-dns.log"},
}

func (k rowKnown) matches(v *edition.Violation) bool {
	return v.Rule == edition.RuleRowSymmetry && v.CID == k.cid && v.Slot == k.slot && v.File == k.file &&
		strings.Contains(v.Msg, "are in no block")
}

func TestRowRules_TheRealTreeHasExactlyTheKnownViolations(t *testing.T) {
	cat, err := catalog.Load(goldenRealDir)
	if err != nil {
		t.Fatalf("catalog.Load(%s): %v", goldenRealDir, err)
	}
	var b17, b19 []*edition.Violation
	slots := 0
	seen := map[string]bool{}
	for _, id := range cat.IDs() {
		ch := cat[id]
		if ch.Type != catalog.TypeInvestigate || ch.Investigate == nil {
			continue
		}
		seen[id] = true
		spec, tmpl := goldenInputs(t, goldenRealDir, ch)
		rep, err := spec.CheckRowRules(id, ch.Investigate.Questions, tmpl)
		slots += rep.AnswerSlots
		b17 = append(b17, crossViolationList(t, err, edition.RuleRowSymmetry)...)
		b19 = append(b19, crossViolationList(t, err, edition.RuleClueSpace)...)
	}
	if !seen[crossIRA] || !seen[crossIRB] {
		t.Fatalf("the catalog does not hold %s and %s: V111 pins that their answer slots are looked at", crossIRA, crossIRB)
	}
	if slots == 0 {
		t.Fatal("B17 looked at no answer slot of the real tree: a comparison of nothing is not a pass")
	}
	matched := make([]bool, len(rowKnownB17))
	for _, v := range b17 {
		found := false
		for i, k := range rowKnownB17 {
			if !matched[i] && k.matches(v) {
				matched[i], found = true, true
				break
			}
		}
		if !found {
			t.Errorf("a violation of B17 that is not a known one (rowKnownB17): %v", v)
		}
	}
	for i, k := range rowKnownB17 {
		if !matched[i] {
			t.Errorf("the known violation of B17 (%s %s, first in %s) is no longer reported: it is fixed, so remove it from rowKnownB17 (ADR-0056 A7-x, PR 5 / PR 6)", k.cid, k.slot, k.file)
		}
	}
	for _, v := range b19 {
		t.Errorf("B19 on the real tree, whose answer slots declare no clue: %v", v)
	}
}
