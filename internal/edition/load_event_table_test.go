package edition_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// ADR-0056 D20 and D19 A4e-1, through the exported names only: the chain the validator runs is
// LoadEventTable, then CheckBundles with the *CheckedTable it gave, then WriteDigests with the
// *CheckedBundles that gave. There is no other way to a digests file: the run id in it is the
// table's, whatever else the caller holds. (The tests of what a CheckedTable carries, and of the
// two doors' words, are load_event_table_internal_test.go's.)
func TestLoadEventTable_ThroughCheckBundlesToTheDigestsFile(t *testing.T) {
	cat := loadCatalog(t)
	ct, runID, err := edition.LoadEventTable(scoredOf(t, cat, t.TempDir()), writeTable(t, render(runA, loadRows())))
	if err != nil {
		t.Fatalf("LoadEventTable: %v", err)
	}
	if ct == nil || runID != runA {
		t.Fatalf("LoadEventTable = (%v, %q), want a CheckedTable and the run id %q", ct, runID, runA)
	}
	in := edition.BundleInput{
		Scope:      edition.ScopeOf(cat),
		Seats:      []string{"seat-a", "seat-b"},
		FlagValues: []string{eventFlg},
		Hints:      []hintleak.Item{{Source: "01-demo hints[0]", Text: hintText}},
		Free:       []hintleak.Item{{Source: "01-demo briefing", Text: "plain words only"}},
		Corpus:     edition.Corpus{[]byte("nothing that is an answer")},
	}
	cb, err := edition.CheckBundles(bundleTree(t, goodBundleFiles()), ct, in)
	if err != nil {
		t.Fatalf("CheckBundles: %v", err)
	}
	if cb.RunID() != runA || len(cb.Rows()) != 2 {
		t.Errorf("CheckedBundles = run id %q and %d rows, want %q and 2", cb.RunID(), len(cb.Rows()), runA)
	}
	var buf bytes.Buffer
	if err := edition.WriteDigests(&buf, cb); err != nil {
		t.Fatalf("WriteDigests: %v", err)
	}
	id, rows, err := edition.ParseDigests(buf.Bytes())
	if err != nil || id != runA || !slices.Equal(rows, cb.Rows()) {
		t.Errorf("the digests file reads back as (%q, %v, %v), want the table's run id and the checked rows", id, rows, err)
	}

	// A tree that a rule refuses gives no *CheckedBundles, so there is nothing to write.
	if cb, err := edition.CheckBundles(bundleTree(t, kv(notesA, "no answer in it\n", notesB, "none here either\n")), ct, in); err == nil || cb != nil {
		t.Errorf("CheckBundles of bundles that hold no answer = (%v, %v), want a violation and no *CheckedBundles", cb, err)
	}
}
