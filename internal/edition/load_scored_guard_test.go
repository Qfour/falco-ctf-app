package edition_test

import (
	"errors"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// ADR-0056 D19 A4a-3 (review #631 R1#1): Load takes the catalog.Scored that
// catalog.LoadScored returned. A Scored that is not one (a zero value, a literal built
// by hand, a scope the tree does not hold) would give an EMPTY practice set, so T6 would
// compare nothing and pass; it is refused instead (ErrInconsistentScored), on every
// path that reads the practice answers, and only on those.

func TestLoad_RefusesAScoredThatIsNotLoadScoredsResult(t *testing.T) {
	dir := writeTree(t, modeFiles())
	cat := scopeOf(t, dir, demoCID)

	damage := func(f func(s *catalog.Scored)) catalog.Scored {
		s := scoredOf(t, cat, dir)
		f(&s)
		return s
	}
	cases := []struct {
		name   string
		scored catalog.Scored
	}{
		{"a scope with no FullCatalog and no dir (a literal)", catalog.Scored{Catalog: cat}},
		{"no FullCatalog", damage(func(s *catalog.Scored) { s.FullCatalog = nil })},
		{"no ChallengesDir", damage(func(s *catalog.Scored) { s.ChallengesDir = "" })},
		{"a scope challenge that the full catalog does not hold", damage(func(s *catalog.Scored) { delete(s.FullCatalog, demoCID) })},
		{"a scope challenge of another type in the full catalog", damage(func(s *catalog.Scored) {
			ch := s.FullCatalog[demoCID]
			ch.Type = catalog.TypeEvade
			s.FullCatalog[demoCID] = ch
		})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// the event mode with a table (T6 would run on an empty set) ...
			j, runID, err := edition.Load(c.scored, eventTable(t), true)
			if !errors.Is(err, edition.ErrInconsistentScored) || j != nil || runID != "" {
				t.Errorf("event mode with a table: Load = %v, %q, %v; want ErrInconsistentScored and nothing else", j, runID, err)
			}
			// ... and the practice mode (the Judge would have no answers to be made of)
			j, runID, err = edition.Load(c.scored, "", false)
			if !errors.Is(err, edition.ErrInconsistentScored) || j != nil || runID != "" {
				t.Errorf("practice mode: Load = %v, %q, %v; want ErrInconsistentScored and nothing else", j, runID, err)
			}
		})
	}
}

// The guard sits where the tree is read, so a start-up with nothing to judge, which
// reads no tree, is as before: even the zero value gives (nil, "", nil), and the event
// mode without a table is still ErrTableMissing, not the new error.
func TestLoad_ScoredGuardIsOnlyWhereThePracticeAnswersAreRead(t *testing.T) {
	for _, event := range []bool{false, true} {
		if j, runID, err := edition.Load(catalog.Scored{}, "", event); err != nil || j != nil || runID != "" {
			t.Errorf("a zero Scored, nothing to judge (event mode %v): Load = %v, %q, %v; want nil, \"\", nil", event, j, runID, err)
		}
	}
	cat := catalog.Catalog{"03-ev": {ID: "03-ev", Type: "evade", ExpectedFlag: plainFlag}}
	if j, _, err := edition.Load(catalog.Scored{Catalog: cat}, "", false); err != nil || j != nil {
		t.Errorf("an evade-only scope with no tree: Load = %v, %v; want nil, nil", j, err)
	}
	dir := writeTree(t, modeFiles())
	inv := scopeOf(t, dir, demoCID)
	if _, _, err := edition.Load(catalog.Scored{Catalog: inv}, "", true); !errors.Is(err, edition.ErrTableMissing) {
		t.Errorf("the event mode, an investigate scope, no table: err = %v, want ErrTableMissing (D8 (i) comes first)", err)
	}
}
