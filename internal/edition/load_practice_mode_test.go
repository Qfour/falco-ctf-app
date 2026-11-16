package edition_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// ADR-0056 D8 (iv) / D19 A4a-2 / V36: outside the event mode, with no ANSWERS_FILE and
// an investigate challenge in scope, edition.Load makes the Judge from the practice
// answers of the scope's challenges. The trees are synthetic, under t.TempDir(); every
// value is made up.

const (
	modeHx      = "cccccccccccc"
	modeOtherHx = "dddddddddddd"
	modeOther   = "other-practice"
)

// modeFiles is a complete practice edition for both investigate challenges of the
// fixture tree (writeTree's two).
func modeFiles() map[string]string {
	return map[string]string{
		practicePath(demoCID): practiceFile([][]string{
			{"*", demoCID, "who", practiceSecret},
			{"*", demoCID, "hx", modeHx},
		}),
		practicePath(otherCID): practiceFile([][]string{
			{"*", otherCID, "who", modeOther},
			{"*", otherCID, "hx", modeOtherHx},
		}),
	}
}

// allRules is every rule of the violations anywhere in err, through single wraps
// and errors.Join alike.
func allRules(err error) []string {
	var out []string
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		var v *edition.Violation
		if errors.As(e, &v) && v == e {
			out = append(out, v.Rule)
			return
		}
		switch x := e.(type) {
		case interface{ Unwrap() []error }:
			for _, c := range x.Unwrap() {
				walk(c)
			}
		case interface{ Unwrap() error }:
			walk(x.Unwrap())
		}
	}
	walk(err)
	slices.Sort(out)
	return slices.Compact(out)
}

func noPracticeValue(t *testing.T, what string, err error) {
	t.Helper()
	for _, leak := range []string{practiceSecret, modeHx, modeOtherHx, modeOther, "AAAAAAAAAAAA"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("%s: the error carries a practice value (%q): %v", what, leak, err)
		}
	}
}

// The Judge answers for the scope's challenges, from the practice edition, for every
// seat; a challenge of the tree that is outside the scope is not in it.
func TestLoad_PracticeMode_JudgesTheScopeFromThePracticeEdition(t *testing.T) {
	dir := writeTree(t, modeFiles())

	j, runID, err := edition.Load(scoredOf(t, scopeOf(t, dir, demoCID), dir), "", false)
	if err != nil || j == nil {
		t.Fatalf("Load = %v, %q, %v; want a judge", j, runID, err)
	}
	if runID != edition.PracticeRunID {
		t.Errorf("run id = %q, want the practice run id (32 zeros)", runID)
	}
	for _, seat := range []string{"seat-a", "seat-q"} { // the seat * answers for every seat
		if ok, known := j.Match(seat, demoCID, "who", practiceSecret); !ok || !known {
			t.Errorf("%s, the practice answer: Match = %v, %v; want true, true", seat, ok, known)
		}
		if ok, known := j.Match(seat, demoCID, "hx", modeHx); !ok || !known {
			t.Errorf("%s, the practice hexid: Match = %v, %v; want true, true", seat, ok, known)
		}
		if ok, known := j.Match(seat, demoCID, "who", "a-wrong-answer"); ok || !known {
			t.Errorf("%s, a wrong answer: Match = %v, %v; want false, true", seat, ok, known)
		}
		if ok, known := j.Match(seat, demoCID, "who", modeHx); ok || !known {
			t.Errorf("%s, the other question's answer: Match = %v, %v; want false, true", seat, ok, known)
		}
	}
	// the other investigate challenge of the tree is outside the scope: not judged
	if ok, known := j.Match("seat-a", otherCID, "hx", modeOtherHx); ok || known {
		t.Errorf("a challenge outside the scope: Match = %v, %v; want false, false (not in the judge)", ok, known)
	}

	// both in scope: both judged
	j, _, err = edition.Load(scoredOf(t, scopeOf(t, dir, demoCID, otherCID), dir), "", false)
	if err != nil || j == nil {
		t.Fatalf("Load with both in scope = %v, %v; want a judge", j, err)
	}
	for _, c := range []struct{ cid, qid, value string }{
		{demoCID, "who", practiceSecret}, {demoCID, "hx", modeHx},
		{otherCID, "who", modeOther}, {otherCID, "hx", modeOtherHx},
	} {
		if ok, known := j.Match("seat-a", c.cid, c.qid, c.value); !ok || !known {
			t.Errorf("%s/%s: Match = %v, %v; want true, true", c.cid, c.qid, ok, known)
		}
	}
}

// T4 and the readers' checks, in the practice mode: a challenge of the scope without a
// practice edition, with one that lacks a question or is empty, with a value that
// normalisation would change, or a broken edition anywhere in the tree, stops the
// start-up. Nothing is returned with the error, and the error carries no value.
func TestLoad_PracticeMode_RefusesWhatCannotBeGraded(t *testing.T) {
	only := func(path string, rows ...[]string) map[string]string {
		return map[string]string{path: practiceFile(rows)}
	}
	whoOnly := [][]string{{"*", demoCID, "who", practiceSecret}}
	cases := []struct {
		name  string
		files map[string]string
		scope []string
		rules []string
		cid   string // a violation names this challenge ("" = not checked)
		plain bool   // add an evade challenge whose flag is the plain flag
	}{
		{"no practice edition at all", map[string]string{}, []string{demoCID}, []string{"T4"}, demoCID, false},
		{"the second challenge of the scope has none", only(practicePath(demoCID), modeFiles0()...), []string{demoCID, otherCID}, []string{"T4"}, otherCID, false},
		{"a question without a row", only(practicePath(demoCID), whoOnly...), []string{demoCID}, []string{"T4"}, demoCID, false},
		{"a practice table with no row", map[string]string{practicePath(demoCID): practiceFile(nil)}, []string{demoCID}, []string{"T4"}, "", false},
		{"a value that normalisation would change", only(practicePath(demoCID), []string{"*", demoCID, "who", practiceSecret}, []string{"*", demoCID, "hx", "AAAAAAAAAAAA"}), []string{demoCID}, []string{"T5"}, demoCID, false},
		{"a broken edition of a challenge outside the scope", map[string]string{
			practicePath(demoCID):  modeFiles()[practicePath(demoCID)],
			practicePath(otherCID): practiceFile([][]string{{"*", otherCID, "hx", "AAAAAAAAAAAA"}}),
		}, []string{demoCID}, []string{"T5"}, otherCID, false},
		{"a practice answer that holds this instance's flag (T7)", only(practicePath(demoCID), []string{"*", demoCID, "who", plainFlag}, []string{"*", demoCID, "hx", modeHx}), []string{demoCID}, []string{"T7"}, demoCID, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeTree(t, c.files)
			cat := scopeOf(t, dir, c.scope...)
			if c.plain {
				cat["03-ev"] = catalog.Challenge{ID: "03-ev", Type: "evade", ExpectedFlag: plainFlag}
			}
			j, runID, err := edition.Load(scoredOf(t, cat, dir), "", false)
			if err == nil {
				t.Fatal("Load accepted a practice edition that cannot grade the scope")
			}
			if j != nil || runID != "" {
				t.Errorf("a judge or a run id came back with the error: %v, %q", j, runID)
			}
			if got := allRules(err); !slices.Equal(got, c.rules) {
				t.Errorf("rules = %v, want %v (err: %v)", got, c.rules, err)
			}
			if c.cid != "" && !strings.Contains(err.Error(), c.cid) {
				t.Errorf("the error does not name %s: %v", c.cid, err)
			}
			if !strings.Contains(err.Error(), "practice answers") {
				t.Errorf("the error does not say it is about the practice answers: %v", err)
			}
			noPracticeValue(t, c.name, err)
			if c.plain && strings.Contains(err.Error(), plainFlag) {
				t.Errorf("the error carries the flag value: %v", err)
			}
		})
	}
}

// modeFiles0 are the rows of demoCID's complete practice table (for a case that has
// only that challenge's edition).
func modeFiles0() [][]string {
	return [][]string{
		{"*", demoCID, "who", practiceSecret},
		{"*", demoCID, "hx", modeHx},
	}
}

// Nothing to judge (no investigate challenge in scope): the practice edition is not
// read at all, so a tree whose editions are broken starts, as every environment does
// today.
func TestLoad_PracticeMode_NoInvestigateInScopeReadsNothing(t *testing.T) {
	dir := writeTree(t, map[string]string{practicePath(demoCID): "not a table\n"})
	cat := catalog.Catalog{"03-ev": {ID: "03-ev", Type: "evade", ExpectedFlag: plainFlag}}
	j, runID, err := edition.Load(scoredOf(t, cat, dir), "", false)
	if err != nil || j != nil || runID != "" {
		t.Errorf("Load = %v, %q, %v; want nil, \"\", nil", j, runID, err)
	}
}

// D8 (iii): in the event mode no Judge is made from the practice edition, however
// complete it is.
func TestLoad_EventMode_NeverJudgesFromThePracticeEdition(t *testing.T) {
	dir := writeTree(t, modeFiles())
	cat := scopeOf(t, dir, demoCID)

	// no ANSWERS_FILE: refused (D8 (i)), not graded from the image's answers
	if j, runID, err := edition.Load(scoredOf(t, cat, dir), "", true); !errors.Is(err, edition.ErrTableMissing) || j != nil || runID != "" {
		t.Errorf("event mode, no table, a complete practice edition: Load = %v, %q, %v; want ErrTableMissing and nothing else", j, runID, err)
	}

	// with the event table: the Judge is the table's. It knows the table's seats and
	// not the seat *, and the practice answer is not an answer of any seat.
	j, runID, err := edition.Load(scoredOf(t, cat, dir), eventTable(t), true)
	if err != nil || j == nil || runID != runA {
		t.Fatalf("event mode with a table: Load = %v, %q, %v; want a judge and run id %s", j, runID, err, runA)
	}
	if ok, known := j.Match("seat-a", demoCID, "who", sentinel+"-a"); !ok || !known {
		t.Errorf("the table's own answer: Match = %v, %v; want true, true", ok, known)
	}
	if ok, known := j.Match("seat-a", demoCID, "who", practiceSecret); ok || !known {
		t.Errorf("the practice answer for a seat of the table: Match = %v, %v; want false, true", ok, known)
	}
	if ok, known := j.Match("seat-z", demoCID, "who", practiceSecret); ok || known {
		t.Errorf("a seat the table does not name, with the practice answer: Match = %v, %v; want false, false (no seat * in an event Judge)", ok, known)
	}

	// a table without the event mode is still the mismatch, whatever the image holds
	if j, _, err := edition.Load(scoredOf(t, cat, dir), eventTable(t), false); !errors.Is(err, edition.ErrTableOutsideEventMode) || j != nil {
		t.Errorf("a table outside the event mode: Load = %v, %v; want ErrTableOutsideEventMode", j, err)
	}
}
