package edition_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// ADR-0056 D8 (i)(ii), D10 T1 / T2: the whole truth table.
func TestModeCheck(t *testing.T) {
	cases := []struct {
		name         string
		event        bool
		hasInvestig  bool
		tablePresent bool
		want         error
	}{
		{"event, investigate in scope, no table (T1)", true, true, false, edition.ErrTableMissing},
		{"event, investigate in scope, table", true, true, true, nil},
		{"event, nothing to judge, no table", true, false, false, nil},
		{"event, nothing to judge, table (Check refuses its rows)", true, false, true, nil},
		{"no event, table, investigate in scope (T2)", false, true, true, edition.ErrTableOutsideEventMode},
		{"no event, table, nothing to judge (T2)", false, false, true, edition.ErrTableOutsideEventMode},
		{"no event, no table, investigate in scope (practice answers)", false, true, false, nil},
		{"no event, no table, nothing to judge", false, false, false, nil},
	}
	for _, c := range cases {
		if got := edition.ModeCheck(c.event, c.hasInvestig, c.tablePresent); !errors.Is(got, c.want) {
			t.Errorf("%s: ModeCheck = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestScopeOf_TakesOnlyInvestigateChallenges(t *testing.T) {
	qs := []catalog.Question{{ID: "who", Format: answerformat.Name, Attempts: 5}}
	cat := catalog.Catalog{
		demoCID:    {ID: demoCID, Type: catalog.TypeInvestigate, Investigate: &catalog.Investigate{Questions: qs}},
		"02-evade": {ID: "02-evade", Type: "evade"},
		"03-trig":  {ID: "03-trig", Type: "trigger"},
	}
	sc := edition.ScopeOf(cat)
	if len(sc) != 1 || len(sc[demoCID]) != 1 || sc[demoCID][0].ID != "who" {
		t.Fatalf("ScopeOf = %v, want only %s with its question", sc, demoCID)
	}
	if !sc.HasInvestigate() {
		t.Error("HasInvestigate = false")
	}
	if edition.ScopeOf(catalog.Catalog{"02-evade": {ID: "02-evade", Type: "evade"}}).HasInvestigate() {
		t.Error("HasInvestigate = true for a catalog with no investigate challenge")
	}
}

func TestCheck_AcceptsAnEventTable(t *testing.T) {
	if err := edition.Check(mustParse(t, render(runA, baseRows())), demoScope, eventOpts()); err != nil {
		t.Fatalf("Check = %v", err)
	}
}

// A practice table: the zero run id and the seat * alone (D8, D12). T6 is not asked.
func TestCheck_AcceptsAPracticeTable(t *testing.T) {
	rows := [][]string{
		{"*", demoCID, "who", "practice-name"},
		{"*", demoCID, "hx", "cccccccccccc"},
		{"*", demoCID, "pick", "ca,cb"},
	}
	opts := edition.Options{Practice: edition.PracticeSet{answerformat.Name: {"practice-name": {}}}}
	if err := edition.Check(mustParse(t, render(edition.PracticeRunID, rows)), demoScope, opts); err != nil {
		t.Fatalf("Check = %v", err)
	}
}

func TestCheck_NilTable(t *testing.T) {
	if err := edition.Check(nil, demoScope, eventOpts()); !errors.Is(err, edition.ErrTableMissing) {
		t.Errorf("Check(nil) = %v, want ErrTableMissing", err)
	}
}

// D10 T3 (run id) and T4-T8, one defect per case. want is the set of rules that
// fire; a defect that is also another rule's (a flag shape never fits a format) says
// so. Every case also checks that no table value is in the error (D13).
func TestCheck_Rejects(t *testing.T) {
	practiceHasName := edition.PracticeSet{}
	practiceHasName.Add(answerformat.Name, sentinel+"-a")
	flagValueOpts := edition.Options{EventMode: true, Practice: edition.PracticeSet{}, FlagValues: []string{"aaaaaaaaaaaa"}}
	practiceMode := edition.Options{}

	cases := []struct {
		name string
		run  string
		opts edition.Options
		rows [][]string
		want []string
	}{
		{"event table with the practice run id", edition.PracticeRunID, eventOpts(), baseRows(), []string{"T3"}},
		{"practice table with a real run id", runA, practiceMode, rename(baseRows(), "seat-a", "*")[:3], []string{"T3"}},
		{"event mode without the practice answers", runA, edition.Options{EventMode: true}, baseRows(), []string{"T6"}},

		{"no row at all", runA, eventOpts(), nil, []string{"T4"}},
		{"seat outside the seat grammar", runA, eventOpts(), rename(baseRows(), "seat-a", "Seat_A"), []string{"T4"}},
		{"seat with a trailing hyphen", runA, eventOpts(), rename(baseRows(), "seat-a", "seat-"), []string{"T4"}},
		{"seat * in an event table", runA, eventOpts(), rename(baseRows(), "seat-a", "*"), []string{"T4"}},
		{"practice table mixing * with a seat", "00000000000000000000000000000000", practiceMode, rename(baseRows(), "seat-a", "*"), []string{"T4"}},
		{"cid outside the scope", runA, eventOpts(), set(baseRows(), 0, 1, "02-other"), []string{"T4"}},
		{"qid outside the challenge", runA, eventOpts(), set(baseRows(), 0, 2, "nope"), []string{"T4"}},
		{"a seat is missing a row", runA, eventOpts(), without(baseRows(), 4), []string{"T4"}},
		{"columns swapped: a value in the seat column", runA, eventOpts(), [][]string{{sentinel + "-a", demoCID, "who", "seat-a"}}, []string{"T4"}},

		{"hexid of the wrong length", runA, eventOpts(), set(baseRows(), 1, 3, "aaaaaaaaaaa"), []string{"T5"}},
		{"hexid not in normalised (lower-case) form", runA, eventOpts(), set(baseRows(), 1, 3, "AAAAAAAAAAAA"), []string{"T5"}},
		{"name with a character outside the format", runA, eventOpts(), set(baseRows(), 0, 3, sentinel+" x"), []string{"T5"}},
		{"name with a leading space (not normalised)", runA, eventOpts(), set(baseRows(), 0, 3, " "+sentinel+"-a"), []string{"T5"}},
		{"choice-set with an option that is not declared", runA, eventOpts(), set(baseRows(), 2, 3, "ca,zz"), []string{"T5"}},
		{"choice-set not sorted (not normalised)", runA, eventOpts(), set(baseRows(), 2, 3, "cb,ca"), []string{"T5"}},

		{"value is a practice answer of the same format", runA, edition.Options{EventMode: true, Practice: practiceHasName}, baseRows(), []string{"T6"}},

		{"value is one of this event's flag values", runA, flagValueOpts, baseRows(), []string{"T7"}},
		{"value holds a flag shape (it fits no format either)", runA, eventOpts(), set(baseRows(), 0, 3, "FALCO{dev-x}"), []string{"T5", "T7"}},
		{"value holds a flag shape in lower case", runA, eventOpts(), set(baseRows(), 0, 3, sentinel+"falco{x"), []string{"T5", "T7"}},

		{"two seats share a per-seat name", runA, eventOpts(), set(baseRows(), 3, 3, sentinel+"-a"), []string{"T8"}},
		{"two seats share a per-seat hexid", runA, eventOpts(), set(baseRows(), 4, 3, "aaaaaaaaaaaa"), []string{"T8"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tb, perr := edition.Parse(render(c.run, c.rows))
			if perr != nil {
				t.Fatalf("the case is meant to pass Parse: %v", perr)
			}
			err := edition.Check(tb, demoScope, c.opts)
			if err == nil {
				t.Fatal("Check accepted it")
			}
			if got := rules(err); !slices.Equal(got, c.want) {
				t.Errorf("rules = %v, want %v (%v)", got, c.want, err)
			}
			noSecret(t, c.name, err)
		})
	}
}

// A choice-set answer is the same for every seat (it cannot vary per seat), and
// that is not a T8 violation: baseRows has it, and Check accepts them.
func TestCheck_T8OnlyForPerSeatFormats(t *testing.T) {
	rows := baseRows()
	if rows[2][3] != rows[5][3] || rows[2][2] != "pick" {
		t.Fatal("the fixture lost the shared choice-set answer")
	}
	if err := edition.Check(mustParse(t, render(runA, rows)), demoScope, eventOpts()); err != nil {
		t.Errorf("Check = %v", err)
	}
}

// An error names a rule, a line and an identifier; the identifier appears only when
// it is inside its own grammar.
func TestCheck_ErrorNamesIdentifiersNotValues(t *testing.T) {
	err := edition.Check(mustParse(t, render(runA, without(baseRows(), 4))), demoScope, eventOpts())
	if err == nil {
		t.Fatal("Check accepted a table with a missing row")
	}
	for _, want := range []string{"T4", "seat=seat-b", "cid=" + demoCID, "qid=hx"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	// A swapped row puts a value in the seat column: it is not named.
	err = edition.Check(mustParse(t, render(runA, set(baseRows(), 0, 0, sentinel+"-a"))), demoScope, eventOpts())
	if err == nil {
		t.Fatal("Check accepted a swapped row")
	}
	noSecret(t, "swapped row", err)
}

func TestCheck_ListsAtMostTwentyViolations(t *testing.T) {
	// 30 seats, each with one bad value and two missing rows: far more than 20.
	var rows [][]string
	for i := range 30 {
		rows = append(rows, []string{fmt.Sprintf("seat-%02d", i), demoCID, "hx", strings.Repeat("g", 12)})
	}
	err := edition.Check(mustParse(t, render(runA, rows)), demoScope, eventOpts())
	if err == nil {
		t.Fatal("Check accepted it")
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("error is not a join: %T", err)
	}
	if n := len(joined.Unwrap()); n != 21 {
		t.Errorf("listed %d errors, want 20 violations and 1 count of the rest", n)
	}
}
