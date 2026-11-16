package catalog

import (
	"errors"
	"strings"
	"testing"
)

// checkPlacement (ADR-0056 A3b-5 / V39) on literal catalogs. The real-tree and
// scenario-file cases, through LoadScored, are in scenario_guard_test.go.
func TestCheckPlacement(t *testing.T) {
	cat := Catalog{
		"01-t":  {ID: "01-t", Type: TypeTrigger},
		"02-e":  {ID: "02-e", Type: TypeEvade},
		"03-e":  {ID: "03-e", Type: TypeEvade},
		"04-d":  {ID: "04-d", Type: TypeDetect},
		"05-i":  {ID: "05-i", Type: TypeInvestigate},
		"06-i2": {ID: "06-i2", Type: TypeInvestigate},
	}
	cases := []struct {
		name    string
		order   []string
		wantLat []string // ids the error must name; nil = no error
	}{
		{"evade then investigate", []string{"02-e", "05-i"}, nil},
		{"investigate then evade", []string{"05-i", "02-e"}, []string{"02-e"}},
		{"both evade challenges late", []string{"01-t", "05-i", "02-e", "04-d", "03-e"}, []string{"02-e", "03-e"}},
		{"a second investigate challenge does not reset the rule", []string{"05-i", "06-i2", "03-e"}, []string{"03-e"}},
		{"trigger and detect after an investigate challenge are allowed", []string{"02-e", "05-i", "01-t", "04-d"}, nil},
		{"no investigate challenge", []string{"01-t", "02-e", "03-e"}, nil},
		{"empty order", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPlacement(cat, tc.order)
			if len(tc.wantLat) == 0 {
				if err != nil {
					t.Fatalf("an allowed order was refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrEvadeAfterInvestigate) {
				t.Fatalf("err = %v, want ErrEvadeAfterInvestigate", err)
			}
			for _, id := range tc.wantLat {
				if !strings.Contains(err.Error(), id) {
					t.Fatalf("the refusal %q does not name %s", err, id)
				}
			}
		})
	}
}

// An id of the order that the catalog does not hold is an error, not a skip: a
// skipped id could hide the evade challenge the rule is about.
func TestCheckPlacement_UnknownIDFailsClosed(t *testing.T) {
	cat := Catalog{"05-i": {ID: "05-i", Type: TypeInvestigate}}
	err := checkPlacement(cat, []string{"05-i", "99-missing"})
	if err == nil || errors.Is(err, ErrEvadeAfterInvestigate) || !strings.Contains(err.Error(), "99-missing") {
		t.Fatalf("err = %v, want a placement-check error naming 99-missing", err)
	}
}
