package api

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// TestStoredDisplayNameViolations_DerivedFromTheSharedCaseTable assigns every
// row of the shared display-name table (testdata/display-name-parity/cases.yaml)
// to a synthetic seat, as if it had been stored verbatim, and checks that
// StoredDisplayNameViolations reports exactly the rows the table says the write
// path would not store as typed: `server: reject` rows, and `server: accept`
// rows whose `stored` (the trimmed form) differs from the input (an edge of
// whitespace, NEL, LF ...). The expectation is derived from the table, not
// listed here, so the rule stays in one place. An empty input is skipped (it
// renders as the seat); the sweep must contain both outcomes.
func TestStoredDisplayNameViolations_DerivedFromTheSharedCaseTable(t *testing.T) {
	names := map[string]string{}
	var want []string
	for i, c := range loadNameParityCases(t) {
		in := c.input()
		seat := fmt.Sprintf("seat%03d", i)
		names[seat] = in
		if in == "" {
			continue
		}
		if c.Server == "reject" || (c.Stored != nil && *c.Stored != in) {
			want = append(want, seat)
		}
	}
	sort.Strings(want)
	if len(want) == 0 || len(want) == len(names) {
		t.Fatalf("the table sweep needs both outcomes: %d violating of %d rows", len(want), len(names))
	}
	got := StoredDisplayNameViolations(names)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("StoredDisplayNameViolations = %v\nwant (derived from cases.yaml) %v", got, want)
	}
}

// TestStoredDisplayNameViolations_EdgeWhitespaceIsReported pins the three seed
// cases of the predicate by name: an edge NEL (C1 but TrimSpace whitespace), an
// edge LF and plain padding all pass validDisplayName on the trimmed form, yet
// are not what the write path stores.
func TestStoredDisplayNameViolations_EdgeWhitespaceIsReported(t *testing.T) {
	got := StoredDisplayNameViolations(map[string]string{
		"nel-end":  "Alice\u0085",
		"lf-start": "\nAlice",
		"padded":   "  Alice  ",
		"clean":    "Alice",
		"empty":    "",
	})
	want := []string{"lf-start", "nel-end", "padded"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
