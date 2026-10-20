package contracttable

import (
	"strings"
	"testing"
)

const doc = "# t\n\n| outside | row |\n\n## Cross-repo 契約\n\ntext\n| a | `x{l}` |\n| b | second |\nnot a row\n\n## Next\n| c | after the section |\n"

func TestRows_AreTheSectionsTableRowsOnly(t *testing.T) {
	got := Rows(doc)
	if len(got) != 2 || got[0] != "| a | `x{l}` |" || got[1] != "| b | second |" {
		t.Fatalf("Rows = %q, want the two rows of the section (not the one before or after it)", got)
	}
}

func TestRowWhere(t *testing.T) {
	if got := RowWhere(doc, func(r string) bool { return strings.Contains(r, "second") }); got != "| b | second |" {
		t.Fatalf("RowWhere = %q", got)
	}
	if got := RowWhere(doc, func(r string) bool { return strings.Contains(r, "after the section") }); got != "" {
		t.Fatalf("a row outside the section was found: %q", got)
	}
}

// A renamed heading finds nothing: the callers read that as a failure, not as "no row".
func TestRows_RenamedHeadingFindsNothing(t *testing.T) {
	if got := Rows(strings.Replace(doc, "Cross-repo 契約", "Cross-repo contracts", 1)); got != nil {
		t.Fatalf("Rows = %q, want nil", got)
	}
}
