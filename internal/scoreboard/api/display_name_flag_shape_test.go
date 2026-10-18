package api

import (
	"regexp"
	"testing"
)

// app#402: a display name is shown to the others next to a participant's posts (the
// author of an audience=all board thread) and on the operator's screens, so it is
// gated by the same flag SHAPE (flagShapePattern, app#292) as a board subject and
// body. The shape is a pattern rule, not a character class, so rule.yaml's code-point
// sweep does not cover it: the rows are in cases.yaml (`reason: flag-shape`, run by
// TestDisplayNameParity_*). This file holds only what that table cannot: the one
// shape scripts/check-flags.sh does not let testdata carry (empty braces), the fixed
// sentence, and the mutation that proves the table depends on the rule.

// emptyBraceShape is a flag shape with nothing between the braces. check-flags.sh
// rejects it in any tracked non-_test.go file, so it cannot be a cases.yaml row.
const emptyBraceShape = "FALCO{}"

func TestDisplayName_EmptyBraceFlagShapeIsRefused(t *testing.T) {
	for _, in := range []string{emptyBraceShape, "Alice " + emptyBraceShape, "  " + emptyBraceShape + "  "} {
		if _, err := validDisplayName(in); err == nil || err.Error() != errMsgDisplayNameFlagShape {
			t.Errorf("validDisplayName(%q) = %v, want %q", in, err, errMsgDisplayNameFlagShape)
		}
	}
}

// The 400 sentence is fixed text: it never contains the input.
func TestDisplayName_FlagShapeSentenceDoesNotEchoTheInput(t *testing.T) {
	_, err := validDisplayName("FALCO{secret-looking}")
	if err == nil {
		t.Fatal("a flag-shaped name was accepted")
	}
	if got := err.Error(); got != errMsgDisplayNameFlagShape || regexp.MustCompile(`secret|FALCO`).MatchString(got) {
		t.Fatalf("sentence = %q, want the fixed %q", got, errMsgDisplayNameFlagShape)
	}
}

// Mutation: with flagShapePattern taken out (it can never match) the table checks go
// red on every `reason: flag-shape` row: the server accepts what the table says it
// refuses, and the never-stricter check no longer finds the flag-shape sentence. So the
// table does depend on the rule in validDisplayName.
func TestDisplayName_FlagShapeMutationGoesRedOnTheTable(t *testing.T) {
	orig := flagShapePattern
	t.Cleanup(func() { flagShapePattern = orig })
	flagShapePattern = regexp.MustCompile(`a^`)

	cases := loadNameParityCases(t)
	var rows, serverRed int
	for _, c := range cases {
		if c.Reason != reasonFlagShape {
			continue
		}
		rows++
		if serverRowProblem(c) != "" {
			serverRed++
		}
	}
	if rows < minFlagShapeRows {
		t.Fatalf("only %d reason: %s rows in the table, want at least %d", rows, reasonFlagShape, minFlagShapeRows)
	}
	if serverRed != rows {
		t.Fatalf("with the gate removed, ServerMatchesTable is red on %d of %d flag-shape rows, want all", serverRed, rows)
	}
	problems, _, _ := neverStricterProblems(cases)
	if len(problems) < rows {
		t.Fatalf("with the gate removed, ClientIsNeverStricter reports %d problems, want at least %d (one per flag-shape row)", len(problems), rows)
	}
}
