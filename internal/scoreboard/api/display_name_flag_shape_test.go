package api

import (
	"regexp"
	"testing"
)

// app#402: a display name is shown to the others next to a participant's posts (the
// author of an audience=all board thread) and on the operator's screens, so it is
// gated by the same flag SHAPE (flagShapePattern, app#292) as a board subject and body. The shape is a pattern rule, not a character class,
// so rule.yaml's code-point sweep does not cover it: cases.yaml has the rows, and
// this file pins the boundary by name and proves the rule is load-bearing.

var flagShapeRejectedNames = []string{"FALCO{x}", "FALCO{}", "Alice FALCO{x}", "  FALCO{x}  ", "FALCO{ab}}"}

// Not the shape: bare word, unclosed, no opening brace, braces alone, lower / mixed
// case (the pattern is case-sensitive: see flagShapePattern).
var flagShapeAcceptedNames = []string{"FALCO", "{}", "FALCO{", "FALCO{x", "FALCO x}", "falco{x}", "Falco{x}", "FALCO {x}"}

// flagShapeNameProblems is every way validDisplayName disagrees with the two lists.
func flagShapeNameProblems() []string {
	var out []string
	for _, n := range flagShapeRejectedNames {
		_, err := validDisplayName(n)
		if err == nil {
			out = append(out, "accepted "+n)
		} else if err.Error() != errMsgDisplayNameFlagShape {
			out = append(out, "wrong sentence for "+n+": "+err.Error())
		}
	}
	for _, n := range flagShapeAcceptedNames {
		if _, err := validDisplayName(n); err != nil {
			out = append(out, "rejected "+n+": "+err.Error())
		}
	}
	return out
}

func TestDisplayName_FlagShapeBoundary(t *testing.T) {
	if p := flagShapeNameProblems(); len(p) != 0 {
		t.Fatalf("validDisplayName and the flag-shape boundary disagree: %v", p)
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

// Mutation: with the rejection gone (the pattern can never match) the boundary
// check above goes red, so it does depend on the rule in validDisplayName.
func TestDisplayName_FlagShapeMutationGoesRed(t *testing.T) {
	orig := flagShapePattern
	t.Cleanup(func() { flagShapePattern = orig })
	flagShapePattern = regexp.MustCompile(`a^`)
	if p := flagShapeNameProblems(); len(p) != len(flagShapeRejectedNames) {
		t.Fatalf("with the gate removed, %d names were reported, want all %d rejected names: %v", len(p), len(flagShapeRejectedNames), p)
	}
}
