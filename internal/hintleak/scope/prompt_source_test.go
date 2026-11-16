package scope_test

// prompt_source_test.go pins the boundary of scope.IsQuestionPromptSource, which
// recognizes the Source of a question prompt item ("<challenge id>
// questions[<question id>].prompt") that scope.Assemble builds. The count check
// of ADR-0056 V24 / V35 counts the items of Free by it, so a wrong answer here is
// a wrong count.
//
// Not pinned on purpose: a Source in which the opening " questions[" occurs more
// than once. The function takes the first occurrence and says true; whether that
// is wanted depends on the grammar of ids, which this package does not own.

import (
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/hintleak/scope"
)

func TestIsQuestionPromptSource(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{"a question prompt source", "01-x questions[q1].prompt", true},
		{"the shortest one-rune id and question id", "a questions[b].prompt", true},
		{"an empty source", "", false},
		{"the challenge id is empty", " questions[q1].prompt", false},
		{"the question id is empty", "01-x questions[].prompt", false},
		{"only the closing suffix", "01-x].prompt", false},
		{"the opening without the closing suffix", "01-x questions[q1]", false},
		{"the suffix without the opening", "01-x questions q1].prompt", false},
		{"the opening is not preceded by a space", "01-xquestions[q1].prompt", false},
		{"the suffix is not at the end", "01-x questions[q1].prompt tail", false},
		{"a hint source", "01-x hints[1]", false},
		{"a briefing source", "01-x briefing", false},
		{"a step label source", "01-x steps[1].label", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scope.IsQuestionPromptSource(tt.src); got != tt.want {
				t.Fatalf("IsQuestionPromptSource(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}
