package hintleak_test

// questionprompt_test.go is ADR-0056 V24 (stage A1e): the questions[] prompts of
// an investigate challenge are Free items of the hintleak scope. The scopes here
// are synthetic and in memory (meaningless words, no real challenge): the real
// tree has no investigate challenge yet, so its own scopes carry 0 prompts and
// must stay green (TestFixtures_CarryNoHintOnlyNgrams runs the same count check).
// The scope is built by assembleScope, the function loadScope uses, so a change
// that stops adding prompts to Free turns these tests red.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// v24Hint exists only in the hint and in the fixture below; its 10-rune
// n-grams are "hint-only" unless a Free item repeats them.
const v24Hint = "golf hotel india juliet kilo lima"

// v24Scope builds one scope with a single investigate challenge that declares
// `declared` questions and whose journey carries the given prompts (q1, q2, ...).
func v24Scope(declared int, prompts []string) scopeData {
	const id = "90-synthetic"
	qs := make([]catalog.Question, declared)
	for i := range qs {
		qs[i] = catalog.Question{ID: fmt.Sprintf("q%d", i+1)}
	}
	j := catalog.Journey{
		ChallengeID: id,
		Title:       "synthetic",
		Briefing:    "delta echo foxtrot",
		Hints:       catalog.JourneyHints{{Kind: "solution", Text: v24Hint}},
	}
	for i, p := range prompts {
		j.Questions = append(j.Questions, catalog.JourneyQuestion{ID: fmt.Sprintf("q%d", i+1), Prompt: p})
	}
	cat := catalog.Catalog{id: {ID: id, Type: catalog.TypeInvestigate, Investigate: &catalog.Investigate{Questions: qs}}}
	fixtures := []hintleak.Item{{Source: id + "/fixtures/notes.txt", Text: "see " + v24Hint + " later"}}
	in, want, got := assembleScope([]string{id}, cat, catalog.Journeys{id: j}, nil, fixtures)
	return scopeData{name: "v24", ids: []string{id}, in: in, wantPrompts: want, gotPrompts: got}
}

func mustCheck(t *testing.T, s scopeData) []hintleak.Violation {
	t.Helper()
	vs, err := hintleak.Check(s.in)
	if err != nil {
		t.Fatalf("hintleak.Check: %v", err)
	}
	return vs
}

func TestQuestionPrompts_AreFreeItems(t *testing.T) {
	carrying := []string{"alpha bravo charlie", "Which is it: " + v24Hint + "?"}
	unrelated := []string{"alpha bravo charlie", "mike november oscar papa"}

	t.Run("a prompt that carries the hint's words makes the fixture pass", func(t *testing.T) {
		s := v24Scope(2, carrying)
		if err := promptCountProblem(s); err != nil {
			t.Fatal(err)
		}
		if vs := mustCheck(t, s); len(vs) != 0 {
			t.Fatalf("want 0 violations (the prompt is shown without paying, so the n-grams are free), got:\n%s", describe(vs))
		}
	})

	t.Run("without the words in a prompt the same fixture is a violation", func(t *testing.T) {
		s := v24Scope(2, unrelated)
		if err := promptCountProblem(s); err != nil {
			t.Fatal(err)
		}
		vs := mustCheck(t, s)
		if len(vs) == 0 {
			t.Fatal("want violations for a hint-only n-gram in the fixture, got none")
		}
		for _, v := range vs {
			if v.Target != "90-synthetic/fixtures/notes.txt" {
				t.Fatalf("violation target = %q, want the fixture", v.Target)
			}
		}
	})

	t.Run("an assembler that does not put the prompts into Free is caught", func(t *testing.T) {
		s := v24Scope(2, carrying)
		var kept []hintleak.Item
		for _, it := range s.in.Free {
			if !strings.Contains(it.Source, ".prompt") {
				kept = append(kept, it)
			}
		}
		if len(kept) == len(s.in.Free) {
			t.Fatal("the scope has no prompt item to remove")
		}
		s.in.Free = kept
		if vs := mustCheck(t, s); len(vs) == 0 {
			t.Fatal("want violations once the prompts are not Free, got none")
		}
	})

	t.Run("prompt items name the file and the question id, and are never targets", func(t *testing.T) {
		s := v24Scope(2, carrying)
		var got []string
		for _, it := range s.in.Free {
			if strings.Contains(it.Source, ".prompt") {
				got = append(got, it.Source)
			}
		}
		want := []string{"90-synthetic questions[q1].prompt", "90-synthetic questions[q2].prompt"}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("prompt item sources = %q, want %q", got, want)
		}
		for _, it := range s.in.Targets {
			if strings.Contains(it.Source, ".prompt") {
				t.Fatalf("prompt item %q is in Targets: a prompt is Free, never a Target", it.Source)
			}
		}
	})
}

func TestQuestionPrompts_CountMustMatchTheQuestions(t *testing.T) {
	two := []string{"alpha bravo charlie", "mike november oscar papa"}
	tests := []struct {
		name     string
		declared int
		prompts  []string
		wantFail bool
	}{
		{"2 questions, 2 prompt items passes", 2, two, false},
		{"2 questions, 0 prompt items fails", 2, nil, true},
		{"2 questions, 1 prompt item fails", 2, two[:1], true},
		{"1 question, 2 prompt items fails", 1, two, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := promptCountProblem(v24Scope(tt.declared, tt.prompts))
			if (err != nil) != tt.wantFail {
				t.Fatalf("promptCountProblem error = %v, wantFail = %v", err, tt.wantFail)
			}
		})
	}

	t.Run("a scope with no investigate challenge has 0 and 0 and passes", func(t *testing.T) {
		const id = "01-synthetic"
		cat := catalog.Catalog{id: {ID: id, Type: catalog.TypeTrigger}}
		in, want, got := assembleScope([]string{id}, cat, catalog.Journeys{id: {ChallengeID: id, Title: "synthetic"}}, nil, nil)
		if want != 0 || got != 0 {
			t.Fatalf("want 0 and 0, got want=%d got=%d (in.Free=%d)", want, got, len(in.Free))
		}
		if err := promptCountProblem(scopeData{name: "none", wantPrompts: want, gotPrompts: got}); err != nil {
			t.Fatal(err)
		}
	})
}
