// Package scope is the ONE place where the inputs of internal/hintleak for a
// scope are assembled from the loaded catalog, journeys and rule excerpts
// (ADR-0026 D5-1; ADR-0056 D10 B5, stage A4c-1). It exists apart from
// internal/hintleak so that hintleak stays a pure function over text it is given
// (it imports no catalog) while the definition of "what is a hint and what is
// shown for free" has exactly one implementation:
//
//   - Hints = every journey hint text of the scope's challenges;
//   - Free  = what a participant is shown without paying: the briefing, each step
//     label and detail, the questions[] prompts of an investigate challenge, and
//     the DISPLAYED parts of rule.yaml (never title / tagline / bridge: the strict
//     side of D5-1);
//   - Targets are the caller's own (ADR-0026: every fixture file; ADR-0056 B5: the
//     files of a seat's bundle) and are passed in.
//
// Import direction: scope imports hintleak and catalog; neither imports scope.
//
// Callers. Today the only callers are the tests of internal/hintleak
// (content_test.go: the V5 / V6 scopes of the real tree; questionprompt_test.go:
// the in-memory V24 scopes). ADR-0056 A4e adds the second: the `edition check`
// subcommand of cmd/scoreboard, which hands [Assemble] the catalog it loaded for
// the event and the bundle files as targets. The source test of this package
// (V56) pins the callers, so that a caller is added on purpose.
package scope

import (
	"fmt"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// ruleItems turns the DISPLAYED parts of a parsed rule.yaml (what the Story
// tab's Falco Rule panel shows) into free items. Comments and unknown keys in
// the file are not shown, so they are not free.
func ruleItems(id string, ex catalog.FalcoRuleExcerpt) []hintleak.Item {
	var out []hintleak.Item
	add := func(what, text string) {
		out = append(out, hintleak.Item{Source: id + " rule.yaml " + what, Text: text})
	}
	for _, r := range ex.Rules {
		add("rule "+r.Name+" name", r.Name)
		add("rule "+r.Name+" desc", r.Desc)
		add("rule "+r.Name+" condition", r.Condition)
		add("rule "+r.Name+" output", r.Output)
		add("rule "+r.Name+" priority", r.Priority)
		for _, tag := range r.Tags {
			add("rule "+r.Name+" tag", tag)
		}
	}
	for _, m := range ex.Macros {
		add("macro "+m.Name+" name", m.Name)
		add("macro "+m.Name+" condition", m.Condition)
	}
	for _, l := range ex.Lists {
		add("list "+l.Name+" name", l.Name)
		for _, it := range l.Items {
			add("list "+l.Name+" item", it)
		}
	}
	return out
}

// A question prompt item's Source is "<challenge id> questions[<question id>].prompt".
// questionPromptSource builds it and IsQuestionPromptSource recognizes it from
// the same two pieces, so the producer and the counter cannot drift apart.
const (
	questionPromptMid = " questions["
	questionPromptEnd = "].prompt"
)

func questionPromptSource(id, qid string) string {
	return id + questionPromptMid + qid + questionPromptEnd
}

// IsQuestionPromptSource reports whether src is the Source of a question prompt
// item built by [Assemble].
func IsQuestionPromptSource(src string) bool {
	i := strings.Index(src, questionPromptMid)
	return i > 0 && strings.HasSuffix(src, questionPromptEnd) && len(src) > i+len(questionPromptMid)+len(questionPromptEnd)
}

// CountPromptItems counts the question prompt items that are really in free.
func CountPromptItems(free []hintleak.Item) int {
	n := 0
	for _, it := range free {
		if IsQuestionPromptSource(it.Source) {
			n++
		}
	}
	return n
}

// questionPromptItems turns the questions[] prompts of an investigate challenge's
// journey into free items (ADR-0056 D1, A1e). A prompt is shown to every
// participant before any hint is bought, exactly like a step label, so a hint
// that repeats a prompt's words is not a leak of the hint. It is a Free item and
// never a Target: the rule scans fixtures for hint-only n-grams, and a prompt is
// not a file the rule guards. Source names the challenge and the question id.
func questionPromptItems(id string, j catalog.Journey) []hintleak.Item {
	var out []hintleak.Item
	for _, q := range j.Questions {
		out = append(out, hintleak.Item{Source: questionPromptSource(id, q.ID), Text: q.Prompt})
	}
	return out
}

// Assemble is the ONE place the D5-1 inputs of a scope are built from the
// loaded catalog, journeys and rule excerpts (production: the loader of the real
// tree; V24: an in-memory scope). wantPrompts is the number of questions the
// scope's investigate challenges declare. The number of prompt items in Free is
// NOT returned: [PromptCountProblem] counts in.Free itself.
func Assemble(ids []string, cat catalog.Catalog, journeys catalog.Journeys, excerpts catalog.FalcoRuleExcerpts, fixtures []hintleak.Item) (in hintleak.Input, wantPrompts int) {
	in = hintleak.Input{Targets: fixtures}
	for _, id := range ids {
		if ch := cat[id]; ch.Type == catalog.TypeInvestigate && ch.Investigate != nil {
			wantPrompts += len(ch.Investigate.Questions)
		}
		if j, ok := journeys[id]; ok {
			for i, h := range j.Hints {
				in.Hints = append(in.Hints, hintleak.Item{Source: fmt.Sprintf("%s hints[%d]", id, i+1), Text: h.Text})
			}
			// Free = what is shown without paying: briefing, step label/detail,
			// the questions[] prompts of an investigate challenge (and rule.yaml
			// below). title / tagline / bridge are deliberately NOT free (D5-1: the
			// strict side).
			in.Free = append(in.Free, hintleak.Item{Source: id + " briefing", Text: j.Briefing})
			for i, st := range j.Steps {
				in.Free = append(in.Free,
					hintleak.Item{Source: fmt.Sprintf("%s steps[%d].label", id, i+1), Text: st.Label},
					hintleak.Item{Source: fmt.Sprintf("%s steps[%d].detail", id, i+1), Text: st.Detail})
			}
			in.Free = append(in.Free, questionPromptItems(id, j)...)
		}
		in.Free = append(in.Free, ruleItems(id, excerpts[id])...)
	}
	return in, wantPrompts
}

// PromptCountProblem is ADR-0056 V24's count check: the prompt items in free
// equal wantPrompts, the number of questions the scope's investigate challenges
// declare (the second result of [Assemble]). "Challenges ask questions but no
// prompt reached Free" (0 of N) fails; a scope with no investigate challenge has
// 0 and 0, which passes. name only labels the message.
func PromptCountProblem(name string, free []hintleak.Item, wantPrompts int) error {
	if got := CountPromptItems(free); wantPrompts != got {
		return fmt.Errorf("scope %s: %d question prompt item(s) in Free, but its investigate challenges declare %d question(s)", name, got, wantPrompts)
	}
	return nil
}
