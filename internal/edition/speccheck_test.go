package edition_test

// ADR-0056 D12 and amendment 8 / D19 A4d-1b: edition.yaml against the challenge's
// questions (D10 E2, including the answer slot's vocab and window against the format), the answer
// space sized from the vocabulary or the params (D3 (a), B8 (a)), V62, and V6 / V21 for
// the edition. The text helpers (specDoc, specWords, ...) are in spec_test.go (A4d-1a).
// One case, one defect, and the rule that must name it.

import (
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

func specI64(n int64) *int64 { return &n }

// specQuestions are the questions the example of amendment 8 is written for: a per-seat
// name, path, hexid and timestamp (an hour), each with 2 attempts (K = 4, space >= 200).
var specQuestions = []catalog.Question{
	{ID: "q1", Format: answerformat.Name, Attempts: 2},
	{ID: "q2", Format: answerformat.Path, Attempts: 2},
	{ID: "q3", Format: answerformat.HexID, Params: answerformat.Params{Length: ip(12)}, Attempts: 2},
	{ID: "q4", Format: answerformat.Timestamp, Params: answerformat.Params{WindowSeconds: specI64(3600)}, Attempts: 2},
}

// specQuestionsWithFixed adds q5, a choice-set that is the same for every seat (2^10 - 1
// >= 200): its answer is in `fixed`.
func specQuestionsWithFixed() []catalog.Question {
	q5 := catalog.Question{
		ID: "q5", Format: answerformat.ChoiceSet, Attempts: 2,
		Params: answerformat.Params{Choices: []string{"c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9"}},
	}
	return append(slices.Clone(specQuestions), q5)
}

// specQuestionsAttempts is specQuestions with q1's attempts changed.
func specQuestionsAttempts(n int) []catalog.Question {
	qs := slices.Clone(specQuestions)
	qs[0].Attempts = n
	return qs
}

const specFixedQ5 = `{q5: "c1,c3"}`

func specCheck(t *testing.T, d specDoc, qs []catalog.Question) error {
	t.Helper()
	spec, err := edition.ParseSpec(d.yaml())
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	return spec.CheckQuestions(demoCID, qs)
}

func TestCheckQuestions_AcceptsTheExample(t *testing.T) {
	if err := specCheck(t, specGoodDoc(), specQuestions); err != nil {
		t.Errorf("the example of amendment 8: %v", err)
	}
	if err := specCheck(t, specGoodDoc().withFixed(specFixedQ5), specQuestionsWithFixed()); err != nil {
		t.Errorf("the example with a fixed question: %v", err)
	}
	// A window of the right width anywhere in the hour's frame.
	d := specGoodDoc().with(slotWhen, func(s *specSlot) { s.window = "{from: 100, to: 3700}" })
	if err := specCheck(t, d, specQuestions); err != nil {
		t.Errorf("a window of 3600 seconds from 100: %v", err)
	}
}

// V62 (E2), V6's edition side (B8 (a)) and V18's E2 part.
func TestCheckQuestions_Refusals(t *testing.T) {
	g := specGoodDoc()
	g5 := g.withFixed(specFixedQ5)
	q5 := specQuestionsWithFixed()
	q1x5 := specQuestionsAttempts(5)
	wordsDoc := func(prefix string, n int) func(*specSlot) {
		return func(s *specSlot) { s.vocab = specVocab(specWords(prefix, n)) }
	}
	extra := func(d specDoc, s specSlot) specDoc {
		d.slots = append(slices.Clone(d.slots), s)
		return d
	}
	hourOf := func(from, to string) func(*specSlot) {
		return func(s *specSlot) { s.window = "{from: " + from + ", to: " + to + "}" }
	}
	q4 := func(seconds int64) []catalog.Question {
		qs := slices.Clone(specQuestions)
		qs[3].Params.WindowSeconds = specI64(seconds)
		return qs
	}

	cases := []struct {
		name string
		doc  specDoc
		qs   []catalog.Question
		want []string // nil: accepted
	}{
		// V62: the answer slots and the questions.
		{"a per-seat question with no answer slot", g.without(slotTag), specQuestions, []string{"E2"}},
		{"two answer slots for one question", extra(g, specSlot{name: "who-two", role: "answer", question: "q1", decoys: "4", vocab: specVocab(specWords("v", 200))}), specQuestions, []string{"E2"}},
		{"an answer slot for a question the challenge does not have", g.with(slotWho, func(s *specSlot) { s.question = "q9" }), specQuestions, []string{"E2"}},
		{"an answer slot for a question that cannot vary per seat", extra(g5, specSlot{name: "pick", role: "answer", question: "q5", decoys: "4"}), q5, []string{"E2"}},

		// V62 / V18: the decoys' number is K = max(2 x attempts, 4).
		{"decoys is K - 1 (3 for 2 attempts)", g.with(slotWho, func(s *specSlot) { s.decoys = "3" }), specQuestions, []string{"E2"}},
		{"decoys is K - 1 (9 for 5 attempts)", g.with(slotWho, func(s *specSlot) { s.decoys = "9"; wordsDoc("w", 500)(s) }), q1x5, []string{"E2"}},
		{"decoys is K (10 for 5 attempts)", g.with(slotWho, func(s *specSlot) { s.decoys = "10"; wordsDoc("w", 500)(s) }), q1x5, nil},
		{"decoys is more than K", g.with(slotWho, func(s *specSlot) { s.decoys = "20" }), specQuestions, nil},

		// V62: the window is as wide as params.windowSeconds.
		{"a window one second too narrow", g.with(slotWhen, hourOf("0", "3599")), specQuestions, []string{"E2"}},
		{"a window one second too wide", g.with(slotWhen, hourOf("0", "3601")), specQuestions, []string{"E2"}},

		// V62: fixed is exactly the questions that cannot vary per seat, with canonical values.
		{"fixed lacks a question that cannot vary per seat", g.withFixed("{}"), q5, []string{"E2"}},
		{"fixed has a key that is not such a question", g.withFixed(specFixedQ5), specQuestions, []string{"E2"}},
		{"fixed has a per-seat question's key", g5.withFixed(`{q5: "c1,c3", q1: x}`), q5, []string{"E2"}},
		{"a fixed value that is not in normalised form", g.withFixed(`{q5: "c3,c1"}`), q5, []string{"E2"}},
		{"a fixed value that is not an option", g.withFixed(`{q5: "zz"}`), q5, []string{"E2"}},

		// V62: the answer slot's vocab and window suit its question's format.
		{"a name question whose vocabulary has two lists", g.with(slotWho, func(s *specSlot) { s.vocab = specVocab(specWords("a", 100), specWords("b", 100)) }), specQuestions, []string{"E2"}},
		{"a name question with a word over 64 bytes", g.with(slotWho, func(s *specSlot) { s.vocab = specVocab("[" + strings.Repeat("a", 65) + "]") }), specQuestions, []string{"E2"}},
		{"a name question with no vocabulary", g.with(slotWho, func(s *specSlot) { s.vocab = "" }), specQuestions, []string{"E2"}},
		{"a path question with no vocabulary", g.with(slotWhere, func(s *specSlot) { s.vocab = "" }), specQuestions, []string{"E2"}},
		{"a name question with a window", g.with(slotWho, func(s *specSlot) { s.window = "{from: 0, to: 60}" }), specQuestions, []string{"E2"}},
		{"a hexid question with a vocabulary", g.with(slotTag, func(s *specSlot) { s.vocab = specVocab(specWords("h", 3)) }), specQuestions, []string{"E2"}},
		{"a hexid question with a window", g.with(slotTag, func(s *specSlot) { s.window = "{from: 0, to: 60}" }), specQuestions, []string{"E2"}},
		{"a timestamp question with no window", g.with(slotWhen, func(s *specSlot) { s.window = "" }), specQuestions, []string{"E2"}},
		{"a timestamp question with a vocabulary", g.with(slotWhen, func(s *specSlot) { s.vocab = specVocab(specWords("h", 3)) }), specQuestions, []string{"E2"}},

		// amendment 28 (c): a filler of one value is a literal.
		{"a name filler of one word", g.with(slotOther, func(s *specSlot) { s.vocab = specVocab(specWords("n", 1)) }), specQuestions, []string{"E2"}},
		{"a name filler of two words", g.with(slotOther, func(s *specSlot) { s.vocab = specVocab(specWords("n", 2)) }), specQuestions, nil},
		{"a path filler of one word at every position", g.with(slotOther, func(s *specSlot) { s.format = "path"; s.vocab = specVocab("[srv]", "[x]") }), specQuestions, []string{"E2"}},
		{"a path filler with a position of two words", g.with(slotOther, func(s *specSlot) { s.format = "path"; s.vocab = specVocab("[srv]", "[x, y]") }), specQuestions, nil},
		{"a timestamp filler of a one-second window", g.with(slotOther, func(s *specSlot) { s.format, s.vocab, s.window = "timestamp", "", "{from: 10, to: 11}" }), specQuestions, []string{"E2"}},
		{"a timestamp filler of a two-second window", g.with(slotOther, func(s *specSlot) { s.format, s.vocab, s.window = "timestamp", "", "{from: 10, to: 12}" }), specQuestions, nil},

		// B8 (a), to the unit (V6's edition side).
		{"a name vocabulary of 199 words (2 attempts)", g.with(slotWho, wordsDoc("w", 199)), specQuestions, []string{"B8"}},
		{"a name vocabulary of 200 words (2 attempts)", g.with(slotWho, wordsDoc("w", 200)), specQuestions, nil},
		{"a name vocabulary that attempts raise the floor of (200 words, 5 attempts)", g.with(slotWho, func(s *specSlot) { s.decoys = "10" }), q1x5, []string{"B8"}},
		{"a path vocabulary of one list of 199 words", g.with(slotWhere, wordsDoc("a", 199)), specQuestions, []string{"B8"}},
		{"a path vocabulary of one list of 200 words", g.with(slotWhere, wordsDoc("a", 200)), specQuestions, nil},
		{"a path product of 10 x 19 = 190", g.with(slotWhere, func(s *specSlot) { s.vocab = specVocab(specWords("a", 10), specWords("b", 19)) }), specQuestions, []string{"B8"}},
		{"a path product of 10 x 20 = 200", g.with(slotWhere, func(s *specSlot) { s.vocab = specVocab(specWords("a", 10), specWords("b", 20)) }), specQuestions, nil},
		{"one-word positions do not make 199 words enough", g.with(slotWhere, func(s *specSlot) { s.vocab = specVocab("[opt]", "[x]", specWords("a", 199)) }), specQuestions, []string{"B8"}},
		{"a timestamp window of 199 seconds (the question's params agree)", g.with(slotWhen, hourOf("0", "199")), q4(199), []string{"B8"}},
		{"a timestamp window of 200 seconds", g.with(slotWhen, hourOf("0", "200")), q4(200), nil},
		{"199 words of the sentinel", g.with(slotWho, wordsDoc(sentinel, 199)), specQuestions, []string{"B8"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := specCheck(t, c.doc, c.qs)
			if c.want == nil {
				if err != nil {
					t.Fatalf("CheckQuestions: %v", err)
				}
				return
			}
			specWantRules(t, err, c.want...)
			noSecret(t, c.name, err)
		})
	}
}

// A violation names the rule, the challenge, the question, the slot and the slot's place
// in the file.
func TestCheckQuestions_AViolationNamesItsPlace(t *testing.T) {
	d := specGoodDoc().with(slotWho, func(s *specSlot) { s.vocab = specVocab(specWords("w", 199)) })
	err := specCheck(t, d, specQuestions)
	var v *edition.Violation
	if !errors.As(err, &v) {
		t.Fatalf("not a *Violation: %v", err)
	}
	if v.Rule != edition.RuleVocabSpace || v.CID != demoCID || v.QID != "q1" || v.Slot != "who" || v.At != "slots[0]" {
		t.Errorf("violation = %+v, want B8 in %s, question q1, slot who at slots[0]", v, demoCID)
	}
	for _, part := range []string{"B8", "cid=" + demoCID, "qid=q1", "slot=who", "at=slots[0]"} {
		if !strings.Contains(v.Error(), part) {
			t.Errorf("%q is not in %q", part, v.Error())
		}
	}
	if edition.RuleVocabSpace != "B8" || edition.RuleSpecShape != "E1" || edition.RuleSpecQuestion != "E2" {
		t.Errorf("rule names changed: %s %s %s", edition.RuleSpecShape, edition.RuleSpecQuestion, edition.RuleVocabSpace)
	}
}

func TestVocabSpace(t *testing.T) {
	words := func(prefix string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = prefix + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		}
		return out
	}
	eq := func(t *testing.T, format string, vocab [][]string, want *big.Int) {
		t.Helper()
		n, err := edition.VocabSpace(format, vocab)
		if err != nil || n.Cmp(want) != 0 {
			t.Errorf("VocabSpace = %v, %v; want %v", n, err, want)
		}
	}
	t.Run("a name is its number of words", func(t *testing.T) {
		eq(t, answerformat.Name, [][]string{words("a", 3)}, big.NewInt(3))
	})
	t.Run("a path is the product of its lists", func(t *testing.T) {
		eq(t, answerformat.Path, [][]string{words("a", 2), words("b", 3), words("c", 4)}, big.NewInt(24))
	})
	t.Run("a one-word position is a factor of 1", func(t *testing.T) {
		eq(t, answerformat.Path, [][]string{{"opt"}, {"x"}, words("a", 5)}, big.NewInt(5))
	})
	t.Run("sixteen lists of a thousand words do not overflow", func(t *testing.T) {
		lists := make([][]string, edition.MaxVocabPositions)
		for i := range lists {
			lists[i] = words("w", 1000)
		}
		eq(t, answerformat.Path, lists, new(big.Int).Exp(big.NewInt(1000), big.NewInt(16), nil))
	})
	t.Run("words are counted after normalisation", func(t *testing.T) {
		eq(t, answerformat.Name, [][]string{{"a", " a", "a "}}, big.NewInt(1))
	})
	t.Run("what has no space is an error, not a space of 1", func(t *testing.T) {
		for _, c := range []struct {
			name   string
			format string
			vocab  [][]string
		}{
			{"a hexid", answerformat.HexID, [][]string{{"a"}}},
			{"no list", answerformat.Name, nil},
			{"a word outside the format", answerformat.Name, [][]string{{"a b"}}},
			{"a path word with a slash", answerformat.Path, [][]string{{"a/b"}}},
		} {
			if n, err := edition.VocabSpace(c.format, c.vocab); err == nil {
				t.Errorf("%s: VocabSpace = %v, want an error", c.name, n)
			}
		}
	})
}

func TestCheckQuestions_ASpecNotFromParseSpecIsRefused(t *testing.T) {
	var none *edition.Spec
	if err := none.CheckQuestions(demoCID, specQuestions); err == nil {
		t.Error("a nil Spec was accepted")
	}
	// A slot with no role is refused, not skipped: a Spec made by hand must not pass for
	// one that ParseSpec checked.
	hand := &edition.Spec{Slots: []edition.Slot{{Name: "who"}}}
	specWantRules(t, hand.CheckQuestions(demoCID, specQuestions[:1]), edition.RuleSpecShape, edition.RuleSpecQuestion)
}
