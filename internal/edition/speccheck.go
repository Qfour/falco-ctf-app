package edition

// speccheck.go is the part of edition.yaml that needs the challenge's questions
// (ADR-0056 D10 E2 and B8 (a), amendment 8, D19 A4d-1b): the slots against the questions,
// the decoys' number, the windows, the fixed answers, and the answer space sized from the
// vocabulary or the params. The schema and E1 are spec.go.

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

const (
	// RuleSpecQuestion is D10 E2: edition.yaml against the challenge's questions, and its
	// `blocks` and `clues` against the template (specblocks.go, amendment 28).
	RuleSpecQuestion = "E2"
	// RuleVocabSpace is D10 B8 (a): the answer space of an answer slot is at least D3
	// (a)'s 100 x attempts.
	RuleVocabSpace = "B8"
)

// VocabSpace is the answer space of a vocabulary of a path or name question (D3 (a)): the
// product, over the lists, of the number of DISTINCT words after the format's
// normalisation (a name has one list). A parsed vocabulary has normalised words and no
// repeat, so this is the product of the lists' lengths; counting after normalisation keeps
// it exact for one built by hand. A path word is one element and the joining `/` is not a
// choice, so distinct choices make distinct paths. It is a big.Int: sixteen lists of a
// thousand words do not fit 64 bits. A format with no vocabulary, no list, or a word the
// format refuses has no space (an error). A list of one word is a factor of 1.
func VocabSpace(format string, vocab [][]string) (*big.Int, error) {
	if !usesVocabulary(format) || len(vocab) == 0 {
		return nil, errors.New("there is no vocabulary to size")
	}
	n := big.NewInt(1)
	for _, words := range vocab {
		seen := make(map[string]struct{}, len(words))
		for _, w := range words {
			v, err := normalizeWord(format, w)
			if err != nil {
				return nil, err
			}
			seen[v] = struct{}{}
		}
		n.Mul(n, big.NewInt(int64(len(seen))))
	}
	return n, nil
}

// CheckQuestions holds the edition of challenge cid to the challenge's questions (qs:
// Scope[cid]). It returns nil, or an errors.Join of *Violation (at most maxViolations
// listed: the slots in file order, then `fixed`, then the questions in catalog
// order). It does not stop at the first one.
//
//   - E2: every answer slot names a question of the challenge that can vary per seat; every
//     such question has exactly one answer slot; `decoys` is at least DecoyK(attempts);
//     a timestamp answer's window is as wide as the question's params.windowSeconds; the
//     keys of `fixed` are exactly the questions that cannot vary per seat, each value
//     satisfying answerformat.Canonical. A decoy inherits format, params, vocabulary and
//     window from its answer slot, so their sameness holds by construction. The answer
//     slot's vocabulary and window suit its question's format: a path or name question has
//     a vocabulary (a name's is one list, of words in the name format) and no window, a
//     timestamp question has a window and no vocabulary, a hexid question has neither.
//     (E1 held the words to a path element only, for want of the format.) A filler has more
//     than one value (checkFillerSpace, amendment 28 (c)).
//   - B8 (a): the answer space of each answer slot, answerformat.Space from the question's
//     params, or VocabSpace for path and name, against answerformat.CheckSpaceN (100 x
//     attempts).
//
// Not here (A4d-2): the template, the renderer, B7's differences in the output, B8 (b).
func (s *Spec) CheckQuestions(cid string, qs []catalog.Question) error {
	if s == nil {
		return errors.New("edition: the spec is missing")
	}
	var c collector
	add := func(rule, msg, qid, slot, at string, err error) {
		c.add(newSpecViolation(rule, msg, 0, cid, qid, slot, at, err))
	}
	answered := make(map[string]struct{})
	for i := range s.Slots {
		sl := &s.Slots[i]
		at := fmt.Sprintf("slots[%d]", i)
		switch sl.Role {
		case RoleFiller:
			checkFillerSpace(sl, at, add)
			continue
		case RoleAnswer:
		default:
			add(RuleSpecShape, "the slot has no role (the spec did not come from ParseSpec)", "", sl.Name, at, nil)
			continue
		}
		q, ok := findQuestion(qs, sl.Question)
		switch {
		case !ok:
			add(RuleSpecQuestion, "the answer slot names a question the challenge does not have", sl.Question, sl.Name, at, nil)
			continue
		case !answerformat.PerSeat(q.Format):
			add(RuleSpecQuestion, "the answer slot names a question that cannot vary per seat (its answer is in fixed)", q.ID, sl.Name, at, nil)
			continue
		}
		if _, dup := answered[q.ID]; dup {
			add(RuleSpecQuestion, "the question has a second answer slot", q.ID, sl.Name, at, nil)
			continue
		}
		answered[q.ID] = struct{}{}
		if sl.Decoys == nil || *sl.Decoys < DecoyK(q.Attempts) {
			add(RuleSpecQuestion, "decoys is below K = max(2 x attempts, 4)", q.ID, sl.Name, at, nil)
		}
		if !checkAnswerShape(sl, q, at, add) {
			continue
		}
		n, err := answerformat.Space(q.Format, q.Params)
		if errors.Is(err, answerformat.ErrSpaceFromVocabulary) {
			n, err = VocabSpace(q.Format, sl.Vocab)
		}
		if err == nil {
			err = answerformat.CheckSpaceN(n, q.Attempts)
		}
		if err != nil {
			add(RuleVocabSpace, "the answer space of the slot cannot be sized or is below 100 x attempts (D3 (a))", q.ID, sl.Name, at, err)
		}
	}
	checkFixed(s, qs, add)
	for _, q := range qs {
		if _, ok := answered[q.ID]; !ok && answerformat.PerSeat(q.Format) {
			add(RuleSpecQuestion, "a question that can vary per seat has no answer slot", q.ID, "", "", nil)
		}
	}
	return c.err()
}

// checkFillerSpace refuses a filler that has one value (E2, ADR-0056 amendment 28 (c)): a
// vocabulary of one word at every position, or a timestamp window of one second. Its value is
// the same for every seat, so it is a literal written as a slot, and B17 would take it for a
// word in which the lines of a group may differ. A fact that tells the answer apart is written
// as text and declared in the answer slot's `clues`. A hexid filler has 16^length values.
func checkFillerSpace(sl *Slot, at string, add func(rule, msg, qid, slot, at string, err error)) {
	switch {
	case usesVocabulary(sl.Format):
		if n, err := VocabSpace(sl.Format, sl.Vocab); err == nil && n.Cmp(big.NewInt(1)) == 0 {
			add(RuleSpecQuestion, "a filler of one word is a literal: write it as text (and declare it in the answer slot's clues if it tells the answer apart)", "", sl.Name, at+".vocab", nil)
		}
	case sl.Format == answerformat.Timestamp:
		if w := sl.Window; w != nil && w.From != nil && w.To != nil && *w.To-*w.From == 1 {
			add(RuleSpecQuestion, "a timestamp filler of a one-second window is a literal: write the time as text", "", sl.Name, at+".window", nil)
		}
	}
}

// fillerSpace is the number of values filler d draws from: its vocabulary's (VocabSpace) for a
// name or a path, 16^length for a hexid, the seconds of its window for a timestamp (the params the
// renderer draws it with, answerformat.Space). A filler that cannot be sized (not declared, no
// window, a format the renderer does not draw) is an error. E2 (e5) reads it for the keys of a
// block.
func fillerSpace(d *Slot) (*big.Int, error) {
	if d == nil {
		return nil, errors.New("the filler is not declared")
	}
	var p answerformat.Params
	switch d.Format {
	case answerformat.HexID:
		p.Length = d.Length
	case answerformat.Timestamp:
		if d.Window == nil || d.Window.From == nil || d.Window.To == nil {
			return nil, errors.New("a timestamp filler has no window")
		}
		width := *d.Window.To - *d.Window.From
		p.WindowSeconds = &width
	}
	n, err := answerformat.Space(d.Format, p)
	if errors.Is(err, answerformat.ErrSpaceFromVocabulary) {
		n, err = VocabSpace(d.Format, d.Vocab)
	}
	return n, err
}

// checkAnswerShape holds an answer slot's vocab and window to its question's format, which
// the slot does not write (E2, ADR-0056 D10). It reports whether the slot can be sized.
func checkAnswerShape(sl *Slot, q catalog.Question, at string, add func(rule, msg, qid, slot, at string, err error)) bool {
	ok := true
	mismatch := func(where, msg string, err error) {
		add(RuleSpecQuestion, msg, q.ID, sl.Name, at+where, err)
		ok = false
	}
	hasVocab := len(sl.Vocab) != 0
	switch {
	case usesVocabulary(q.Format):
		if !hasVocab {
			mismatch(".vocab", "a path or name question needs a vocabulary", nil)
		}
		if sl.Window != nil {
			mismatch(".window", "window is a timestamp question's", nil)
		}
		if q.Format == answerformat.Name && hasVocab {
			if len(sl.Vocab) != 1 {
				mismatch(".vocab", "a name vocabulary is exactly one list of words", nil)
			} else if wi, err := checkWords(answerformat.Name, sl.Vocab[0]); err != nil {
				where := ".vocab[0]"
				if wi >= 0 {
					where += fmt.Sprintf("[%d]", wi)
				}
				mismatch(where, "a vocabulary list or word is refused", err)
			}
		}
	case q.Format == answerformat.Timestamp:
		if hasVocab {
			mismatch(".vocab", "this format takes no vocabulary", nil)
		}
		switch w := sl.Window; {
		case w == nil || w.From == nil || w.To == nil:
			mismatch(".window", "a timestamp question needs a window", nil)
		case q.Params.WindowSeconds == nil || *w.To-*w.From != *q.Params.WindowSeconds:
			add(RuleSpecQuestion, "the window is not as wide as the question's params.windowSeconds", q.ID, sl.Name, at+".window", nil)
			ok = false
		}
	default:
		if hasVocab {
			mismatch(".vocab", "this format takes no vocabulary", nil)
		}
		if sl.Window != nil {
			mismatch(".window", "window is a timestamp question's", nil)
		}
	}
	return ok
}

// checkFixed: the keys of `fixed` are exactly the questions that cannot vary per seat, and
// each value is canonical for its question.
func checkFixed(s *Spec, qs []catalog.Question, add func(rule, msg, qid, slot, at string, err error)) {
	fixedQ := make(map[string]catalog.Question)
	for _, q := range qs {
		if !answerformat.PerSeat(q.Format) {
			fixedQ[q.ID] = q
		}
	}
	keys := make([]string, 0, len(s.Fixed))
	for k := range s.Fixed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		q, ok := fixedQ[k]
		if !ok {
			add(RuleSpecQuestion, "a key of fixed is not a question that cannot vary per seat", k, "", "fixed", nil)
			continue
		}
		if err := answerformat.Canonical(q.Format, q.Params, s.Fixed[k]); err != nil {
			add(RuleSpecQuestion, "a fixed value does not fit its question's format in normalised form", k, "", "fixed", err)
		}
	}
	missing := make([]string, 0, len(fixedQ))
	for id := range fixedQ {
		if _, ok := s.Fixed[id]; !ok {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	for _, id := range missing {
		add(RuleSpecQuestion, "a question that cannot vary per seat has no value in fixed", id, "", "fixed", nil)
	}
}
