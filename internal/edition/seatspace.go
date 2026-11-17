package edition

// seatspace.go is the part of B8 (a) that needs the seats (ADR-0056 D3 (a), D10 B8 (a2),
// amendment 10): each answer slot of a per-seat question has a space S of at least 2 x N,
// N being the number of seats, so that the renderer can give every seat a value of its own
// at each position (U2) with a draw that is rejected less than half the time. B8 (a1), the
// edition.yaml's own 100 x attempts, is CheckQuestions. The check is DETERMINISTIC: it
// compares two numbers and reads no random draw, so a key never changes its outcome.
//
// It is one function with two callers: the renderer refuses with E3 before it draws, and
// the validator (A4e) refuses with B8 on the seat list it is given. It holds no answer and
// no key, so it is not a renderer file.

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

// CheckSeatSpace holds every answer slot of the edition of challenge cid to S >= 2 x seats.
// qs are the challenge's questions (the ones CheckQuestions was given). rule is the rule a
// violation carries: RuleSpecRender (E3) from the renderer, RuleVocabSpace (B8) from the
// validator. It returns nil, or an errors.Join of *Violation (at most maxViolations listed),
// one per answer slot that is short, naming the slot. An answer slot's decoys have its
// space, so they are not listed again. Fewer than 1 seat is an error of its own.
func (s *Spec) CheckSeatSpace(cid string, qs []catalog.Question, seats int, rule string) error {
	if s == nil {
		return errors.New("edition: the spec is missing")
	}
	if seats < 1 {
		return newViolation(rule, "there is no seat to give a value to", 0, cell{cid: cid}, nil)
	}
	need := big.NewInt(2 * int64(seats))
	var c collector
	for i := range s.Slots {
		sl := &s.Slots[i]
		if sl.Role != RoleAnswer {
			continue
		}
		q, ok := findQuestion(qs, sl.Question)
		if !ok || !answerformat.PerSeat(q.Format) {
			continue // CheckQuestions's (E2)
		}
		n, err := answerformat.Space(q.Format, q.Params)
		if errors.Is(err, answerformat.ErrSpaceFromVocabulary) {
			n, err = VocabSpace(q.Format, sl.Vocab)
		}
		if err == nil && n.Cmp(need) >= 0 {
			continue
		}
		v := newSpecViolation(rule, fmt.Sprintf("the answer space of the slot is below 2 x the number of seats (%d), so each seat cannot have a value of its own (B8 (a2))", seats), 0, cid, q.ID, sl.Name, fmt.Sprintf("slots[%d]", i), nil)
		c.add(v)
	}
	return c.err()
}
