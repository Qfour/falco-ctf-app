package edition

// seatspace.go is the part of B8 (a) that needs the seats (ADR-0056 D3 (a), D10 B8 (a2),
// amendment 10): each answer slot of a per-seat question has a space S of at least 2 x N,
// N being the number of seats, so that the renderer can give every seat a value of its own
// at each position (U2) with a draw that is rejected less than half the time. B8 (a1), the
// edition.yaml's own 100 x attempts, is CheckQuestions. A group in a block (amendment 28, as
// revised) needs 2 x N x (k + 1), k its decoys (CheckSeatSpace). The check is DETERMINISTIC: it
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

// CheckSeatSpace holds every answer slot of the edition of challenge cid to S >= 2 x seats,
// and an answer slot whose group is in a block (ADR-0056 amendment 28, as revised) to
// S >= 2 x seats x (k + 1): the renderer keeps every value of the group (the answer and each
// decoy) apart from every value of the group in every other seat (r1), so N seats take N x
// (k + 1) values of the one space. k is the larger of K (DecoyK of the question's attempts) and
// the decoys the slot declares, which E2 holds to be at least K: the group has that many
// decoys. S is the same space as the plain rule's (answerformat.Space from the question's
// params, or VocabSpace). template is the files of template/: which groups are in a block is
// read from it (blockGroups, the one reading E2 uses too); when a block's group cannot be read
// (E2 refuses such a block), every answer slot is held to the block's bound (fail-closed).
//
// qs are the challenge's questions (the ones CheckQuestions was given). rule is the rule a
// violation carries: RuleSpecRender (E3) from the renderer, RuleVocabSpace (B8) from the
// validator. It returns nil, or an errors.Join of *Violation (at most maxViolations listed),
// one per answer slot that is short, naming the slot. An answer slot's decoys have its
// space, so they are not listed again. Fewer than 1 seat is an error of its own.
func (s *Spec) CheckSeatSpace(cid string, qs []catalog.Question, template []BundleFile, seats int, rule string) error {
	if s == nil {
		return errors.New("edition: the spec is missing")
	}
	if seats < 1 {
		return newViolation(rule, "there is no seat to give a value to", 0, cell{cid: cid}, nil)
	}
	blocked, unread := s.blockGroups(template)
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
		need := big.NewInt(2 * int64(seats))
		msg := fmt.Sprintf("the answer space of the slot is below 2 x the number of seats (%d), so each seat cannot have a value of its own (B8 (a2))", seats)
		if blocked[sl.Name] || unread {
			need.Mul(need, big.NewInt(int64(groupDecoys(q.Attempts, sl))+1))
			msg = fmt.Sprintf("the answer space of the slot, whose group is in a block, is below 2 x the number of seats (%d) x (the decoys + 1), so the values of the group cannot all differ between the seats (B8 (a2), amendment 28)", seats)
		}
		n, err := answerformat.Space(q.Format, q.Params)
		if errors.Is(err, answerformat.ErrSpaceFromVocabulary) {
			n, err = VocabSpace(q.Format, sl.Vocab)
		}
		if err == nil && n.Cmp(need) >= 0 {
			continue
		}
		c.add(newSpecViolation(rule, msg, 0, cid, q.ID, sl.Name, fmt.Sprintf("slots[%d]", i), nil))
	}
	return c.err()
}

// groupDecoys is k of an answer slot's group: the larger of K (DecoyK of the question's attempts)
// and the decoys the slot declares (E2 holds the second to at least the first). B8 (a2)'s bound of
// a group in a block and B19's threshold (k + 1, rowsymmetry.go) read it from here, the one
// place it is taken.
func groupDecoys(attempts int, sl *Slot) int {
	k := DecoyK(attempts)
	if sl.Decoys != nil && *sl.Decoys > k {
		k = *sl.Decoys
	}
	return k
}
