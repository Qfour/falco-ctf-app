package edition

// practiceclues.go is D10 B18 (ADR-0056 amendment 27, revised by amendments 28 and 30, A7-x PR
// 4b; the event only): the clue words that lead to an event answer do not hold the clue words that
// lead to the image's practice answer of the same question.
//
// What a reader of the repository can take from the public practice edition, and use on an event
// bundle, is the combination of clues that leads to a practice answer (which container and which
// process, say): one grep with it, and the key, and the event answer is reached. So, for every
// question (its id, qid: the catalog fixes it, and E2 ties one answer slot to it, so it is the
// same in the event and in the practice edition; the slots' names may differ), the clue words of
// the event's answer lines (E_c) must not hold every clue word of the practice edition's answer
// lines (P_c): an E_c that holds P_c (a superset of it, or the same set) is refused. The words of a line are its combination of (b17-3)
// (clueCombination: the clues of the slot in the line and in its clue lines, the lines outside
// every block that share a filler mark with it, one step), read as B17 and B19 read them
// (readRows). Two sets are compared: the union of the combinations of the answer's lines, and each
// combination of an event answer line with each of a practice answer line (an answer written in
// more than one block has more than one line; a combination of one of them is a grep of its own).
//
// The practice edition is read from the image: its edition.yaml (ParseSpec; it holds no key) and
// its template (readPracticeFiles, through the CheckedTable). An input that does not let B18 name
// the practice's clue lines is a violation of B18, never a pass (fail-closed, as B4's completeness
// of its input): the practice edition, its edition.yaml or its template missing or unreadable, an
// edition.yaml that does not parse, a practice edition that does not hold to E2, and a question
// the practice edition has no answer slot for. A P_c that is empty (the practice edition declares
// no clue of the question, or none is on its answer's lines) is held by every E_c, so it is
// refused too: such a practice edition does not say what leads to its answer, and B18 cannot tell
// that the event does not copy it (a practice edition in the form B17 and E2 ask for has clues).
//
// It is not a render file: it holds no key and no answer and draws nothing. A violation names the
// rule, the challenge and the question, never a word of a template or a clue.

import (
	"errors"
	"maps"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// RulePracticeClues is D10 B18 (amendment 30): the clue words of an event answer do not hold the
// clue words of the practice answer of the same question.
const RulePracticeClues = "B18"

// answerClues is the clue combinations of an answer slot's lines (each line that holds its mark)
// and their union.
type answerClues struct {
	lines []map[string]bool
	union map[string]bool
}

// holdsAll reports whether every word of p is in e.
func holdsAll(e, p map[string]bool) bool {
	for w := range p {
		if !e[w] {
			return false
		}
	}
	return true
}

// holds reports whether the event's clue words e hold the practice's p: the union holds the union,
// or one line's combination holds one line's.
func (e *answerClues) holds(p *answerClues) bool {
	if holdsAll(e.union, p.union) {
		return true
	}
	for _, el := range e.lines {
		for _, pl := range p.lines {
			if holdsAll(el, pl) {
				return true
			}
		}
	}
	return false
}

// answerCluesOf is the answerClues of every answer slot of an edition read by readRows, by the
// question of the slot.
func (s *Spec) answerCluesOf(rows *editionRows) map[string]*answerClues {
	out := make(map[string]*answerClues)
	for i := range s.Slots {
		sl := &s.Slots[i]
		if sl.Role != RoleAnswer {
			continue
		}
		clues := clueSet(sl)
		ac := &answerClues{union: make(map[string]bool)}
		for _, ln := range rows.x.bySlot[sl.Name] {
			m := clueCombination(ln, clues, rows.gi, rows.x)
			ac.lines = append(ac.lines, m)
			maps.Copy(ac.union, m)
		}
		out[sl.Question] = ac
	}
	return out
}

// CheckPracticeClues applies B18 to the event edition of challenge cid (s: its edition.yaml; qs:
// its questions, the ones CheckQuestions is given; template: its template/) and the image's
// practice edition of the same challenge (practiceSpec: the bytes of its edition.yaml, nil when it
// is missing or could not be read; practiceTemplate: its template/). It returns nil, or an
// errors.Join of *Violation (at most maxViolations listed: an input B18 cannot read is one
// violation and nothing is compared; else the answer slots of the event in the order of its
// edition.yaml). It reads no file.
func (s *Spec) CheckPracticeClues(cid string, qs []catalog.Question, template []BundleFile, practiceSpec []byte, practiceTemplate []BundleFile) error {
	if s == nil {
		return errors.New("edition: the spec is missing")
	}
	refuse := func(msg, qid string) *Violation {
		return newSpecViolation(RulePracticeClues, msg, 0, cid, qid, "", "", nil)
	}
	event, why, _ := s.readRows(cid, qs, template)
	if event == nil {
		return refuse(why+", so B18 cannot name the clue lines of its answers", "")
	}
	if practiceSpec == nil {
		return refuse("the image's practice edition of the challenge has no edition.yaml that can be read, so B18 cannot name the clue lines of its answers (fail-closed)", "")
	}
	if len(practiceTemplate) == 0 {
		return refuse("the image's practice edition of the challenge has no template, so B18 cannot name the clue lines of its answers (fail-closed)", "")
	}
	ps, err := ParseSpec(practiceSpec)
	if err != nil {
		return refuse("the edition.yaml of the image's practice edition of the challenge does not parse (E1), so B18 cannot name the clue lines of its answers (fail-closed)", "")
	}
	practice, why, _ := ps.readRows(cid, qs, practiceTemplate)
	if practice == nil {
		return refuse("in the image's practice edition of the challenge, "+why+", so B18 cannot name the clue lines of its answers (fail-closed)", "")
	}
	ev, pr := s.answerCluesOf(event), ps.answerCluesOf(practice)
	var c collector
	for i := range s.Slots {
		sl := &s.Slots[i]
		if sl.Role != RoleAnswer {
			continue
		}
		p, ok := pr[sl.Question]
		switch {
		case !ok:
			c.add(refuse("the image's practice edition has no answer slot of the question, so B18 cannot compare its clue words (fail-closed)", sl.Question))
		case ev[sl.Question].holds(p):
			c.add(refuse("the clue words of the event's answer hold every clue word of the practice edition's answer of the same question (a grep with the practice's clues would reach the event's answer; a practice answer with no clue word is held by every event)", sl.Question))
		}
	}
	return c.err()
}
