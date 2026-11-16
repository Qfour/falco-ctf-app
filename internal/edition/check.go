package edition

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
)

// The rule a Violation belongs to (ADR-0056 D10). T1 and T2 are ModeCheck's
// sentinel errors, not Violations.
const (
	RuleShape    = "T3"
	RuleComplete = "T4"
	RuleFormat   = "T5"
	RulePractice = "T6"
	RuleFlag     = "T7"
	RulePerSeat  = "T8"
)

// maxViolations bounds how many violations Check lists; the rest are counted.
const maxViolations = 20

var (
	// ErrTableMissing is D8 (i): the event mode, an investigate challenge in the
	// scope, and no answers table. It is also what Check returns for a nil table.
	ErrTableMissing = errors.New("edition: the answers table is missing (the event mode with an investigate challenge in scope needs one)")
	// ErrTableOutsideEventMode is D8 (ii): an answers table without the event mode
	// (the two signals disagree).
	ErrTableOutsideEventMode = errors.New("edition: an answers table was given outside the event mode")
)

// ModeCheck is D8 (i) and (ii), D10 T1 / T2, as a pure function of three facts.
// The caller (A2b) derives them: eventMode = FLAGS_FILE is not empty,
// scopeHasInvestigate = Scope.HasInvestigate, tablePresent = ANSWERS_FILE is set.
//
// Not an error: no event mode, an investigate challenge and no table (the practice
// answers of the image are used, outside this package); and the event mode with a
// table but nothing to judge (Check refuses every row of that table as unknown).
func ModeCheck(eventMode, scopeHasInvestigate, tablePresent bool) error {
	switch {
	case eventMode && scopeHasInvestigate && !tablePresent:
		return ErrTableMissing
	case !eventMode && tablePresent:
		return ErrTableOutsideEventMode
	}
	return nil
}

// Violation is one rejected thing. It carries a rule, a fixed sentence, a line,
// and the seat / cid / qid of the row: never a table value. A seat, cid or qid is
// kept only if it is inside its own grammar, so a table whose columns are swapped
// does not put a value in the message through the identifier columns. (A value that
// is also grammatically a seat, in the seat column of a swapped row, can still be
// named; that is the ADR's accepted identifier set.)
type Violation struct {
	Rule string
	Msg  string
	Line int
	Seat string
	CID  string
	QID  string
	err  error
}

func newViolation(rule, msg string, line int, c cell, err error) *Violation {
	v := &Violation{Rule: rule, Msg: msg, Line: line, err: err}
	if c.seat == AnySeat || identity.ValidSeat(c.seat) {
		v.Seat = c.seat
	}
	if challengeid.Valid(c.cid) {
		v.CID = c.cid
	}
	if answerformat.ValidID(c.qid) {
		v.QID = c.qid
	}
	return v
}

func (v *Violation) Error() string {
	var b strings.Builder
	b.WriteString(v.Rule + ": " + v.Msg)
	if v.Line > 0 {
		fmt.Fprintf(&b, " (line %d)", v.Line)
	}
	if v.Seat != "" {
		b.WriteString(" seat=" + v.Seat)
	}
	if v.CID != "" {
		b.WriteString(" cid=" + v.CID)
	}
	if v.QID != "" {
		b.WriteString(" qid=" + v.QID)
	}
	// answerformat's errors describe the rule that failed and never the text.
	if v.err != nil {
		b.WriteString(": " + v.err.Error())
	}
	return b.String()
}

// Unwrap lets a caller test for answerformat.ErrFormat / ErrNotCanonical.
func (v *Violation) Unwrap() error { return v.err }

// Scope is the investigate challenges of the event and their questions
// (cid -> the questions, in catalog order). It is the only thing Check needs from
// the catalog.
type Scope map[string][]catalog.Question

// ScopeOf is the investigate challenges of c. Pass the catalog the scoreboard
// scores (catalog.Scored.Catalog), so the scope is the event's.
func ScopeOf(c catalog.Catalog) Scope {
	out := make(Scope)
	for id, ch := range c {
		if ch.Type != catalog.TypeInvestigate {
			continue
		}
		var qs []catalog.Question
		if ch.Investigate != nil {
			qs = ch.Investigate.Questions
		}
		out[id] = qs
	}
	return out
}

// HasInvestigate is ModeCheck's scopeHasInvestigate.
func (s Scope) HasInvestigate() bool { return len(s) > 0 }

// PracticeSet is the answers of the practice editions, by format
// (format -> the set of values). Loading them is A4 / A7; here it is an argument.
type PracticeSet map[string]map[string]struct{}

// Add records one practice answer. The set must be made (PracticeSet{}): Add on a
// nil PracticeSet panics, and a nil one is "not supplied" to Check, not "empty".
func (p PracticeSet) Add(format, value string) {
	if p[format] == nil {
		p[format] = make(map[string]struct{})
	}
	p[format][value] = struct{}{}
}

// Has reports whether value is a practice answer of that format.
func (p PracticeSet) Has(format, value string) bool {
	_, ok := p[format][value]
	return ok
}

// Options are Check's inputs besides the table and the scope.
type Options struct {
	// EventMode is "FLAGS_FILE is not empty". An event table must not carry the
	// practice run id or the seat *; a practice table (EventMode false) must carry
	// the practice run id.
	EventMode bool
	// Practice is the practice editions' answers (T6). In the event mode nil is an
	// error (the check could not run); pass PracticeSet{} for "there are none".
	Practice PracticeSet
	// FlagValues are the values of this event's FLAGS_FILE (T7).
	FlagValues []string
}

type valueKey struct {
	cid   string
	qid   string
	value string
}

type collector struct {
	errs    []error
	dropped int
}

func (c *collector) add(v *Violation) {
	if len(c.errs) >= maxViolations {
		c.dropped++
		return
	}
	c.errs = append(c.errs, v)
}

func (c *collector) err() error {
	if c.dropped > 0 {
		c.errs = append(c.errs, fmt.Errorf("%d further violations are not listed", c.dropped))
	}
	return errors.Join(c.errs...)
}

// Check is D10 T3 (run id), T4-T8 for a parsed table against the scope. It
// returns nil, or an errors.Join of *Violation (at most maxViolations, in a fixed
// order: run id, then the rows in file order, then the missing rows by seat, cid,
// qid). It does not stop at the first one.
//
// T4: a seat set that is not empty, every seat in ADR-0042's grammar (a practice
// table, EventMode false, has the seat * and no other), no seat * in an event table, no cid / qid outside
// the scope, and a row for every seat x every (cid, qid) of the scope. T5: the value
// fits the format and is already normalised (answerformat.Canonical). T6 (event
// mode): the value is not a practice answer of the same format. T7: the value holds
// no flag shape (catalog.MentionsFlag) and none of opts.FlagValues. T8: in a format
// that can vary per seat, no two seats share a value for one question.
func Check(t *Table, scope Scope, opts Options) error {
	if t == nil {
		return ErrTableMissing
	}
	var c collector
	zero := t.runID == PracticeRunID
	switch {
	case opts.EventMode && zero:
		c.add(newViolation(RuleShape, "an event table must not carry the practice run id (all zeros)", 1, cell{}, nil))
	case !opts.EventMode && !zero:
		c.add(newViolation(RuleShape, "a practice table must carry the practice run id (all zeros)", 1, cell{}, nil))
	}
	if opts.EventMode && opts.Practice == nil {
		c.add(newViolation(RulePractice, "the practice answers were not supplied, so T6 cannot run", 0, cell{}, nil))
	}
	seats := t.Seats()
	if len(seats) == 0 {
		c.add(newViolation(RuleComplete, "the table has no seat", 0, cell{}, nil))
	}

	seen := make(map[valueKey]struct{}, len(t.rows))
	for _, r := range t.rows {
		switch {
		case r.c.seat == AnySeat:
			if opts.EventMode {
				c.add(newViolation(RuleComplete, "seat * is not allowed in an event table", r.line, r.c, nil))
			}
		case !identity.ValidSeat(r.c.seat):
			c.add(newViolation(RuleComplete, "seat is outside the seat grammar (ADR-0042)", r.line, r.c, nil))
			continue
		case !opts.EventMode:
			c.add(newViolation(RuleComplete, "a practice table has only the seat *", r.line, r.c, nil))
		}
		qs, ok := scope[r.c.cid]
		if !ok {
			c.add(newViolation(RuleComplete, "cid is not an investigate challenge of the scope", r.line, r.c, nil))
			continue
		}
		q, ok := findQuestion(qs, r.c.qid)
		if !ok {
			c.add(newViolation(RuleComplete, "qid is not a question of that challenge", r.line, r.c, nil))
			continue
		}
		if err := answerformat.Canonical(q.Format, q.Params, r.value); err != nil {
			c.add(newViolation(RuleFormat, "value does not fit the format of its question", r.line, r.c, err))
		}
		if opts.EventMode && opts.Practice.Has(q.Format, r.value) {
			c.add(newViolation(RulePractice, "value is a practice answer of the same format", r.line, r.c, nil))
		}
		if catalog.MentionsFlag(r.value) || containsAny(r.value, opts.FlagValues) {
			c.add(newViolation(RuleFlag, "value holds a flag shape or a value of this event's flags", r.line, r.c, nil))
		}
		if answerformat.PerSeat(q.Format) {
			k := valueKey{cid: r.c.cid, qid: r.c.qid, value: r.value}
			if _, dup := seen[k]; dup {
				c.add(newViolation(RulePerSeat, "two seats share a value of a per-seat format", r.line, r.c, nil))
			}
			seen[k] = struct{}{}
		}
	}

	cids := make([]string, 0, len(scope))
	for cid := range scope {
		cids = append(cids, cid)
	}
	sort.Strings(cids)
	for _, seat := range seats {
		if seat != AnySeat && !identity.ValidSeat(seat) {
			continue // already reported above, and not nameable
		}
		for _, cid := range cids {
			for _, q := range scope[cid] {
				k := cell{seat: seat, cid: cid, qid: q.ID}
				if _, ok := t.index[k]; !ok {
					c.add(newViolation(RuleComplete, "no row for this seat and question", 0, k, nil))
				}
			}
		}
	}
	return c.err()
}

func findQuestion(qs []catalog.Question, qid string) (catalog.Question, bool) {
	for _, q := range qs {
		if q.ID == qid {
			return q, true
		}
	}
	return catalog.Question{}, false
}

// containsAny reports whether v contains one of the non-empty needles.
func containsAny(v string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(v, n) {
			return true
		}
	}
	return false
}
