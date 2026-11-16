package scoring

// answers.go is the Grader's side of an investigate challenge (ADR-0056 D5, D6,
// D7, D13): a participant answers one question at a time, the scoreboard spends
// one attempt, and only then compares the answer with the table. Grader.
// SubmitAnswer is the ONE place that compares (Judge.Match) and the one place that
// turns answers into a solve (judge_door_test.go in internal/edition fixes the first
// by reading the sources, singledoor_test.go the second).
//
// The route is the adapter in internal/scoreboard/api/answer.go (A3b-1); the
// metrics come with A3b-2. catalog.LoadScored still refuses a scope that holds an
// investigate challenge (until A3b-3), so nothing reaches SubmitAnswer in a running
// scoreboard.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// AnswerStore is the port of the answer budget (ADR-0056 D7); *store.Store
// implements it. TryAnswerAttempt and MarkAnswerCorrect write, and only the
// Grader calls them.
type AnswerStore interface {
	// TryAnswerAttempt adds one attempt in one transaction, or says why not. The
	// answer is compared only after it returns AnswerAttemptCounted with a nil error.
	TryAnswerAttempt(user, challenge, question string, limit int) (store.AnswerAttempt, int, error)
	// MarkAnswerCorrect marks the question answered (it needs a counted attempt).
	MarkAnswerCorrect(user, challenge, question string) error
	// AnswerAttempts is the (user, challenge) rows by question id: counts and flags.
	AnswerAttempts(user, challenge string) (map[string]store.AnswerState, error)
}

var _ AnswerStore = (*store.Store)(nil)

// AnswerJudge is the comparison port: *edition.Judge implements it. Nothing but
// SubmitAnswer calls it.
type AnswerJudge interface {
	// Match compares the normalised input with the value of (seat, cid, qid). known
	// is false when the table has no such row.
	Match(seat, cid, qid, normalizedInput string) (ok, known bool)
	// OtherSeat is the seat, other than ownSeat, whose value the input equals. It is
	// for the operator-only audit log and nothing else.
	OtherSeat(ownSeat, cid, qid, normalizedInput string) (seat string, found bool)
}

// The errors SubmitAnswer returns, for the adapter (A3b) to map to a status. None
// of them, and nothing wrapped in them, carries the input, an expected value, a
// length or a hint of either (ADR-0056 D13).
var (
	// ErrUnknownChallenge: cid is not in the catalog (404).
	ErrUnknownChallenge = errors.New("scoring: unknown challenge")
	// ErrNotInvestigate: the challenge exists but is not an investigate challenge (400).
	ErrNotInvestigate = errors.New("scoring: challenge is not an investigate challenge")
	// ErrUnknownQuestion: qid is not a question of the challenge (404).
	ErrUnknownQuestion = errors.New("scoring: unknown question")
	// ErrAnswerFormat: the answer does not fit the question's format (400). No attempt
	// was spent. It is answerformat.ErrFormat, so errors.Is works with either; the
	// message names the rule that failed, never the text.
	ErrAnswerFormat = answerformat.ErrFormat
	// ErrAnswersUnavailable: the Grader has no answers table or no attempt store
	// (a scoreboard started without one). Nothing was spent or compared (500).
	ErrAnswersUnavailable = errors.New("scoring: no answers table is loaded")
	// ErrAnswerCellMissing: the table has no row for this seat and question. An
	// attempt WAS spent (the comparison comes after the count); it is logged for the
	// operator here, once, with ids only (500).
	ErrAnswerCellMissing = errors.New("scoring: the answers table has no row for this seat and question")
)

// AnswerStatus is the closed enum of AnswerResult.Status (ADR-0056 D6). A value is
// never added later; a new fact would be a new field.
type AnswerStatus string

const (
	AnswerCorrect        AnswerStatus = "correct"
	AnswerIncorrect      AnswerStatus = "incorrect"
	AnswerExhausted      AnswerStatus = "exhausted"
	AnswerAlreadyCorrect AnswerStatus = "already-correct"
)

// AnswerResult is what SubmitAnswer says (D6). Nothing about where an answer is
// wrong, what it should be, how long it is, or another seat.
type AnswerResult struct {
	Status AnswerStatus
	// Correct: the question is answered (by this or an earlier submission).
	Correct bool
	// Solved: the challenge is solved.
	Solved bool
	// Newly: THIS call recorded the solve (MarkSolved's "newly", like
	// EvadeOutcome.Newly). It is a Go-only field for the adapter's solve metric
	// (A3b) and is not one of the four fields of the API's AnswerResult (D6): the
	// adapter must not serialise it. It is true for at most one call per
	// (user, challenge) until an admin reset.
	Newly bool
	// Remaining: attempts left on this question (>= 0).
	Remaining int
}

// WithAnswers wires the investigate challenge's ports (ADR-0056 D5): the attempt
// store, the answers-table Judge and the operator logger. Without it SubmitAnswer
// returns ErrAnswersUnavailable. The wiring site passes a Judge only when one
// exists (a nil *edition.Judge inside the interface would not be caught here).
// Returns the same *Grader for chaining.
func (g *Grader) WithAnswers(st AnswerStore, judge AnswerJudge, logger *slog.Logger) *Grader {
	if logger == nil {
		logger = slog.Default() // an audit line must not be lost for want of a logger
	}
	g.answers, g.judge, g.answerLog = st, judge, logger
	return g
}

// SubmitAnswer grades one answer to one question of an investigate challenge
// (ADR-0056 D5). `user` is the seat: in this program a user is a seat slug, and
// the table is keyed by the same name. The order is fixed:
//
//  1. user is a seat (ErrInvalidUser); the Grader has an answers table and a
//     budget store (ErrAnswersUnavailable); cid and qid are in the catalog and the
//     challenge is an investigate one (ErrUnknownChallenge, ErrNotInvestigate,
//     ErrUnknownQuestion). Nothing is spent before these.
//  2. the input is normalised by the question's format; one that does not fit is
//     ErrAnswerFormat and costs nothing.
//  3. COUNT: TryAnswerAttempt adds one attempt and commits, or says exhausted /
//     already-correct / the challenge is solved. In those three the answer is NOT
//     compared. If the store fails, the error is returned and nothing is compared.
//  4. COMPARE: Judge.Match, and only now. A seat with no row is
//     ErrAnswerCellMissing (logged, ids only).
//  5. a match marks the question answered; when every question is answered the
//     challenge is solved through MarkSolved (the hint penalty is the score's, as
//     for every challenge). If either write fails the error is returned and the
//     challenge is not solved; the attempt stays spent.
//  6. no match: if the input equals another seat's value, one operator-only audit
//     line says so (user, challenge, question, seat; never the value). The result
//     is the same as for any other wrong answer.
//
// A question that is answered but whose challenge is not solved (a failed write in
// 5) is finished by the next submission to it: it returns already-correct, and
// before it does it solves the challenge if every question is answered. That is a
// read of what is recorded, never a comparison.
//
// An error is logged by the caller once; the only lines written here are the
// audit line of 6 and the missing-row line of 4 (the second because it is the one
// the operator must see even if the adapter's log is sampled).
func (g *Grader) SubmitAnswer(ctx context.Context, user, cid, qid, rawInput string) (AnswerResult, error) {
	if !identity.ValidSeat(user) {
		return AnswerResult{}, ErrInvalidUser
	}
	if g.answers == nil || g.judge == nil || g.answerLog == nil {
		return AnswerResult{}, ErrAnswersUnavailable
	}
	ch, ok := g.cat[cid]
	if !ok {
		return AnswerResult{}, ErrUnknownChallenge
	}
	if ch.Type != catalog.TypeInvestigate || ch.Investigate == nil {
		return AnswerResult{}, ErrNotInvestigate
	}
	var q *catalog.Question
	for i := range ch.Investigate.Questions {
		if ch.Investigate.Questions[i].ID == qid {
			q = &ch.Investigate.Questions[i]
			break
		}
	}
	if q == nil {
		return AnswerResult{}, ErrUnknownQuestion
	}
	if q.Attempts < 1 {
		return AnswerResult{}, errors.New("scoring: question has no valid attempt budget")
	}
	// A request that is already cancelled must not spend an attempt.
	if err := ctx.Err(); err != nil {
		return AnswerResult{}, err
	}

	normalized, err := answerformat.Normalize(q.Format, q.Params, rawInput)
	if err != nil {
		return AnswerResult{}, fmt.Errorf("scoring: answer: %w", err)
	}

	outcome, spent, err := g.answers.TryAnswerAttempt(user, cid, qid, q.Attempts)
	if err != nil {
		return AnswerResult{}, fmt.Errorf("scoring: answer attempt: %w", err)
	}
	remaining := max(q.Attempts-spent, 0)
	switch outcome {
	case store.AnswerAttemptCounted:
		// fall through to the comparison below
	case store.AnswerAttemptChallengeSolved:
		// An investigate challenge is solved only when every one of its questions is
		// answered (solveIfAllAnswered is the only way to solve it), so a solved
		// challenge reads as answered, and Newly is false: this call did not solve it.
		return AnswerResult{Status: AnswerAlreadyCorrect, Correct: true, Solved: true, Remaining: remaining}, nil
	case store.AnswerAttemptAlreadyCorrect:
		solved, newly, err := g.solveIfAllAnswered(user, ch)
		if err != nil {
			return AnswerResult{}, err
		}
		return AnswerResult{Status: AnswerAlreadyCorrect, Correct: true, Solved: solved, Newly: newly, Remaining: remaining}, nil
	case store.AnswerAttemptExhausted:
		return AnswerResult{Status: AnswerExhausted, Solved: g.store.IsSolved(user, cid), Remaining: 0}, nil
	default:
		return AnswerResult{}, errors.New("scoring: unknown answer attempt outcome")
	}

	match, known := g.judge.Match(user, cid, qid, normalized)
	if !known {
		g.answerLog.ErrorContext(ctx, "answers table has no row for this seat and question",
			"user", user, "cid", cid, "qid", qid)
		return AnswerResult{}, ErrAnswerCellMissing
	}
	if match {
		if err := g.answers.MarkAnswerCorrect(user, cid, qid); err != nil {
			return AnswerResult{}, fmt.Errorf("scoring: mark answer correct: %w", err)
		}
		solved, newly, err := g.solveIfAllAnswered(user, ch)
		if err != nil {
			return AnswerResult{}, err
		}
		return AnswerResult{Status: AnswerCorrect, Correct: true, Solved: solved, Newly: newly, Remaining: remaining}, nil
	}

	if other, found := g.judge.OtherSeat(user, cid, qid, normalized); found {
		g.answerLog.WarnContext(ctx, "answer matched another seat",
			"user", user, "cid", cid, "qid", qid, "seat", other)
	}
	return AnswerResult{Status: AnswerIncorrect, Solved: g.store.IsSolved(user, cid), Remaining: remaining}, nil
}

// solveIfAllAnswered solves the challenge when every one of its questions is
// recorded as answered. It reports whether the challenge is solved and whether
// this call recorded the solve (MarkSolved's "newly", as SubmitEvade's Newly).
// It reads what is recorded; it compares nothing. A challenge with no question is
// never solved.
func (g *Grader) solveIfAllAnswered(user string, ch catalog.Challenge) (solved, newly bool, err error) {
	if ch.Investigate == nil || len(ch.Investigate.Questions) == 0 {
		return false, false, nil
	}
	state, err := g.answers.AnswerAttempts(user, ch.ID)
	if err != nil {
		return false, false, fmt.Errorf("scoring: read answers: %w", err)
	}
	for _, q := range ch.Investigate.Questions {
		if !state[q.ID].Correct {
			return false, false, nil
		}
	}
	at := g.now().UTC().Format(time.RFC3339Nano)
	newly, err = g.store.MarkSolved(user, ch.ID, at)
	if err != nil {
		return false, false, fmt.Errorf("scoring: solve: %w", err)
	}
	return true, newly, nil
}
