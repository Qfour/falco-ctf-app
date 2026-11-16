package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// answers.go is the persistence side of an investigate challenge's attempt
// budget (ADR-0056 D5 3, D7): how many answers a participant has spent on one
// question, and whether it is answered. The table holds a count and a flag and
// nothing else: never the text of an answer, a hash of it, or a time (D13).
//
// The table is read and written through the database only (no in-memory
// mirror, unlike the solve tables): a count that is read from memory could
// disagree with the row the transaction below just committed, and the budget is
// the one thing that stops a brute force. The Grader (internal/scoreboard/
// scoring, SubmitAnswer) is the only caller of the two writes; an adapter does
// not write it (singledoor_test.go checks).

// AnswerAttempt is the outcome of TryAnswerAttempt. The zero value is not a
// valid outcome, so an uninitialised result can never read as "counted".
type AnswerAttempt int

const (
	// AnswerAttemptCounted: one attempt was added and committed; the caller may now
	// compare the answer (and only now).
	AnswerAttemptCounted AnswerAttempt = iota + 1
	// AnswerAttemptExhausted: the question has no attempt left. Nothing was added.
	AnswerAttemptExhausted
	// AnswerAttemptAlreadyCorrect: the question is already answered. Nothing was added.
	AnswerAttemptAlreadyCorrect
	// AnswerAttemptChallengeSolved: the participant has already solved the challenge.
	// Nothing was added.
	AnswerAttemptChallengeSolved
)

// ErrNoAnswerAttempt is returned by MarkAnswerCorrect when there is no counted
// attempt to mark: the row is missing (an admin reset ran in between) or its
// count is 0. Marking a question correct without an attempt having been counted
// is refused (fail-closed), not repaired.
var ErrNoAnswerAttempt = errors.New("store: no counted answer attempt for this question")

// AnswerState is one question's row: the attempts spent and whether it is answered.
type AnswerState struct {
	N       int
	Correct bool
}

// TryAnswerAttempt is ADR-0056 D5 3. In ONE transaction it checks that the
// participant has not solved the challenge, that the question is not answered
// and that fewer than `limit` attempts are spent, and adds one attempt (creating
// the row when there is none). It returns what happened and the attempts spent
// after it (for Counted that is the new count).
//
// The comparison of the answer happens AFTER this returns Counted, and only
// then. A failed commit returns an error and the caller does not compare (the
// same order as MarkDirty: the failure is on the side of a refusal).
// `limit` must be at least 1 (the catalog guarantees 1..10); anything else is
// an error, never "unlimited".
func (s *Store) TryAnswerAttempt(user, challenge, question string, limit int) (AnswerAttempt, int, error) {
	if limit < 1 {
		return 0, 0, fmt.Errorf("store: answer attempt limit must be at least 1, got %d", limit)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	var one int
	switch err := tx.QueryRow(
		"SELECT 1 FROM solved WHERE user = ? AND challenge = ?", user, challenge,
	).Scan(&one); {
	case err == nil:
		n, _, err := readAnswerRow(tx, user, challenge, question)
		if err != nil {
			return 0, 0, err
		}
		return AnswerAttemptChallengeSolved, n, nil
	case !errors.Is(err, sql.ErrNoRows):
		return 0, 0, err
	}

	if _, err := tx.Exec(
		"INSERT OR IGNORE INTO answer_attempts (user, challenge, question, n, correct) VALUES (?, ?, ?, 0, 0)",
		user, challenge, question,
	); err != nil {
		return 0, 0, err
	}
	res, err := tx.Exec(
		"UPDATE answer_attempts SET n = n + 1 WHERE user = ? AND challenge = ? AND question = ? AND n < ? AND correct = 0",
		user, challenge, question, limit,
	)
	if err != nil {
		return 0, 0, err
	}
	added, err := res.RowsAffected()
	if err != nil {
		return 0, 0, err
	}
	n, correct, err := readAnswerRow(tx, user, challenge, question)
	if err != nil {
		return 0, 0, err
	}
	switch {
	case added == 1:
		if err := tx.Commit(); err != nil {
			return 0, 0, err
		}
		return AnswerAttemptCounted, n, nil
	case added != 0:
		return 0, 0, fmt.Errorf("store: answer attempt updated %d rows, want 0 or 1", added)
	case correct:
		return AnswerAttemptAlreadyCorrect, n, nil
	default:
		return AnswerAttemptExhausted, n, nil
	}
}

// readAnswerRow reads one row; a missing row is (0, false).
func readAnswerRow(tx *sql.Tx, user, challenge, question string) (n int, correct bool, err error) {
	var c int
	err = tx.QueryRow(
		"SELECT n, correct FROM answer_attempts WHERE user = ? AND challenge = ? AND question = ?",
		user, challenge, question,
	).Scan(&n, &c)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return n, c == 1, nil
}

// MarkAnswerCorrect records that the question is answered (ADR-0056 D5 5). It
// needs a counted attempt (n >= 1); otherwise it returns ErrNoAnswerAttempt.
// Idempotent. It does not solve the challenge: the Grader decides that, from
// AnswerAttempts, and calls MarkSolved.
func (s *Store) MarkAnswerCorrect(user, challenge, question string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		"UPDATE answer_attempts SET correct = 1 WHERE user = ? AND challenge = ? AND question = ? AND n >= 1",
		user, challenge, question,
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNoAnswerAttempt
	}
	return nil
}

// AnswerAttempts returns the rows of (user, challenge) by question id. A question
// with no row (never answered) is absent. It returns counts and flags only.
func (s *Store) AnswerAttempts(user, challenge string) (map[string]AnswerState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		"SELECT question, n, correct FROM answer_attempts WHERE user = ? AND challenge = ?",
		user, challenge,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AnswerState{}
	for rows.Next() {
		var q string
		var n, c int
		if err := rows.Scan(&q, &n, &c); err != nil {
			return nil, err
		}
		out[q] = AnswerState{N: n, Correct: c == 1}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
