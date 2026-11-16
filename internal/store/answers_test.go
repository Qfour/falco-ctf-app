package store_test

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/store"
)

// ADR-0056 D5 3 / D7 at the store: the attempt budget of (user, challenge, question).

const (
	invCID = "90-investigate"
	invQID = "who"
)

func TestTryAnswerAttempt_CountsUpToTheLimitThenRefuses(t *testing.T) {
	s := newStore(t)
	for i := 1; i <= 3; i++ {
		res, n, err := s.TryAnswerAttempt("alice", invCID, invQID, 3)
		if err != nil || res != store.AnswerAttemptCounted || n != i {
			t.Fatalf("attempt %d: res=%v n=%d err=%v, want Counted, %d", i, res, n, err, i)
		}
	}
	for i := 0; i < 3; i++ { // the budget does not move once it is spent
		res, n, err := s.TryAnswerAttempt("alice", invCID, invQID, 3)
		if err != nil || res != store.AnswerAttemptExhausted || n != 3 {
			t.Fatalf("after the limit: res=%v n=%d err=%v, want Exhausted, 3", res, n, err)
		}
	}
	st, err := s.AnswerAttempts("alice", invCID)
	if err != nil || st[invQID] != (store.AnswerState{N: 3}) {
		t.Fatalf("AnswerAttempts = %v, %v, want n=3 not correct", st, err)
	}
}

func TestTryAnswerAttempt_BudgetIsPerUserChallengeAndQuestion(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 2; i++ {
		if _, _, err := s.TryAnswerAttempt("alice", invCID, invQID, 2); err != nil {
			t.Fatal(err)
		}
	}
	if res, _, _ := s.TryAnswerAttempt("alice", invCID, invQID, 2); res != store.AnswerAttemptExhausted {
		t.Fatalf("alice/who: %v, want Exhausted", res)
	}
	// another user, another question, another challenge
	for _, c := range []struct{ user, cid, qid string }{
		{"bob", invCID, invQID},
		{"alice", invCID, "other"},
		{"alice", "91-other", "who"},
	} {
		res, n, err := s.TryAnswerAttempt(c.user, c.cid, c.qid, 2)
		if err != nil || res != store.AnswerAttemptCounted || n != 1 {
			t.Fatalf("%+v: res=%v n=%d err=%v, want a fresh budget", c, res, n, err)
		}
	}
}

func TestTryAnswerAttempt_AnsweredQuestionIsNotCountedAgain(t *testing.T) {
	s := newStore(t)
	if _, _, err := s.TryAnswerAttempt("alice", invCID, invQID, 5); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAnswerCorrect("alice", invCID, invQID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		res, n, err := s.TryAnswerAttempt("alice", invCID, invQID, 5)
		if err != nil || res != store.AnswerAttemptAlreadyCorrect || n != 1 {
			t.Fatalf("after correct: res=%v n=%d err=%v, want AlreadyCorrect, 1", res, n, err)
		}
	}
}

func TestTryAnswerAttempt_SolvedChallengeIsNotCountedAndLeavesNoRow(t *testing.T) {
	s := newStore(t)
	if _, err := s.MarkSolved("alice", invCID, "t"); err != nil {
		t.Fatal(err)
	}
	res, n, err := s.TryAnswerAttempt("alice", invCID, invQID, 5)
	if err != nil || res != store.AnswerAttemptChallengeSolved || n != 0 {
		t.Fatalf("res=%v n=%d err=%v, want ChallengeSolved, 0", res, n, err)
	}
	if st, err := s.AnswerAttempts("alice", invCID); err != nil || len(st) != 0 {
		t.Fatalf("a solved challenge left rows: %v, %v", st, err)
	}
}

func TestTryAnswerAttempt_LimitBelowOneIsAnErrorNotUnlimited(t *testing.T) {
	s := newStore(t)
	for _, limit := range []int{0, -1} {
		if res, _, err := s.TryAnswerAttempt("alice", invCID, invQID, limit); err == nil {
			t.Fatalf("limit %d: res=%v, want an error", limit, res)
		}
	}
	if st, _ := s.AnswerAttempts("alice", invCID); len(st) != 0 {
		t.Fatalf("a refused call left rows: %v", st)
	}
}

func TestMarkAnswerCorrect_NeedsACountedAttempt(t *testing.T) {
	s := newStore(t)
	if err := s.MarkAnswerCorrect("alice", invCID, invQID); !errors.Is(err, store.ErrNoAnswerAttempt) {
		t.Fatalf("no row: err = %v, want ErrNoAnswerAttempt", err)
	}
	if st, _ := s.AnswerAttempts("alice", invCID); len(st) != 0 {
		t.Fatalf("a refused mark created a row: %v", st)
	}
	if _, _, err := s.TryAnswerAttempt("alice", invCID, invQID, 5); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // idempotent
		if err := s.MarkAnswerCorrect("alice", invCID, invQID); err != nil {
			t.Fatalf("mark %d: %v", i, err)
		}
	}
	if st, _ := s.AnswerAttempts("alice", invCID); st[invQID] != (store.AnswerState{N: 1, Correct: true}) {
		t.Fatalf("state = %v, want n=1 correct", st)
	}
}

func TestTryAnswerAttempt_SurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scoreboard.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, _, err := s.TryAnswerAttempt("alice", invCID, invQID, 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if res, n, err := s2.TryAnswerAttempt("alice", invCID, invQID, 3); err != nil || res != store.AnswerAttemptCounted || n != 3 {
		t.Fatalf("after a restart: res=%v n=%d err=%v, want Counted, 3 (the budget is not reset by a restart)", res, n, err)
	}
	if res, _, _ := s2.TryAnswerAttempt("alice", invCID, invQID, 3); res != store.AnswerAttemptExhausted {
		t.Fatalf("res=%v, want Exhausted", res)
	}
}

// N callers at once: exactly `limit` are counted, whatever the interleaving. Run
// with -race.
func TestTryAnswerAttempt_ConcurrentCallsNeverExceedTheLimit(t *testing.T) {
	s := newStore(t)
	const callers, limit = 32, 5
	results := make([]store.AnswerAttempt, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _, errs[i] = s.TryAnswerAttempt("alice", invCID, invQID, limit)
		}()
	}
	wg.Wait()
	counted := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		switch results[i] {
		case store.AnswerAttemptCounted:
			counted++
		case store.AnswerAttemptExhausted:
		default:
			t.Fatalf("caller %d: %v", i, results[i])
		}
	}
	if counted != limit {
		t.Fatalf("counted %d attempts, want exactly %d", counted, limit)
	}
	if st, _ := s.AnswerAttempts("alice", invCID); st[invQID].N != limit {
		t.Fatalf("stored n = %d, want %d", st[invQID].N, limit)
	}
}

// POST /api/admin/reset clears the counts with the solves; reset-dirty does not
// touch them (ADR-0056 D7).
func TestReset_ClearsAnswerAttemptsAndResetDirtyDoesNot(t *testing.T) {
	s := newStore(t)
	if _, _, err := s.TryAnswerAttempt("alice", invCID, invQID, 5); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAnswerCorrect("alice", invCID, invQID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkSolved("alice", invCID, "t"); err != nil {
		t.Fatal(err)
	}

	if err := s.ResetDirty("alice", invCID); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.AnswerAttempts("alice", invCID); st[invQID] != (store.AnswerState{N: 1, Correct: true}) {
		t.Fatalf("reset-dirty changed the counts: %v", st)
	}

	if n, err := s.Reset(); err != nil || n != 1 {
		t.Fatalf("Reset = %d, %v, want 1 solve cleared", n, err)
	}
	if st, err := s.AnswerAttempts("alice", invCID); err != nil || len(st) != 0 {
		t.Fatalf("Reset left answer counts: %v, %v", st, err)
	}
	if res, n, err := s.TryAnswerAttempt("alice", invCID, invQID, 5); err != nil || res != store.AnswerAttemptCounted || n != 1 {
		t.Fatalf("after Reset: res=%v n=%d err=%v, want a fresh budget on an unsolved challenge", res, n, err)
	}
}
