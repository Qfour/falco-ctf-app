package store_test

import (
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestMarkSolved_IsIdempotent(t *testing.T) {
	s := newStore(t)
	newly, err := s.MarkSolved("alice", "01-read-shadow", "2026-05-11T00:00:00Z")
	if err != nil || !newly {
		t.Fatalf("first MarkSolved: newly=%v err=%v", newly, err)
	}
	newly, err = s.MarkSolved("alice", "01-read-shadow", "2026-05-11T01:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if newly {
		t.Fatal("second MarkSolved should report not-newly (first solve wins)")
	}
	snap := s.Snapshot()
	if got := snap.Solved[store.SolveKey{User: "alice", Challenge: "01-read-shadow"}]; got != "2026-05-11T00:00:00Z" {
		t.Fatalf("first-solve timestamp must be preserved; got %q", got)
	}
}

func TestRecordRuleFire_BumpsCount(t *testing.T) {
	s := newStore(t)
	c1, err := s.RecordRuleFire("alice", "rule-x", 1000.0)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := s.RecordRuleFire("alice", "rule-y", 1001.0)
	if err != nil {
		t.Fatal(err)
	}
	if c1 != 1 || c2 != 2 {
		t.Fatalf("counts: %d, %d", c1, c2)
	}
}

func TestRecentFiresMatching_WithinWindow(t *testing.T) {
	s := newStore(t)
	if _, err := s.RecordRuleFire("alice", "forbidden-A", 100.0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordRuleFire("alice", "ok-rule", 100.5); err != nil {
		t.Fatal(err)
	}
	got := s.RecentFiresMatching("alice", []string{"forbidden-A", "forbidden-B"}, 105.0, 10)
	if len(got) != 1 || got[0] != "forbidden-A" {
		t.Fatalf("expected [forbidden-A], got %v", got)
	}
}

func TestRecentFiresMatching_OutsideWindow(t *testing.T) {
	s := newStore(t)
	if _, err := s.RecordRuleFire("alice", "forbidden-A", 100.0); err != nil {
		t.Fatal(err)
	}
	// now=200, window=10s -> cutoff=190, fire at 100 is outside
	got := s.RecentFiresMatching("alice", []string{"forbidden-A"}, 200.0, 10)
	if len(got) != 0 {
		t.Fatalf("fire outside window must not count; got %v", got)
	}
}

func TestRecentFiresMatching_OnlyMatchingRulesReturned(t *testing.T) {
	s := newStore(t)
	if _, err := s.RecordRuleFire("alice", "allowed-rule", 100.0); err != nil {
		t.Fatal(err)
	}
	got := s.RecentFiresMatching("alice", []string{"forbidden-A"}, 105.0, 10)
	if len(got) != 0 {
		t.Fatalf("non-forbidden rules must not appear; got %v", got)
	}
}

func TestRecentFiresMatching_DeduplicatesAndSorts(t *testing.T) {
	s := newStore(t)
	for _, r := range []string{"B", "A", "B", "A"} {
		if _, err := s.RecordRuleFire("alice", r, 100.0); err != nil {
			t.Fatal(err)
		}
	}
	got := s.RecentFiresMatching("alice", []string{"A", "B"}, 105.0, 10)
	if len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("expected sorted dedup [A B], got %v", got)
	}
}

func TestRuleFires_BoundedByRetention(t *testing.T) {
	s := newStore(t)
	// Insert an ancient fire (well outside the 300s retention).
	if _, err := s.RecordRuleFire("alice", "forbidden-A", 0.0); err != nil {
		t.Fatal(err)
	}
	// A new fire far enough ahead that the cutoff drops the first one.
	if _, err := s.RecordRuleFire("alice", "forbidden-A", 1000.0); err != nil {
		t.Fatal(err)
	}
	// At now=1000, window=10 → cutoff=990, both expected to be visible only
	// if RetentionSeconds didn't drop the first. The first was dropped
	// because the retention prune (~700s) kicked in. The second one at 1000
	// is in window.
	got := s.RecentFiresMatching("alice", []string{"forbidden-A"}, 1000.0, 10)
	if len(got) != 1 {
		t.Fatalf("expected one rule after retention pruning, got %v", got)
	}
}

func TestPersistence_ReopenLoadsState(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "scoreboard.db")

	s1, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.MarkSolved("alice", "01-read", "2026-05-11T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.RecordRuleFire("alice", "x", 100.0); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.RecordRuleFire("alice", "y", 101.0); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	snap := s2.Snapshot()
	if snap.Solved[store.SolveKey{User: "alice", Challenge: "01-read"}] != "2026-05-11T00:00:00Z" {
		t.Fatal("solved row did not persist")
	}
	// eventsPerUser is in-memory only — resets to zero on restart by design.
	if snap.EventsPerUser["alice"] != 0 {
		t.Fatalf("event count should reset on reopen (in-memory only): got %d", snap.EventsPerUser["alice"])
	}
}

func TestSolvedCount(t *testing.T) {
	s := newStore(t)
	if got := s.SolvedCount(); got != 0 {
		t.Fatalf("empty: got %d", got)
	}
	_, _ = s.MarkSolved("a", "1", "t")
	_, _ = s.MarkSolved("b", "1", "t")
	if got := s.SolvedCount(); got != 2 {
		t.Fatalf("after 2 solves: got %d", got)
	}
}

// --- Journey: hint_views + step_checks --------------------------------------

func TestHintViews_RecordAndQuery(t *testing.T) {
	s := newStore(t)
	newly, err := s.RecordHintView("alice", "01-recon", 1, "2026-07-13T00:00:00Z")
	if err != nil || !newly {
		t.Fatalf("first RecordHintView: newly=%v err=%v", newly, err)
	}
	// idempotent: re-revealing the same hint is not newly.
	newly, err = s.RecordHintView("alice", "01-recon", 1, "2026-07-13T01:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if newly {
		t.Fatal("second RecordHintView of same hint must not be newly")
	}
	if _, err := s.RecordHintView("alice", "01-recon", 2, "2026-07-13T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	// a different user's views must not leak.
	if _, err := s.RecordHintView("bob", "01-recon", 1, "2026-07-13T00:00:02Z"); err != nil {
		t.Fatal(err)
	}
	got := s.HintViews("alice")
	if idxs := got["01-recon"]; len(idxs) != 2 || idxs[0] != 1 || idxs[1] != 2 {
		t.Fatalf("alice hint views: got %v, want [1 2]", idxs)
	}
	if len(s.HintViews("carol")) != 0 {
		t.Fatal("carol should have no hint views")
	}
}

func TestStepChecks_TickAndClear(t *testing.T) {
	s := newStore(t)
	if err := s.SetStepCheck("alice", "01-recon", 0, true, "t"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStepCheck("alice", "01-recon", 2, true, "t"); err != nil {
		t.Fatal(err)
	}
	got := s.StepChecks("alice")["01-recon"]
	if len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("checked steps: got %v, want [0 2]", got)
	}
	// clearing a step removes it.
	if err := s.SetStepCheck("alice", "01-recon", 0, false, "t"); err != nil {
		t.Fatal(err)
	}
	got = s.StepChecks("alice")["01-recon"]
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("after clear: got %v, want [2]", got)
	}
}

// hint_views and step_checks must survive a store reopen (SQLite persistence).
func TestHintViewsAndStepChecks_PersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scoreboard.db")
	s1, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.RecordHintView("alice", "05-evade", 3, "t"); err != nil {
		t.Fatal(err)
	}
	if err := s1.SetStepCheck("alice", "05-evade", 1, true, "t"); err != nil {
		t.Fatal(err)
	}
	_ = s1.Close()

	s2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if idxs := s2.HintViews("alice")["05-evade"]; len(idxs) != 1 || idxs[0] != 3 {
		t.Fatalf("hint views not persisted: got %v", idxs)
	}
	if idxs := s2.StepChecks("alice")["05-evade"]; len(idxs) != 1 || idxs[0] != 1 {
		t.Fatalf("step checks not persisted: got %v", idxs)
	}
}

// Reset must clear per-participant Journey progress alongside solves.
func TestReset_ClearsHintViewsAndStepChecks(t *testing.T) {
	s := newStore(t)
	if _, err := s.RecordHintView("alice", "01-recon", 1, "t"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStepCheck("alice", "01-recon", 0, true, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if len(s.HintViews("alice")) != 0 {
		t.Fatal("hint views must be cleared by Reset")
	}
	if len(s.StepChecks("alice")) != 0 {
		t.Fatal("step checks must be cleared by Reset")
	}
}

func TestHasExfilAny(t *testing.T) {
	s := newStore(t)
	if s.HasExfilAny("alice", "03-boss") {
		t.Fatal("no receipt yet")
	}
	if err := s.RecordExfil("alice", "03-boss", "FALCO{boss}", "t"); err != nil {
		t.Fatal(err)
	}
	if !s.HasExfilAny("alice", "03-boss") {
		t.Fatal("receipt recorded → HasExfilAny must be true")
	}
	// HasExfilAny is flag-agnostic; even a wrong-value receipt counts as
	// "received here" while HasExfil (exact match) stays false.
	if err := s.RecordExfil("bob", "03-boss", "FALCO{wrong}", "t"); err != nil {
		t.Fatal(err)
	}
	if !s.HasExfilAny("bob", "03-boss") {
		t.Fatal("wrong-value receipt still counts for HasExfilAny")
	}
	if s.HasExfil("bob", "03-boss", "FALCO{boss}") {
		t.Fatal("HasExfil must still require the exact flag")
	}
}

// PendingExfilSolves returns only received-but-unsolved receipts; solved pairs
// drop out of the queue.
func TestPendingExfilSolves(t *testing.T) {
	s := newStore(t)
	if got := s.PendingExfilSolves(); len(got) != 0 {
		t.Fatalf("empty store must yield no pending solves, got %+v", got)
	}
	if err := s.RecordExfil("alice", "03-boss", "FALCO{boss}", "t"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordExfil("bob", "03-boss", "FALCO{boss}", "t"); err != nil {
		t.Fatal(err)
	}
	pending := s.PendingExfilSolves()
	if len(pending) != 2 {
		t.Fatalf("two receipts, none solved → two pending, got %+v", pending)
	}
	// Sorted by (user, challenge): alice before bob.
	if pending[0].User != "alice" || pending[0].Challenge != "03-boss" || pending[0].Flag != "FALCO{boss}" {
		t.Fatalf("first pending receipt wrong: %+v", pending[0])
	}

	// Solve alice's pair — it must leave the pending queue; bob's remains.
	if _, err := s.MarkSolved("alice", "03-boss", "t"); err != nil {
		t.Fatal(err)
	}
	pending = s.PendingExfilSolves()
	if len(pending) != 1 || pending[0].User != "bob" {
		t.Fatalf("solved pair must drop out; got %+v", pending)
	}
}

// --- App-H2: persistent evade dirty flag ------------------------------------

// TestDirtyRules_EmptyByDefault proves a never-touched (user, challenge) pair
// reports clean (nil/empty), matching the "false" initial value the accept
// criteria requires.
func TestDirtyRules_EmptyByDefault(t *testing.T) {
	s := newStore(t)
	if got := s.DirtyRules("alice", "02-evade"); len(got) != 0 {
		t.Fatalf("untouched pair must report clean, got %v", got)
	}
}

// TestMarkDirty_SetsAndAccumulatesRules proves MarkDirty is additive: a second
// distinct forbidden rule adds to the offending set rather than replacing it,
// and re-marking the SAME rule is a no-op (idempotent per (user, challenge,
// rule) — the DB's PRIMARY KEY enforces this).
func TestMarkDirty_SetsAndAccumulatesRules(t *testing.T) {
	s := newStore(t)
	if err := s.MarkDirty("alice", "02-evade", "Rule A", "2026-05-11T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if got := s.DirtyRules("alice", "02-evade"); len(got) != 1 || got[0] != "Rule A" {
		t.Fatalf("want [Rule A], got %v", got)
	}
	if err := s.MarkDirty("alice", "02-evade", "Rule B", "2026-05-11T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	if got := s.DirtyRules("alice", "02-evade"); len(got) != 2 || got[0] != "Rule A" || got[1] != "Rule B" {
		t.Fatalf("want sorted [Rule A, Rule B], got %v", got)
	}
	// Re-marking the same rule must not duplicate or error.
	if err := s.MarkDirty("alice", "02-evade", "Rule A", "2026-05-11T00:00:02Z"); err != nil {
		t.Fatal(err)
	}
	if got := s.DirtyRules("alice", "02-evade"); len(got) != 2 {
		t.Fatalf("re-marking an existing rule must not duplicate, got %v", got)
	}
}

// TestMarkDirty_ScopedPerUserAndChallenge proves the taint does not leak
// across users or across challenges for the same user — a fairness property
// as important as the taint itself (a bystander must never be blocked by
// another participant's forbidden fire, and one challenge's taint must not
// bleed into a sibling challenge that happens to share the same rule name in
// its own forbiddenRules).
func TestMarkDirty_ScopedPerUserAndChallenge(t *testing.T) {
	s := newStore(t)
	if err := s.MarkDirty("alice", "02-evade", "Rule A", "t"); err != nil {
		t.Fatal(err)
	}
	if got := s.DirtyRules("bob", "02-evade"); len(got) != 0 {
		t.Fatalf("bob must not inherit alice's taint, got %v", got)
	}
	if got := s.DirtyRules("alice", "03-boss"); len(got) != 0 {
		t.Fatalf("a different challenge for the same user must stay clean, got %v", got)
	}
}

// TestResetDirty_ClearsAndIsIdempotent proves ResetDirty is the ONLY way back
// to clean, and that resetting twice (or resetting an already-clean pair) is
// a harmless no-op rather than an error.
func TestResetDirty_ClearsAndIsIdempotent(t *testing.T) {
	s := newStore(t)
	if err := s.MarkDirty("alice", "02-evade", "Rule A", "t"); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetDirty("alice", "02-evade"); err != nil {
		t.Fatal(err)
	}
	if got := s.DirtyRules("alice", "02-evade"); len(got) != 0 {
		t.Fatalf("reset must clear the taint, got %v", got)
	}
	// Idempotent: resetting an already-clean pair is a no-op, not an error.
	if err := s.ResetDirty("alice", "02-evade"); err != nil {
		t.Fatalf("reset of an already-clean pair must not error: %v", err)
	}
}

// TestDirtyFlag_SurvivesReopen is the store-level half of the App-H2
// restart regression (the scoring-level half, which also exercises the
// Sweeper, lives in scoring_test.go's TestDirtyFlag_SurvivesStoreRestart).
// Before this fix the equivalent fact (RecentFiresMatching's in-memory
// ruleFires) was wiped on every scoreboard restart (I1: single replica +
// Recreate strategy). This proves the persisted dirty flag survives a
// Close+re-Open on the SAME file — the exact sequence store.Open runs on
// every process boot.
func TestDirtyFlag_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "scoreboard.db")

	s1, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.MarkDirty("alice", "02-evade", "Read sensitive file untrusted", "2026-05-11T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got := s2.DirtyRules("alice", "02-evade")
	if len(got) != 1 || got[0] != "Read sensitive file untrusted" {
		t.Fatalf("App-H2 regression: dirty flag did not survive a store restart, got %v", got)
	}
}

// TestReset_ClearsDirtyFlags proves the admin bulk Reset() (fresh-start /
// demo-run wipe) also clears evade_dirty — consistent with it already
// clearing solved/exfil/hint_views/step_checks. A leftover dirty row after an
// admin reset would otherwise permanently lock a challenge for a user who
// never got a chance to redo it in the new run.
func TestReset_ClearsDirtyFlags(t *testing.T) {
	s := newStore(t)
	if err := s.MarkDirty("alice", "02-evade", "Rule A", "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if got := s.DirtyRules("alice", "02-evade"); len(got) != 0 {
		t.Fatalf("admin Reset must clear dirty flags too, got %v", got)
	}
}
