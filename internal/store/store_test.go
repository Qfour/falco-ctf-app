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

func TestRecentForbiddenFires_WithinWindow(t *testing.T) {
	s := newStore(t)
	if _, err := s.RecordRuleFire("alice", "forbidden-A", 100.0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordRuleFire("alice", "ok-rule", 100.5); err != nil {
		t.Fatal(err)
	}
	got := s.RecentForbiddenFires("alice", []string{"forbidden-A", "forbidden-B"}, 105.0, 10)
	if len(got) != 1 || got[0] != "forbidden-A" {
		t.Fatalf("expected [forbidden-A], got %v", got)
	}
}

func TestRecentForbiddenFires_OutsideWindow(t *testing.T) {
	s := newStore(t)
	if _, err := s.RecordRuleFire("alice", "forbidden-A", 100.0); err != nil {
		t.Fatal(err)
	}
	// now=200, window=10s -> cutoff=190, fire at 100 is outside
	got := s.RecentForbiddenFires("alice", []string{"forbidden-A"}, 200.0, 10)
	if len(got) != 0 {
		t.Fatalf("fire outside window must not count; got %v", got)
	}
}

func TestRecentForbiddenFires_OnlyForbiddenRulesReturned(t *testing.T) {
	s := newStore(t)
	if _, err := s.RecordRuleFire("alice", "allowed-rule", 100.0); err != nil {
		t.Fatal(err)
	}
	got := s.RecentForbiddenFires("alice", []string{"forbidden-A"}, 105.0, 10)
	if len(got) != 0 {
		t.Fatalf("non-forbidden rules must not appear; got %v", got)
	}
}

func TestRecentForbiddenFires_DeduplicatesAndSorts(t *testing.T) {
	s := newStore(t)
	for _, r := range []string{"B", "A", "B", "A"} {
		if _, err := s.RecordRuleFire("alice", r, 100.0); err != nil {
			t.Fatal(err)
		}
	}
	got := s.RecentForbiddenFires("alice", []string{"A", "B"}, 105.0, 10)
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
	got := s.RecentForbiddenFires("alice", []string{"forbidden-A"}, 1000.0, 10)
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
	if snap.EventsPerUser["alice"] != 2 {
		t.Fatalf("event count did not persist: got %d, want 2", snap.EventsPerUser["alice"])
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
