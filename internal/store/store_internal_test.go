package store

import (
	"path/filepath"
	"testing"
)

// TestResetDirty_TransactionRollsBackOnPartialFailure is the store-level
// regression proof for app#124 5x review finding #1 (R1 security / R2 qa /
// R4 architect independently flagged the same fail-open bug): the original
// ResetDirty ran two bare *sql.DB.Exec calls, deleting evade_dirty (AND its
// in-memory mirror) FIRST and only then attempting to delete exfil. If the
// second statement failed, the handler returned a 500 — but the taint was
// already gone, on disk and in memory, while the stale exfil receipt was
// not. That is exactly the "dirty cleared, receipt still present" state the
// Sweeper (current()-independent, 5s tick) auto-solves on its very next
// pass, silently reopening the ADR-0003 A2-2 exploit ResetDirty exists to
// close — through its own error path.
//
// This is white-box (package store, not store_test) because it needs direct
// access to s.db to break ONLY the second statement's table while leaving
// evade_dirty's table intact, which store_test.go's black-box helpers can't
// do (there is no other way to make exactly one of the two DELETEs fail).
//
// A correct fix (both DELETEs in one transaction, in-memory maps updated
// only after Commit) must leave BOTH the taint and the receipt exactly as
// they were before this call — this test asserts the taint side of that;
// TestResetDirty_ClearsExfilReceiptToo in store_test.go covers the
// already-passing success path for the receipt side.
func TestResetDirty_TransactionRollsBackOnPartialFailure(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.RecordExfil("alice", "10-final-exfil", "FALCO{x}", "t"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDirty("alice", "10-final-exfil", "Rule A", "t"); err != nil {
		t.Fatal(err)
	}

	// Break ONLY the second statement's table so the first (evade_dirty)
	// would succeed in isolation — the whole point is to prove a mid-way
	// failure can't leave a partially-reset pair behind.
	if _, err := s.db.Exec("DROP TABLE exfil"); err != nil {
		t.Fatal(err)
	}

	if err := s.ResetDirty("alice", "10-final-exfil"); err == nil {
		t.Fatal("test precondition: expected ResetDirty to fail once the exfil table is gone")
	}

	// Fail-closed assertion: the taint must STILL be present (not
	// half-cleared) because the transaction rolled back the evade_dirty
	// delete too, and the in-memory delete never ran (it only runs after
	// Commit succeeds).
	if got := s.DirtyRules("alice", "10-final-exfil"); len(got) != 1 || got[0] != "Rule A" {
		t.Fatalf("app#124 5x fix: a partial failure must leave the taint intact (fail-closed), got %v", got)
	}
}
