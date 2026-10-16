package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
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

// TestSetProfile_TransactionRollsBackOnPartialFailure is the ADR-0034 V2
// store-level proof for "表示名だけが変わって絵柄が変わらない" (a half-applied
// profile): the display_names write goes first and would succeed in
// isolation, so only a real transaction undoes it when the avatars write fails.
func TestSetProfile_TransactionRollsBackOnPartialFailure(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	old, nw := "Old", "New"
	if err := s.SetProfile("alice", &old, nil, "t0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DROP TABLE avatars"); err != nil {
		t.Fatal(err)
	}
	av := "bug-lime"
	if err := s.SetProfile("alice", &nw, &av, "t1"); err == nil {
		t.Fatal("test precondition: expected SetProfile to fail once the avatars table is gone")
	}
	if got := s.DisplayName("alice"); got != "Old" {
		t.Fatalf("in-memory display name = %q after a failed profile write, want Old (mirrors move only after Commit)", got)
	}
	var name string
	if err := s.db.QueryRow("SELECT name FROM display_names WHERE user = 'alice'").Scan(&name); err != nil || name != "Old" {
		t.Fatalf("persisted display name = %q (err=%v) after a failed profile write, want Old (rolled back)", name, err)
	}
	if got := s.Avatar("alice"); got != "" {
		t.Fatalf("in-memory avatar = %q after a failed profile write, want none", got)
	}
}

// TestMigrate_AvatarsTable_ColumnSetIsPinned is ADR-0034 V7: the avatars table
// holds a user, an avatar id and a timestamp, and nothing else. A future column
// for an email, a real name or an image must fail this test and so force a new
// ADR (conditions 8 and 9 of the identity ADR).
func TestMigrate_AvatarsTable_ColumnSetIsPinned(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	rows, err := s.db.Query("SELECT name, type, pk FROM pragma_table_info('avatars') ORDER BY cid")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name, typ string
		var pk int
		if err := rows.Scan(&name, &typ, &pk); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprintf("%s:%s:pk=%d", name, typ, pk))
	}
	want := []string{"user:TEXT:pk=1", "avatar:TEXT:pk=0", "set_at:TEXT:pk=0"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("avatars columns = %v, want exactly %v (no email / name / image column may be added)", got, want)
	}
}

// TestMigrate_V1DBGainsAvatarsAndKeepsDisplayNames: a DB a pre-ADR-0034 binary
// left at user_version 1 upgrades in place (ADR-0020 additive discipline) and
// its display_names rows are untouched.
func TestMigrate_V1DBGainsAvatarsAndKeepsDisplayNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scoreboard.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate(db, migrations[:1]); err != nil {
		t.Fatalf("migrate to v1: %v", err)
	}
	if _, err := db.Exec("INSERT INTO display_names (user, name, set_at) VALUES ('user3', 'Alice', 't')"); err != nil {
		t.Fatal(err)
	}
	if got := userVersion(t, db); got != 1 {
		t.Fatalf("precondition: user_version = %d, want 1", got)
	}
	_ = db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a v1 db: %v", err)
	}
	defer func() { _ = s.Close() }()
	if got := userVersion(t, s.db); got != latestSchemaVersion(migrations) {
		t.Fatalf("user_version = %d, want latest %d", got, latestSchemaVersion(migrations))
	}
	if got := s.DisplayName("user3"); got != "Alice" {
		t.Fatalf("display name lost in the v1 -> v2 upgrade: %q", got)
	}
	if err := s.SetProfile("user3", nil, func() *string { a := "key-amber"; return &a }(), "t"); err != nil {
		t.Fatalf("avatars table unusable after upgrade: %v", err)
	}
}

// TestMigrate_RollbackToV1_OldBinaryRunsAndAReUpgradeKeepsAvatars is the
// evidence behind the CHANGELOG upgrade note for migration 2. Pointing a
// pre-ADR-0034 image (it knows only migration 1) at a v2 database is refused
// (ADR-0020's downgrade guard, fail-closed). The documented recovery is to set
// `PRAGMA user_version = 1`: `avatars` is additive and the old binary never
// reads it, so the old binary then opens the file and its own tables are
// intact; and re-upgrading later (migration 2 is CREATE TABLE IF NOT EXISTS)
// keeps every avatar row written before the rollback.
func TestMigrate_RollbackToV1_OldBinaryRunsAndAReUpgradeKeepsAvatars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scoreboard.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	name, av := "Alice", "key-amber"
	if err := s.SetProfile("user3", &name, &av, "t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	oldBinary := migrations[:1] // what a pre-ADR-0034 image knows

	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	// 1. unchanged: the old binary refuses a v2 database.
	if err := migrate(db, oldBinary); err == nil || !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("old binary on a v2 db: err = %v, want the downgrade refusal", err)
	}
	// 2. the recovery: set user_version back to 1.
	if _, err := db.Exec("PRAGMA user_version = 1"); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db, oldBinary); err != nil {
		t.Fatalf("old binary on a db rolled back to v1: %v", err)
	}
	if got := userVersion(t, db); got != 1 {
		t.Fatalf("user_version = %d after the old binary ran, want 1 (it must not touch the counter)", got)
	}
	var n string
	if err := db.QueryRow("SELECT name FROM display_names WHERE user = 'user3'").Scan(&n); err != nil || n != "Alice" {
		t.Fatalf("display_names row after rollback = %q, %v, want Alice", n, err)
	}
	// ...and the old binary can keep writing its own tables.
	if _, err := db.Exec("INSERT INTO display_names (user, name, set_at) VALUES ('user4', 'Bob', 't') ON CONFLICT(user) DO UPDATE SET name = excluded.name"); err != nil {
		t.Fatalf("old binary's own write failed: %v", err)
	}
	_ = db.Close()

	// 3. re-upgrade: migration 2 runs again and the avatar row survived.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("Open (re-upgrade): %v", err)
	}
	defer func() { _ = s2.Close() }()
	if got := userVersion(t, s2.db); got != latestSchemaVersion(migrations) {
		t.Fatalf("user_version = %d after re-upgrade, want %d", got, latestSchemaVersion(migrations))
	}
	if got := s2.Avatar("user3"); got != "key-amber" {
		t.Fatalf("avatar after rollback + re-upgrade = %q, want key-amber (CREATE TABLE IF NOT EXISTS must keep the rows)", got)
	}
	if got := s2.DisplayName("user4"); got != "Bob" {
		t.Fatalf("a row the old binary wrote = %q, want Bob", got)
	}
}
