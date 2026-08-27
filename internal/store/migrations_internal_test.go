package store

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMigrate_FreshDB_BootstrapsToLatestVersion covers Issue #117's core
// claim: a brand-new database file, opened through the normal Store.Open
// path, ends up stamped at the highest version this binary knows about (not
// left at SQLite's own PRAGMA user_version default of 0).
func TestMigrate_FreshDB_BootstrapsToLatestVersion(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	got := userVersion(t, s.db)
	want := latestSchemaVersion(migrations)
	if got != want {
		t.Fatalf("fresh DB user_version = %d, want latestSchemaVersion() = %d", got, want)
	}
}

// TestMigrate_LegacyDBWithoutUserVersion_UpgradesAndPreservesData simulates
// a production DB file created by the OLD pre-#117 code: unconditional
// CREATE TABLE IF NOT EXISTS statements that never touched user_version, so
// it reads back as SQLite's default of 0 — indistinguishable from "no
// migrations applied yet". Opening that file through the new Store.Open
// must (a) advance it to the latest version and (b) leave pre-existing rows
// exactly as they were, proving migration #1's "bootstrap DDL == migration
// #1" design (migrations.go doc) does not disturb real data.
func TestMigrate_LegacyDBWithoutUserVersion_UpgradesAndPreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scoreboard.db")

	legacy, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	// Verbatim reproduction of the schema the pre-#117 code ran on every
	// Open() call, deliberately NOT going through migrate() / PRAGMA
	// user_version — this is what every already-deployed scoreboard.db
	// looks like today.
	if _, err := legacy.Exec(`
		CREATE TABLE IF NOT EXISTS solved (
		  user      TEXT NOT NULL,
		  challenge TEXT NOT NULL,
		  at        TEXT NOT NULL,
		  PRIMARY KEY (user, challenge)
		);
		CREATE TABLE IF NOT EXISTS display_names (
		  user   TEXT PRIMARY KEY,
		  name   TEXT NOT NULL,
		  set_at TEXT NOT NULL
		);
	`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	if _, err := legacy.Exec(
		"INSERT INTO solved (user, challenge, at) VALUES (?, ?, ?)",
		"alice", "01-read-shadow", "2026-05-11T00:00:00Z",
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if got := userVersion(t, legacy); got != 0 {
		t.Fatalf("precondition: legacy db user_version = %d, want 0 (never touched)", got)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on legacy db: %v", err)
	}
	defer func() { _ = s.Close() }()

	if got, want := userVersion(t, s.db), latestSchemaVersion(migrations); got != want {
		t.Fatalf("legacy db after Open: user_version = %d, want %d", got, want)
	}
	if !s.IsSolved("alice", "01-read-shadow") {
		t.Fatal("pre-existing solved row lost during migration — migration #1 must not disturb existing data")
	}
	var at string
	if err := s.db.QueryRow(
		"SELECT at FROM solved WHERE user = ? AND challenge = ?", "alice", "01-read-shadow",
	).Scan(&at); err != nil {
		t.Fatalf("query preserved row: %v", err)
	}
	if at != "2026-05-11T00:00:00Z" {
		t.Fatalf("preserved row's `at` = %q, want original timestamp unchanged", at)
	}
}

// TestMigrate_CanAddAColumn_AndPreservesExistingRows is the migration-path
// proof Issue #117 exists for: before this file, the store package had no
// way to add a column to an existing DB (no ALTER TABLE path, no version
// tracking to decide whether one was needed). This test proves the NEW
// mechanism can — using a synthetic version-N+1 migration defined only in
// this test (the production `migrations` slice in migrations.go is
// deliberately left untouched; see the task's "no real column addition"
// constraint). It seeds a v1 DB with a real row, applies a migration that
// ALTERs the `solved` table, and asserts both that the new column exists
// AND that the pre-existing row's data survived untouched.
func TestMigrate_CanAddAColumnAndPreservesExistingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scoreboard.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := migrate(db, migrations); err != nil {
		t.Fatalf("bootstrap migrate: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO solved (user, challenge, at) VALUES (?, ?, ?)",
		"bob", "02-priv-esc", "2026-05-12T00:00:00Z",
	); err != nil {
		t.Fatalf("seed row before column migration: %v", err)
	}

	nextVersion := latestSchemaVersion(migrations) + 1
	withNewColumn := append(append([]migration{}, migrations...), migration{
		version: nextVersion,
		name:    "test-only: add solved.note column",
		apply: func(tx *sql.Tx) error {
			_, err := tx.Exec(`ALTER TABLE solved ADD COLUMN note TEXT NOT NULL DEFAULT ''`)
			return err
		},
	})

	if err := migrate(db, withNewColumn); err != nil {
		t.Fatalf("apply column migration: %v", err)
	}

	if got := userVersion(t, db); got != nextVersion {
		t.Fatalf("user_version after column migration = %d, want %d", got, nextVersion)
	}

	var user, challenge, at, note string
	if err := db.QueryRow(
		"SELECT user, challenge, at, note FROM solved WHERE user = ? AND challenge = ?",
		"bob", "02-priv-esc",
	).Scan(&user, &challenge, &at, &note); err != nil {
		t.Fatalf("query row via new column (proves ALTER TABLE applied): %v", err)
	}
	if user != "bob" || challenge != "02-priv-esc" || at != "2026-05-12T00:00:00Z" {
		t.Fatalf("pre-existing row corrupted by column migration: got (%q, %q, %q)", user, challenge, at)
	}
	if note != "" {
		t.Fatalf("new column default = %q, want empty string default", note)
	}

	// Re-applying the same migration list must be a no-op (idempotent
	// Open()-on-an-already-migrated-DB path) rather than erroring on a
	// duplicate ALTER TABLE.
	if err := migrate(db, withNewColumn); err != nil {
		t.Fatalf("re-applying an already-applied migration list must be a no-op: %v", err)
	}
}

// TestMigrate_FailsClosed_WhenDBVersionNewerThanBinary is the fail-closed
// downgrade-protection proof the task requires: a database whose recorded
// user_version is ahead of what this binary's migrations list knows about
// (e.g. an older binary deployed against a DB a newer one already migrated)
// must refuse to open rather than silently proceeding.
func TestMigrate_FailsClosed_WhenDBVersionNewerThanBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scoreboard.db")

	// Bring a fresh DB to the latest version, then simulate "a future
	// binary already migrated this file further than what we know about"
	// by bumping user_version past latestSchemaVersion directly.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	future := latestSchemaVersion(migrations) + 3
	if _, err := s.db.Exec("PRAGMA user_version = " + strconv.Itoa(future)); err != nil {
		t.Fatalf("simulate future version: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	again, err := Open(path)
	if err == nil {
		_ = again.Close()
		t.Fatalf("Open on a DB with user_version=%d (newer than latestSchemaVersion=%d) must fail-closed, got nil error",
			future, latestSchemaVersion(migrations))
	}
	if again != nil {
		t.Fatal("Open must return a nil *Store alongside a non-nil error")
	}

	// The error must name BOTH versions (task requirement) so an operator
	// reading logs can immediately see the mismatch without instrumenting
	// further.
	msg := err.Error()
	if !strings.Contains(msg, strconv.Itoa(future)) {
		t.Fatalf("error %q must mention the database's version (%d)", msg, future)
	}
	if !strings.Contains(msg, strconv.Itoa(latestSchemaVersion(migrations))) {
		t.Fatalf("error %q must mention the binary's latest known version (%d)", msg, latestSchemaVersion(migrations))
	}
}

// TestAssertConsecutiveVersions_PanicsOnGap guards migrations.go's own
// invariant: version numbers must be exactly 1..len(ms) in order. A gap or
// duplicate here would mean some intermediate schema state was never
// reachable, which is a bug in this package, not a runtime condition to
// recover from — hence the panic (caught here via recover to prove it
// fires, not to make it a soft failure in production).
func TestAssertConsecutiveVersions_PanicsOnGap(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("assertConsecutiveVersions must panic on a non-consecutive version list")
		}
	}()
	assertConsecutiveVersions([]migration{
		{version: 1, name: "a", apply: func(tx *sql.Tx) error { return nil }},
		{version: 3, name: "b (gap: skipped 2)", apply: func(tx *sql.Tx) error { return nil }},
	})
}

// userVersion reads PRAGMA user_version directly, bypassing any Store
// method — these tests need to observe the raw schema-version counter
// migrate() maintains, which Store deliberately does not expose as public
// API (it is an implementation detail of this package, not something
// callers outside it should branch on).
func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	return v
}
