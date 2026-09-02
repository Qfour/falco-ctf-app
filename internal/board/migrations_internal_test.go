package board

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMigrate_FreshDB_BootstrapsToLatestVersion mirrors
// internal/store's identically-named test: a brand-new board.db file,
// opened through the normal Store.Open path, ends up stamped at the
// highest version this binary knows about (not left at SQLite's own
// PRAGMA user_version default of 0).
func TestMigrate_FreshDB_BootstrapsToLatestVersion(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "board.db"))
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

// TestMigrate_FreshDB_CreatesAllThreeTables proves v1's DDL actually landed
// all three tables this package's Store methods depend on — a check that
// would catch a copy-paste mistake in migrations.go's apply func that
// TestMigrate_FreshDB_BootstrapsToLatestVersion alone (which only checks
// the version counter) would not.
func TestMigrate_FreshDB_CreatesAllThreeTables(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "board.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	for _, table := range []string{"board_threads", "board_messages", "board_likes"} {
		var name string
		err := s.db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
		).Scan(&name)
		if err != nil {
			t.Fatalf("table %q missing after migrate: %v", table, err)
		}
	}
}

// TestMigrate_PartialFailure_RollsBackAndDoesNotAdvanceVersion is the
// negative-path proof for applyOne's single-transaction design (same shape
// as internal/store's identically-named test): a migration that gets
// partway through its own schema change before failing must leave the
// database exactly as it was — no advanced user_version, none of the
// partially-applied DDL visible, and the connection returned to the pool.
func TestMigrate_PartialFailure_RollsBackAndDoesNotAdvanceVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "board.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := migrate(db, migrations); err != nil {
		t.Fatalf("bootstrap migrate: %v", err)
	}
	baseline := userVersion(t, db)

	failing := append(append([]migration{}, migrations...), migration{
		version: baseline + 1,
		name:    "test-only: partial DDL then fail",
		apply: func(tx *sql.Tx) error {
			if _, err := tx.Exec(`CREATE TABLE mutation_marker (id INTEGER)`); err != nil {
				return err
			}
			return fmt.Errorf("intentional failure after partial DDL")
		},
	})

	if err := migrate(db, failing); err == nil {
		t.Fatal("expected migrate to fail")
	}

	if got := userVersion(t, db); got != baseline {
		t.Fatalf("user_version advanced despite a failed migration: got %d, want unchanged %d", got, baseline)
	}

	var name string
	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'mutation_marker'`,
	).Scan(&name)
	if err != sql.ErrNoRows {
		t.Fatalf("partially-applied schema change (mutation_marker table) leaked out of the failed migration, err=%v", err)
	}

	if stats := db.Stats(); stats.InUse != 0 {
		t.Fatalf("failed migration leaked a checked-out pooled connection (InUse=%d) — applyOne must roll back the transaction so it returns to the pool", stats.InUse)
	}
}

// TestMigrate_FailsClosed_WhenDBVersionNewerThanBinary is the fail-closed
// downgrade-protection proof: a database whose recorded user_version is
// ahead of what this binary's migrations list knows about must refuse to
// open rather than silently proceeding.
func TestMigrate_FailsClosed_WhenDBVersionNewerThanBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "board.db")

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

	msg := err.Error()
	if !strings.Contains(msg, strconv.Itoa(future)) {
		t.Fatalf("error %q must mention the database's version (%d)", msg, future)
	}
	if !strings.Contains(msg, strconv.Itoa(latestSchemaVersion(migrations))) {
		t.Fatalf("error %q must mention the binary's latest known version (%d)", msg, latestSchemaVersion(migrations))
	}
}

// TestAssertConsecutiveVersions_PanicsOnGap guards migrations.go's own
// invariant: version numbers must be exactly 1..len(ms) in order.
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
// migrate() maintains.
func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	return v
}
