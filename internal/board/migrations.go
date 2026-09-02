package board

import (
	"database/sql"
	"fmt"
)

// Schema migrations for board.db, tracked via SQLite's built-in `PRAGMA
// user_version` integer counter — no new table, no external migration
// library. This is a DELIBERATE duplication of internal/store/migrations.go's
// mechanism (same `PRAGMA user_version` + linear migration list + single-tx
// apply + fail-closed downgrade + assertConsecutiveVersions shape), not a
// shared helper — internal/board must not import internal/store (see
// board.go's package doc and internal/apispec/board_boundary_test.go), so
// the two packages carry independent copies of the same small mechanism
// rather than a shared dependency that would violate that boundary.
//
// Concurrency: identical reasoning to internal/store/migrations.go — a
// single scoreboard replica (Hard Invariant I1) means migrate() never has to
// coordinate against a concurrent migrator in a second process.
//
// Future migrations MUST be additive and MUST NOT edit or renumber a
// migration that has already shipped — append a new entry with the next
// version number instead.
type migration struct {
	version int
	name    string
	// apply runs the migration's schema change inside a transaction that
	// migrate() will commit together with the PRAGMA user_version bump. It
	// must not commit or roll back tx itself.
	apply func(tx *sql.Tx) error
}

// migrations is the ordered, append-only list of schema migrations this
// package knows about. version values must be consecutive starting at 1 —
// migrate() asserts this via assertConsecutiveVersions.
//
// v1 is the FULL destination-model schema (board_threads / board_messages /
// board_likes) — there is no pre-#292 schema to carry forward the way
// internal/store's v1 had to fold in a pre-migrations bootstrap DDL. board.db
// is a brand-new file (never internal/qa's qa.db — see board.go's package
// doc), so v1 can simply be "the schema", nothing more.
var migrations = []migration{
	{
		version: 1,
		name:    "bootstrap: board_threads, board_messages, board_likes",
		apply: func(tx *sql.Tx) error {
			_, err := tx.Exec(`
				CREATE TABLE IF NOT EXISTS board_threads (
				  id         TEXT PRIMARY KEY,
				  author     TEXT NOT NULL,
				  audience   TEXT NOT NULL DEFAULT 'admin' CHECK (audience IN ('admin','all')),
				  subject    TEXT NOT NULL,
				  created_at TEXT NOT NULL,
				  pinned     INTEGER NOT NULL DEFAULT 0,
				  answered   INTEGER NOT NULL DEFAULT 0,
				  state      TEXT NOT NULL DEFAULT 'visible' CHECK (state IN ('visible','hidden','deleted'))
				);
				CREATE TABLE IF NOT EXISTS board_messages (
				  id          TEXT PRIMARY KEY,
				  thread_id   TEXT NOT NULL REFERENCES board_threads(id),
				  author_role TEXT NOT NULL CHECK (author_role IN ('participant','admin')),
				  author      TEXT NOT NULL,
				  body        TEXT NOT NULL,
				  created_at  TEXT NOT NULL,
				  state       TEXT NOT NULL DEFAULT 'visible' CHECK (state IN ('visible','hidden','deleted'))
				);
				CREATE INDEX IF NOT EXISTS idx_bmsg_thread ON board_messages(thread_id);
				CREATE TABLE IF NOT EXISTS board_likes (
				  thread_id  TEXT NOT NULL REFERENCES board_threads(id),
				  user       TEXT NOT NULL,
				  created_at TEXT NOT NULL,
				  PRIMARY KEY (thread_id, user)
				);
			`)
			return err
		},
	},
}

// latestSchemaVersion is the highest version number in ms, derived from the
// list itself (never hand-maintained) so it cannot drift from what
// migrate() actually applies.
func latestSchemaVersion(ms []migration) int {
	max := 0
	for _, m := range ms {
		if m.version > max {
			max = m.version
		}
	}
	return max
}

// migrate applies every migration in ms whose version is greater than db's
// current `PRAGMA user_version`, in ascending version order, each inside its
// own transaction — the schema change and the version-counter bump commit
// together, so a failure partway through a migration can never leave
// user_version pointing past a schema that only half-applied.
//
// Fail-closed on downgrade: if db's recorded version is NEWER than the
// highest version in ms, migrate refuses to touch the database at all and
// returns an error naming both versions — see
// internal/store/migrations.go's identical function for the full rationale
// (an older binary must never guess at a newer binary's schema).
func migrate(db *sql.DB, ms []migration) error {
	assertConsecutiveVersions(ms)

	var current int
	if err := db.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	latest := latestSchemaVersion(ms)
	if current > latest {
		return fmt.Errorf(
			"board database schema version v%d is newer than this binary supports (v%d); "+
				"refusing to start — this looks like a downgrade (an older binary is "+
				"pointed at a database a newer binary already migrated forward)",
			current, latest,
		)
	}

	for _, m := range ms {
		if m.version <= current {
			continue
		}
		if err := applyOne(db, m); err != nil {
			return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
		}
	}
	return nil
}

// applyOne runs one migration's schema change and its PRAGMA user_version
// bump inside a single transaction, committing only if both succeed.
func applyOne(db *sql.DB, m migration) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	if err := m.apply(tx); err != nil {
		return err
	}
	// PRAGMA user_version does not accept a bound parameter for the value in
	// SQLite; m.version is a compile-time int literal owned by this
	// package's own migrations slice, never external/user input, so
	// building the statement with Sprintf carries no injection risk.
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return tx.Commit()
}

// assertConsecutiveVersions panics if ms's version numbers are not exactly
// 1..len(ms) in order. This is a programmer-error guard on THIS package's
// own migrations slice (never on data read from a database), so panicking
// at call time is the right failure mode — a gap or duplicate here is a bug
// in this file, not a runtime condition callers should have to handle.
func assertConsecutiveVersions(ms []migration) {
	for i, m := range ms {
		if want := i + 1; m.version != want {
			panic(fmt.Sprintf("board: migrations[%d] has version %d, want %d (migrations must be numbered consecutively starting at 1)", i, m.version, want))
		}
	}
}
