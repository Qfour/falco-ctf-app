package store

import (
	"database/sql"
	"fmt"
)

// Schema migrations, tracked via SQLite's built-in `PRAGMA user_version`
// integer counter — no new table, no external migration library (go.mod
// stays as-is; see Issue #117).
//
// Concurrency: scoreboard runs as a SINGLE replica with strategy: Recreate
// and SQLite itself is a single-writer store (Hard Invariant I1 —
// .claude/rules/falco-ctf-app-conventions.md). migrate() therefore never has
// to coordinate against a concurrent migrator running in a second process:
// there is at most one Store.Open call touching this file at a time in any
// real deployment. No advisory lock / "schema_migrations lock row" is
// implemented here — that would be solving a problem this deployment
// topology cannot have. If scoreboard is ever run with replicas > 1, that
// change requires its own design work (well beyond this file) and the
// deployment.yaml `fail` guard described in the k8s chart already blocks it
// long before migrate() would run concurrently.
//
// Versioning: migration #1 is declared to be *exactly* the schema that used
// to run unconditionally on every Open() before this file existed — the
// eight `CREATE TABLE IF NOT EXISTS` statements plus the `DROP TABLE IF
// EXISTS events_per_user` cleanup. Because every one of those statements is
// already idempotent, migration #1 doubles as both:
//
//   - the bootstrap path for a brand-new DB file (PRAGMA user_version starts
//     at SQLite's own default of 0, migration #1 runs, creates the tables,
//     and stamps user_version=1), and
//   - the upgrade path for every pre-existing production DB (created by the
//     OLD code, which never touched user_version — so it also reads back as
//     0, indistinguishable from "nothing applied yet"). Re-running the
//     identical DDL against it is a no-op for the tables (IF NOT EXISTS) and
//     only advances the version counter.
//
// There is deliberately no separate "bootstrap schema" function distinct
// from migration #1 — a second code path that has to independently stay in
// sync with the same DDL would be a drift risk this design avoids.
//
// Future migrations MUST be additive (CREATE TABLE / ALTER TABLE ADD COLUMN
// / CREATE INDEX, etc.) and MUST NOT edit or renumber a migration that has
// already shipped — once a version has run against a production DB, its
// definition is frozen. Append a new entry with the next version number
// instead.
type migration struct {
	version int
	name    string
	// apply runs the migration's schema change inside a transaction that
	// migrate() will commit together with the PRAGMA user_version bump. It
	// must not commit or roll back tx itself.
	apply func(tx *sql.Tx) error
}

// migrations is the ordered, append-only list of schema migrations this
// binary knows about. version values must be consecutive starting at 1 —
// migrate() asserts this (see the "non-consecutive migration versions"
// panic below) rather than silently tolerating a gap, since a gap would
// mean some intermediate schema state was never reachable by design.
var migrations = []migration{
	{
		version: 1,
		name:    "bootstrap: solved, display_names, hint_release, exfil, hint_views, step_checks, evade_dirty, expected_rule_fire",
		apply: func(tx *sql.Tx) error {
			_, err := tx.Exec(`
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
				CREATE TABLE IF NOT EXISTS hint_release (
				  mission TEXT NOT NULL,
				  hint    INTEGER NOT NULL,
				  at      TEXT NOT NULL,
				  PRIMARY KEY (mission, hint)
				);
				CREATE TABLE IF NOT EXISTS exfil (
				  user      TEXT NOT NULL,
				  challenge TEXT NOT NULL,
				  flag      TEXT NOT NULL,
				  at        TEXT NOT NULL,
				  PRIMARY KEY (user, challenge)
				);
				CREATE TABLE IF NOT EXISTS hint_views (
				  user      TEXT NOT NULL,
				  challenge TEXT NOT NULL,
				  hint_idx  INTEGER NOT NULL,
				  at        TEXT NOT NULL,
				  PRIMARY KEY (user, challenge, hint_idx)
				);
				CREATE TABLE IF NOT EXISTS step_checks (
				  user      TEXT NOT NULL,
				  challenge TEXT NOT NULL,
				  step_idx  INTEGER NOT NULL,
				  at        TEXT NOT NULL,
				  PRIMARY KEY (user, challenge, step_idx)
				);
				CREATE TABLE IF NOT EXISTS evade_dirty (
				  user      TEXT NOT NULL,
				  challenge TEXT NOT NULL,
				  rule      TEXT NOT NULL,
				  at        TEXT NOT NULL,
				  PRIMARY KEY (user, challenge, rule)
				);
				CREATE TABLE IF NOT EXISTS expected_rule_fire (
				  user      TEXT NOT NULL,
				  challenge TEXT NOT NULL,
				  rule      TEXT NOT NULL,
				  at        TEXT NOT NULL,
				  PRIMARY KEY (user, challenge, rule)
				);
				DROP TABLE IF EXISTS events_per_user;
			`)
			return err
		},
	},
}

// latestSchemaVersion is the highest version number in migrations, i.e. the
// schema version this binary produces on a fresh DB and expects on an
// up-to-date one. Derived from the list itself (never hand-maintained) so it
// cannot drift from what migrate() actually applies.
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
// returns an error naming both versions. This guards against pointing an
// OLDER binary at a database a NEWER binary already migrated forward — the
// old binary's ms slice has no idea what that future version's schema looks
// like, so silently proceeding (or worse, treating the gap as "nothing to
// do" and just opening the DB) risks the old code reading/writing a schema
// it does not understand.
func migrate(db *sql.DB, ms []migration) error {
	assertConsecutiveVersions(ms)

	var current int
	if err := db.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	latest := latestSchemaVersion(ms)
	if current > latest {
		return fmt.Errorf(
			"database schema version v%d is newer than this binary supports (v%d); "+
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
// at call time (every Store.Open, and every test that calls migrate
// directly) is the right failure mode — a gap or duplicate here is a bug in
// this file, not a runtime condition callers should have to handle.
func assertConsecutiveVersions(ms []migration) {
	for i, m := range ms {
		if want := i + 1; m.version != want {
			panic(fmt.Sprintf("store: migrations[%d] has version %d, want %d (migrations must be numbered consecutively starting at 1)", i, m.version, want))
		}
	}
}
