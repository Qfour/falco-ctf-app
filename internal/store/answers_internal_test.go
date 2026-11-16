package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

// TestMigrate_AnswerAttemptsTable_ColumnSetIsPinned is ADR-0056 D13 at the store:
// answer_attempts holds the key, a count and a flag, and nothing else. A column for
// the text of an answer, a hash of it or a time must fail this test and so force a
// new ADR.
func TestMigrate_AnswerAttemptsTable_ColumnSetIsPinned(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	rows, err := s.db.Query("SELECT name, type, pk FROM pragma_table_info('answer_attempts') ORDER BY cid")
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
	want := []string{"user:TEXT:pk=1", "challenge:TEXT:pk=2", "question:TEXT:pk=3", "n:INTEGER:pk=0", "correct:INTEGER:pk=0"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("answer_attempts columns = %v, want exactly %v (no answer text, hash or time may be added)", got, want)
	}
}

// A corrupt row is a failed write, not a free attempt.
func TestAnswerAttempts_ChecksRefuseACorruptRow(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	for _, q := range []string{
		"INSERT INTO answer_attempts (user, challenge, question, n, correct) VALUES ('a', 'c', 'q1', -1, 0)",
		"INSERT INTO answer_attempts (user, challenge, question, n, correct) VALUES ('a', 'c', 'q2', 0, 2)",
	} {
		if _, err := s.db.Exec(q); err == nil {
			t.Fatalf("the table accepted %q", q)
		}
	}
}

// A database a binary without migration 3 left at user_version 2 gains the table
// in place (ADR-0020 additive discipline) and keeps what it had.
func TestMigrate_V2DBGainsAnswerAttemptsAndKeepsItsRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scoreboard.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate(db, migrations[:2]); err != nil {
		t.Fatalf("migrate to v2: %v", err)
	}
	if _, err := db.Exec("INSERT INTO solved (user, challenge, at) VALUES ('user3', '01-x', 't')"); err != nil {
		t.Fatal(err)
	}
	if got := userVersion(t, db); got != 2 {
		t.Fatalf("precondition: user_version = %d, want 2", got)
	}
	_ = db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a v2 db: %v", err)
	}
	defer func() { _ = s.Close() }()
	if got := userVersion(t, s.db); got != 3 || got != latestSchemaVersion(migrations) {
		t.Fatalf("user_version = %d, want 3 (the latest)", got)
	}
	if !s.IsSolved("user3", "01-x") {
		t.Fatal("a solve was lost in the v2 -> v3 upgrade")
	}
	if res, n, err := s.TryAnswerAttempt("user3", "90-investigate", "who", 2); err != nil || res != AnswerAttemptCounted || n != 1 {
		t.Fatalf("answer_attempts unusable after the upgrade: res=%v n=%d err=%v", res, n, err)
	}
}

// Reset is one transaction (ADR-0056 D7): when the answer counts cannot be
// cleared, the solves are not cleared either, on disk or in memory. Before it, a
// failure on the last table would have left the earlier ones wiped.
func TestReset_IsOneTransactionOverTheSolvesAndTheAnswerCounts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	if _, err := s.MarkSolved("alice", "01-x", "t"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordExfil("alice", "10-final-exfil", "FALCO{x}", "t"); err != nil {
		t.Fatal(err)
	}
	// Break ONLY the last table of the reset, so every earlier DELETE would
	// succeed in isolation.
	if _, err := s.db.Exec("DROP TABLE answer_attempts"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reset(); err == nil {
		t.Fatal("test precondition: expected Reset to fail once answer_attempts is gone")
	}
	if !s.IsSolved("alice", "01-x") || !s.HasExfilAny("alice", "10-final-exfil") {
		t.Fatal("a failed Reset cleared the in-memory solves or receipt")
	}
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM solved").Scan(&n); err != nil || n != 1 {
		t.Fatalf("persisted solves after a failed Reset = %d (%v), want 1 (rolled back)", n, err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM exfil").Scan(&n); err != nil || n != 1 {
		t.Fatalf("persisted exfil after a failed Reset = %d (%v), want 1 (rolled back)", n, err)
	}
}
