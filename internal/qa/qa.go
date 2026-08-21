// Package qa persists P25's participant -> operator QA ticket chat state
// (ADR-0006) in its own dedicated SQLite file — physically separate from
// internal/store (scoring/solve state) and internal/scoreboard/scoring
// (grading domain logic). This package imports NEITHER (internal/apispec's
// qa_boundary_test.go machine-checks that, per ADR-0006 Verification 1); the
// separation is structural, not just a naming convention, so a future change
// to the scoring/store packages cannot accidentally couple to (or corrupt)
// QA state, and vice versa.
//
// One "question" is one ticket = one thread: a participant opens it with a
// subject and a first message, and any number of participant follow-ups /
// operator replies get appended to the SAME thread (question_messages),
// never a new one. There is no participant-to-participant path anywhere in
// this package's API — every method either scopes writes to the caller's
// own {user} or is the admin-only, no-{user} variant (ADR-0006 Decision 1's
// one-way design).
//
// "answered" is DERIVED per listing (at least one question_messages row has
// author_role = "admin"), never a stored status column — a cached boolean
// alongside the messages that justify it is a second, independently-mutable
// copy of the same fact, and ADR-0006 Decision 1 explicitly declines that
// drift risk in exchange for a per-listing aggregate query.
//
// IDOR discipline (ADR-0006 Decision 2 / security-engineer finding 4): every
// participant-facing method that takes a question id ALSO takes the
// caller's {user} and performs the (id, user) ownership check and the
// subsequent read/write inside the SAME method call, under the SAME mutex
// hold — never a "check ownership" call followed by a separate "now do the
// thing" call. Splitting those two into separate calls would open a TOCTOU
// gap (a concurrent write landing between the check and the write) and,
// worse, would make it easy for a future caller to invoke the "do the
// thing" half without ever calling the "check" half first. There is
// deliberately no public method that skips the check.
package qa

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned by every lookup-by-id method (GetThread,
// GetThreadForUser, AppendMessageForUser, AppendAdminReply) when no
// matching row exists. For the User-scoped methods this covers TWO distinct
// underlying cases — an unknown id, and an id that exists but belongs to a
// DIFFERENT user — and they are deliberately indistinguishable to the
// caller: a participant probing another participant's ticket id must see
// exactly the same error an unknown id would produce (no existence oracle;
// ADR-0006 Decision 2).
var ErrNotFound = errors.New("qa: question not found")

// AuthorRole is a question_messages row's author_role column value. This
// package has no opinion on trust — it stores whatever AuthorRole its
// caller passes. The discipline of "never take author/author_role from
// request-body input, always hardcode it per-route" lives entirely in
// internal/scoreboard/api's HTTP handlers (ADR-0006 Decision 1 /
// security-engineer finding 1), not here; this package's job is narrower
// (persist + enforce the composite-key ownership check).
type AuthorRole string

const (
	RoleParticipant AuthorRole = "participant"
	RoleAdmin       AuthorRole = "admin"
)

// Message is one question_messages row.
type Message struct {
	AuthorRole AuthorRole `json:"author_role"`
	Author     string     `json:"author"`
	Body       string     `json:"body"`
	CreatedAt  string     `json:"created_at"`
}

// Thread is a full ticket: the question row plus every message, oldest
// first (ADR-0006 Decision 1's QuestionThread response shape).
type Thread struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Subject   string    `json:"subject"`
	CreatedAt string    `json:"created_at"`
	Messages  []Message `json:"messages"`
}

// Summary is one row of a ticket LISTING — never the message bodies
// (ADR-0006 Decision 1's QuestionSummary response shape). User is left
// empty by ListForUser (the caller already knows — it is their own
// {user}) and populated by ListAll (the admin listing adds the owner, per
// Decision 1: "admin一覧のみuserを追加").
type Summary struct {
	ID           string `json:"id"`
	Subject      string `json:"subject"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	Answered     bool   `json:"answered"`
	MessageCount int    `json:"message_count"`
	User         string `json:"user,omitempty"`
}

// Store owns one QA SQLite database. All access goes through methods on
// Store, serialized by a single mutex — the same single-writer discipline
// internal/store.Store uses (conventions I1), applied to this second,
// physically separate file.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

// Open opens (creating if absent) the QA SQLite file at path and ensures
// its schema. Same WAL/synchronous/busy_timeout pragmas as
// internal/store.Open — by convention this lives in the SAME PVC directory
// as SCOREBOARD_DB as a second file (ADR-0006 Decision 3: no new env var,
// no new chart value; the caller derives path from SCOREBOARD_DB's
// directory).
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		// Best-effort, matching internal/store.Open: if the directory already
		// exists (the common case — it is the same PVC mount SCOREBOARD_DB
		// already lives in) this is a no-op; a real failure surfaces from the
		// sql.Open/Exec calls below.
		_ = os.MkdirAll(dir, 0o755)
	}
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS questions (
          id         TEXT PRIMARY KEY,
          user       TEXT NOT NULL,
          subject    TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_questions_user ON questions(user);

        CREATE TABLE IF NOT EXISTS question_messages (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          question_id TEXT NOT NULL REFERENCES questions(id),
          author_role TEXT NOT NULL CHECK (author_role IN ('participant','admin')),
          author      TEXT NOT NULL,
          body        TEXT NOT NULL,
          created_at  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_qmsg_question ON question_messages(question_id);
    `); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema init: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// newID returns a 32-hex-char (16 random bytes) ticket id: URL-path safe
// (unlike base64, which uses '+'/'/'), and non-enumerable — defense in
// depth ON TOP OF the composite-key ownership check (ADR-0006 Decision 3),
// never a substitute for it.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate question id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CreateQuestion opens a new ticket for user: one questions row plus its
// first message, in one transaction so a ticket can never exist with zero
// messages. role/author for that first message are ALWAYS RoleParticipant
// and user — callers (internal/scoreboard/api) must never let request-body
// input reach either parameter.
func (s *Store) CreateQuestion(user, subject, body, at string) (Thread, error) {
	id, err := newID()
	if err != nil {
		return Thread{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return Thread{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	if _, err := tx.Exec(
		`INSERT INTO questions (id, user, subject, created_at) VALUES (?, ?, ?, ?)`,
		id, user, subject, at,
	); err != nil {
		return Thread{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO question_messages (question_id, author_role, author, body, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, string(RoleParticipant), user, body, at,
	); err != nil {
		return Thread{}, err
	}
	if err := tx.Commit(); err != nil {
		return Thread{}, err
	}

	return Thread{
		ID:        id,
		User:      user,
		Subject:   subject,
		CreatedAt: at,
		Messages: []Message{
			{AuthorRole: RoleParticipant, Author: user, Body: body, CreatedAt: at},
		},
	}, nil
}

// ListForUser returns user's own tickets, most-recently-active first.
func (s *Store) ListForUser(user string) ([]Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(`WHERE q.user = ?`, []any{user}, false)
}

// ListAll is the admin listing — every ticket, every user, with Summary.User
// populated on each row (ADR-0006 Decision 1).
func (s *Store) ListAll() ([]Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(``, nil, true)
}

// listLocked implements both ListForUser and ListAll. updated_at is the
// latest message's created_at, falling back to the question's OWN
// created_at via COALESCE for the (currently impossible, since
// CreateQuestion always inserts exactly one message atomically) case of a
// question with zero messages — a LEFT JOIN + aggregate, never a second
// nullable column that could drift out of sync with the messages it
// describes. Caller must hold s.mu.
func (s *Store) listLocked(where string, args []any, withUser bool) ([]Summary, error) {
	query := `
        SELECT q.id, q.user, q.subject, q.created_at,
               COALESCE(MAX(m.created_at), q.created_at) AS updated_at,
               COUNT(m.id) AS message_count,
               SUM(CASE WHEN m.author_role = 'admin' THEN 1 ELSE 0 END) AS admin_count
        FROM questions q
        LEFT JOIN question_messages m ON m.question_id = q.id
        ` + where + `
        GROUP BY q.id
        ORDER BY updated_at DESC
    `
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Summary, 0)
	for rows.Next() {
		var sm Summary
		var user string
		var adminCount int
		if err := rows.Scan(&sm.ID, &user, &sm.Subject, &sm.CreatedAt, &sm.UpdatedAt, &sm.MessageCount, &adminCount); err != nil {
			return nil, err
		}
		sm.Answered = adminCount > 0
		if withUser {
			sm.User = user
		}
		out = append(out, sm)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetThreadForUser fetches qid's full thread, but only when it belongs to
// user — the composite-key ownership check and the read happen inside this
// one call, under one mutex hold (ADR-0006 Decision 2).
func (s *Store) GetThreadForUser(qid, user string) (Thread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadThreadLocked(`WHERE id = ? AND user = ?`, []any{qid, user})
}

// GetThread is the admin variant: no {user} filter — an admin route reaches
// a ticket by qid alone (ADR-0006 Decision 2: admin routes do not go
// through {user}, so there is no composite key to check).
func (s *Store) GetThread(qid string) (Thread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadThreadLocked(`WHERE id = ?`, []any{qid})
}

// loadThreadLocked loads the questions row matching where/args plus its
// full message list. Caller must hold s.mu.
func (s *Store) loadThreadLocked(where string, args []any) (Thread, error) {
	var th Thread
	row := s.db.QueryRow(`SELECT id, user, subject, created_at FROM questions `+where, args...)
	if err := row.Scan(&th.ID, &th.User, &th.Subject, &th.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Thread{}, ErrNotFound
		}
		return Thread{}, err
	}
	msgs, err := s.loadMessagesLocked(th.ID)
	if err != nil {
		return Thread{}, err
	}
	th.Messages = msgs
	return th, nil
}

// loadMessagesLocked returns qid's messages, oldest first. Caller must hold
// s.mu.
func (s *Store) loadMessagesLocked(qid string) ([]Message, error) {
	rows, err := s.db.Query(
		`SELECT author_role, author, body, created_at FROM question_messages WHERE question_id = ? ORDER BY id ASC`,
		qid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Message, 0)
	for rows.Next() {
		var m Message
		var role string
		if err := rows.Scan(&role, &m.Author, &m.Body, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.AuthorRole = AuthorRole(role)
		out = append(out, m)
	}
	return out, rows.Err()
}

// AppendMessageForUser appends a participant follow-up to qid, but only
// when qid belongs to user. The ownership check and the insert happen
// inside ONE transaction, under one mutex hold (ADR-0006 Decision 2 /
// security-engineer finding 4) — there is no separate "check" call a
// caller could invoke without the "write" half, and no window between the
// check and the write for a concurrent mutation to land in. role/author for
// the new message are ALWAYS RoleParticipant and user — callers must never
// let request-body input reach either.
func (s *Store) AppendMessageForUser(qid, user, body, at string) (Thread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return Thread{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	var owner string
	if err := tx.QueryRow(`SELECT user FROM questions WHERE id = ?`, qid).Scan(&owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Thread{}, ErrNotFound
		}
		return Thread{}, err
	}
	if owner != user {
		// Same ErrNotFound as "unknown id" — no existence oracle for another
		// participant's ticket (ADR-0006 Decision 2).
		return Thread{}, ErrNotFound
	}
	if _, err := tx.Exec(
		`INSERT INTO question_messages (question_id, author_role, author, body, created_at) VALUES (?, ?, ?, ?, ?)`,
		qid, string(RoleParticipant), user, body, at,
	); err != nil {
		return Thread{}, err
	}
	if err := tx.Commit(); err != nil {
		return Thread{}, err
	}

	return s.loadThreadLocked(`WHERE id = ?`, []any{qid})
}

// AppendAdminReply appends an operator reply to qid. No ownership check —
// an admin route reaches any qid by id alone (ADR-0006 Decision 2).
// role/author are ALWAYS RoleAdmin and adminEmail — callers must never let
// request-body input reach either (this is what keeps "answered" honest:
// it is derived from author_role = "admin" rows, and this is the ONLY
// method that ever writes one).
func (s *Store) AppendAdminReply(qid, adminEmail, body, at string) (Thread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return Thread{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM questions WHERE id = ?`, qid).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Thread{}, ErrNotFound
		}
		return Thread{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO question_messages (question_id, author_role, author, body, created_at) VALUES (?, ?, ?, ?, ?)`,
		qid, string(RoleAdmin), adminEmail, body, at,
	); err != nil {
		return Thread{}, err
	}
	if err := tx.Commit(); err != nil {
		return Thread{}, err
	}

	return s.loadThreadLocked(`WHERE id = ?`, []any{qid})
}
