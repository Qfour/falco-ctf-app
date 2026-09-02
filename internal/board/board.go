// Package board persists the QA Board (app#292 Phase 1) — a
// destination-based replacement for P25's per-user QA ticket chat
// (internal/qa) — in its own dedicated SQLite file (board.db), physically
// separate from internal/store (scoring/solve state) and
// internal/scoreboard/scoring (grading domain logic). This package imports
// NEITHER (internal/apispec's board_boundary_test.go machine-checks that,
// the same shape ADR-0006 Verification 1 already applies to internal/qa);
// the separation is structural, not just a naming convention, so a future
// change to the scoring/store packages cannot accidentally couple to (or
// corrupt) Board state, and vice versa.
//
// board.db is a NEW file — this package never opens qa.db. P25's per-user
// QA tickets are not migrated forward; the design intentionally starts
// Board from an empty file rather than reading qa.db's rows, so a bug in a
// hypothetical migrator could never leak one participant's private P25
// ticket into the wrong audience under the new model. (P25 never shipped to
// a live event — there is no production data this would lose.)
//
// Destination model (architect design, app#292): every thread declares an
// Audience at creation time — "admin" (visible ONLY to its author and
// admins; the P25 default, fail-closed) or "all" (visible to every
// authenticated participant; the new public-board case). Audience is fixed
// at creation — no method in this package changes it.
//
// Authorization is enforced HERE, mechanically, not left to callers to get
// right per-route:
//   - Every method that reads or writes a specific thread by id takes the
//     caller's identity ({viewer}/{author}) as an explicit parameter and
//     performs the ownership/audience check and the read/write inside the
//     SAME method call — never a separate "check" call followed by a
//     separate "now do the thing" call (the same IDOR discipline
//     internal/qa's package doc describes, applied to a richer visibility
//     rule: audience OR ownership, not ownership alone).
//   - There is no existence oracle: an unknown thread id, an "admin"
//     audience thread belonging to a different participant, and a
//     moderated-away (hidden/deleted) thread all produce the exact same
//     ErrNotFound to a non-admin caller.
//   - Replies are admin-only. There is deliberately no method that lets one
//     participant post into another participant's thread, or into someone
//     else's "all"-audience thread as anything other than a like — the
//     participant write surface is exactly three shapes: CreateThread (a
//     new thread, own audience choice), AppendOwnMessage (append to a
//     thread THEY opened), and Like/Unlike (a toggle on an "all"-audience
//     thread that is not their own). Every other mutation
//     (AppendAdminReply, SetThreadState, SetMessageState) takes no
//     ownership parameter because it is reachable only from an admin route.
//
// Moderation state ("visible" / "hidden" / "deleted") is a STORED column on
// both board_threads and board_messages, set only by SetThreadState /
// SetMessageState (admin-only). "hidden" removes a thread/message from
// non-admin reads (list AND get) while leaving it fully intact for admins.
// "deleted" goes further: a deleted MESSAGE's Body is scrubbed to "" in
// EVERY method's return value, including the admin's — deleting is a
// content removal, not a from-participants-only hide. (A deleted THREAD's
// messages are still individually visible-or-not per their own message
// state to an admin; deleted only changes the thread's own listing/get
// visibility to non-admins, same as hidden.)
//
// Answered is a stored column (unlike P25's derived-per-listing Answered),
// per app#292's design: admin moderation sets it explicitly via
// SetThreadState. AppendAdminReply also flips it to true as a convenience
// (a reply is presumptively an answer), but it remains overridable — an
// admin can still explicitly set Answered back to false via SetThreadState
// (e.g. "we replied to ask a clarifying question, this isn't answered yet").
package board

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned by every lookup-by-id method when the caller may
// not see the target thread — an unknown id, a wrong-audience id, and a
// moderated-away id are all indistinguishable to a non-admin caller (no
// existence oracle; mirrors internal/qa's ErrNotFound discipline).
var ErrNotFound = errors.New("board: thread not found")

// ErrSelfLike is returned by Like when the caller is the thread's own
// author — liking your own thread is not a like/dislike signal worth
// storing, and the destination model already lets a participant see their
// own "admin"-audience threads without the like affordance meaning
// anything there (Like is audience='all' only in the first place).
var ErrSelfLike = errors.New("board: cannot like your own thread")

// ErrInvalidAudience is returned by CreateThread when audience is neither
// AudienceAdmin nor AudienceAll.
var ErrInvalidAudience = errors.New(`board: audience must be "admin" or "all"`)

// ErrInvalidState is returned by SetThreadState/SetMessageState when the
// requested state is not one of StateVisible/StateHidden/StateDeleted.
var ErrInvalidState = errors.New(`board: state must be "visible", "hidden", or "deleted"`)

// Audience is a board_threads.audience column value, fixed at CreateThread
// time and never changed afterward by any method in this package.
type Audience string

const (
	// AudienceAdmin: visible only to the thread's own author and admins —
	// the private, P25-equivalent case. This is the schema's DEFAULT
	// (fail-closed side: a thread whose audience somehow failed to be set
	// explicitly stays private, never public).
	AudienceAdmin Audience = "admin"
	// AudienceAll: visible to every authenticated participant — the new
	// public-board case.
	AudienceAll Audience = "all"
)

// AuthorRole is a board_messages.author_role column value. Like
// internal/qa, this package has no opinion on trust — it stores whatever
// AuthorRole its caller passes. The discipline of "never take author/
// author_role from request-body input, always hardcode it per-route" lives
// in the HTTP layer (a future phase), not here.
type AuthorRole string

const (
	RoleParticipant AuthorRole = "participant"
	RoleAdmin       AuthorRole = "admin"
)

// State is a moderation state shared by both board_threads.state and
// board_messages.state — the two columns use the identical three-value
// enum, so one Go type serves both rather than two structurally identical
// types that could drift apart.
type State string

const (
	StateVisible State = "visible"
	StateHidden  State = "hidden"
	StateDeleted State = "deleted"
)

// Message is one board_messages row. Body is forced to "" whenever State is
// StateDeleted, in every method that returns a Message — see the package
// doc's "Moderation state" paragraph.
type Message struct {
	ID         string     `json:"id"`
	AuthorRole AuthorRole `json:"author_role"`
	Author     string     `json:"author"`
	Body       string     `json:"body"`
	CreatedAt  string     `json:"created_at"`
	State      State      `json:"state"`
}

// Thread is a full board thread: the board_threads row plus every message
// this viewer/role is entitled to see (oldest first), plus this thread's
// like count and whether the CALLER (the {viewer} passed to GetThread) has
// liked it.
type Thread struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Audience  Audience  `json:"audience"`
	Subject   string    `json:"subject"`
	CreatedAt string    `json:"created_at"`
	Pinned    bool      `json:"pinned"`
	Answered  bool      `json:"answered"`
	State     State     `json:"state"`
	Messages  []Message `json:"messages"`
	LikeCount int       `json:"like_count"`
	Liked     bool      `json:"liked"`
}

// ThreadSummary is one row of a thread LISTING — never the message bodies.
type ThreadSummary struct {
	ID           string   `json:"id"`
	Author       string   `json:"author"`
	Audience     Audience `json:"audience"`
	Subject      string   `json:"subject"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
	Pinned       bool     `json:"pinned"`
	Answered     bool     `json:"answered"`
	State        State    `json:"state"`
	MessageCount int      `json:"message_count"`
	LikeCount    int      `json:"like_count"`
	Liked        bool     `json:"liked"`
}

// ThreadStateUpdate is SetThreadState's partial-update argument: only
// non-nil fields are written. This lets an admin flip just `pinned`, or
// just `state`, or any combination, in one UPDATE, without callers having
// to first read the current row to fill in the fields they don't want to
// change.
type ThreadStateUpdate struct {
	Pinned   *bool
	Answered *bool
	State    *State
}

// Store owns one board SQLite database. All access goes through methods on
// Store, serialized by a single mutex — the same single-writer discipline
// internal/store.Store and internal/qa.Store use (Hard Invariant I1),
// applied to this third, physically separate file.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

// Open opens (creating if absent) the board SQLite file at path and
// migrates its schema to the latest version (migrations.go). Same
// WAL/synchronous/busy_timeout pragmas as internal/store.Open and
// internal/qa.Open.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		// Best-effort, matching internal/store.Open and internal/qa.Open: if
		// the directory already exists (the common case — it is the same
		// PVC mount SCOREBOARD_DB/qa.db already live in) this is a no-op; a
		// real failure surfaces from the sql.Open/migrate calls below.
		_ = os.MkdirAll(dir, 0o755)
	}
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := migrate(db, migrations); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// sqliteDSN builds the modernc.org/sqlite DSN this package always opens
// with. Factored out so migration tests can open the exact same DSN a real
// Store.Open would, without duplicating the pragma string (mirrors
// internal/store.sqliteDSN).
func sqliteDSN(path string) string {
	return path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
}

// Close closes the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// newID returns a 32-hex-char (16 random bytes) id: URL-path safe, and
// non-enumerable — defense in depth ON TOP OF the ownership/audience check
// every method performs, never a substitute for it (same rationale as
// internal/qa.newID).
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate board id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateThread opens a new thread for author with the given audience: one
// board_threads row plus its first message, in one transaction so a thread
// can never exist with zero messages. audience must be AudienceAdmin or
// AudienceAll (any other value, including empty string, is
// ErrInvalidAudience — never silently coerced to the schema's fail-closed
// DEFAULT). role/author for that first message are ALWAYS RoleParticipant
// and author — callers (a future HTTP layer) must never let request-body
// input reach either parameter.
func (s *Store) CreateThread(author string, audience Audience, subject, firstBody, at string) (string, error) {
	if audience != AudienceAdmin && audience != AudienceAll {
		return "", ErrInvalidAudience
	}
	tid, err := newID()
	if err != nil {
		return "", err
	}
	mid, err := newID()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	if _, err := tx.Exec(
		`INSERT INTO board_threads (id, author, audience, subject, created_at) VALUES (?, ?, ?, ?, ?)`,
		tid, author, string(audience), subject, at,
	); err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO board_messages (id, thread_id, author_role, author, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		mid, tid, string(RoleParticipant), author, firstBody, at,
	); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return tid, nil
}

// ListThreads returns a thread listing, pinned-first then
// most-recently-active first.
//
// isAdmin=true (admin listing): every thread, every audience, every state
// (hidden/deleted included) — an admin moderation queue needs to see what
// it has already acted on, not just the live/public set.
//
// isAdmin=false (participant listing, scoped to viewer): only
// state='visible' threads where EITHER audience='all' (every participant
// sees every public thread) OR (audience='admin' AND author=viewer) (a
// participant sees their own private threads, never anyone else's).
func (s *Store) ListThreads(viewer string, isAdmin bool) ([]ThreadSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	where := ""
	args := []any{viewer} // for the `liked` correlated subquery, always first
	if !isAdmin {
		where = `WHERE t.state = 'visible' AND (t.audience = 'all' OR (t.audience = 'admin' AND t.author = ?))`
		args = append(args, viewer)
	}
	query := `
        SELECT t.id, t.author, t.audience, t.subject, t.created_at, t.pinned, t.answered, t.state,
               COALESCE(MAX(m.created_at), t.created_at) AS updated_at,
               COUNT(DISTINCT m.id) AS message_count,
               (SELECT COUNT(*) FROM board_likes l WHERE l.thread_id = t.id) AS like_count,
               EXISTS(SELECT 1 FROM board_likes l2 WHERE l2.thread_id = t.id AND l2.user = ?) AS liked
        FROM board_threads t
        LEFT JOIN board_messages m ON m.thread_id = t.id
        ` + where + `
        GROUP BY t.id
        ORDER BY t.pinned DESC, updated_at DESC
    `
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ThreadSummary, 0)
	for rows.Next() {
		var sm ThreadSummary
		var audience, state string
		var pinned, answered, liked int
		if err := rows.Scan(
			&sm.ID, &sm.Author, &audience, &sm.Subject, &sm.CreatedAt, &pinned, &answered, &state,
			&sm.UpdatedAt, &sm.MessageCount, &sm.LikeCount, &liked,
		); err != nil {
			return nil, err
		}
		sm.Audience = Audience(audience)
		sm.State = State(state)
		sm.Pinned = pinned != 0
		sm.Answered = answered != 0
		sm.Liked = liked != 0
		out = append(out, sm)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetThread fetches tid's full thread, but only when viewer is entitled to
// see it (isAdmin=true bypasses that check entirely — an admin route
// reaches any tid by id alone, no ownership/audience gate). The
// entitlement check and the read happen inside this one call, under one
// mutex hold (same IDOR discipline internal/qa.GetThreadForUser documents).
func (s *Store) GetThread(viewer string, isAdmin bool, tid string) (Thread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	th, err := s.loadThreadLocked(tid, isAdmin)
	if err != nil {
		return Thread{}, err
	}
	if !isAdmin && !visibleToParticipant(th, viewer) {
		// Same ErrNotFound as "unknown id" — no existence oracle for a
		// wrong-audience or moderated-away thread.
		return Thread{}, ErrNotFound
	}

	count, liked, err := s.likeStatusLocked(tid, viewer)
	if err != nil {
		return Thread{}, err
	}
	th.LikeCount = count
	th.Liked = liked
	return th, nil
}

// visibleToParticipant is GetThread/AppendOwnMessage's shared entitlement
// rule for a non-admin viewer: the thread must be state='visible', AND
// either audience='all' (public) or (audience='admin' AND the viewer is
// its own author).
func visibleToParticipant(th Thread, viewer string) bool {
	if th.State != StateVisible {
		return false
	}
	if th.Audience == AudienceAll {
		return true
	}
	return th.Audience == AudienceAdmin && th.Author == viewer
}

// loadThreadLocked loads the board_threads row for tid (regardless of
// state/audience — visibility is the CALLER's job, see visibleToParticipant
// above) plus its message list, filtered per isAdmin (see
// loadMessagesLocked). Caller must hold s.mu.
func (s *Store) loadThreadLocked(tid string, isAdmin bool) (Thread, error) {
	var th Thread
	var audience, state string
	var pinned, answered int
	row := s.db.QueryRow(
		`SELECT id, author, audience, subject, created_at, pinned, answered, state FROM board_threads WHERE id = ?`,
		tid,
	)
	if err := row.Scan(&th.ID, &th.Author, &audience, &th.Subject, &th.CreatedAt, &pinned, &answered, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Thread{}, ErrNotFound
		}
		return Thread{}, err
	}
	th.Audience = Audience(audience)
	th.State = State(state)
	th.Pinned = pinned != 0
	th.Answered = answered != 0

	msgs, err := s.loadMessagesLocked(tid, isAdmin)
	if err != nil {
		return Thread{}, err
	}
	th.Messages = msgs
	return th, nil
}

// loadMessagesLocked returns tid's messages, oldest first (ORDER BY rowid —
// board_messages' primary key is the TEXT id, not an AUTOINCREMENT integer
// like internal/qa's question_messages, so insertion order is recovered via
// SQLite's implicit rowid rather than the declared PK; a TEXT PRIMARY KEY
// does not suppress the hidden rowid column unless the table is declared
// WITHOUT ROWID, which this schema does not do). Caller must hold s.mu.
//
// isAdmin=false: only state='visible' messages (hidden/deleted messages are
// omitted from the slice ENTIRELY, not merely body-scrubbed — "messages は
// 非 admin には visible のみ").
//
// isAdmin=true: every message regardless of state, but a state='deleted'
// message's Body is forced to "" — deleted content is scrubbed from every
// return value, including the admin's (see package doc).
func (s *Store) loadMessagesLocked(tid string, isAdmin bool) ([]Message, error) {
	where := `WHERE thread_id = ?`
	if !isAdmin {
		where += ` AND state = 'visible'`
	}
	rows, err := s.db.Query(
		`SELECT id, author_role, author, body, created_at, state FROM board_messages `+where+` ORDER BY rowid ASC`,
		tid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Message, 0)
	for rows.Next() {
		var m Message
		var role, state string
		if err := rows.Scan(&m.ID, &role, &m.Author, &m.Body, &m.CreatedAt, &state); err != nil {
			return nil, err
		}
		m.AuthorRole = AuthorRole(role)
		m.State = State(state)
		if m.State == StateDeleted {
			m.Body = ""
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// likeStatusLocked returns tid's total like count and whether viewer
// specifically has liked it. viewer="" (no authenticated identity to check)
// always reports liked=false. Caller must hold s.mu.
func (s *Store) likeStatusLocked(tid, viewer string) (count int, liked bool, err error) {
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM board_likes WHERE thread_id = ?`, tid).Scan(&count); err != nil {
		return 0, false, err
	}
	if viewer == "" {
		return count, false, nil
	}
	var exists int
	err = s.db.QueryRow(`SELECT 1 FROM board_likes WHERE thread_id = ? AND user = ?`, tid, viewer).Scan(&exists)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return count, false, nil
		}
		return 0, false, err
	}
	return count, true, nil
}

// AppendOwnMessage appends a participant follow-up to tid, but only when
// tid was opened by author — the ownership check and the insert happen
// inside ONE transaction, under one mutex hold (no separate "check" call a
// caller could invoke without the "write" half — same discipline
// internal/qa.AppendMessageForUser documents). role/author for the new
// message are ALWAYS RoleParticipant and author — callers must never let
// request-body input reach either.
func (s *Store) AppendOwnMessage(author, tid, body, at string) (Thread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return Thread{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	var owner string
	if err := tx.QueryRow(`SELECT author FROM board_threads WHERE id = ?`, tid).Scan(&owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Thread{}, ErrNotFound
		}
		return Thread{}, err
	}
	if owner != author {
		// Same ErrNotFound as "unknown id" — no existence oracle for
		// another participant's thread.
		return Thread{}, ErrNotFound
	}

	mid, err := newID()
	if err != nil {
		return Thread{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO board_messages (id, thread_id, author_role, author, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		mid, tid, string(RoleParticipant), author, body, at,
	); err != nil {
		return Thread{}, err
	}
	if err := tx.Commit(); err != nil {
		return Thread{}, err
	}

	th, err := s.loadThreadLocked(tid, false)
	if err != nil {
		return Thread{}, err
	}
	count, liked, err := s.likeStatusLocked(tid, author)
	if err != nil {
		return Thread{}, err
	}
	th.LikeCount, th.Liked = count, liked
	return th, nil
}

// AppendAdminReply appends an operator reply to tid. No ownership check —
// an admin route reaches any tid by id alone. role/author are ALWAYS
// RoleAdmin and adminAuthor — callers must never let request-body input
// reach either. As a convenience, the thread's `answered` column is also
// set to true (an admin reply is presumptively an answer — see package doc;
// this does not prevent a later SetThreadState call from setting it back to
// false).
func (s *Store) AppendAdminReply(adminAuthor, tid, body, at string) (Thread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return Thread{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM board_threads WHERE id = ?`, tid).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Thread{}, ErrNotFound
		}
		return Thread{}, err
	}

	mid, err := newID()
	if err != nil {
		return Thread{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO board_messages (id, thread_id, author_role, author, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		mid, tid, string(RoleAdmin), adminAuthor, body, at,
	); err != nil {
		return Thread{}, err
	}
	if _, err := tx.Exec(`UPDATE board_threads SET answered = 1 WHERE id = ?`, tid); err != nil {
		return Thread{}, err
	}
	if err := tx.Commit(); err != nil {
		return Thread{}, err
	}

	th, err := s.loadThreadLocked(tid, true)
	if err != nil {
		return Thread{}, err
	}
	count, liked, err := s.likeStatusLocked(tid, adminAuthor)
	if err != nil {
		return Thread{}, err
	}
	th.LikeCount, th.Liked = count, liked
	return th, nil
}

// Like registers user's like on tid, idempotently (INSERT OR IGNORE — a
// second Like call from the same user is a no-op, never an error; this is
// the toggle's "already on" case). Two conditions are enforced BEFORE the
// insert, both fail-closed to ErrNotFound/ErrSelfLike rather than silently
// doing nothing:
//
//   - audience must be AudienceAll. An "admin"-audience thread is never
//     likeable — the participant UI never even shows a like affordance for
//     one, and a forged request against one gets the SAME ErrNotFound an
//     unknown tid would (no existence/audience oracle).
//   - the thread's state must be StateVisible. A hidden/deleted thread is
//     likewise indistinguishable from unknown to this call.
//   - user must not be the thread's own author (ErrSelfLike — a distinct
//     error from ErrNotFound because self-like is a well-formed request
//     about a thread the caller CAN see, just a disallowed action on it,
//     unlike the audience/state checks above which are about a thread the
//     caller should not even know exists).
func (s *Store) Like(user, tid, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var author, audience, state string
	err := s.db.QueryRow(`SELECT author, audience, state FROM board_threads WHERE id = ?`, tid).Scan(&author, &audience, &state)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if audience != string(AudienceAll) || state != string(StateVisible) {
		return ErrNotFound
	}
	if author == user {
		return ErrSelfLike
	}

	_, err = s.db.Exec(
		`INSERT OR IGNORE INTO board_likes (thread_id, user, created_at) VALUES (?, ?, ?)`,
		tid, user, at,
	)
	return err
}

// Unlike removes user's like from tid, idempotently (DELETE is a no-op if
// no row exists — the toggle's "already off" case, and equally a no-op for
// a tid that was never likeable in the first place; there is nothing to
// leak by allowing an unconditional delete here, unlike Like's insert
// path).
func (s *Store) Unlike(user, tid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM board_likes WHERE thread_id = ? AND user = ?`, tid, user)
	return err
}

// SetThreadState applies an admin moderation update to tid: any combination
// of Pinned/Answered/State's non-nil fields, in one UPDATE. Returns
// ErrNotFound if tid does not exist, ErrInvalidState if upd.State is
// non-nil but not one of StateVisible/StateHidden/StateDeleted. A zero-value
// ThreadStateUpdate (no fields set) is a valid no-op call that still
// confirms tid exists (never a silent success for an unknown id).
func (s *Store) SetThreadState(tid string, upd ThreadStateUpdate) error {
	if upd.State != nil {
		switch *upd.State {
		case StateVisible, StateHidden, StateDeleted:
		default:
			return ErrInvalidState
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sets := make([]string, 0, 3)
	args := make([]any, 0, 4)
	if upd.Pinned != nil {
		sets = append(sets, "pinned = ?")
		args = append(args, boolToInt(*upd.Pinned))
	}
	if upd.Answered != nil {
		sets = append(sets, "answered = ?")
		args = append(args, boolToInt(*upd.Answered))
	}
	if upd.State != nil {
		sets = append(sets, "state = ?")
		args = append(args, string(*upd.State))
	}
	if len(sets) == 0 {
		var exists int
		err := s.db.QueryRow(`SELECT 1 FROM board_threads WHERE id = ?`, tid).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	args = append(args, tid)
	res, err := s.db.Exec(`UPDATE board_threads SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetMessageState applies an admin moderation state change to a single
// message by id. Returns ErrNotFound if mid does not exist, ErrInvalidState
// if state is not one of StateVisible/StateHidden/StateDeleted.
func (s *Store) SetMessageState(mid string, state State) error {
	switch state {
	case StateVisible, StateHidden, StateDeleted:
	default:
		return ErrInvalidState
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`UPDATE board_messages SET state = ? WHERE id = ?`, string(state), mid)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
