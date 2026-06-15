// Package store owns scoreboard persistence and in-memory state.
//
// Persistence (SQLite, WAL):
//   - solved (user, challenge, at)  PRIMARY KEY (user, challenge)
//
// In-memory only (reset on pod restart):
//   - eventsPerUser: dashboard counter. Not used for scoring.
//   - ruleFires per user: bounded to the last 5 minutes per user.
//     Evade windowing is briefly less strict after a restart until
//     events flow again.
//
// All state mutations go through methods on Store and are guarded by a
// single mutex. Concurrent reads use the same mutex — fine for the
// expected scale (single replica, low QPS).
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	_ "modernc.org/sqlite"
)

// RetentionSeconds is how long recent Falco rule-fires are kept for the evade
// forbidden-rule lookback. Intentionally fixed at 5 min: comfortably covers the
// largest challenge windowSeconds (30s today) plus operator margin, while
// bounding the in-memory/table growth. Not an operator tuning knob — raising it
// only matters if a challenge ever needs a >5min evade window.
const RetentionSeconds = 300

type SolveKey struct {
	User      string
	Challenge string
}

type Store struct {
	mu sync.Mutex
	db *sql.DB

	solved        map[SolveKey]string // value = ISO-8601 timestamp
	eventsPerUser map[string]int
	ruleFires     map[string][]ruleFire // user -> bounded list (RetentionSeconds)
	displayNames  map[string]string     // user -> participant-chosen display name
}

type ruleFire struct {
	Rule string
	At   float64 // unix seconds
}

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		// Best-effort. If the directory already exists or is a mount point,
		// MkdirAll is a no-op. If it can't be created, db open will surface
		// the real error below.
		_ = os.MkdirAll(dir, 0o755)
	}
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(`
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
        DROP TABLE IF EXISTS events_per_user;
    `); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema init: %w", err)
	}

	s := &Store{
		db:            db,
		solved:        make(map[SolveKey]string),
		eventsPerUser: make(map[string]int),
		ruleFires:     make(map[string][]ruleFire),
		displayNames:  make(map[string]string),
	}
	if err := s.loadFromDB(); err != nil {
		db.Close()
		return nil, fmt.Errorf("load initial state: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) loadFromDB() error {
	rows, err := s.db.Query("SELECT user, challenge, at FROM solved")
	if err != nil {
		return err
	}
	for rows.Next() {
		var k SolveKey
		var at string
		if err := rows.Scan(&k.User, &k.Challenge, &at); err != nil {
			rows.Close()
			return err
		}
		s.solved[k] = at
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	dn, err := s.db.Query("SELECT user, name FROM display_names")
	if err != nil {
		return err
	}
	defer dn.Close()
	for dn.Next() {
		var user, name string
		if err := dn.Scan(&user, &name); err != nil {
			return err
		}
		s.displayNames[user] = name
	}
	return dn.Err()
}

// ErrDisplayNameAlreadySet is returned by SetDisplayName when the user
// already has a name recorded. Display names are operator-seeded at
// workspace deploy time (via deploy-user.sh --display-name) and not
// re-settable afterwards — the property keeps the leaderboard's name ↔
// real participant binding stable across the event.
var ErrDisplayNameAlreadySet = errors.New("display name already set")

// SetDisplayName records the operator-supplied display name for `user`.
// First-set-wins: if a display name is already recorded, the call
// returns ErrDisplayNameAlreadySet without modifying the row. Identity
// (`user`) is the auth-derived stable key — anything that scores or
// audits goes via identity; `name` is purely cosmetic.
func (s *Store) SetDisplayName(user, name, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.displayNames[user]; ok && existing != "" {
		return ErrDisplayNameAlreadySet
	}
	if _, err := s.db.Exec(
		`INSERT INTO display_names (user, name, set_at) VALUES (?, ?, ?)`,
		user, name, at,
	); err != nil {
		return err
	}
	s.displayNames[user] = name
	return nil
}

// DisplayName returns the chosen name for `user`, falling back to `user`
// itself when none is set. Callers should not need to handle the missing
// case — the fallback keeps rendering paths uniform.
func (s *Store) DisplayName(user string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.displayNames[user]; ok && n != "" {
		return n
	}
	return user
}

// RecordRuleFire bumps the per-user event count (in-memory only) and appends
// to the bounded ruleFires window. Returns the user's new event count.
func (s *Store) RecordRuleFire(user, rule string, atUnix float64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.eventsPerUser[user]++
	count := s.eventsPerUser[user]

	fires := append(s.ruleFires[user], ruleFire{Rule: rule, At: atUnix})
	cutoff := atUnix - float64(RetentionSeconds)
	kept := fires[:0]
	for _, f := range fires {
		if f.At >= cutoff {
			kept = append(kept, f)
		}
	}
	s.ruleFires[user] = kept
	return count, nil
}

// MarkSolved records a (user, challenge) solve at `at`. Idempotent — the
// first solve wins.
func (s *Store) MarkSolved(user, challenge, at string) (newly bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := SolveKey{User: user, Challenge: challenge}
	if _, exists := s.solved[key]; exists {
		return false, nil
	}
	if _, err := s.db.Exec(
		"INSERT OR IGNORE INTO solved (user, challenge, at) VALUES (?, ?, ?)",
		user, challenge, at,
	); err != nil {
		return false, err
	}
	s.solved[key] = at
	return true, nil
}

// RuleFire is the public projection of a recorded Falco rule fire.
// Returned by RecentRuleFires for participant self-service displays.
type RuleFire struct {
	Rule string  `json:"rule"`
	At   float64 `json:"at"` // unix seconds
}

// RecentRuleFires returns all rule fires for `user` within the last
// `windowSeconds`, in arrival order. Unlike RecentForbiddenFires (which
// returns a *set* of rule names for evade-window checks), this returns the
// raw stream so the participant /me page can show what they just triggered.
func (s *Store) RecentRuleFires(user string, now float64, windowSeconds int) []RuleFire {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now - float64(windowSeconds)
	fires := s.ruleFires[user]
	out := make([]RuleFire, 0, len(fires))
	for _, f := range fires {
		if f.At >= cutoff {
			out = append(out, RuleFire{Rule: f.Rule, At: f.At})
		}
	}
	return out
}

// RecentForbiddenFires returns the *set* of forbidden rules (sorted) that
// fired for `user` within the last `windowSeconds` from `now`. Empty slice
// means the evade window is clean.
func (s *Store) RecentForbiddenFires(user string, forbidden []string, now float64, windowSeconds int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now - float64(windowSeconds)
	want := make(map[string]struct{}, len(forbidden))
	for _, r := range forbidden {
		want[r] = struct{}{}
	}
	seen := make(map[string]struct{})
	for _, f := range s.ruleFires[user] {
		if f.At < cutoff {
			continue
		}
		if _, ok := want[f.Rule]; !ok {
			continue
		}
		seen[f.Rule] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// Snapshot returns a deep-copied view of persisted state. Used by /api/state
// to build the dashboard JSON without holding the lock during serialization.
type Snapshot struct {
	Solved        map[SolveKey]string
	EventsPerUser map[string]int
	DisplayNames  map[string]string
}

func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Snapshot{
		Solved:        make(map[SolveKey]string, len(s.solved)),
		EventsPerUser: make(map[string]int, len(s.eventsPerUser)),
		DisplayNames:  make(map[string]string, len(s.displayNames)),
	}
	for k, v := range s.solved {
		out.Solved[k] = v
	}
	for k, v := range s.eventsPerUser {
		out.EventsPerUser[k] = v
	}
	for k, v := range s.displayNames {
		out.DisplayNames[k] = v
	}
	return out
}

func (s *Store) SolvedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.solved)
}

// Reset clears all solves (DB + memory) and the in-memory event / rule-fire
// counters, returning the scoreboard to an empty state. Returns how many
// solves were cleared. Display names are deliberately preserved — they are
// operator-seeded participant identities (re-set only on workspace deploy),
// not "results". Used by the admin reset endpoint to wipe a demo/test run
// before the real event starts.
func (s *Store) Reset() (clearedSolves int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec("DELETE FROM solved"); err != nil {
		return 0, fmt.Errorf("reset solved: %w", err)
	}
	clearedSolves = len(s.solved)
	s.solved = make(map[SolveKey]string)
	s.eventsPerUser = make(map[string]int)
	s.ruleFires = make(map[string][]ruleFire)
	return clearedSolves, nil
}
