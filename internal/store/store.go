// Package store owns scoreboard persistence and in-memory state.
//
// Persistence (SQLite, WAL):
//   - solved          (user, challenge, at)  PRIMARY KEY (user, challenge)
//   - events_per_user (user PRIMARY KEY, count)
//
// In-memory only:
//   - ruleFires per user: bounded to the last 5 minutes per user. Pod
//     restart loses this; evade windowing is briefly less strict until
//     events flow again.
//
// All state mutations go through methods on Store and are guarded by a
// single mutex. Concurrent reads use the same mutex — fine for the
// expected scale (single replica, low QPS).
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	_ "modernc.org/sqlite"
)

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
        CREATE TABLE IF NOT EXISTS events_per_user (
          user  TEXT PRIMARY KEY,
          count INTEGER NOT NULL DEFAULT 0
        );
    `); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema init: %w", err)
	}

	s := &Store{
		db:            db,
		solved:        make(map[SolveKey]string),
		eventsPerUser: make(map[string]int),
		ruleFires:     make(map[string][]ruleFire),
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

	rows, err = s.db.Query("SELECT user, count FROM events_per_user")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		var c int
		if err := rows.Scan(&u, &c); err != nil {
			return err
		}
		s.eventsPerUser[u] = c
	}
	return nil
}

// RecordRuleFire bumps the per-user event count, persists it, and appends to
// the bounded in-memory ruleFires window. Returns the user's new event count.
func (s *Store) RecordRuleFire(user, rule string, atUnix float64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.eventsPerUser[user]++
	count := s.eventsPerUser[user]
	if _, err := s.db.Exec(
		`INSERT INTO events_per_user (user, count) VALUES (?, ?)
         ON CONFLICT(user) DO UPDATE SET count = excluded.count`,
		user, count,
	); err != nil {
		return 0, err
	}

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
}

func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Snapshot{
		Solved:        make(map[SolveKey]string, len(s.solved)),
		EventsPerUser: make(map[string]int, len(s.eventsPerUser)),
	}
	for k, v := range s.solved {
		out.Solved[k] = v
	}
	for k, v := range s.eventsPerUser {
		out.EventsPerUser[k] = v
	}
	return out
}

func (s *Store) SolvedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.solved)
}
