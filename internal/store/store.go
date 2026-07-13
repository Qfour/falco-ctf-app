// Package store owns scoreboard persistence and in-memory state.
//
// Persistence (SQLite, WAL):
//   - solved      (user, challenge, at)            PRIMARY KEY (user, challenge)
//   - display_names (user, name, set_at)           PRIMARY KEY (user)
//   - hint_release  (mission, hint, at)            PRIMARY KEY (mission, hint)
//   - exfil       (user, challenge, flag, at)      PRIMARY KEY (user, challenge)
//   - hint_views  (user, challenge, hint_idx, at)  PRIMARY KEY (user, challenge, hint_idx)
//     Journey UI: per-participant hint reveals (progressive hint gating).
//     Mission `steps` are info-only (no per-step auto-detect / persistence) —
//     the CLEARED verdict stays with solve (trigger fire / evade flag).
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
	exfil         map[SolveKey]string // value = exfiltrated flag (collector receipt)
	eventsPerUser map[string]int
	ruleFires     map[string][]ruleFire // user -> bounded list (RetentionSeconds)
	displayNames  map[string]string     // user -> participant-chosen display name
	hintReleased  map[hintKey]bool      // (mission,hint) operator-released to participants
	hintViews     map[hintViewKey]bool  // (user,challenge,hintIdx) participant-revealed
	stepChecks    map[stepCheckKey]bool // (user,challenge,stepIdx) participant self-checked
}

// stepCheckKey identifies one step of one challenge that a specific participant
// has ticked in the Journey UI checklist. Presentational only — a checked step
// never contributes to the solve verdict.
type stepCheckKey struct {
	User      string
	Challenge string
	StepIdx   int
}

// hintViewKey identifies one hint of one challenge that a specific participant
// has revealed in the Journey UI. Distinct from hintKey (operator release):
// this records *individual* consumption, so the UI can keep a hint open across
// polls and post-event triage can see how much help each agent pulled.
type hintViewKey struct {
	User      string
	Challenge string
	HintIdx   int
}

// hintKey identifies one hint of one mission for operator-controlled release.
type hintKey struct {
	Mission string
	Hint    int
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
        DROP TABLE IF EXISTS events_per_user;
    `); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema init: %w", err)
	}

	s := &Store{
		db:            db,
		solved:        make(map[SolveKey]string),
		exfil:         make(map[SolveKey]string),
		eventsPerUser: make(map[string]int),
		ruleFires:     make(map[string][]ruleFire),
		displayNames:  make(map[string]string),
		hintReleased:  make(map[hintKey]bool),
		hintViews:     make(map[hintViewKey]bool),
		stepChecks:    make(map[stepCheckKey]bool),
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
	if err := dn.Err(); err != nil {
		return err
	}

	hr, err := s.db.Query("SELECT mission, hint FROM hint_release")
	if err != nil {
		return err
	}
	for hr.Next() {
		var k hintKey
		if err := hr.Scan(&k.Mission, &k.Hint); err != nil {
			hr.Close()
			return err
		}
		s.hintReleased[k] = true
	}
	hr.Close()
	if err := hr.Err(); err != nil {
		return err
	}

	ex, err := s.db.Query("SELECT user, challenge, flag FROM exfil")
	if err != nil {
		return err
	}
	for ex.Next() {
		var k SolveKey
		var flag string
		if err := ex.Scan(&k.User, &k.Challenge, &flag); err != nil {
			ex.Close()
			return err
		}
		s.exfil[k] = flag
	}
	ex.Close()
	if err := ex.Err(); err != nil {
		return err
	}

	hv, err := s.db.Query("SELECT user, challenge, hint_idx FROM hint_views")
	if err != nil {
		return err
	}
	for hv.Next() {
		var k hintViewKey
		if err := hv.Scan(&k.User, &k.Challenge, &k.HintIdx); err != nil {
			hv.Close()
			return err
		}
		s.hintViews[k] = true
	}
	hv.Close()
	if err := hv.Err(); err != nil {
		return err
	}

	sc, err := s.db.Query("SELECT user, challenge, step_idx FROM step_checks")
	if err != nil {
		return err
	}
	defer sc.Close()
	for sc.Next() {
		var k stepCheckKey
		if err := sc.Scan(&k.User, &k.Challenge, &k.StepIdx); err != nil {
			return err
		}
		s.stepChecks[k] = true
	}
	return sc.Err()
}

// ReleaseHint marks (mission, hint) as released to participants, or revokes it
// when released=false. Operator-controlled; the participant docs site polls
// ReleasedHints and reveals only released hints. Idempotent.
func (s *Store) ReleaseHint(mission string, hint int, released bool, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if released {
		if _, err := s.db.Exec(
			`INSERT INTO hint_release (mission, hint, at) VALUES (?, ?, ?)
			 ON CONFLICT(mission, hint) DO UPDATE SET at = excluded.at`,
			mission, hint, at,
		); err != nil {
			return err
		}
		s.hintReleased[hintKey{mission, hint}] = true
		return nil
	}
	if _, err := s.db.Exec("DELETE FROM hint_release WHERE mission = ? AND hint = ?", mission, hint); err != nil {
		return err
	}
	delete(s.hintReleased, hintKey{mission, hint})
	return nil
}

// ReleasedHints returns the released hints as mission -> sorted hint indices.
func (s *Store) ReleasedHints() map[string][]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]int, len(s.hintReleased))
	for k := range s.hintReleased {
		out[k.Mission] = append(out[k.Mission], k.Hint)
	}
	for _, hs := range out {
		sort.Ints(hs)
	}
	return out
}

// RecordHintView records that `user` revealed hint `hintIdx` (1-based) of
// `challenge` in the Journey UI. Idempotent per (user, challenge, hintIdx):
// re-revealing the same hint keeps the first-view timestamp. Returns whether
// this was the first time the participant opened that hint (newly), so the API
// can distinguish a first reveal from a repeat poll in the audit log.
func (s *Store) RecordHintView(user, challenge string, hintIdx int, at string) (newly bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hintViewKey{User: user, Challenge: challenge, HintIdx: hintIdx}
	if s.hintViews[key] {
		return false, nil
	}
	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO hint_views (user, challenge, hint_idx, at) VALUES (?, ?, ?, ?)`,
		user, challenge, hintIdx, at,
	); err != nil {
		return false, err
	}
	s.hintViews[key] = true
	return true, nil
}

// HintViews returns, for `user`, the set of hint indices revealed per challenge
// (challenge -> sorted 1-based indices). Used by the Journey /me projection so
// a revealed hint stays open across polls.
func (s *Store) HintViews(user string) map[string][]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]int)
	for k := range s.hintViews {
		if k.User != user {
			continue
		}
		out[k.Challenge] = append(out[k.Challenge], k.HintIdx)
	}
	for _, idxs := range out {
		sort.Ints(idxs)
	}
	return out
}

// SetStepCheck ticks (checked=true) or clears (checked=false) step `stepIdx`
// (0-based) of `challenge` for `user` in the Journey checklist. Idempotent.
// Purely presentational — a checked step never affects the solve verdict.
func (s *Store) SetStepCheck(user, challenge string, stepIdx int, checked bool, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := stepCheckKey{User: user, Challenge: challenge, StepIdx: stepIdx}
	if checked {
		if _, err := s.db.Exec(
			`INSERT INTO step_checks (user, challenge, step_idx, at) VALUES (?, ?, ?, ?)
			 ON CONFLICT(user, challenge, step_idx) DO UPDATE SET at = excluded.at`,
			user, challenge, stepIdx, at,
		); err != nil {
			return err
		}
		s.stepChecks[key] = true
		return nil
	}
	if _, err := s.db.Exec(
		`DELETE FROM step_checks WHERE user = ? AND challenge = ? AND step_idx = ?`,
		user, challenge, stepIdx,
	); err != nil {
		return err
	}
	delete(s.stepChecks, key)
	return nil
}

// StepChecks returns, for `user`, the set of checked step indices per challenge
// (challenge -> sorted 0-based indices). Used by the Journey /me projection so
// a ticked step stays ticked across polls.
func (s *Store) StepChecks(user string) map[string][]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]int)
	for k := range s.stepChecks {
		if k.User != user {
			continue
		}
		out[k.Challenge] = append(out[k.Challenge], k.StepIdx)
	}
	for _, idxs := range out {
		sort.Ints(idxs)
	}
	return out
}

// SetDisplayName sets or OVERWRITES the display name for `user`
// (last-write-wins). Used by both the participant self-service path
// (`/api/users/{user}/display-name`, keyed to the workspace's own
// $FALCO_CTF_USER) and the admin override (`/api/admin/users/{user}/...`).
// Identity (`user`) is the auth-derived stable key; `name` is purely cosmetic.
// Unset users render as their username (see DisplayName).
func (s *Store) SetDisplayName(user, name, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(
		`INSERT INTO display_names (user, name, set_at) VALUES (?, ?, ?)
		 ON CONFLICT(user) DO UPDATE SET name = excluded.name, set_at = excluded.set_at`,
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

// RecordExfil records that `user` exfiltrated `flag` for `challenge` at `at`
// (the collector receipt). Last-write-wins per (user, challenge). Used by the
// boss capstone: the participant must deliver the flag to the in-cluster
// collector over HTTP before a submit will be accepted (RequireExfil).
func (s *Store) RecordExfil(user, challenge, flag, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(
		`INSERT INTO exfil (user, challenge, flag, at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(user, challenge) DO UPDATE SET flag = excluded.flag, at = excluded.at`,
		user, challenge, flag, at,
	); err != nil {
		return err
	}
	s.exfil[SolveKey{User: user, Challenge: challenge}] = flag
	return nil
}

// HasExfil reports whether `user` has exfiltrated exactly `flag` for
// `challenge` to the collector.
func (s *Store) HasExfil(user, challenge, flag string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	got, ok := s.exfil[SolveKey{User: user, Challenge: challenge}]
	return ok && got == flag
}

// HasExfilAny reports whether the collector has received *any* exfil receipt
// for (user, challenge), regardless of the flag value. Used by the Journey
// projection to surface a "collector received your flag" live status without
// leaking the flag itself. Distinct from HasExfil (which matches an exact flag
// for the solve gate) — a wrong-value receipt still counts as "received here"
// for UX, while the solve gate keeps matching the exact expected flag.
func (s *Store) HasExfilAny(user, challenge string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.exfil[SolveKey{User: user, Challenge: challenge}]
	return ok
}

// ExfilReceipt is the public projection of one stored collector receipt.
// Returned by PendingExfilSolves for the auto-solve sweeper. Receipt time is
// deliberately omitted: the sweeper's clean-window gate is evaluated against
// server now(), never against the (attacker-influenced) delivery time, so the
// receipt timestamp plays no part in the solve decision.
type ExfilReceipt struct {
	User      string
	Challenge string
	Flag      string
}

// PendingExfilSolves returns every recorded exfil receipt whose (user,
// challenge) pair has NOT been solved yet. It is the sweeper's work queue: the
// scoring layer re-applies the RequireExfil / evade-type filter (catalog is the
// authority for those) and the clean-window + exact-flag gate before solving,
// so this method deliberately returns *all* unsolved receipts and does not
// itself decide eligibility. Snapshot semantics: the returned slice is a copy
// taken under the lock, safe to iterate without holding it.
//
// "Unsolved" is evaluated against the in-memory solved set (the same set
// MarkSolved maintains), so a receipt whose pair was solved by either the
// manual /submit path or a prior sweep is excluded — keeping the sweeper's
// queue idempotent and bounded to genuinely-pending work.
func (s *Store) PendingExfilSolves() []ExfilReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ExfilReceipt, 0, len(s.exfil))
	for k, flag := range s.exfil {
		if _, solved := s.solved[k]; solved {
			continue
		}
		out = append(out, ExfilReceipt{
			User:      k.User,
			Challenge: k.Challenge,
			Flag:      flag,
		})
	}
	// Sort by a stable key (user, challenge) for deterministic iteration in
	// tests and logs.
	sort.Slice(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		return out[i].Challenge < out[j].Challenge
	})
	return out
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
	if _, err := s.db.Exec("DELETE FROM exfil"); err != nil {
		return 0, fmt.Errorf("reset exfil: %w", err)
	}
	if _, err := s.db.Exec("DELETE FROM hint_views"); err != nil {
		return 0, fmt.Errorf("reset hint_views: %w", err)
	}
	if _, err := s.db.Exec("DELETE FROM step_checks"); err != nil {
		return 0, fmt.Errorf("reset step_checks: %w", err)
	}
	clearedSolves = len(s.solved)
	s.solved = make(map[SolveKey]string)
	s.exfil = make(map[SolveKey]string)
	s.eventsPerUser = make(map[string]int)
	s.ruleFires = make(map[string][]ruleFire)
	s.hintViews = make(map[hintViewKey]bool)
	s.stepChecks = make(map[stepCheckKey]bool)
	return clearedSolves, nil
}
