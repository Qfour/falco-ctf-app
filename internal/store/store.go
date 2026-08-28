// Package store owns scoreboard persistence and in-memory state.
//
// Schema versioning: the on-disk schema is tracked with SQLite's built-in
// `PRAGMA user_version` counter and evolved via the ordered migration list
// in migrations.go (Issue #117) — see that file's package doc for the
// bootstrap-vs-migration design and the fail-closed downgrade check.
//
// Persistence (SQLite, WAL):
//   - solved      (user, challenge, at)            PRIMARY KEY (user, challenge)
//   - display_names (user, name, set_at)           PRIMARY KEY (user)
//   - hint_release  (mission, hint, at)            PRIMARY KEY (mission, hint)
//     Orphaned (app#84, P22-1 follow-up): the operator-broadcast hint API
//     (GET /api/hints, POST /api/admin/hints, ReleaseHint/ReleasedHints) that
//     read/wrote this table was removed as dead code once the participant-side
//     docs-site hint timer it served was retired. The table itself is kept
//     per ADR-0020's additive-only migration discipline (no code path touches
//     it anymore; any pre-existing rows are inert).
//   - exfil       (user, challenge, flag, at)      PRIMARY KEY (user, challenge)
//   - hint_views  (user, challenge, hint_idx, at)  PRIMARY KEY (user, challenge, hint_idx)
//     Journey UI: per-participant hint reveals (progressive hint gating).
//     Mission `steps` are info-only (no per-step auto-detect / persistence) —
//     the CLEARED verdict stays with solve (trigger fire / evade flag).
//   - evade_dirty (user, challenge, rule, at)      PRIMARY KEY (user, challenge, rule)
//     App-H2 + ADR-0003: the evade solve gate's forbidden-rule taint. A row's
//     mere EXISTENCE means (user, challenge) is dirty — there is no expiry, no
//     windowSeconds lookback, and no "clean again after N seconds". A row is
//     only ever written for the participant's CURRENT mission (ADR-0003 A1:
//     attempt scope — scoring.Grader.markDirtyOnRuleFire decides WHICH
//     challenge, this table has no such awareness), and once written the pair
//     stays dirty FOREVER until the participant calls the explicit reset
//     endpoint (ResetDirty, which ALSO clears that pair's `exfil` row — A2-2).
//     This is deliberately persisted (not in-memory like ruleFires below): the
//     old in-memory-only windowing was the root cause of two exploits — (1)
//     fire-then-wait-past-the-window always solves, and (2) a scoreboard
//     restart (I1: single replica, Recreate strategy — happens on every image
//     bump / node drain / OOM) wipes the in-memory fire history and
//     auto-solves every exfil-delivered-but-dirty pair within one Sweeper
//     tick. Persisting the taint (not just the raw fire) closes both: waiting
//     can never clear a persisted row, and a restart reloads it from disk
//     exactly like `solved` and `exfil` do. Attempt scope (ADR-0003) closes a
//     THIRD, later-discovered hole App-H2 alone introduced: an unscoped
//     persistent taint permanently blocks any evade mission whose
//     forbiddenRules happen to be an EARLIER trigger mission's REQUIRED
//     expectedRule (the catalog's 02→03 / 04→05 twin-mission pairs) for every
//     regular participant, the instant they legitimately clear the earlier
//     mission.
//   - expected_rule_fire (user, challenge, rule, at) PRIMARY KEY (user, challenge, rule)
//     ADR-0008: the evade solve gate's POSITIVE-proof record — the mirror
//     image of evade_dirty above. A row's mere EXISTENCE means (user,
//     challenge) has, at some point, fired one of the challenge's
//     expectedRules (proof the participant actually exercised the evasion
//     technique, not merely never triggered forbiddenRules — ADR-0003 C5's
//     "negative gate alone is unsound" concern). Same shape as evade_dirty
//     (persisted, `INSERT OR IGNORE`, no time/windowSeconds dimension), but
//     with the OPPOSITE reset behavior: ResetDirty (the participant
//     self-service endpoint) does NOT touch this table, while the admin's
//     full-event Reset() does. This asymmetry is deliberate (ADR-0008
//     Decision (4)) — evade_dirty's rows are a NEGATIVE fact tied to the
//     participant's current attempt (resetting the attempt must also reset
//     the taint, or the participant could never clear it), while a row here
//     is a context-free POSITIVE fact ("this shell, at some point, opened
//     this path for reading") that a forbidden-rule fire or a taint reset
//     can never make untrue. Requiring the participant to re-prove the
//     technique after every reset would add friction with no security
//     benefit (the technique was already proven once), so a reset-dirty
//     call leaves this table alone; only the admin's event-wide wipe clears
//     it, symmetric with every other per-participant table Reset() clears.
//
// In-memory only (reset on pod restart):
//   - eventsPerUser: dashboard counter. Not used for scoring.
//   - ruleFires per user: bounded to the last 5 minutes per user. Presentational
//     only (Journey UI "you just triggered X" feed / trigger-challenge live
//     status) — it never gates a solve. The evade forbidden-rule gate reads
//     evade_dirty (above), not this map, so a restart cannot resurrect the old
//     wait-it-out or restart-auto-solve exploits via this map going empty.
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

// RetentionSeconds bounds the in-memory ruleFires window (presentational
// only — the Journey UI's trigger "detected" live-status feed and the
// participant /me recent-fires display; see triggerDetectWindowSeconds in
// api.go). It no longer backs any solve decision: the evade forbidden-rule
// gate is the persisted, attempt-scoped evade_dirty taint (ADR-0003), not a
// lookback over this map. Intentionally fixed at 5 min: comfortably covers
// the UI's own lookback (60s today) plus operator margin, while bounding the
// in-memory/table growth. Not an operator tuning knob.
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
	hintViews     map[hintViewKey]bool  // (user,challenge,hintIdx) participant-revealed
	stepChecks    map[stepCheckKey]bool // (user,challenge,stepIdx) participant self-checked
	// dirtyRules mirrors the evade_dirty table: (user,challenge) -> set of
	// forbidden rule names that have fired (App-H2). Non-empty set == dirty.
	// Never cleared by time; only ResetDirty removes an entry.
	dirtyRules map[SolveKey]map[string]struct{}
	// expectedRuleFire mirrors the expected_rule_fire table (ADR-0008):
	// (user,challenge) -> set of expectedRules that have fired. Non-empty set
	// == positive proof recorded. Never cleared by ResetDirty (see this
	// package's doc comment on the expected_rule_fire table for why); only
	// the admin's full Reset() clears it.
	expectedRuleFire map[SolveKey]map[string]struct{}
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
// has revealed in the Journey UI. This records *individual* consumption, so
// the UI can keep a hint open across polls and post-event triage can see how
// much help each agent pulled.
type hintViewKey struct {
	User      string
	Challenge string
	HintIdx   int
}

type ruleFire struct {
	Rule string
	At   float64 // unix seconds
}

// sqliteDSN builds the modernc.org/sqlite DSN this package always opens
// with (WAL journal, NORMAL sync, a busy timeout so a lock contended for a
// moment doesn't immediately surface SQLITE_BUSY to a caller — even though
// I1 means there is only ever one writer, a reader mid-transaction can still
// briefly hold the lock). Factored out so migration tests can open the exact
// same DSN a real Store.Open would, without duplicating the pragma string.
func sqliteDSN(path string) string {
	return path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
}

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		// Best-effort. If the directory already exists or is a mount point,
		// MkdirAll is a no-op. If it can't be created, db open will surface
		// the real error below.
		_ = os.MkdirAll(dir, 0o755)
	}
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Schema is versioned via PRAGMA user_version (see migrations.go, Issue
	// #117). migrate() bootstraps a brand-new file AND upgrades an existing
	// one through the same migration list — see that file's package doc for
	// why there is no separate bootstrap path, and it fails closed (refuses
	// to open) if the DB's recorded version is newer than this binary knows
	// about, e.g. an older binary pointed at a DB a newer one already
	// migrated forward.
	if err := migrate(db, migrations); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	s := &Store{
		db:               db,
		solved:           make(map[SolveKey]string),
		exfil:            make(map[SolveKey]string),
		eventsPerUser:    make(map[string]int),
		ruleFires:        make(map[string][]ruleFire),
		displayNames:     make(map[string]string),
		hintViews:        make(map[hintViewKey]bool),
		stepChecks:       make(map[stepCheckKey]bool),
		dirtyRules:       make(map[SolveKey]map[string]struct{}),
		expectedRuleFire: make(map[SolveKey]map[string]struct{}),
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
	for sc.Next() {
		var k stepCheckKey
		if err := sc.Scan(&k.User, &k.Challenge, &k.StepIdx); err != nil {
			sc.Close()
			return err
		}
		s.stepChecks[k] = true
	}
	sc.Close()
	if err := sc.Err(); err != nil {
		return err
	}

	dr, err := s.db.Query("SELECT user, challenge, rule FROM evade_dirty")
	if err != nil {
		return err
	}
	defer dr.Close()
	for dr.Next() {
		var k SolveKey
		var rule string
		if err := dr.Scan(&k.User, &k.Challenge, &rule); err != nil {
			return err
		}
		if s.dirtyRules[k] == nil {
			s.dirtyRules[k] = make(map[string]struct{})
		}
		s.dirtyRules[k][rule] = struct{}{}
	}
	if err := dr.Err(); err != nil {
		return err
	}

	efr, err := s.db.Query("SELECT user, challenge, rule FROM expected_rule_fire")
	if err != nil {
		return err
	}
	defer efr.Close()
	for efr.Next() {
		var k SolveKey
		var rule string
		if err := efr.Scan(&k.User, &k.Challenge, &rule); err != nil {
			return err
		}
		if s.expectedRuleFire[k] == nil {
			s.expectedRuleFire[k] = make(map[string]struct{})
		}
		s.expectedRuleFire[k][rule] = struct{}{}
	}
	return efr.Err()
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

// IsSolved reports whether (user, challenge) has already been solved. Used by
// scoring.Grader's attempt-scope current() derivation (ADR-0003 A1) to walk
// the progression order one id at a time; the api journey handler instead
// builds its own set from a single Snapshot() call (cheaper for a whole-order
// scan) and shares the SAME CurrentMission scan function against a different
// backing predicate — see scoring.CurrentMission's doc.
func (s *Store) IsSolved(user, challenge string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.solved[SolveKey{User: user, Challenge: challenge}]
	return ok
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
// `windowSeconds`, in arrival order. Unlike RecentFiresMatching (which
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

// RecentFiresMatching returns the *set* (sorted, deduplicated) of the rule
// names in `rules` that fired for `user` within the last `windowSeconds` from
// `now`. Empty slice means none of the given rules fired in the window.
//
// Generic by design: it answers "of these rule names, which fired recently".
// Two callers use it with different rule sets:
//   - the evade Grader passes the challenge's forbiddenRules to detect a
//     dirty window (any match → not evaded);
//   - the Journey UI projection passes a trigger challenge's expectedRules to
//     show which success signals the participant has already fired.
//
// The method is a pure read-only projection over the bounded ruleFires window
// and never mutates state, so neither use can affect a solve verdict.
func (s *Store) RecentFiresMatching(user string, rules []string, now float64, windowSeconds int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now - float64(windowSeconds)
	want := make(map[string]struct{}, len(rules))
	for _, r := range rules {
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

// MarkDirty records that `rule` (one of a challenge's forbiddenRules) fired
// for `user` against `challenge` (App-H2 persistent taint; ADR-0003 A1 scopes
// WHICH challenge this is called for — see scoring.Grader.markDirtyOnRuleFire
// — this method has no catalog or attempt-scope awareness and simply records
// what it is told). Persists to SQLite — NOT a windowed/in-memory fact — so
// the taint survives a scoreboard restart (conventions I1: single replica,
// Recreate strategy) exactly like `solved` and `exfil` do. Idempotent per
// (user, challenge, rule): a repeat fire of the same rule is a no-op (INSERT
// OR IGNORE), so `at` only ever reflects the FIRST time this specific rule
// dirtied this pair.
//
// There is deliberately no time parameter driving expiry and no companion
// "clear after N seconds" — DirtyRules below reports this pair dirty until
// ResetDirty explicitly deletes the row(s).
//
// Fail-closed (ADR-0003 A5): the in-memory dirtyRules map is updated FIRST,
// before the SQLite write is attempted, and unconditionally on the return
// path — a persistence failure below is reported to the caller (who must
// react per RuleFireOutcome.TaintErr's doc) but does NOT unset the in-memory
// taint that was just set. This is a deliberate asymmetry: an over-taint that
// outlives a failed persistence write is recoverable (the participant's
// reset endpoint clears it); a taint that is silently NOT set in memory
// because the DB write failed is NOT recoverable — it is a permanent
// false-clean gap for that rule fire. (Before ADR-0003 this method returned
// on the db.Exec error BEFORE touching the in-memory map at all, so a
// transient SQLite error dropped the taint outright — see A5.)
func (s *Store) MarkDirty(user, challenge, rule, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := SolveKey{User: user, Challenge: challenge}
	if s.dirtyRules[key] == nil {
		s.dirtyRules[key] = make(map[string]struct{})
	}
	s.dirtyRules[key][rule] = struct{}{}

	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO evade_dirty (user, challenge, rule, at) VALUES (?, ?, ?, ?)`,
		user, challenge, rule, at,
	); err != nil {
		return err
	}
	return nil
}

// DirtyRules returns the sorted, deduplicated set of forbidden rule names that
// have ever fired for (user, challenge) since the last ResetDirty. An empty
// (nil) slice means clean. This is a pure read-only projection over persisted
// state — never derived from a time window — so it gives the identical answer
// immediately after a restart as it did right before one (the App-H2 fix: see
// the package doc's evade_dirty note for why that property matters).
func (s *Store) DirtyRules(user, challenge string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.dirtyRules[SolveKey{User: user, Challenge: challenge}]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// RecordExpectedRuleFire records that `rule` (one of a challenge's
// expectedRules) fired for `user` against `challenge` — ADR-0008's POSITIVE
// proof-of-technique gate (the mirror image of MarkDirty above). Like
// MarkDirty, this method has no catalog or attempt-scope awareness and
// simply records what it is told; scoring.Grader.recordExpectedRuleFire
// decides WHICH (user, challenge) pairs this is called for.
//
// Persists to SQLite exactly like evade_dirty (`INSERT OR IGNORE`,
// idempotent per (user, challenge, rule): a repeat fire is a no-op, so `at`
// only ever reflects the FIRST time this rule satisfied this pair's gate).
//
// Fail-closed (same rationale as MarkDirty, ADR-0003 A5): the in-memory
// expectedRuleFire map is updated FIRST, before the SQLite write is
// attempted, and unconditionally on the return path. Here the asymmetry cuts
// the OTHER way from MarkDirty's: an in-memory-only "proven" fact that
// outlives a failed persistence write is not a security hole (worst case,
// the participant can just fire the rule again — the technique is genuinely
// reproducible), but silently NOT recording a real proof event because of a
// transient DB error would incorrectly re-block a participant who did
// exactly what was asked of them. Setting the in-memory copy unconditionally
// avoids that false negative even when persistence fails.
func (s *Store) RecordExpectedRuleFire(user, challenge, rule, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := SolveKey{User: user, Challenge: challenge}
	if s.expectedRuleFire[key] == nil {
		s.expectedRuleFire[key] = make(map[string]struct{})
	}
	s.expectedRuleFire[key][rule] = struct{}{}

	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO expected_rule_fire (user, challenge, rule, at) VALUES (?, ?, ?, ?)`,
		user, challenge, rule, at,
	); err != nil {
		return err
	}
	return nil
}

// HasExpectedRuleFire reports whether ANY of (user, challenge)'s expected
// rules has ever fired — the read side of ADR-0008's positive-proof gate.
// Pure read-only projection over persisted state, so it gives the identical
// answer immediately after a restart as it did right before one, matching
// DirtyRules' restart-survival property. Unlike DirtyRules there is no
// ResetDirty counterpart that clears this — see the package doc's
// expected_rule_fire note for why that asymmetry is deliberate and safe.
func (s *Store) HasExpectedRuleFire(user, challenge string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.expectedRuleFire[SolveKey{User: user, Challenge: challenge}]) > 0
}

// ResetDirty is the ONLY way (user, challenge) returns to clean — there is no
// time-based path. Called from the participant self-service reset endpoint
// (self-or-admin gated at the API layer, conventions I8) after the
// participant redoes the attack cleanly. Idempotent: resetting an
// already-clean pair (with no exfil receipt either) is a harmless no-op.
//
// ADR-0003 A2-2 (CEO enforce decision, 2026-08-18): ALSO deletes the same
// (user, challenge) pair's exfil receipt, if any. Before this, ResetDirty
// cleared only evade_dirty and left the `exfil` row in place — for a
// RequireExfil challenge (the boss capstone, 10-final-exfil) that reopened
// the App-H2 exploit through a different door: fire a forbidden rule (dirty),
// call reset-dirty, and the Sweeper's very next tick auto-solves the capstone
// off the STALE receipt with no fresh exfil delivery at all ("fire → reset →
// solve" replacing #124's "fire → wait → solve"). Deleting both rows in the
// same call means a reset truly restarts the attempt: a RequireExfil
// challenge needs a BRAND NEW exfil delivery after every reset, not just a
// clean taint. (The "honor" alternative — leaving the receipt and documenting
// the auto-solve as intentional — was considered and explicitly rejected by
// the CEO; see ADR-0003 §A2 point 3.)
//
// app#124 5x review (R1/R2/R4, independently): the original two-Exec version
// deleted evade_dirty FIRST — including the in-memory delete(s.dirtyRules,
// key) — and only then deleted exfil. If the second DELETE failed, the
// handler surfaced a 500, but the taint was ALREADY gone (both on disk and
// in memory) while the stale exfil receipt was NOT: exactly the "dirty
// cleared, receipt still present" state the Sweeper (current-independent,
// 5s tick) auto-solves on its very next pass. A 500 response gave the
// caller no reason to believe anything had actually changed, so the
// A2-2 exploit this function exists to close reopened through its own
// error path. Both DELETEs (and their in-memory mirrors) now run inside a
// single SQLite transaction, committed only if both succeed, with the
// in-memory maps updated only AFTER Commit returns nil — so a mid-way
// failure leaves BOTH the taint and the receipt exactly as they were
// (fail-closed: still dirty, still un-resettable, submit stays blocked)
// instead of a partially-cleared state a background sweep can exploit.
//
// This is the first use of db.Begin/*sql.Tx anywhere in this package.
// Safe under I1 (scoreboard is single-replica, and all Store methods —
// including this one — already serialize through s.mu, so there is no
// concurrent writer to interleave with these two statements).
//
// ADR-0008 Decision (4): this function deliberately does NOT touch
// expected_rule_fire. That table's rows are a context-free positive fact
// ("this participant's shell fired this expectedRule at some point") which
// a taint or its reset can never make untrue — unlike evade_dirty/exfil
// above, whose whole point IS to be reset here. Only the admin's full-event
// Reset() (below) clears expected_rule_fire, symmetric with every other
// per-participant table it wipes.
func (s *Store) ResetDirty(user, challenge string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := SolveKey{User: user, Challenge: challenge}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	if _, err := tx.Exec(
		"DELETE FROM evade_dirty WHERE user = ? AND challenge = ?",
		user, challenge,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(
		"DELETE FROM exfil WHERE user = ? AND challenge = ?",
		user, challenge,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	// In-memory mirrors are only mutated after the transaction is durably
	// committed — see the fail-closed rationale above.
	delete(s.dirtyRules, key)
	delete(s.exfil, key)
	return nil
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
	if _, err := s.db.Exec("DELETE FROM evade_dirty"); err != nil {
		return 0, fmt.Errorf("reset evade_dirty: %w", err)
	}
	// ADR-0008 Decision (4): unlike ResetDirty (which deliberately leaves
	// expected_rule_fire alone — see that function's doc), the admin's
	// full-event wipe DOES clear it, symmetric with every other
	// per-participant table above.
	if _, err := s.db.Exec("DELETE FROM expected_rule_fire"); err != nil {
		return 0, fmt.Errorf("reset expected_rule_fire: %w", err)
	}
	clearedSolves = len(s.solved)
	s.solved = make(map[SolveKey]string)
	s.exfil = make(map[SolveKey]string)
	s.eventsPerUser = make(map[string]int)
	s.ruleFires = make(map[string][]ruleFire)
	s.hintViews = make(map[hintViewKey]bool)
	s.stepChecks = make(map[stepCheckKey]bool)
	s.dirtyRules = make(map[SolveKey]map[string]struct{})
	s.expectedRuleFire = make(map[SolveKey]map[string]struct{})
	return clearedSolves, nil
}
