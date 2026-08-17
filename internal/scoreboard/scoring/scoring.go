// Package scoring holds the scoreboard's solve-decision business rules as a
// single domain service (Grader). It is the one place that decides whether a
// participant has solved a challenge and the sole caller of the store's
// MarkSolved — reinforcing the single-writer discipline (conventions I1).
//
// Before this package the verdict logic was spread across three handler sites:
//
//   - ingest (trigger auto-solve on a Falco rule fire),
//   - api /submit (evade flag + forbidden-window + exfil gate),
//   - api /internal/exfil (recording the collector receipt that the gate reads).
//
// The Grader collects those into EvaluateTrigger / SubmitEvade / RecordExfil so
// the rules can be unit-tested without HTTP, and so the ingest / api handlers
// become thin inbound adapters (drivers) that only translate the returned
// outcome into a response + metrics.
//
// Dependency direction: scoring depends on catalog (challenge metadata) and on
// the ScoreStore port; it never imports the handlers. The concrete *store.Store
// satisfies ScoreStore, so the store is a repository adapter behind the port.
// It also imports the store package for the plain ExfilReceipt value type the
// PendingExfilSolves port method returns — a data type, not a handler, so the
// "never import the handlers" rule is preserved.
//
// Auto-solve (P16): a store-backed Sweeper periodically re-derives the set of
// exfil-delivered-but-unsolved (user, challenge) pairs and runs each through the
// exact same clean-window + exfil gate the manual /submit path uses (the shared
// evaluateClean helper). Because the verdict is re-derived from the store on
// every tick, it survives a scoreboard restart (conventions I1: single replica,
// no in-memory pending timers to lose).
package scoring

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// ScoreStore is the repository port the Grader depends on. It is the minimal
// slice of the persistence layer the solve rules need; *store.Store implements
// it. Keeping the Grader behind this interface makes the rules unit-testable
// with a fake store + fake clock (see scoring_test.go).
//
// The methods mirror the existing store signatures verbatim so the refactor is
// behaviour-preserving:
//   - MarkSolved is idempotent (first solve wins) and reports whether the solve
//     was newly recorded.
//   - RecentFiresMatching returns the subset of the given rules that fired for
//     the user within windowSeconds of now (unix seconds). The Grader passes
//     the challenge's forbiddenRules, so empty = clean window.
//   - HasExfil reports whether the user delivered exactly this flag to the
//     collector for this challenge.
type ScoreStore interface {
	MarkSolved(user, challenge, at string) (newly bool, err error)
	RecentFiresMatching(user string, rules []string, now float64, windowSeconds int) []string
	HasExfil(user, challenge, flag string) bool
	RecordExfil(user, challenge, flag, at string) error
	// PendingExfilSolves enumerates every recorded collector receipt whose
	// (user, challenge) pair is not yet solved. It is the sweeper's work queue;
	// the Grader re-applies the RequireExfil / evade-type / clean-window / exact
	// -flag gates before solving (see Sweep). Kept on the same port so the
	// concrete *store.Store satisfies it and tests can drive a fake queue.
	PendingExfilSolves() []store.ExfilReceipt
	// HintViews returns, for `user`, the set of self-revealed hint indices per
	// challenge (challenge -> 1-based indices). The Grader sums the reveal count
	// across challenges to apply the per-hint score penalty (#40). Kept on the
	// same port so *store.Store satisfies it and tests drive a fake reveal set.
	HintViews(user string) map[string][]int
}

// Grader is the scoring domain service. It owns the catalog (challenge rules),
// the clock, and the points policy, and is the only component that calls
// MarkSolved. It is also the single owner of the points arithmetic (#40): the
// api handler asks it for a user's score rather than computing it inline (#39
// direction — no domain calculation in the handlers).
type Grader struct {
	cat    catalog.Catalog
	store  ScoreStore
	now    func() time.Time
	points PointsPolicy
}

// New builds a Grader. `now` is injected (WithNow pattern) so tests drive a
// deterministic clock; production wires time.Now. The points policy defaults to
// the placeholder DefaultPointsPolicy; production overrides it via WithPoints
// from env (cmd/scoreboard).
func New(cat catalog.Catalog, store ScoreStore, now func() time.Time) *Grader {
	if now == nil {
		now = time.Now
	}
	return &Grader{cat: cat, store: store, now: now, points: DefaultPointsPolicy()}
}

// WithPoints overrides the Grader's points policy (base award per solve +
// per-hint penalty). Returns the same *Grader for chaining at wiring time.
// Passing the zero policy is honoured verbatim (0 award / 0 penalty) — callers
// that want the placeholder defaults simply do not call WithPoints.
func (g *Grader) WithPoints(p PointsPolicy) *Grader {
	g.points = p
	return g
}

// Points returns the Grader's active points policy so an adapter can surface
// the per-hint penalty schedule to the UI (e.g. "opening this hint costs N
// points") without re-deriving or hard-coding the value on the handler side.
//
// The policy is returned NORMALISED (R1): a misconfigured negative penalty /
// award is floored to 0, so the UI can never show a negative "costs -N points"
// figure — the same normalisation ComputeScore applies before the arithmetic,
// so what the UI advertises and what the score subtracts always agree.
func (g *Grader) Points() PointsPolicy { return g.points.normalise() }

// HintPenaltyFor returns the (normalised) cost of revealing 1-based hint
// index idx under the Grader's active schedule. The api handler uses this to
// project "opening hint N costs -M points" onto the button for the specific
// next-unopened index, rather than a single flat value (#40 hint-index
// schedule). idx <= 0 costs nothing (not a valid hint index).
func (g *Grader) HintPenaltyFor(idx int) int { return g.points.normalise().penaltyFor(idx) }

// UserScore computes `user`'s current score: the base award per solved
// challenge minus the per-hint-index schedule penalty for every hint the user
// self-revealed, clamped at 0 (see ComputeScore). `solvedCount` is supplied by
// the caller — the api projections already filter solves to catalog membership
// (excluding solves for since-removed challenges), so passing that same count
// keeps score consistent with the displayed solved_count without duplicating
// the catalog-membership filter here.
//
// Revealed hint indices are collected ONLY over challenges that are still in
// the active catalog (g.cat), symmetric with how the caller filters
// solvedCount. Without this filter a stale hint_views row for a
// since-removed challenge (e.g. a scenario reshuffle) would keep deducting the
// penalty forever, over-penalising a user for a challenge they can no longer
// even see — an unfair asymmetry with the catalog-filtered solve side. Each
// hint is counted once (RecordHintView is idempotent per (user, challenge,
// hintIdx)); the SAME hint index revealed on two different challenges is
// charged the schedule's per-index penalty independently for each (the
// schedule prices "which hint slot", not "how many hints total").
//
// Pure over the store's persisted state: the score is fully reconstructible
// after a restart from `solved` + `hint_views`, with no running total to lose.
func (g *Grader) UserScore(user string, solvedCount int) int {
	var revealed []int
	for cid, idxs := range g.store.HintViews(user) {
		if _, ok := g.cat[cid]; !ok {
			continue // stale reveal for a challenge no longer in the catalog
		}
		revealed = append(revealed, idxs...)
	}
	return ComputeScore(g.points, solvedCount, revealed)
}

// TriggerResult reports, per challenge, whether a Falco rule fire solved it.
// Newly is true only the first time that (user, challenge) is recorded, so the
// adapter can decide when to bump the solve metric (behaviour-identical to the
// old inline loop).
type TriggerResult struct {
	Challenge string
	Newly     bool
}

// EvaluateTrigger applies a single Falco rule fire to every trigger-type
// challenge whose expectedRules contain `rule`, marking each solved. It mirrors
// the old ingest loop exactly: iterate catalog ids in order, skip non-trigger
// challenges and non-matching rules, MarkSolved for the rest.
//
// Store errors are continue-on-error, exactly as the old ingest loop was: a
// failing MarkSolved skips only that challenge (the others still get marked)
// and the failures are collected and returned joined via errors.Join. The
// adapter logs the joined error and still uses the successful results — so one
// challenge's transient DB error never suppresses solves for the others.
func (g *Grader) EvaluateTrigger(user, rule string) ([]TriggerResult, error) {
	var results []TriggerResult
	var errs []error
	recvAt := g.now().UTC().Format(time.RFC3339Nano)
	for _, cid := range g.cat.IDs() {
		ch := g.cat[cid]
		if ch.Type != "trigger" {
			continue
		}
		if !slices.Contains(ch.ExpectedRules, rule) {
			continue
		}
		newly, err := g.store.MarkSolved(user, cid, recvAt)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, TriggerResult{Challenge: cid, Newly: newly})
	}
	return results, errors.Join(errs...)
}

// EvadeStatus enumerates the outcome of an evade-challenge submission. The
// handler maps each value to the same HTTP response shape it produced inline
// before the extraction.
type EvadeStatus int

const (
	// EvadeUnknownChallenge: cid is not in the catalog.
	EvadeUnknownChallenge EvadeStatus = iota
	// EvadeNotEvadeType: the challenge exists but is not an evade challenge.
	EvadeNotEvadeType
	// EvadeWrongFlag: the submitted flag does not match expectedFlag.
	EvadeWrongFlag
	// EvadeForbiddenFired: flag correct, but a forbidden rule fired inside the
	// window (offending rules populated).
	EvadeForbiddenFired
	// EvadeExfilRequired: flag correct + window clean, but the challenge
	// requires exfil and the collector has not received the matching flag.
	EvadeExfilRequired
	// EvadeSolved: all gates passed; the solve was recorded (Newly reports
	// whether it was the first time).
	EvadeSolved
)

// EvadeOutcome is the full result of SubmitEvade. Only the fields relevant to
// Status are populated:
//   - EvadeForbiddenFired: Offending holds the sorted forbidden rules.
//   - EvadeSolved: Newly reports whether this was the first solve.
type EvadeOutcome struct {
	Status    EvadeStatus
	Offending []string // forbidden rules that fired (EvadeForbiddenFired only)
	Newly     bool     // first-time solve (EvadeSolved only)
}

// SubmitEvade evaluates an evade-challenge flag submission through the same
// ordered gates the /submit handler used inline:
//
//  1. challenge exists (else EvadeUnknownChallenge)
//  2. challenge is evade type (else EvadeNotEvadeType)
//  3. flag matches expectedFlag (else EvadeWrongFlag)
//  4. no forbidden rule fired within windowSeconds of server now (else
//     EvadeForbiddenFired) — the window is evaluated against server time and
//     never references attacker-supplied time: now derives from g.now(), not
//     from any event field.
//  5. if RequireExfil, the collector has the matching flag (else
//     EvadeExfilRequired)
//  6. record the solve → EvadeSolved.
//
// `flag` is expected pre-trimmed by the adapter (the handler trims user input),
// matching the prior behaviour where the comparison and the exfil lookup both
// used the trimmed value.
func (g *Grader) SubmitEvade(user, cid, flag string) (EvadeOutcome, error) {
	ch, ok := g.cat[cid]
	if !ok {
		return EvadeOutcome{Status: EvadeUnknownChallenge}, nil
	}
	if ch.Type != "evade" {
		return EvadeOutcome{Status: EvadeNotEvadeType}, nil
	}
	if flag != ch.ExpectedFlag {
		return EvadeOutcome{Status: EvadeWrongFlag}, nil
	}
	// Gates 4-6 (forbidden window → exfil gate → MarkSolved) are the *single
	// source of truth* shared with the auto-solve sweeper (evaluateClean). Any
	// change to the clean-window / exfil / record logic must be made there so
	// manual submit and sweeper stay bit-for-bit identical.
	return g.evaluateClean(user, ch, flag)
}

// evaluateClean applies the evade challenge's clean-window + exfil gate and
// records the solve. It is the ONE place gates 4-6 live, shared verbatim by the
// manual /submit path (SubmitEvade) and the auto-solve Sweeper (Sweep). Callers
// must have already established (per SubmitEvade's gates 1-3): the challenge
// exists, is evade type, and `flag` equals ch.ExpectedFlag.
//
//  4. no forbidden rule fired within windowSeconds of server now() — the window
//     is evaluated against g.now(), NEVER attacker-supplied event time.
//  5. if RequireExfil, the collector holds the matching flag (HasExfil).
//  6. record the solve → EvadeSolved (Newly = first-time).
//
// Fail-closed: any store error from MarkSolved is returned unrecorded; a
// non-clean window or unmet exfil returns the corresponding non-solved status,
// so a caller that mis-drives this (e.g. the sweeper enqueuing a not-yet-clean
// pair) simply does not solve — it never records a solve it should not.
func (g *Grader) evaluateClean(user string, ch catalog.Challenge, flag string) (EvadeOutcome, error) {
	now := float64(g.now().Unix())
	offending := g.store.RecentFiresMatching(user, ch.ForbiddenRules, now, ch.WindowSeconds)
	if len(offending) > 0 {
		return EvadeOutcome{Status: EvadeForbiddenFired, Offending: offending}, nil
	}
	if ch.RequireExfil && !g.store.HasExfil(user, ch.ID, flag) {
		return EvadeOutcome{Status: EvadeExfilRequired}, nil
	}

	at := g.now().UTC().Format(time.RFC3339Nano)
	newly, err := g.store.MarkSolved(user, ch.ID, at)
	if err != nil {
		return EvadeOutcome{}, err
	}
	return EvadeOutcome{Status: EvadeSolved, Newly: newly}, nil
}

// ExfilStatus enumerates the outcome of recording a collector exfil receipt.
type ExfilStatus int

const (
	// ExfilUnknownChallenge: cid is not in the catalog.
	ExfilUnknownChallenge ExfilStatus = iota
	// ExfilNotRequired: the challenge does not accept exfil (RequireExfil false).
	ExfilNotRequired
	// ExfilRecorded: the receipt was stored (last-write-wins per user/challenge).
	ExfilRecorded
)

// RecordExfil stores a collector exfil receipt for the boss capstone, applying
// the same guards the /internal/exfil handler used inline: the challenge must
// exist and must require exfil. The flag is not validated here — it is matched
// later at SubmitEvade time via HasExfil (a wrong value simply fails the gate),
// exactly as before.
//
// `user` and `flag` are expected pre-trimmed / pre-validated (non-empty) by the
// adapter, matching prior handler behaviour.
//
// The returned ExfilStatus is only meaningful when err == nil (standard Go
// convention: when err != nil the other return values are undefined). On a
// store error the status is reported as ExfilRecorded but the receipt was NOT
// persisted — callers must branch on err first and never trust the status
// when err is non-nil.
func (g *Grader) RecordExfil(user, cid, flag string) (ExfilStatus, error) {
	ch, ok := g.cat[cid]
	if !ok {
		return ExfilUnknownChallenge, nil
	}
	if !ch.RequireExfil {
		return ExfilNotRequired, nil
	}
	at := g.now().UTC().Format(time.RFC3339Nano)
	if err := g.store.RecordExfil(user, cid, flag, at); err != nil {
		return ExfilRecorded, err
	}
	return ExfilRecorded, nil
}

// --- detect challenges ------------------------------------------------------

// DetectRunner is the port through which the Grader replays a participant's
// submitted Falco condition against a detect challenge's capture pair. The
// scoring package NEVER shells out to Falco itself — an injected runner (local
// -exec for dev/colima/CI, or a k8s-Job for prod) does, keeping scoring
// falco-free and unit-testable with a fake runner (see scoring_test.go).
//
// Grade wraps `condition` into the challenge's fixed rule skeleton, runs the
// `falco -V` compile gate, and — only if it compiles — replays the evasion and
// benign captures, returning the fire counts. Contract:
//
//   - invalid=true  → the condition failed `falco -V` (compile error / undefined
//     macro). The runner MUST NOT run any replay when invalid; the counts are
//     meaningless and ignored by the Grader.
//   - invalid=false → both replays ran; evasionFires/benignFires are the counts
//     of the participant rule firing on each capture.
//   - err != nil     → an infrastructure failure (Job/exec could not run,
//     timeout, result-authenticity mismatch). The Grader surfaces it as a 500;
//     it is NOT a grading verdict and never solves.
//
// cid identifies the detect challenge so the runner can locate its captures via
// the catalog-resolved relative paths (the single-source paths from
// catalog.Detect); the runner is the only component that turns those into a
// concrete filesystem/mount location, and only ever by joining under a base it
// controls.
type DetectRunner interface {
	Grade(ctx context.Context, cid, condition string) (evasionFires, benignFires int, invalid bool, err error)
}

// DetectStatus enumerates the outcome of a detect-challenge condition
// submission. The handler maps each value to an HTTP response shape.
type DetectStatus int

const (
	// DetectUnknownChallenge: cid is not in the catalog.
	DetectUnknownChallenge DetectStatus = iota
	// DetectNotDetectType: the challenge exists but is not a detect challenge.
	DetectNotDetectType
	// DetectInvalidCondition: `falco -V` rejected the condition (compile error /
	// undefined macro). No replay ran.
	DetectInvalidCondition
	// DetectMissedEvasion: the condition compiled but did not fire on the evasion
	// capture (evasionFires == 0).
	DetectMissedEvasion
	// DetectFalsePositive: the condition fired on the evasion capture but ALSO
	// fired on the benign capture (benignFires > 0).
	DetectFalsePositive
	// DetectSolved: fired on the evasion capture and NOT on the benign capture;
	// the solve was recorded (Newly reports whether it was the first time).
	DetectSolved
)

// DetectOutcome is the full result of SubmitDetect. EvasionFires / BenignFires
// are populated whenever a replay ran (every status except
// DetectUnknownChallenge / DetectNotDetectType / DetectInvalidCondition, where
// no replay produced counts) so the handler can surface pedagogic feedback
// ("your rule fired 0× on the attack"). Newly is meaningful only for
// DetectSolved.
type DetectOutcome struct {
	Status       DetectStatus
	EvasionFires int
	BenignFires  int
	Newly        bool
}

// SubmitDetect evaluates a detect-challenge condition submission. Gates 1-2
// (challenge exists / is detect type) are Grader-owned, mirroring SubmitEvade.
// The compile gate + replay are delegated to the injected DetectRunner; the
// Grader interprets the returned counts into a DetectStatus:
//
//  1. challenge exists (else DetectUnknownChallenge)
//  2. challenge is detect type (else DetectNotDetectType)
//  3. runner.Grade: `falco -V` compile gate runs FIRST — if invalid, no replay
//     runs and the status is DetectInvalidCondition
//  4. evasionFires == 0 → DetectMissedEvasion
//  5. benignFires  > 0 → DetectFalsePositive
//  6. else (evasionFires > 0 && benignFires == 0) → record the solve via the
//     EXISTING store.MarkSolved (I1 single writer) → DetectSolved
//
// A runner infrastructure error (err != nil) is returned unrecorded so the
// handler fails closed (500) and never solves. The verdict is a pure function
// of (static capture pair, submitted condition) — deterministic and replay
// -stable across scoreboard restarts, and it references no attacker-supplied
// time (I1).
func (g *Grader) SubmitDetect(ctx context.Context, runner DetectRunner, user, cid, condition string) (DetectOutcome, error) {
	ch, ok := g.cat[cid]
	if !ok {
		return DetectOutcome{Status: DetectUnknownChallenge}, nil
	}
	if ch.Type != "detect" {
		return DetectOutcome{Status: DetectNotDetectType}, nil
	}

	evasionFires, benignFires, invalid, err := runner.Grade(ctx, cid, condition)
	if err != nil {
		return DetectOutcome{}, err
	}
	if invalid {
		// Compile gate rejected it: no replay ran, counts are meaningless.
		return DetectOutcome{Status: DetectInvalidCondition}, nil
	}
	if evasionFires == 0 {
		return DetectOutcome{Status: DetectMissedEvasion, EvasionFires: 0, BenignFires: benignFires}, nil
	}
	if benignFires > 0 {
		return DetectOutcome{Status: DetectFalsePositive, EvasionFires: evasionFires, BenignFires: benignFires}, nil
	}

	at := g.now().UTC().Format(time.RFC3339Nano)
	newly, err := g.store.MarkSolved(user, ch.ID, at)
	if err != nil {
		return DetectOutcome{}, err
	}
	return DetectOutcome{
		Status:       DetectSolved,
		EvasionFires: evasionFires,
		BenignFires:  benignFires,
		Newly:        newly,
	}, nil
}

// SweepResult reports one auto-solve the sweeper performed on a tick. Only
// (user, challenge) pairs newly solved on this tick are returned, so the caller
// (the Sweeper loop) can bump the solve metric exactly once per solve — never
// on the idempotent re-visit of an already-solved pair.
type SweepResult struct {
	User      string
	Challenge string
}

// Sweep runs one auto-solve pass over the store's pending exfil receipts. For
// each exfil-delivered-but-unsolved (user, challenge) pair it re-applies the
// SAME gates as manual submit: the challenge must still be evade type with
// RequireExfil set (catalog is the authority — a receipt for a since-changed
// challenge is skipped), the delivered flag must equal ch.ExpectedFlag, and
// then the shared evaluateClean gate (clean window → HasExfil → MarkSolved)
// must pass. Only pairs that clear every gate are solved this tick.
//
// Fail-closed by construction:
//   - a not-yet-clean window returns EvadeForbiddenFired → not solved (retried
//     next tick, since the pair stays pending);
//   - an exfil value that does not match the expected flag returns
//     EvadeWrongFlag / EvadeExfilRequired → never solved (the wrong receipt can
//     never satisfy HasExfil for the real flag);
//   - a store error on one pair is collected and the pass continues to the next
//     (one transient DB error must not stall every other pending solve), and the
//     joined error is returned so the caller can log it.
//
// Idempotent: PendingExfilSolves already excludes solved pairs, and MarkSolved
// is first-wins, so a pair solved by the manual path (or a prior sweep) is never
// double-counted even under a manual/sweeper race.
func (g *Grader) Sweep() ([]SweepResult, error) {
	var solved []SweepResult
	var errs []error
	for _, r := range g.store.PendingExfilSolves() {
		ch, ok := g.cat[r.Challenge]
		if !ok {
			continue // challenge left the catalog since the receipt was recorded
		}
		if ch.Type != "evade" || !ch.RequireExfil {
			continue // only exfil-required evade challenges auto-solve
		}
		if r.Flag != ch.ExpectedFlag {
			continue // wrong exfil value can never satisfy the exact-flag gate
		}
		out, err := g.evaluateClean(r.User, ch, r.Flag)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if out.Status == EvadeSolved && out.Newly {
			solved = append(solved, SweepResult{User: r.User, Challenge: r.Challenge})
		}
	}
	return solved, errors.Join(errs...)
}

// Sweeper drives Grader.Sweep on a fixed cadence until its context is
// cancelled. It holds no state of its own beyond the ticker — the pending work
// is re-derived from the store every tick, so a scoreboard restart resumes
// auto-solving without any handoff (conventions I1: single replica, so a single
// sweeper is the whole population; no leader election needed).
type Sweeper struct {
	grader   *Grader
	cadence  time.Duration
	logger   *slog.Logger
	onSolved func(SweepResult) // optional metric hook; nil = no-op
}

// NewSweeper builds a Sweeper. cadence <= 0 falls back to DefaultSweepCadence.
// onSolved (may be nil) is invoked once per newly auto-solved pair so the caller
// can bump the solve metric outside the scoring package (keeping scoring free of
// a metrics dependency, matching the ingest/api driver split).
func NewSweeper(g *Grader, cadence time.Duration, logger *slog.Logger, onSolved func(SweepResult)) *Sweeper {
	if cadence <= 0 {
		cadence = DefaultSweepCadence
	}
	return &Sweeper{grader: g, cadence: cadence, logger: logger, onSolved: onSolved}
}

// DefaultSweepCadence is how often the auto-solve sweeper re-derives pending
// solves. 5s keeps the "flag received → auto-clear" latency low enough to feel
// live in the Journey UI (which polls every 2s) while the per-tick work is a
// single mutex-guarded map scan over the exfil set (tiny at CTF scale).
const DefaultSweepCadence = 5 * time.Second

// Run blocks, sweeping every cadence until ctx is cancelled, then returns. It
// does one immediate sweep on entry so a pair that became clean while the
// process was starting up is not delayed a full tick. Safe to run in its own
// goroutine; cancelling ctx (e.g. on SIGTERM) stops the ticker and returns —
// no goroutine leak.
func (s *Sweeper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cadence)
	defer ticker.Stop()
	s.sweepOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepOnce()
		}
	}
}

func (s *Sweeper) sweepOnce() {
	solved, err := s.grader.Sweep()
	if err != nil && s.logger != nil {
		s.logger.Error("auto-solve sweep", "err", err)
	}
	for _, r := range solved {
		if s.logger != nil {
			s.logger.Info("auto_solve", "user", r.User, "cid", r.Challenge)
		}
		if s.onSolved != nil {
			s.onSolved(r)
		}
	}
}
