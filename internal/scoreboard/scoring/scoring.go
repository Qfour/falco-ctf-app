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
// The Grader collects those into OnRuleFire / SubmitEvade / RecordExfil so
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
// exact same clean-taint + exfil gate the manual /submit path uses (the shared
// evaluateClean helper). Because the verdict is re-derived from the store on
// every tick, it survives a scoreboard restart (conventions I1: single replica,
// no in-memory pending timers to lose).
//
// App-H2 (persistent dirty flag): the evade "clean" gate used to be a
// windowSeconds lookback over an in-memory rule-fire history
// (store.RecentFiresMatching). That had two exploitable holes: (1) firing a
// forbidden rule once and then simply waiting past the window always solved —
// the window measured recency, not "ever fired since last reset" — and (2)
// the in-memory history reset to empty on every scoreboard restart (I1:
// single replica + Recreate strategy — image bumps, node drains, OOM kills),
// which auto-solved every exfil-delivered pair within one Sweeper tick
// regardless of how noisy the attack had been. The gate now reads a
// persistent per-(user,challenge) dirty flag (store.DirtyRules / MarkDirty /
// ResetDirty): once fired for a pair it stays dirty across any amount of
// waiting AND across restarts, and only the participant's explicit reset
// endpoint clears it.
//
// ADR-0003 (attempt scope) — THE unresolved half of App-H2, shipped as a
// follow-up after PR #124 shipped the persistent flag WITHOUT it and broke
// every regular participant: a persistent taint with no scope taints a
// challenge FOREVER the instant any of its forbiddenRules fires anywhere,
// for any reason. Several real missions (03/05/10) forbid the exact same
// Falco rule an EARLIER trigger mission REQUIRES firing to solve (e.g.
// 02-credential-files's required "Read sensitive file untrusted" is
// 03-stealth-read's forbidden rule) — so a persistent, unscoped taint makes
// the normal, honest progression permanently taint the very mission a
// participant is about to reach, before they ever attempt it.
//
// The fix: a rule fire only taints the evade challenge that is the
// participant's CURRENT mission (the first unsolved id in the progression
// order — see CurrentMission, the single source of truth this package shares
// with the Journey projection, api.Handler.journey). A required fire that
// clears an earlier trigger mission is exempt because, at the moment it
// fires, the trigger mission — not the sibling evade mission — is current.
// "Time-independent" (the App-H2 property above) was NEVER the whole
// invariant; "attempt-scoped" is. OnRuleFire is the single public entry point
// that enforces the regnorm evaluation order this depends on: it resolves
// current() BEFORE applying this event's trigger solve, then taints, then
// applies the trigger solve (see OnRuleFire's doc). Reversing that order
// reopens the exact regression #124 shipped (see markDirtyOnRuleFire's doc).
//
// Residual risk this ADR explicitly accepts rather than hides (do not read
// this package as "the hole is fully closed"): 03-stealth-read and
// 05-silent-search have no RequireExfil / no positive proof-of-technique —
// they are pure negative gates (forbiddenRules absence), so a participant who
// solves the twin trigger mission's REQUIRED rule and then submits the evade
// mission WITHOUT ever separately exercising the evasion technique still
// solves it (an honor-system gap; closing it is Issue #121's positive-proof
// work, which must land AFTER this ADR — doing it first would re-taint these
// missions the same way #124 did). See also A5's residual risk note on
// markDirtyOnRuleFire's fail-closed in-memory update: if the scoreboard
// process is killed in the narrow window between a failed persistence write
// and the next successful one, the in-memory-only taint for that write is
// lost on restart (mitigated only by the taint_error metric + a runbook
// check, not eliminated).
//
// A SECOND, larger-blast-radius consequence of the same 03/05 honor gap
// (app#124 5x review, R1 finding C2 — do not read the paragraph above as
// scoped to "03/05 alone can be honor-gapped"; it also lets a participant
// neuter the forbiddenRules gate on 10-final-exfil, the RequireExfil
// capstone that DOES matter for scoring):
//
//   - CurrentMission (see below) is "the first id in `order` that is not yet
//     solved." 03/05 solve ONLY via a manual, correctly-flagged /submit —
//     there is no auto-solve path for them — so a participant can leave 03
//     (or 05) permanently unsolved on purpose. Doing so pins current() at 03
//     for as long as they like: nothing about markDirtyOnRuleFire or
//     evaluateTrigger ever forces current to advance.
//   - While current is pinned at 03, markDirtyOnRuleFire only ever taints
//     WHATEVER current() returns — 03, and only 03. 10-final-exfil's own
//     seven forbiddenRules (10 is a distinct catalog id from 03, with its
//     own list) are never current while 03 is unsolved, so firing ANY of
//     them — including "Read sensitive file untrusted", which happens to
//     be both 03's and 10's forbidden rule — taints 03 at most, never 10.
//     The other six have no such collision and simply taint nothing at
//     all. This is not "some of 10's rules slip through"; it is "none of
//     10's rules CAN taint 10" for as long as something earlier in `order`
//     stays deliberately unsolved, no matter how many times any of them
//     fire, because the gate has exactly one target — current — and it is
//     never 10 in this state. evaluateTrigger runs unconditionally
//     regardless of current (deliberately, see its own doc), so 04/06/07/
//     08/09 still solve normally throughout; only the attempt-scoped taint
//     gate is starved of a target that is ever 10.
//   - Sweep (below) re-derives the pending-solve set from the store on every
//     tick and evaluates the SAME evaluateClean gate the manual /submit path
//     uses — DirtyRules(user, cid), not current(). It has no opinion on
//     which mission is "current" today; it only asks "is this receipt's
//     (user, challenge) pair clean and does it have a matching exfil
//     receipt." So once 10's exfil receipt is delivered, a 10 that was
//     never once current while any of its forbiddenRules fired — because 03
//     was pinned as current the whole time — is clean by construction and
//     auto-solves on the Sweeper's next tick.
//   - This is not even an edge case a careful attacker has to engineer:
//     challenges/submit-yaml.sh gives every participant a one-shot "solve
//     everything you have flags for, then submit the whole batch at the
//     end" workflow, which is exactly "leave the earlier evade missions
//     unsubmitted until last, exfiltrate 10 along the way, submit
//     everything at once" — the natural, unremarkable way to use the
//     provided tooling, not a crafted exploit path.
//   - This is NOT a regression this ADR introduces: main's PRE-App-H2
//     windowSeconds lookback gate had the identical property (fire, then
//     stop firing before the window elapses, then submit) with an even
//     shorter fuse (30s) — so ADR-0003 does not make 10's gate any weaker
//     than it already was; it just does not make it any STRONGER either.
//     Do not describe this ADR as having closed 10's gate — it has not.
//     Only Issue #121's positive proof-of-technique work (submitting
//     EVIDENCE that the evasion was actually exercised, rather than only
//     the ABSENCE of a forbidden-rule taint) can close this, and per the
//     ordering note above it must land strictly after this ADR.
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
//   - DirtyRules / MarkDirty are the App-H2 persistent taint: DirtyRules
//     returns the (possibly empty) set of forbidden rules that have fired for
//     (user, challenge) since the last reset — empty means clean, non-empty
//     blocks the solve regardless of how long ago the fire was. MarkDirty
//     records one forbidden-rule fire against one (user, challenge) pair;
//     idempotent per (user, challenge, rule).
//   - HasExfil reports whether the user delivered exactly this flag to the
//     collector for this challenge.
type ScoreStore interface {
	MarkSolved(user, challenge, at string) (newly bool, err error)
	// IsSolved reports whether `user` has already solved `challenge`. It is
	// the read CurrentMission needs, one (user, challenge) pair at a time —
	// the Grader's attempt-scope current() derivation (ADR-0003 A1) calls
	// this once per id while walking the progression order.
	IsSolved(user, challenge string) bool
	DirtyRules(user, challenge string) []string
	MarkDirty(user, challenge, rule, at string) error
	// HasExpectedRuleFire / RecordExpectedRuleFire are ADR-0008's
	// positive-proof gate — the mirror of DirtyRules/MarkDirty above.
	// HasExpectedRuleFire reports whether ANY of the challenge's
	// expectedRules has ever fired for (user, challenge) (no time window,
	// same as DirtyRules); RecordExpectedRuleFire records one such fire
	// (idempotent per (user, challenge, rule), same as MarkDirty).
	HasExpectedRuleFire(user, challenge string) bool
	RecordExpectedRuleFire(user, challenge, rule, at string) error
	HasExfil(user, challenge, flag string) bool
	RecordExfil(user, challenge, flag, at string) error
	// PendingExfilSolves enumerates every recorded collector receipt whose
	// (user, challenge) pair is not yet solved. It is the sweeper's work queue;
	// the Grader re-applies the RequireExfil / evade-type / dirty-flag / exact
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
	// order is the mission progression order (ADR-0003 A1: attempt scope).
	// nil/empty falls back to g.cat.IDs() (sorted catalog order), mirroring
	// api.New's identical default so a Grader built without WithOrder still
	// behaves consistently with the Journey projection's default.
	order []string
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

// WithOrder sets the mission progression order (ADR-0003 A1: attempt scope) —
// the SAME order the Journey UI walks (scenario order when SCENARIO_FILE is
// pinned, else sorted catalog ids; see cmd/scoreboard/main.go and
// api.JourneyConfig.Order). Returns the same *Grader for chaining at wiring
// time, matching WithPoints.
//
// This must be wired to the identical slice the api.Handler receives via
// WithOrder(order) (internal/scoreboard/server.go) — CurrentMission is the
// single source of truth both the Grader's attempt-scope taint gate and the
// Journey projection call, but they call it with their OWN copy of `order`,
// so a caller that wires them to two different orders reintroduces exactly
// the "two definitions of current" drift ADR-0003 §A1 warns against.
func (g *Grader) WithOrder(order []string) *Grader {
	g.order = order
	return g
}

// CurrentMission returns the first id in `order` that is present in `cat` and
// for which `solved(id)` is false — "current" as ADR-0003 §A1 defines it: the
// participant's attempt-in-progress mission. Empty order, or every id solved,
// returns "".
//
// This is the SINGLE SOURCE both the Grader's attempt-scope taint gate
// (currentMission) and the Journey projection (api.Handler.journey) must
// call — do not reimplement this filter+scan at either call site. `solved` is
// a predicate rather than a fixed set so each caller can back it with
// whatever it already has on hand: the Journey handler already built an
// in-memory set from one Snapshot() call (a map lookup), while the Grader
// asks the store one id at a time via ScoreStore.IsSolved — same contract,
// different but equally valid backing reads.
func CurrentMission(order []string, cat catalog.Catalog, solved func(id string) bool) string {
	for _, id := range order {
		if _, ok := cat[id]; !ok {
			continue // order references an id no longer in the catalog
		}
		if !solved(id) {
			return id
		}
	}
	return ""
}

// currentMission is the Grader's own call to CurrentMission: it supplies the
// Grader's configured order (falling back to sorted catalog ids, mirroring
// api.New's identical default) and backs `solved` with the store's per-pair
// ScoreStore.IsSolved read.
func (g *Grader) currentMission(user string) string {
	order := g.order
	if len(order) == 0 {
		order = g.cat.IDs()
	}
	return CurrentMission(order, g.cat, func(id string) bool {
		return g.store.IsSolved(user, id)
	})
}

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
		ch, ok := g.cat[cid]
		if !ok {
			continue // stale reveal for a challenge no longer in the catalog
		}
		if ch.NoHintPenalty {
			continue // e.g. 00-tutorial: hints are free on this challenge
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

// evaluateTrigger applies a single Falco rule fire to every trigger-type
// challenge whose expectedRules contain `rule`, marking each solved. It mirrors
// the old ingest loop exactly: iterate catalog ids in order, skip non-trigger
// challenges and non-matching rules, MarkSolved for the rest.
//
// Deliberately NOT attempt-scoped (unlike markDirtyOnRuleFire below): a
// trigger challenge auto-solves as soon as its own expectedRule fires,
// regardless of progression order — ADR-0003 only scopes the evade taint
// gate. A participant who fires a later mission's rule out of order still
// gets that solve recorded (this predates ADR-0003 and is unchanged by it).
//
// Store errors are continue-on-error, exactly as the old ingest loop was: a
// failing MarkSolved skips only that challenge (the others still get marked)
// and the failures are collected and returned joined via errors.Join.
//
// unexported (ADR-0003 A4): OnRuleFire is the only public entry point that
// may call this — see its doc for why the two stages must never be reachable
// independently.
func (g *Grader) evaluateTrigger(user, rule string) ([]TriggerResult, error) {
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

// markDirtyOnRuleFire applies a single Falco rule fire to the participant's
// CURRENT mission ONLY (ADR-0003 §A1: attempt scope), persisting a dirty
// taint if — and only if — that mission is evade-type and lists `rule` among
// its forbiddenRules.
//
// Before ADR-0003 (App-H2 alone) this fanned out to EVERY evade challenge
// whose forbiddenRules matched `rule`, unconditionally. That is PR #124's
// regression: several real missions (03/05/10) forbid the exact rule an
// EARLIER trigger mission REQUIRES firing to solve, so the unconditional
// fan-out permanently taints missions the participant has not attempted yet,
// the instant they legitimately clear the mission before it. Scoping the
// write to "only if this challenge is current right now" is what makes the
// twin-mission pairs work: while the earlier trigger mission is current, its
// own evade twin is never current, so the required fire cannot taint it.
//
// current() is resolved via currentMission → CurrentMission, the SAME
// function api.Handler.journey's projection calls (single source, §A1), and
// — this is the load-bearing ordering fact, not an implementation detail —
// MUST be resolved BEFORE this event's trigger solve is applied. OnRuleFire
// (the sole public entry point) enforces exactly that order: taint first,
// trigger solve second. Reversing it would let the SAME event that clears
// the earlier trigger mission also advance current to the evade twin before
// the taint check runs, re-tainting it in the same breath #124's bug did.
//
// A5 residual note: `rule` fired in the real world regardless of whether the
// store write below succeeds; store.MarkDirty is itself fail-closed (sets its
// in-memory taint even if the SQLite write errors — see store.go), so a
// returned error here means "the in-memory taint IS set, but persistence may
// not have happened" — see OnRuleFire's TaintErr doc for how the caller must
// react.
//
// unexported (ADR-0003 A4): OnRuleFire is the only public entry point that
// may call this.
func (g *Grader) markDirtyOnRuleFire(user, rule string) error {
	cur := g.currentMission(user)
	if cur == "" {
		return nil // every mission solved; nothing can be "current"
	}
	ch, ok := g.cat[cur]
	if !ok || ch.Type != "evade" {
		return nil
	}
	if !slices.Contains(ch.ForbiddenRules, rule) {
		return nil
	}
	at := g.now().UTC().Format(time.RFC3339Nano)
	return g.store.MarkDirty(user, cur, rule, at)
}

// recordExpectedRuleFire is ADR-0008's positive-proof write: for EVERY evade
// challenge (regardless of which mission is current — see below) that has
// RequireExpectedRuleFire set and lists `rule` among its ExpectedRules,
// record that the fire happened.
//
// Deliberately NOT attempt-scoped (unlike markDirtyOnRuleFire above): the
// challenge whose ExpectedRules this fire can satisfy is, by construction, a
// single evade mission with a rule name unique to it (ADR-0008 Decision (3):
// "Shell Redirected Private Key Read" is 05-only, never shared with another
// challenge's forbiddenRules/expectedRules the way ADR-0003's twin-mission
// pairs share a rule name). Attempt-scoping this write closes no exploit
// (there is no twin-mission collision to guard against here) and would only
// unfairly penalise a participant who happens to prove the technique before
// the mission becomes their "current" one — see ADR-0008 Decision (3)'s
// "write side" note for the full rationale.
//
// The `ch.Type == "evade"` guard below is NOT optional: ExpectedRules is a
// field shared with type=="trigger" challenges (evaluateTrigger reads the
// same slice, gated the opposite way — `ch.Type != "trigger"` continues).
// Dropping this guard would let a trigger challenge's ExpectedRules leak
// into expected_rule_fire, which would silently defeat Verification (c)'s
// uniqueness check on this ADR's new rule name.
//
// unexported (mirrors ADR-0003 A4's markDirtyOnRuleFire/evaluateTrigger
// split): OnRuleFire is the only public entry point that may call this.
func (g *Grader) recordExpectedRuleFire(user, rule string) error {
	var errs []error
	at := g.now().UTC().Format(time.RFC3339Nano)
	for _, cid := range g.cat.IDs() {
		ch := g.cat[cid]
		if ch.Type != "evade" {
			continue
		}
		if !ch.RequireExpectedRuleFire {
			continue
		}
		if !slices.Contains(ch.ExpectedRules, rule) {
			continue
		}
		if err := g.store.RecordExpectedRuleFire(user, cid, rule, at); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RuleFireOutcome is the result of Grader.OnRuleFire: the trigger solves the
// event produced, plus the taint / expected-fire / trigger errors kept
// SEPARATE (not errors.Join'd into one) because the ingest handler must
// react to them differently (ADR-0003 A5, extended by ADR-0008):
//
//   - TaintErr non-nil means the scoring authority may have failed to
//     PERSIST a taint for the participant's current mission (the in-memory
//     side of it is still set — store.MarkDirty is fail-closed). The caller
//     must surface this loudly: a 5xx response and the
//     FalcoEventsReceived{outcome="taint_error"} metric, never a silent 200 —
//     an unpersisted taint that also never got counted is a false-clean gap
//     that survives the next restart undetected.
//   - ExpectedFireErr non-nil (ADR-0008) means a positive-proof write may
//     have failed to persist (the in-memory side is still set —
//     store.RecordExpectedRuleFire is fail-closed, same pattern as
//     MarkDirty). Handled like TriggerErr below (log and still serve 200,
//     not TaintErr's 5xx escalation): a lost write here just means the
//     participant proves the technique again on a later fire of the same
//     rule, which does not create the kind of false-clean gap a lost taint
//     does. Kept as its own named field (not folded into TriggerErr) purely
//     for independent observability — the ingest handler logs each under
//     its own label.
//   - TriggerErr non-nil mirrors the pre-ADR-0003 continue-on-error posture:
//     log and still serve 200. A failed trigger solve just delays that
//     mission's auto-solve to the next matching Falco fire; it never creates
//     a false-clean gap the way a lost taint does, so it does not warrant the
//     same escalation.
type RuleFireOutcome struct {
	Results         []TriggerResult
	TaintErr        error
	ExpectedFireErr error
	TriggerErr      error
}

// OnRuleFire is the Grader's single public entry point for a Falco rule fire
// event (ADR-0003 A4). The ingest handler calls this ONCE per event and
// nothing else in this package's rule-fire path — markDirtyOnRuleFire and
// evaluateTrigger are unexported specifically so no other call site can
// invoke one half without the other, or invoke them out of order.
//
// Both reasons this matters:
//
//   - Before A4, ingest called MarkDirtyOnRuleFire and EvaluateTrigger as two
//     separate exported methods. A future caller (a replay tool, a test, an
//     alternate ingest source) that only wired up EvaluateTrigger would
//     silently reopen #120's original hole: rule fires would solve triggers
//     but never taint evade challenges, with no compile-time or code-review
//     signal that anything was missing.
//   - A1's attempt-scope regnorm requires current() to be resolved BEFORE
//     this event's trigger solve is applied (see markDirtyOnRuleFire's doc
//     for why — the 02→03 / 04→05 twin-mission structure depends on this
//     exact ordering). Two independently-callable methods make that ordering
//     a call-site convention instead of a structural guarantee; OnRuleFire
//     makes it a fact the type system enforces: taint first, trigger second,
//     every time, with no way to call them the other way around.
func (g *Grader) OnRuleFire(user, rule string) RuleFireOutcome {
	taintErr := g.markDirtyOnRuleFire(user, rule)
	// ADR-0008's positive-proof write. Order relative to the taint write
	// above is free (the two never interact — see recordExpectedRuleFire's
	// doc); placed after it to keep the diff minimal against the pre-ADR-0008
	// two-step. Must still run BEFORE evaluateTrigger for the same reason the
	// taint write does: no functional dependency, just keeping this event's
	// bookkeeping steps together before the (unrelated) trigger-solve step.
	expectedFireErr := g.recordExpectedRuleFire(user, rule)
	results, triggerErr := g.evaluateTrigger(user, rule)
	return RuleFireOutcome{
		Results:         results,
		TaintErr:        taintErr,
		ExpectedFireErr: expectedFireErr,
		TriggerErr:      triggerErr,
	}
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
	// EvadeForbiddenFired: flag correct, but the challenge is dirty — one or
	// more forbidden rules have fired since the last reset (offending rules
	// populated). Persistent (App-H2): no amount of waiting clears this: only
	// the explicit reset endpoint does.
	EvadeForbiddenFired
	// EvadeExpectedRuleFireRequired (ADR-0008): flag correct + not dirty, but
	// the challenge requires positive proof-of-technique
	// (RequireExpectedRuleFire) and none of its expectedRules has ever fired
	// for this (user, challenge). Declared here — between EvadeForbiddenFired
	// and EvadeExfilRequired — to match evaluateClean's gate execution order
	// (dirty -> expectedRuleFire -> exfil -> solve): this package's existing
	// self-documenting convention is "declaration order == gate order".
	EvadeExpectedRuleFireRequired
	// EvadeExfilRequired: flag correct + not dirty + proof satisfied, but the
	// challenge requires exfil and the collector has not received the
	// matching flag.
	EvadeExfilRequired
	// EvadeSolved: all gates passed; the solve was recorded (Newly reports
	// whether it was the first time).
	EvadeSolved
)

// EvadeOutcome is the full result of SubmitEvade. Only the fields relevant to
// Status are populated:
//   - EvadeForbiddenFired: Offending holds the sorted set of forbidden rules
//     that have EVER fired for this (user, challenge) since the last reset
//     (App-H2's persistent dirty flag — not a recent-window snapshot).
//   - EvadeSolved: Newly reports whether this was the first solve.
type EvadeOutcome struct {
	Status    EvadeStatus
	Offending []string // dirtying forbidden rules (EvadeForbiddenFired only)
	Newly     bool     // first-time solve (EvadeSolved only)
}

// SubmitEvade evaluates an evade-challenge flag submission through the same
// ordered gates the /submit handler used inline:
//
//  1. challenge exists (else EvadeUnknownChallenge)
//  2. challenge is evade type (else EvadeNotEvadeType)
//  3. flag matches expectedFlag (else EvadeWrongFlag)
//  4. the challenge is not dirty — no forbidden rule has EVER fired for this
//     (user, challenge) since the last explicit reset (else
//     EvadeForbiddenFired). App-H2: this is a persistent taint, not a
//     recent-window check — there is no server time involved in the decision
//     at all (contrast the pre-fix version, which read RecentFiresMatching
//     against g.now()).
//  5. if RequireExpectedRuleFire (ADR-0008), at least one expectedRule has
//     EVER fired for this (user, challenge) (else
//     EvadeExpectedRuleFireRequired) — the positive-proof counterpart to
//     gate 4's negative-proof taint.
//  6. if RequireExfil, the collector has the matching flag (else
//     EvadeExfilRequired)
//  7. record the solve → EvadeSolved.
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
	// Gates 4-7 (dirty-flag → expectedRuleFire gate → exfil gate → MarkSolved)
	// are the *single source of truth* shared with the auto-solve sweeper
	// (evaluateClean). Any change to the taint / proof / exfil / record logic
	// must be made there so manual submit and sweeper stay bit-for-bit
	// identical.
	return g.evaluateClean(user, ch, flag)
}

// evaluateClean applies the evade challenge's dirty-flag + expectedRuleFire +
// exfil gate and records the solve. It is the ONE place gates 4-7 live,
// shared verbatim by the manual /submit path (SubmitEvade) and the
// auto-solve Sweeper (Sweep). Callers must have already established (per
// SubmitEvade's gates 1-3): the challenge exists, is evade type, and `flag`
// equals ch.ExpectedFlag.
//
//  4. the pair is not dirty (store.DirtyRules empty) — App-H2: a PERSISTENT
//     taint, not a time window. g.now() plays no part in this decision at
//     all, so there is nothing here for an attacker-supplied or
//     server-advancing clock to influence.
//  5. if RequireExpectedRuleFire (ADR-0008), store.HasExpectedRuleFire holds
//     for this (user, challenge) — the positive-proof counterpart to gate 4,
//     same no-time-window property.
//  6. if RequireExfil, the collector holds the matching flag (HasExfil).
//  7. record the solve → EvadeSolved (Newly = first-time).
//
// Fail-closed: any store error from MarkSolved is returned unrecorded; a
// dirty pair, unmet proof, or unmet exfil returns the corresponding
// non-solved status, so a caller that mis-drives this (e.g. the sweeper
// enqueuing a still-dirty pair) simply does not solve — it never records a
// solve it should not.
func (g *Grader) evaluateClean(user string, ch catalog.Challenge, flag string) (EvadeOutcome, error) {
	offending := g.store.DirtyRules(user, ch.ID)
	if len(offending) > 0 {
		return EvadeOutcome{Status: EvadeForbiddenFired, Offending: offending}, nil
	}
	if ch.RequireExpectedRuleFire && !g.store.HasExpectedRuleFire(user, ch.ID) {
		return EvadeOutcome{Status: EvadeExpectedRuleFireRequired}, nil
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
// then the shared evaluateClean gate (dirty-flag check → HasExfil → MarkSolved)
// must pass. Only pairs that clear every gate are solved this tick.
//
// Fail-closed by construction:
//   - a dirty pair returns EvadeForbiddenFired → not solved (retried next
//     tick — and stays not-solved forever unless the participant explicitly
//     resets the taint, App-H2);
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
