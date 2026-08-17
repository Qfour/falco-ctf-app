package scoring

// points.go holds the CTF *points* model: a participant earns a fixed base
// award per solved challenge and forfeits a per-hint-index penalty for every
// hint they self-reveal in the Journey UI (Issue #40 — self-service
// progressive hints with a score penalty). Keeping the arithmetic here (not
// in the api handler) follows the #39 direction: the scoring domain service
// is the single owner of every solve/score decision, and the handlers stay
// thin adapters that only project the returned number.
//
// The per-hint penalty is a SCHEDULE keyed by hint index (HINT1/HINT2/HINT3
// cost different amounts), not a flat per-hint value — CEO-confirmed values
// are [10, 30, 50] for hint index 1/2/3 (steeper hints cost more, discouraging
// "reveal everything immediately"). A hint index beyond the schedule's length
// reuses the schedule's LAST value (rather than 0 or erroring) so a challenge
// with more hints than the tuned schedule still costs *something* per reveal
// (fail-closed: an out-of-schedule index must never become free).
//
// Fail-closed by construction (a hint reveal must never *raise* a score):
//   - each schedule entry is only ever subtracted, never added;
//   - a negative policy value (PerSolve, or any schedule entry) is normalised
//     to a non-negative value so a misconfiguration can only reduce (never
//     invert) the effect;
//   - the final score is clamped at 0 — revealing more hints than a participant
//     has earned points for floors the score, it never wraps negative.
//
// The score is a pure function of a store-derived solve count and the set of
// revealed hint indices, so it is fully reconstructible after a scoreboard
// restart from the persisted `solved` + `hint_views` tables — no in-memory
// running total to lose (conventions I1: single replica, state lives in
// SQLite).

// DefaultPointsPerSolve is the placeholder base award per solved challenge.
// PLACEHOLDER — the real value is a content-lead / CEO tuning decision; it is
// supplied at runtime via SCORE_POINTS_PER_SOLVE (cmd/scoreboard).
const DefaultPointsPerSolve = 100

// DefaultHintPenalties is the CEO-confirmed per-hint-index penalty schedule:
// HINT1 costs 10, HINT2 costs 30, HINT3 costs 50 (index i (1-based) -> slice
// index i-1). Steeper hints cost more, so a full 3-hint reveal costs 90 points
// (~90% of one solve's base award) — hints stay useful-but-costly, weighted so
// early hints are cheap nudges and later hints (closer to the answer) are
// expensive. Supplied at runtime via SCORE_HINT_PENALTIES (comma-separated,
// cmd/scoreboard); an index beyond len(schedule) reuses the last entry (see
// penaltyFor).
var DefaultHintPenalties = []int{10, 30, 50}

// PointsPolicy is the (base award, per-hint-index penalty schedule) pair the
// score computation uses. It is a plain value type so it can be constructed
// from env, passed by value into the Grader, and unit-tested without any
// store or clock.
type PointsPolicy struct {
	// PerSolve is the points awarded for each solved challenge.
	PerSolve int
	// HintPenalties is the per-hint-index penalty schedule: HintPenalties[i-1]
	// is the cost of revealing hint index i (1-based). An index beyond the
	// slice's length reuses the LAST entry (see penaltyFor) — never free.
	// Empty/nil is treated as "no schedule configured" and normalises to
	// DefaultHintPenalties (never to an all-free schedule) — see normalise.
	HintPenalties []int
}

// DefaultPointsPolicy is the placeholder policy used when the operator supplies
// no override. Both values are event-tuning knobs (see the const docs).
func DefaultPointsPolicy() PointsPolicy {
	return PointsPolicy{PerSolve: DefaultPointsPerSolve, HintPenalties: DefaultHintPenalties}
}

// normalise returns a policy whose fields are safe for the score arithmetic:
// negatives are floored to 0 so a misconfigured env can only weaken the
// effect, never invert it (a negative penalty would otherwise turn a hint
// reveal into a *reward* — the exact fail-open we must prevent). A negative
// PerSolve is floored to 0 (no negative awards). A zero penalty entry is
// allowed (hints free at that index — a valid operator choice); only a
// *negative* entry is corrected, to 0.
//
// An empty/nil HintPenalties falls back to DefaultHintPenalties rather than
// normalising to "no penalty at all" — an operator who successfully overrides
// SCORE_POINTS_PER_SOLVE but fails to set SCORE_HINT_PENALTIES (or sets it to
// an unparsable value) must not silently get free hints; cmd/scoreboard's env
// parsing already fails soft to DefaultHintPenalties for that case, and this
// is the same fail-closed posture applied at the policy-value level for any
// other caller that constructs a PointsPolicy directly (e.g. tests, or a
// future adapter).
func (p PointsPolicy) normalise() PointsPolicy {
	if p.PerSolve < 0 {
		p.PerSolve = 0
	}
	if len(p.HintPenalties) == 0 {
		p.HintPenalties = DefaultHintPenalties
	} else {
		cleaned := make([]int, len(p.HintPenalties))
		for i, v := range p.HintPenalties {
			if v < 0 {
				v = 0
			}
			cleaned[i] = v
		}
		p.HintPenalties = cleaned
	}
	return p
}

// penaltyFor returns the (already-normalised) policy's penalty for revealing
// 1-based hint index idx. idx <= 0 costs nothing (not a valid hint index —
// defensive). idx beyond the schedule's length reuses the LAST scheduled
// value, so a challenge authored with more hints than the tuned schedule
// still costs something per reveal rather than becoming free past the
// schedule's end (fail-closed: an unconfigured tail must never be a discount).
func (p PointsPolicy) penaltyFor(idx int) int {
	if idx <= 0 || len(p.HintPenalties) == 0 {
		return 0
	}
	if idx > len(p.HintPenalties) {
		idx = len(p.HintPenalties)
	}
	return p.HintPenalties[idx-1]
}

// ComputeScore is the pure score function: base award per solve minus the sum
// of the per-hint-index schedule penalty for every revealed hint index,
// clamped at 0. It never returns a negative score (fail-closed clamp) and the
// policy is normalised first so a negative schedule entry cannot turn a
// reveal into a reward. solvedCount is expected to already be de-duplicated by
// the store (MarkSolved is first-wins); hintIndices is expected to already be
// de-duplicated per (user, challenge, hintIdx) (RecordHintView is idempotent),
// so each solve/hint is counted exactly once. Duplicate entries within
// hintIndices (should not happen given the idempotent store, but not assumed)
// would double-charge that index — callers must pass a de-duplicated slice.
func ComputeScore(policy PointsPolicy, solvedCount int, hintIndices []int) int {
	p := policy.normalise()
	if solvedCount < 0 {
		solvedCount = 0
	}
	score := solvedCount * p.PerSolve
	for _, idx := range hintIndices {
		score -= p.penaltyFor(idx)
	}
	if score < 0 {
		return 0
	}
	return score
}
