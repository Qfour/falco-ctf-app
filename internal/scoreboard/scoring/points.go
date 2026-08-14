package scoring

// points.go holds the CTF *points* model: a participant earns a fixed base
// award per solved challenge and forfeits a fixed penalty for every hint they
// self-reveal in the Journey UI (Issue #40 — self-service progressive hints
// with a score penalty). Keeping the arithmetic here (not in the api handler)
// follows the #39 direction: the scoring domain service is the single owner of
// every solve/score decision, and the handlers stay thin adapters that only
// project the returned number.
//
// This is deliberately a *flat* per-hint penalty, not a per-hint schedule: the
// concrete point values are an event-tuning knob (content-lead / CEO confirm),
// so the framework carries safe placeholder defaults and reads the real values
// from env at wiring time (cmd/scoreboard). Over-modelling per-hint weights now
// would bake an unconfirmed content decision into code.
//
// Fail-closed by construction (a hint reveal must never *raise* a score):
//   - the penalty is only ever subtracted, never added;
//   - a negative or zero policy value is normalised to a non-negative default /
//     zero so a misconfiguration can only reduce (never invert) the effect;
//   - the final score is clamped at 0 — revealing more hints than a participant
//     has earned points for floors the score, it never wraps negative.
//
// The score is a pure function of two store-derived counts (solves, hint
// reveals), so it is fully reconstructible after a scoreboard restart from the
// persisted `solved` + `hint_views` tables — no in-memory running total to lose
// (conventions I1: single replica, state lives in SQLite).

// DefaultPointsPerSolve is the placeholder base award per solved challenge.
// PLACEHOLDER — the real value is a content-lead / CEO tuning decision; it is
// supplied at runtime via SCORE_POINTS_PER_SOLVE (cmd/scoreboard).
const DefaultPointsPerSolve = 100

// DefaultHintPenalty is the placeholder points forfeited per self-revealed
// hint. PLACEHOLDER — supplied at runtime via SCORE_HINT_PENALTY. Chosen so a
// full 3-hint reveal (the current per-challenge max) costs ~30% of one solve's
// base award, keeping hints useful-but-costly rather than free or ruinous.
const DefaultHintPenalty = 10

// PointsPolicy is the (base award, per-hint penalty) pair the score computation
// uses. It is a plain value type so it can be constructed from env, passed by
// value into the Grader, and unit-tested without any store or clock.
type PointsPolicy struct {
	// PerSolve is the points awarded for each solved challenge.
	PerSolve int
	// HintPenalty is the points forfeited for each self-revealed hint.
	HintPenalty int
}

// DefaultPointsPolicy is the placeholder policy used when the operator supplies
// no override. Both values are event-tuning knobs (see the const docs).
func DefaultPointsPolicy() PointsPolicy {
	return PointsPolicy{PerSolve: DefaultPointsPerSolve, HintPenalty: DefaultHintPenalty}
}

// normalise returns a policy whose fields are safe for the score arithmetic:
// negatives are floored to a non-negative value so a misconfigured env can only
// weaken the effect, never invert it (a negative HintPenalty would otherwise
// turn a hint reveal into a *reward* — the exact fail-open we must prevent).
// A negative PerSolve is floored to 0 (no negative awards). A zero HintPenalty
// is allowed (hints free — a valid operator choice); only a *negative* penalty
// is corrected, to 0.
func (p PointsPolicy) normalise() PointsPolicy {
	if p.PerSolve < 0 {
		p.PerSolve = 0
	}
	if p.HintPenalty < 0 {
		p.HintPenalty = 0
	}
	return p
}

// ComputeScore is the pure score function: base award per solve minus the flat
// penalty per revealed hint, clamped at 0. It never returns a negative score
// (fail-closed clamp) and the policy is normalised first so a negative penalty
// cannot turn a reveal into a reward. Both counts are expected to already be
// de-duplicated by the store (MarkSolved is first-wins; RecordHintView is
// idempotent per (user, challenge, hintIdx)), so each solve/hint is counted
// exactly once.
func ComputeScore(policy PointsPolicy, solvedCount, hintsRevealed int) int {
	p := policy.normalise()
	if solvedCount < 0 {
		solvedCount = 0
	}
	if hintsRevealed < 0 {
		hintsRevealed = 0
	}
	score := solvedCount*p.PerSolve - hintsRevealed*p.HintPenalty
	if score < 0 {
		return 0
	}
	return score
}
