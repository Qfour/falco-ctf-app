package scoring_test

import (
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
)

// TestComputeScore covers the pure score arithmetic (#40): base award per solve
// minus a flat per-hint penalty, with the fail-closed guarantees (never
// negative, a negative penalty cannot become a reward).
func TestComputeScore(t *testing.T) {
	p := scoring.PointsPolicy{PerSolve: 100, HintPenalty: 10}
	cases := []struct {
		name          string
		policy        scoring.PointsPolicy
		solved, hints int
		want          int
	}{
		{"no solves no hints", p, 0, 0, 0},
		{"solves no hints", p, 3, 0, 300},
		{"solves minus hints", p, 3, 4, 260},
		{"hints exceed award clamps at zero", p, 1, 20, 0},
		{"exact zero", p, 1, 10, 0},
		{"zero penalty keeps full award", scoring.PointsPolicy{PerSolve: 100, HintPenalty: 0}, 2, 5, 200},
		// Fail-closed: a negative penalty is normalised to 0 so a reveal can never
		// *raise* the score (would otherwise yield 100 + 3*10 = 130).
		{"negative penalty normalised to zero", scoring.PointsPolicy{PerSolve: 100, HintPenalty: -10}, 1, 3, 100},
		// Fail-closed: a negative award is floored to 0 (no negative base).
		{"negative per-solve floored to zero", scoring.PointsPolicy{PerSolve: -100, HintPenalty: 10}, 3, 1, 0},
		// Defensive: negative counts (should never happen) are treated as 0.
		{"negative counts treated as zero", p, -2, -5, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scoring.ComputeScore(tc.policy, tc.solved, tc.hints); got != tc.want {
				t.Fatalf("ComputeScore(%+v, solved=%d, hints=%d) = %d, want %d",
					tc.policy, tc.solved, tc.hints, got, tc.want)
			}
		})
	}
}

// TestDefaultPointsPolicy pins the placeholder defaults so a change to the
// event-tuning values is a deliberate, reviewed edit (the real values are a
// content-lead / CEO decision — this guards the framework's safe fallback).
func TestDefaultPointsPolicy(t *testing.T) {
	p := scoring.DefaultPointsPolicy()
	if p.PerSolve != scoring.DefaultPointsPerSolve || p.HintPenalty != scoring.DefaultHintPenalty {
		t.Fatalf("DefaultPointsPolicy() = %+v, want {PerSolve:%d HintPenalty:%d}",
			p, scoring.DefaultPointsPerSolve, scoring.DefaultHintPenalty)
	}
	if p.PerSolve <= 0 || p.HintPenalty < 0 {
		t.Fatalf("placeholder defaults must be a positive award and non-negative penalty, got %+v", p)
	}
}

// TestUserScore_SumsHintRevealsAcrossChallenges proves the Grader sums a user's
// hint reveals across every challenge (not just the current one) and applies
// the policy penalty, using the caller-supplied solved count.
func TestUserScore_SumsHintRevealsAcrossChallenges(t *testing.T) {
	f := newFakeStore()
	f.hintViews = map[string]map[string][]int{
		"alice": {
			"01-trigger": {1, 2}, // 2 reveals
			"02-evade":   {1},    // 1 reveal
		},
		"bob": {"01-trigger": {1}}, // isolated: must not affect alice
	}
	g := scoring.New(testCatalog(), f, nil).WithPoints(scoring.PointsPolicy{PerSolve: 100, HintPenalty: 10})

	// alice solved 2 challenges, revealed 3 hints total → 200 - 30 = 170.
	if got := g.UserScore("alice", 2); got != 170 {
		t.Fatalf("alice score = %d, want 170", got)
	}
	// A user with no reveals recorded loses nothing.
	if got := g.UserScore("carol", 1); got != 100 {
		t.Fatalf("carol score = %d, want 100", got)
	}
}

// TestUserScore_DefaultPolicyWhenUnset confirms a Grader built without
// WithPoints uses the placeholder defaults (100/solve, 10/hint).
func TestUserScore_DefaultPolicyWhenUnset(t *testing.T) {
	f := newFakeStore()
	f.hintViews = map[string]map[string][]int{"alice": {"01-trigger": {1, 2, 3}}}
	g := scoring.New(testCatalog(), f, nil) // no WithPoints → defaults

	// 2 solves * 100 - 3 hints * 10 = 170.
	if got := g.UserScore("alice", 2); got != 170 {
		t.Fatalf("default-policy score = %d, want 170", got)
	}
	if p := g.Points(); p.PerSolve != scoring.DefaultPointsPerSolve || p.HintPenalty != scoring.DefaultHintPenalty {
		t.Fatalf("Points() = %+v, want defaults", p)
	}
}

// TestUserScore_IgnoresStaleHintViewsOutsideCatalog is the #40 R2 regression:
// UserScore must sum hint reveals ONLY over challenges still in the active
// catalog, symmetric with the caller's catalog-filtered solvedCount. A stale
// hint_views row for a since-removed challenge (e.g. a scenario reshuffle) must
// NOT keep deducting the penalty — otherwise a user is over-penalised for a
// challenge they can no longer see. Verified at the score-value level.
func TestUserScore_IgnoresStaleHintViewsOutsideCatalog(t *testing.T) {
	f := newFakeStore()
	f.hintViews = map[string]map[string][]int{
		"alice": {
			"01-trigger":  {1, 2}, // 2 reveals — IN catalog (counted)
			"99-removed":  {1, 2}, // 2 reveals — NOT in catalog (must be ignored)
			"88-scenario": {1},    // 1 reveal  — NOT in catalog (must be ignored)
		},
	}
	g := scoring.New(testCatalog(), f, nil).
		WithPoints(scoring.PointsPolicy{PerSolve: 100, HintPenalty: 10})

	// Only the 2 in-catalog reveals count: 2 solves*100 - 2 hints*10 = 180.
	// If the stale rows leaked in it would be 200 - 5*10 = 150 (over-penalised).
	if got := g.UserScore("alice", 2); got != 180 {
		t.Fatalf("alice score = %d, want 180 (stale out-of-catalog hint_views must not deduct)", got)
	}

	// Fail-closed sanity: a user whose ONLY reveals are for removed challenges
	// loses nothing — the penalty side is fully catalog-gated.
	f.hintViews["bob"] = map[string][]int{"99-removed": {1, 2, 3}}
	if got := g.UserScore("bob", 1); got != 100 {
		t.Fatalf("bob score = %d, want 100 (all reveals out-of-catalog → no penalty)", got)
	}
}

// TestPoints_ReturnsNormalised proves the adapter-facing Points() never surfaces
// a negative penalty/award to the UI (R1): a misconfigured negative policy is
// floored to 0, matching the normalisation ComputeScore applies — so what the
// UI advertises ("costs N points") and what the score subtracts always agree.
func TestPoints_ReturnsNormalised(t *testing.T) {
	f := newFakeStore()
	g := scoring.New(testCatalog(), f, nil).
		WithPoints(scoring.PointsPolicy{PerSolve: -100, HintPenalty: -10})

	p := g.Points()
	if p.HintPenalty != 0 {
		t.Errorf("Points().HintPenalty = %d, want 0 (negative floored — UI must not show a negative cost)", p.HintPenalty)
	}
	if p.PerSolve != 0 {
		t.Errorf("Points().PerSolve = %d, want 0 (negative floored)", p.PerSolve)
	}
}
