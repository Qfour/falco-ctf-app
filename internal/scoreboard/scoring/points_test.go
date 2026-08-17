package scoring_test

import (
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
)

// TestComputeScore covers the pure score arithmetic (#40): base award per solve
// minus the per-hint-index schedule penalty, with the fail-closed guarantees
// (never negative, a negative schedule entry cannot become a reward).
func TestComputeScore(t *testing.T) {
	p := scoring.PointsPolicy{PerSolve: 100, HintPenalties: []int{10, 30, 50}}
	cases := []struct {
		name        string
		policy      scoring.PointsPolicy
		solved      int
		hintIndices []int
		want        int
	}{
		{"no solves no hints", p, 0, nil, 0},
		{"solves no hints", p, 3, nil, 300},
		// HINT1 (10) + HINT2 (30) = 40 forfeited: 300 - 40 = 260.
		{"solves minus scheduled hints", p, 3, []int{1, 2}, 260},
		// HINT1+HINT2+HINT3 = 10+30+50 = 90 forfeited: 100 - 90 = 10.
		{"all three hints", p, 1, []int{1, 2, 3}, 10},
		// Index 4 is beyond the 3-entry schedule -> reuses the LAST entry (50).
		// 100 - 50 = 50.
		{"index beyond schedule reuses last entry", p, 1, []int{4}, 50},
		{"hints exceed award clamps at zero", p, 1, []int{1, 2, 3, 3, 3, 3, 3, 3, 3, 3}, 0},
		{"zero penalty schedule keeps full award", scoring.PointsPolicy{PerSolve: 100, HintPenalties: []int{0, 0, 0}}, 2, []int{1, 2, 3}, 200},
		// Fail-closed: a negative schedule entry is normalised to 0 so a reveal
		// can never *raise* the score (would otherwise yield 100 + 10 = 110).
		{"negative penalty normalised to zero", scoring.PointsPolicy{PerSolve: 100, HintPenalties: []int{-10, 30, 50}}, 1, []int{1}, 100},
		// Fail-closed: a negative award is floored to 0 (no negative base).
		{"negative per-solve floored to zero", scoring.PointsPolicy{PerSolve: -100, HintPenalties: []int{10}}, 3, []int{1}, 0},
		// Defensive: a negative solved count (should never happen) is treated as 0.
		{"negative solved count treated as zero", p, -2, nil, 0},
		// Empty/nil HintPenalties falls back to the default schedule rather than
		// "no penalty at all" (fail-closed — see PointsPolicy.normalise doc).
		{"empty schedule falls back to default", scoring.PointsPolicy{PerSolve: 100, HintPenalties: nil}, 1, []int{1, 2}, 60},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scoring.ComputeScore(tc.policy, tc.solved, tc.hintIndices); got != tc.want {
				t.Fatalf("ComputeScore(%+v, solved=%d, hints=%v) = %d, want %d",
					tc.policy, tc.solved, tc.hintIndices, got, tc.want)
			}
		})
	}
}

// TestDefaultPointsPolicy pins the CEO-confirmed default schedule
// ([10, 30, 50] for HINT1/HINT2/HINT3) so a change to the event-tuning values
// is a deliberate, reviewed edit.
func TestDefaultPointsPolicy(t *testing.T) {
	p := scoring.DefaultPointsPolicy()
	if p.PerSolve != scoring.DefaultPointsPerSolve {
		t.Fatalf("DefaultPointsPolicy().PerSolve = %d, want %d", p.PerSolve, scoring.DefaultPointsPerSolve)
	}
	want := []int{10, 30, 50}
	if len(p.HintPenalties) != len(want) {
		t.Fatalf("DefaultPointsPolicy().HintPenalties = %v, want %v", p.HintPenalties, want)
	}
	for i, w := range want {
		if p.HintPenalties[i] != w {
			t.Fatalf("DefaultPointsPolicy().HintPenalties[%d] = %d, want %d", i, p.HintPenalties[i], w)
		}
	}
	if p.PerSolve <= 0 {
		t.Fatalf("placeholder default must be a positive award, got %+v", p)
	}
	for _, v := range p.HintPenalties {
		if v < 0 {
			t.Fatalf("placeholder default schedule must be non-negative, got %+v", p)
		}
	}
}

// TestUserScore_SumsHintRevealsAcrossChallenges proves the Grader sums a user's
// hint reveals across every challenge (not just the current one) and applies
// the per-hint-index schedule penalty, using the caller-supplied solved count.
func TestUserScore_SumsHintRevealsAcrossChallenges(t *testing.T) {
	f := newFakeStore()
	f.hintViews = map[string]map[string][]int{
		"alice": {
			"01-trigger": {1, 2}, // HINT1(10) + HINT2(30) = 40
			"02-evade":   {1},    // HINT1(10) = 10
		},
		"bob": {"01-trigger": {1}}, // isolated: must not affect alice
	}
	g := scoring.New(testCatalog(), f, nil).WithPoints(scoring.PointsPolicy{PerSolve: 100, HintPenalties: []int{10, 30, 50}})

	// alice solved 2 challenges (200) minus 40+10=50 forfeited -> 150.
	if got := g.UserScore("alice", 2); got != 150 {
		t.Fatalf("alice score = %d, want 150", got)
	}
	// A user with no reveals recorded loses nothing.
	if got := g.UserScore("carol", 1); got != 100 {
		t.Fatalf("carol score = %d, want 100", got)
	}
}

// TestUserScore_DefaultPolicyWhenUnset confirms a Grader built without
// WithPoints uses the placeholder defaults (100/solve, [10,30,50] schedule).
func TestUserScore_DefaultPolicyWhenUnset(t *testing.T) {
	f := newFakeStore()
	f.hintViews = map[string]map[string][]int{"alice": {"01-trigger": {1, 2, 3}}}
	g := scoring.New(testCatalog(), f, nil) // no WithPoints -> defaults

	// 2 solves * 100 - (10+30+50) = 200 - 90 = 110.
	if got := g.UserScore("alice", 2); got != 110 {
		t.Fatalf("default-policy score = %d, want 110", got)
	}
	p := g.Points()
	if p.PerSolve != scoring.DefaultPointsPerSolve {
		t.Fatalf("Points().PerSolve = %d, want default", p.PerSolve)
	}
	if len(p.HintPenalties) != 3 || p.HintPenalties[0] != 10 || p.HintPenalties[1] != 30 || p.HintPenalties[2] != 50 {
		t.Fatalf("Points().HintPenalties = %v, want default schedule", p.HintPenalties)
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
			"01-trigger":  {1, 2}, // HINT1+HINT2 = 40 — IN catalog (counted)
			"99-removed":  {1, 2}, // NOT in catalog (must be ignored)
			"88-scenario": {1},    // NOT in catalog (must be ignored)
		},
	}
	g := scoring.New(testCatalog(), f, nil).
		WithPoints(scoring.PointsPolicy{PerSolve: 100, HintPenalties: []int{10, 30, 50}})

	// Only the 2 in-catalog reveals count: 2*100 - (10+30) = 160.
	// If the stale rows leaked in it would be 200 - (10+30+10+30+10) = 110 (over-penalised).
	if got := g.UserScore("alice", 2); got != 160 {
		t.Fatalf("alice score = %d, want 160 (stale out-of-catalog hint_views must not deduct)", got)
	}

	// Fail-closed sanity: a user whose ONLY reveals are for removed challenges
	// loses nothing — the penalty side is fully catalog-gated.
	f.hintViews["bob"] = map[string][]int{"99-removed": {1, 2, 3}}
	if got := g.UserScore("bob", 1); got != 100 {
		t.Fatalf("bob score = %d, want 100 (all reveals out-of-catalog -> no penalty)", got)
	}
}

// TestPoints_ReturnsNormalised proves the adapter-facing Points() never surfaces
// a negative penalty/award to the UI (R1): a misconfigured negative policy is
// floored to 0, matching the normalisation ComputeScore applies — so what the
// UI advertises ("costs N points") and what the score subtracts always agree.
func TestPoints_ReturnsNormalised(t *testing.T) {
	f := newFakeStore()
	g := scoring.New(testCatalog(), f, nil).
		WithPoints(scoring.PointsPolicy{PerSolve: -100, HintPenalties: []int{-10, -30, -50}})

	p := g.Points()
	for i, v := range p.HintPenalties {
		if v != 0 {
			t.Errorf("Points().HintPenalties[%d] = %d, want 0 (negative floored — UI must not show a negative cost)", i, v)
		}
	}
	if p.PerSolve != 0 {
		t.Errorf("Points().PerSolve = %d, want 0 (negative floored)", p.PerSolve)
	}
}

// TestHintPenaltyFor covers the per-index lookup the api handler uses to price
// the SPECIFIC next-unopened hint (missionDetail's hints.penalty projection):
// HINT1/HINT2/HINT3 cost different amounts, an index beyond the schedule
// reuses the last entry (never free), and idx<=0 (nothing to reveal) costs 0.
func TestHintPenaltyFor(t *testing.T) {
	g := scoring.New(testCatalog(), newFakeStore(), nil).
		WithPoints(scoring.PointsPolicy{PerSolve: 100, HintPenalties: []int{10, 30, 50}})

	cases := []struct {
		idx  int
		want int
	}{
		{0, 0},   // nothing to reveal
		{-1, 0},  // defensive: invalid index
		{1, 10},  // HINT1
		{2, 30},  // HINT2
		{3, 50},  // HINT3
		{4, 50},  // beyond schedule -> reuse last entry
		{99, 50}, // far beyond -> still reuse last entry
	}
	for _, tc := range cases {
		if got := g.HintPenaltyFor(tc.idx); got != tc.want {
			t.Errorf("HintPenaltyFor(%d) = %d, want %d", tc.idx, got, tc.want)
		}
	}
}

// TestHintPenaltyFor_NegativeScheduleNormalised proves HintPenaltyFor projects
// the SAME normalisation Points() does — a misconfigured negative entry is
// floored to 0, never surfaced as a negative "cost".
func TestHintPenaltyFor_NegativeScheduleNormalised(t *testing.T) {
	g := scoring.New(testCatalog(), newFakeStore(), nil).
		WithPoints(scoring.PointsPolicy{PerSolve: 100, HintPenalties: []int{-10, 30}})
	if got := g.HintPenaltyFor(1); got != 0 {
		t.Errorf("HintPenaltyFor(1) = %d, want 0 (negative floored)", got)
	}
	if got := g.HintPenaltyFor(2); got != 30 {
		t.Errorf("HintPenaltyFor(2) = %d, want 30", got)
	}
}
