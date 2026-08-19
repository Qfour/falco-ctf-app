package apispec

// This file is ADR-0005 V8's generic, algorithm-level "prove the detector
// itself is fail-closed" evidence: table-driven mutation tests against the
// comparison primitives (RouteSetDiff, BoolExtParity,
// CollectorForwardBijection, ResetDirty*, CompareResponse) using small
// synthetic fixtures — NOT the real docs/openapi-*.yaml files (those are
// exercised for real by internal/scoreboard, internal/collector and
// internal/authpolicy's own parity tests). Keeping the mutation proof here,
// against hand-built inputs, means it stays fast, has no service-fixture
// dependency, and — most importantly — proves the ALGORITHM catches each of
// the three ADR-0005 V8 mutation classes (route removed, origin-guard flag
// flipped, field renamed) in isolation, before ever trusting it against a
// 1,600-line real spec.

import "testing"

func baseSpecOps() map[string]map[string]any {
	return map[string]map[string]any{
		"GET /api/state": {
			"x-ctf-origin-guard":      false,
			"x-ctf-collector-forward": false,
		},
		"POST /api/admin/reset": {
			"x-ctf-origin-guard":      true,
			"x-ctf-collector-forward": false,
		},
		"POST /api/challenges/{cid}/submit": {
			"x-ctf-origin-guard":      false,
			"x-ctf-collector-forward": true,
		},
	}
}

func baseRoutes() []Route {
	return []Route{
		{Method: "GET", Pattern: "/api/state", OriginGuarded: false, CollectorForward: false},
		{Method: "POST", Pattern: "/api/admin/reset", OriginGuarded: true, CollectorForward: false},
		{Method: "POST", Pattern: "/api/challenges/{cid}/submit", OriginGuarded: false, CollectorForward: true},
	}
}

// TestRouteSetDiff_CleanIsEmpty pins the non-mutated baseline: matching spec
// and route sets must report no diff at all. Every mutation test below
// starts from this same baseline so a failure there (not the mutation) can't
// be mistaken for the detector working.
func TestRouteSetDiff_CleanIsEmpty(t *testing.T) {
	specOnly, implOnly := RouteSetDiff(baseSpecOps(), baseRoutes())
	if len(specOnly) != 0 || len(implOnly) != 0 {
		t.Fatalf("clean fixture must have no diff, got specOnly=%v implOnly=%v", specOnly, implOnly)
	}
}

// TestRouteSetDiff_CatchesRemovedRoute is V8 mutation class 1: deleting one
// route from the IMPLEMENTATION side (simulating "a handler's Register
// dropped a route") must surface it as specOnly (documented but not
// implemented) and nothing else.
func TestRouteSetDiff_CatchesRemovedRoute(t *testing.T) {
	routes := baseRoutes()
	mutated := routes[:len(routes)-1] // drop "POST /api/challenges/{cid}/submit"
	specOnly, implOnly := RouteSetDiff(baseSpecOps(), mutated)
	if len(implOnly) != 0 {
		t.Fatalf("removing an implemented route must not produce implOnly entries, got %v", implOnly)
	}
	if len(specOnly) != 1 || specOnly[0] != "POST /api/challenges/{cid}/submit" {
		t.Fatalf("expected specOnly=[POST /api/challenges/{cid}/submit], got %v", specOnly)
	}
}

// TestRouteSetDiff_CatchesRemovedSpecEntry is the mirror direction: deleting
// a route from the SPEC side (simulating "a route was added to Register but
// nobody wrote it down") must surface as implOnly.
func TestRouteSetDiff_CatchesRemovedSpecEntry(t *testing.T) {
	specOps := baseSpecOps()
	delete(specOps, "POST /api/admin/reset")
	specOnly, implOnly := RouteSetDiff(specOps, baseRoutes())
	if len(specOnly) != 0 {
		t.Fatalf("removing a spec entry must not produce specOnly entries, got %v", specOnly)
	}
	if len(implOnly) != 1 || implOnly[0] != "POST /api/admin/reset" {
		t.Fatalf("expected implOnly=[POST /api/admin/reset], got %v", implOnly)
	}
}

// TestBoolExtParity_CatchesFlippedFlag is V8 mutation class 2: flipping one
// route's OriginGuarded value (simulating an accidental h.og(...) removal or
// addition) against an UNCHANGED spec must be caught as a mismatch, on the
// correct side (onlySpec: spec says true, impl now says false).
func TestBoolExtParity_CatchesFlippedFlag(t *testing.T) {
	routes := baseRoutes()
	for i := range routes {
		if routes[i].MuxPattern() == "POST /api/admin/reset" {
			routes[i].OriginGuarded = false // was true — flip it
		}
	}
	missingKey, onlyImpl, onlySpec := BoolExtParity(baseSpecOps(), routes, "x-ctf-origin-guard", func(rt Route) bool { return rt.OriginGuarded })
	if len(missingKey) != 0 {
		t.Fatalf("no key should be reported missing here, got %v", missingKey)
	}
	if len(onlyImpl) != 0 {
		t.Fatalf("expected no onlyImpl entries, got %v", onlyImpl)
	}
	if len(onlySpec) != 1 || onlySpec[0] != "POST /api/admin/reset" {
		t.Fatalf("expected onlySpec=[POST /api/admin/reset], got %v", onlySpec)
	}
}

// TestBoolExtParity_CatchesMissingKey is ADR-0005 V3's specific fail-closed
// rule: an ABSENT x-ctf-origin-guard key must be reported (never silently
// treated as "false").
func TestBoolExtParity_CatchesMissingKey(t *testing.T) {
	specOps := baseSpecOps()
	delete(specOps["POST /api/admin/reset"], "x-ctf-origin-guard")
	missingKey, _, _ := BoolExtParity(specOps, baseRoutes(), "x-ctf-origin-guard", func(rt Route) bool { return rt.OriginGuarded })
	if len(missingKey) != 1 || missingKey[0] != "POST /api/admin/reset" {
		t.Fatalf("expected missingKey=[POST /api/admin/reset], got %v", missingKey)
	}
}

// TestCollectorForwardBijection_Clean pins the non-mutated baseline for the
// spec-to-spec bijection.
func TestCollectorForwardBijection_Clean(t *testing.T) {
	collectorOps := map[string]map[string]any{
		"POST /api/challenges/{cid}/submit": {
			"x-ctf-collector-forward": true,
			"x-ctf-forward-target":    "POST /api/challenges/{cid}/submit",
		},
	}
	scoreboardOps := baseSpecOps()
	if probs := CollectorForwardBijection(collectorOps, scoreboardOps); len(probs) != 0 {
		t.Fatalf("clean bijection fixture must have no problems, got %v", probs)
	}
}

// TestCollectorForwardBijection_CatchesResetDirtyAddedToForward is V8
// mutation class 2 applied to the ADR-0003 A2-2 guard specifically: if
// reset-dirty is (mis)marked x-ctf-collector-forward: true in the
// scoreboard spec, ResetDirtySpecViolation must catch it even though
// nothing names it from the collector side (so the general bijection alone
// would only flag "no collector op claims it", not the security-relevant
// reason). This is why ADR-0005 V4 wants a DEDICATED assert, not just the
// bijection.
func TestCollectorForwardBijection_CatchesResetDirtyAddedToForward(t *testing.T) {
	scoreboardOps := baseSpecOps()
	scoreboardOps[ResetDirtyPattern] = map[string]any{"x-ctf-collector-forward": true}

	if got := ResetDirtySpecViolation(scoreboardOps); got == "" {
		t.Fatal("expected ResetDirtySpecViolation to flag reset-dirty marked collector-forward:true, got empty string")
	}

	// The general bijection must ALSO notice (as "no collector op claims
	// it") — belt and suspenders, not a replacement for the dedicated check.
	probs := CollectorForwardBijection(map[string]map[string]any{}, scoreboardOps)
	if len(probs) == 0 {
		t.Fatal("expected the general bijection to also flag the unclaimed forwardable scoreboard route")
	}
}

// TestResetDirtyRouteViolation_CatchesTableMutation is
// TestCollectorForwardBijection_CatchesResetDirtyAddedToForward's
// implementation-side twin: mutating the ACTUAL route table (not the spec)
// must be caught the same way.
func TestResetDirtyRouteViolation_CatchesTableMutation(t *testing.T) {
	routes := []Route{{Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/reset-dirty", CollectorForward: true}}
	if got := ResetDirtyRouteViolation(routes); got == "" {
		t.Fatal("expected ResetDirtyRouteViolation to flag a reset-dirty Route with CollectorForward=true")
	}
	clean := []Route{{Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/reset-dirty", CollectorForward: false}}
	if got := ResetDirtyRouteViolation(clean); got != "" {
		t.Fatalf("expected no violation for CollectorForward=false, got %q", got)
	}
}

// --- V5 (CompareResponse) mutation proof ------------------------------------

func journeySchemaFixture() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"user":  map[string]any{"type": "string"},
			"score": map[string]any{"type": "integer"},
			"detail": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":     map[string]any{"type": "string"},
					"status": map[string]any{"type": "string"},
				},
			},
			"missions": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":     map[string]any{"type": "string"},
						"status": map[string]any{"type": "string"},
					},
				},
			},
		},
	}
}

func journeyActualFixture() map[string]any {
	return map[string]any{
		"user":  "alice",
		"score": float64(10),
		"detail": map[string]any{
			"id":     "01-x",
			"status": "current",
		},
		"missions": []any{
			map[string]any{"id": "01-x", "status": "current"},
			map[string]any{"id": "02-y", "status": "locked"},
		},
	}
}

func newFixtureSpec(schemas map[string]any) *Spec {
	return &Spec{raw: map[string]any{
		"components": map[string]any{"schemas": schemas},
	}}
}

// TestCompareResponse_CleanIsEmpty pins the non-mutated baseline for the
// nested V5 comparator (top level + detail + missions[0]).
func TestCompareResponse_CleanIsEmpty(t *testing.T) {
	s := newFixtureSpec(nil)
	mismatches := CompareResponse(s, journeySchemaFixture(), journeyActualFixture(), "journey")
	if len(mismatches) != 0 {
		t.Fatalf("clean fixture must have no mismatches, got %+v", mismatches)
	}
}

// TestCompareResponse_CatchesRenamedTopLevelField is V8 mutation class 3
// (field rename) at the TOP level: renaming "score" to "points" in the
// actual JSON (simulating a handler rename that forgot the spec, or vice
// versa) must be caught as an extra+missing pair at path "journey".
func TestCompareResponse_CatchesRenamedTopLevelField(t *testing.T) {
	actual := journeyActualFixture()
	actual["points"] = actual["score"]
	delete(actual, "score")

	s := newFixtureSpec(nil)
	mismatches := CompareResponse(s, journeySchemaFixture(), actual, "journey")
	if len(mismatches) != 1 {
		t.Fatalf("expected exactly one mismatch location, got %d: %+v", len(mismatches), mismatches)
	}
	m := mismatches[0]
	if m.Path != "journey" {
		t.Fatalf("expected mismatch at path %q, got %q", "journey", m.Path)
	}
	if len(m.Extra) != 1 || m.Extra[0] != "points" {
		t.Fatalf("expected Extra=[points], got %v", m.Extra)
	}
	if len(m.Missing) != 1 || m.Missing[0] != "score" {
		t.Fatalf("expected Missing=[score], got %v", m.Missing)
	}
}

// TestCompareResponse_CatchesRenamedNestedField proves the SAME mutation
// class is caught at a NESTED level (detail.status -> detail.state) — this
// is the specific hole a literal top-level-only key check would miss, and
// exactly what ADR-0005 V5 means by "ネストは spec が properties を宣言している
// 箇所だけ再帰する".
func TestCompareResponse_CatchesRenamedNestedField(t *testing.T) {
	actual := journeyActualFixture()
	detail := actual["detail"].(map[string]any)
	detail["state"] = detail["status"]
	delete(detail, "status")

	s := newFixtureSpec(nil)
	mismatches := CompareResponse(s, journeySchemaFixture(), actual, "journey")
	if len(mismatches) != 1 {
		t.Fatalf("expected exactly one mismatch location, got %d: %+v", len(mismatches), mismatches)
	}
	if mismatches[0].Path != "journey.detail" {
		t.Fatalf("expected mismatch at path %q, got %q", "journey.detail", mismatches[0].Path)
	}
}

// TestCompareResponse_CatchesRenamedArrayItemField proves the same class is
// caught inside an array's first-element check (missions[0].id ->
// missions[0].slug).
func TestCompareResponse_CatchesRenamedArrayItemField(t *testing.T) {
	actual := journeyActualFixture()
	missions := actual["missions"].([]any)
	first := missions[0].(map[string]any)
	first["slug"] = first["id"]
	delete(first, "id")

	s := newFixtureSpec(nil)
	mismatches := CompareResponse(s, journeySchemaFixture(), actual, "journey")
	if len(mismatches) != 1 {
		t.Fatalf("expected exactly one mismatch location, got %d: %+v", len(mismatches), mismatches)
	}
	if mismatches[0].Path != "journey.missions[0]" {
		t.Fatalf("expected mismatch at path %q, got %q", "journey.missions[0]", mismatches[0].Path)
	}
}

// TestCompareResponse_UsesPropertiesNotRequired is ADR-0005 V5's other
// explicit rule: comparison is against `properties`, not `required`. A
// schema with a property absent from `required` (i.e. nullable / pointer in
// generated code) must still be checked for presence in `properties`, and a
// schema that declares NO `required` at all must not be treated as "nothing
// to check".
func TestCompareResponse_UsesPropertiesNotRequired(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		// no "required" key at all
		"properties": map[string]any{
			"a": map[string]any{"type": "string"},
			"b": map[string]any{"type": "string"},
		},
	}
	s := newFixtureSpec(nil)
	// actual is missing "b" — must still be flagged even though nothing was
	// ever in `required`.
	mismatches := CompareResponse(s, schema, map[string]any{"a": "x"}, "root")
	if len(mismatches) != 1 || len(mismatches[0].Missing) != 1 || mismatches[0].Missing[0] != "b" {
		t.Fatalf("expected a missing-b mismatch, got %+v", mismatches)
	}
}

// TestPropertyNames_ResolvesRefAndAllOf pins the $ref/allOf resolution
// CompareResponse depends on for nested $ref properties (e.g.
// Journey.detail: {allOf: [{$ref: "#/components/schemas/MissionDetail"}]}).
func TestPropertyNames_ResolvesRefAndAllOf(t *testing.T) {
	s := newFixtureSpec(map[string]any{
		"Inner": map[string]any{
			"type":       "object",
			"properties": map[string]any{"x": map[string]any{"type": "string"}},
		},
	})
	viaRef := map[string]any{"$ref": "#/components/schemas/Inner"}
	if got := s.PropertyNames(viaRef); !got["x"] || len(got) != 1 {
		t.Fatalf("$ref resolution: expected {x}, got %v", got)
	}
	viaAllOf := map[string]any{
		"description": "sibling doc text",
		"allOf":       []any{map[string]any{"$ref": "#/components/schemas/Inner"}},
	}
	if got := s.PropertyNames(viaAllOf); !got["x"] || len(got) != 1 {
		t.Fatalf("allOf resolution: expected {x}, got %v", got)
	}
}
