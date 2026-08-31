package specparity

// This file is ADR-0005 V8's generic, algorithm-level "prove the detector
// itself is fail-closed" evidence: table-driven mutation tests against the
// comparison primitives (RouteSetDiff, BoolExtParity, StringExtParity,
// CollectorForwardBijection, ResetDirty*, CompareResponse) using small
// synthetic fixtures — NOT the real docs/openapi-*.yaml files (those are
// exercised for real by internal/scoreboard, internal/collector and
// internal/authpolicy's own parity tests). Keeping the mutation proof here,
// against hand-built inputs, means it stays fast, has no service-fixture
// dependency, and — most importantly — proves the ALGORITHM catches each of
// the ADR-0005 V8 mutation classes (route removed, origin-guard flag
// flipped, field renamed, x-ctf-authz reversed) in isolation, before ever
// trusting it against a 1,600-line real spec.

import (
	"sort"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

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

func baseRoutes() []apispec.Route {
	return []apispec.Route{
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
	missingKey, onlyImpl, onlySpec := BoolExtParity(baseSpecOps(), routes, "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
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
	missingKey, _, _ := BoolExtParity(specOps, baseRoutes(), "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
	if len(missingKey) != 1 || missingKey[0] != "POST /api/admin/reset" {
		t.Fatalf("expected missingKey=[POST /api/admin/reset], got %v", missingKey)
	}
}

// --- StringExtParity (HIGH 4) mutation proof ---------------------------

func baseSpecOpsWithAuthz() map[string]map[string]any {
	ops := baseSpecOps()
	ops["GET /api/state"]["x-ctf-authz"] = "admin"
	ops["POST /api/admin/reset"]["x-ctf-authz"] = "admin"
	ops["POST /api/challenges/{cid}/submit"]["x-ctf-authz"] = "claimed-identity"
	return ops
}

func baseRoutesWithAuthz() []apispec.Route {
	routes := baseRoutes()
	for i := range routes {
		switch routes[i].MuxPattern() {
		case "GET /api/state":
			routes[i].Authz = apispec.AuthzAdmin
		case "POST /api/admin/reset":
			routes[i].Authz = apispec.AuthzAdmin
		case "POST /api/challenges/{cid}/submit":
			routes[i].Authz = apispec.AuthzClaimedIdentity
		}
	}
	return routes
}

func authzTableValue(rt apispec.Route) string { return string(rt.Authz) }

// TestStringExtParity_CleanIsEmpty pins the non-mutated baseline for the
// string-valued twin of BoolExtParity.
func TestStringExtParity_CleanIsEmpty(t *testing.T) {
	missingKey, mismatched := StringExtParity(baseSpecOpsWithAuthz(), baseRoutesWithAuthz(), "x-ctf-authz", authzTableValue)
	if len(missingKey) != 0 || len(mismatched) != 0 {
		t.Fatalf("clean fixture must have no diff, got missingKey=%v mismatched=%v", missingKey, mismatched)
	}
}

// TestStringExtParity_CatchesReversedAuthz is HIGH 4's own motivating
// mutation: the spec's x-ctf-authz for a route is reversed from "admin" to
// "none" (or vice versa) WITHOUT touching the route table — exactly the
// "documented but a lie" drift ADR-0005 calls out as worst, and exactly what
// GET /api/hints' x-ctf-authz would have looked like reversed with no
// detector wired (5x review, R2/R3: StringExt had zero callers before this
// function existed).
func TestStringExtParity_CatchesReversedAuthz(t *testing.T) {
	specOps := baseSpecOpsWithAuthz()
	specOps["POST /api/admin/reset"]["x-ctf-authz"] = "none" // real Route.Authz stays admin

	_, mismatched := StringExtParity(specOps, baseRoutesWithAuthz(), "x-ctf-authz", authzTableValue)
	found := false
	for _, m := range mismatched {
		if m == `POST /api/admin/reset: impl="admin" spec="none"` {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a mismatch entry for POST /api/admin/reset, got %v", mismatched)
	}
}

// TestStringExtParity_CatchesMissingKey mirrors BoolExtParity's fail-closed
// rule for the string case: an ABSENT x-ctf-authz key is a parity failure,
// never an implicit "no requirement".
func TestStringExtParity_CatchesMissingKey(t *testing.T) {
	specOps := baseSpecOpsWithAuthz()
	delete(specOps["POST /api/admin/reset"], "x-ctf-authz")
	missingKey, _ := StringExtParity(specOps, baseRoutesWithAuthz(), "x-ctf-authz", authzTableValue)
	if len(missingKey) != 1 || missingKey[0] != "POST /api/admin/reset" {
		t.Fatalf("expected missingKey=[POST /api/admin/reset], got %v", missingKey)
	}
}

// TestStringExtParity_CatchesUnsetRouteField proves the OTHER direction: a
// Route that never sets the field at all (zero-value "") against a spec that
// DOES declare a value must be flagged as a mismatch, not silently skipped —
// an unset field is exactly the kind of drift (a new route added without its
// x-ctf-authz counterpart wired into the table) this check must catch.
func TestStringExtParity_CatchesUnsetRouteField(t *testing.T) {
	specOps := baseSpecOpsWithAuthz()
	routes := baseRoutesWithAuthz()
	for i := range routes {
		if routes[i].MuxPattern() == "POST /api/admin/reset" {
			routes[i].Authz = "" // simulate a route that forgot to set Authz
		}
	}
	_, mismatched := StringExtParity(specOps, routes, "x-ctf-authz", authzTableValue)
	found := false
	for _, m := range mismatched {
		if m == `POST /api/admin/reset: impl="" spec="admin"` {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a mismatch entry for the unset Authz field, got %v", mismatched)
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
	routes := []apispec.Route{{Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/reset-dirty", CollectorForward: true}}
	if got := ResetDirtyRouteViolation(routes); got == "" {
		t.Fatal("expected ResetDirtyRouteViolation to flag a reset-dirty Route with CollectorForward=true")
	}
	clean := []apispec.Route{{Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/reset-dirty", CollectorForward: false}}
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

// --- ADR-0009 Decision B (fail-closed CompareResponse + oneOf/anyOf) -----

// TestCompareResponse_NoPropertiesNoOneOf_IsFailClosed is ADR-0009
// Verification V(B)-1: a schema node that declares NEITHER `properties` NOR
// `oneOf`/`anyOf` (a dropped-`properties` typo, in effect) used to be a
// silent leaf — CompareResponse(spec, {"type":"object"}, {"totally_wrong_key":
// true}, "root") returned mismatches=[] before ADR-0009 (confirmed by
// real-code inspection in the ADR's Context C3, and reproduced here as a
// permanent regression pin). It must now report a non-empty mismatch,
// because `actual` unambiguously IS an object at this path.
func TestCompareResponse_NoPropertiesNoOneOf_IsFailClosed(t *testing.T) {
	s := newFixtureSpec(nil)
	schema := map[string]any{"type": "object"} // no properties, no oneOf/anyOf, no additionalProperties
	actual := map[string]any{"totally_wrong_key": true}

	mismatches := CompareResponse(s, schema, actual, "root")
	if len(mismatches) == 0 {
		t.Fatal("expected a non-empty mismatch for a properties-less object schema node with an object actual, got none (fail-open regression)")
	}
	if mismatches[0].Note == "" {
		t.Fatalf("expected a Note explaining the failure, got %+v", mismatches[0])
	}
}

// TestCompareResponse_AdditionalPropertiesOnlyMap_StaysLeaf is B-1's
// explicit carve-out, proved as a NEGATIVE (no-false-positive) test: a
// schema node with `additionalProperties` declared (a genuinely free-form
// map, e.g. State.events_per_user in docs/openapi-scoreboard.yaml) and no
// `properties` must NOT be flagged — ADR-0005's "見ないもの" list keeps
// additionalProperties map CONTENTS out of scope, and ADR-0009 does not
// widen that boundary.
func TestCompareResponse_AdditionalPropertiesOnlyMap_StaysLeaf(t *testing.T) {
	s := newFixtureSpec(nil)
	schema := map[string]any{
		"type":                 "object",
		"additionalProperties": map[string]any{"type": "integer"},
	}
	actual := map[string]any{"alice": float64(3), "bob": float64(1)}

	mismatches := CompareResponse(s, schema, actual, "root")
	if len(mismatches) != 0 {
		t.Fatalf("additionalProperties-only map must stay a leaf (no mismatch), got %+v", mismatches)
	}
}

// TestCompareResponse_DanglingRef_IsReported is ADR-0009 Decision B-3: a
// `$ref` naming a components.schemas entry that does not exist must be an
// explicit, reported failure — not silent nil propagation through
// SchemaByName the way resolve() (unchanged, still used by
// PropertyNames/PropertySchema/ItemsSchema) does.
func TestCompareResponse_DanglingRef_IsReported(t *testing.T) {
	s := newFixtureSpec(map[string]any{
		// Note: deliberately does NOT define "DoesNotExist".
	})
	schema := map[string]any{"$ref": "#/components/schemas/DoesNotExist"}
	actual := map[string]any{"x": "y"}

	mismatches := CompareResponse(s, schema, actual, "root")
	if len(mismatches) != 1 {
		t.Fatalf("expected exactly one mismatch for a dangling $ref, got %d: %+v", len(mismatches), mismatches)
	}
	if mismatches[0].Note != "dangling $ref: DoesNotExist" {
		t.Fatalf("expected Note=%q, got %q", "dangling $ref: DoesNotExist", mismatches[0].Note)
	}
}

// oneOfFixtureSpec is the synthetic twin of docs/openapi-scoreboard.yaml's
// `POST /falco/events` 200 = oneOf[IngestAccepted, IngestIgnored] shape: two
// disjoint $ref branches, each a plain object with `properties`.
func oneOfFixtureSpec() *Spec {
	return newFixtureSpec(map[string]any{
		"Accepted": map[string]any{
			"type":       "object",
			"properties": map[string]any{"accepted": map[string]any{"type": "boolean"}, "user": map[string]any{"type": "string"}},
		},
		"Ignored": map[string]any{
			"type":       "object",
			"properties": map[string]any{"ignored": map[string]any{"type": "boolean"}, "reason": map[string]any{"type": "string"}},
		},
	})
}

func oneOfFixtureSchema() map[string]any {
	return map[string]any{
		"oneOf": []any{
			map[string]any{"$ref": "#/components/schemas/Accepted"},
			map[string]any{"$ref": "#/components/schemas/Ignored"},
		},
	}
}

// TestCompareResponse_OneOf_MatchingBranchIsClean is V(B)-2's positive case:
// actual matching EXACTLY one branch's key set must produce no mismatch.
func TestCompareResponse_OneOf_MatchingBranchIsClean(t *testing.T) {
	s := oneOfFixtureSpec()
	accepted := map[string]any{"accepted": true, "user": "u1"}
	if mismatches := CompareResponse(s, oneOfFixtureSchema(), accepted, "root"); len(mismatches) != 0 {
		t.Fatalf("expected no mismatch for an actual matching the Accepted branch exactly, got %+v", mismatches)
	}
	ignored := map[string]any{"ignored": true, "reason": "nope"}
	if mismatches := CompareResponse(s, oneOfFixtureSchema(), ignored, "root"); len(mismatches) != 0 {
		t.Fatalf("expected no mismatch for an actual matching the Ignored branch exactly, got %+v", mismatches)
	}
}

// TestCompareResponse_OneOf_NoBranchMatches_IsReported is V(B)-2's negative
// case: an actual that fits NEITHER documented branch (the exact fail-open
// scenario ADR-0009's Context C3 reproduced against the real spec) must be
// reported as a mismatch.
func TestCompareResponse_OneOf_NoBranchMatches_IsReported(t *testing.T) {
	s := oneOfFixtureSpec()
	neither := map[string]any{"totally_wrong_key": true}
	mismatches := CompareResponse(s, oneOfFixtureSchema(), neither, "root")
	if len(mismatches) == 0 {
		t.Fatal("expected a non-empty mismatch for an actual matching no oneOf branch, got none")
	}
}

// TestCompareResponse_OneOf_OverlappingBranches_IsReported is the Signposts
// 3 / Decision B-2 "2+ matches" case: if the SPEC itself declares two
// branches with identical `properties` key sets (an overlap bug — no actual
// value could ever disambiguate which branch it "is"), that must be
// reported too, not silently accepted as a match against either one.
func TestCompareResponse_OneOf_OverlappingBranches_IsReported(t *testing.T) {
	s := newFixtureSpec(map[string]any{
		"BranchA": map[string]any{
			"type":       "object",
			"properties": map[string]any{"x": map[string]any{"type": "string"}},
		},
		"BranchB": map[string]any{
			"type":       "object",
			"properties": map[string]any{"x": map[string]any{"type": "string"}}, // same key set as BranchA — overlap bug
		},
	})
	schema := map[string]any{
		"oneOf": []any{
			map[string]any{"$ref": "#/components/schemas/BranchA"},
			map[string]any{"$ref": "#/components/schemas/BranchB"},
		},
	}
	mismatches := CompareResponse(s, schema, map[string]any{"x": "hello"}, "root")
	if len(mismatches) == 0 {
		t.Fatal("expected a non-empty mismatch for overlapping oneOf branches, got none")
	}
}

// TestCompareResponse_AnyOf_UsesSameCodePath proves anyOf is handled by the
// identical branch-matching logic as oneOf (ADR-0009 Decision B-2 says "同一
// コード経路でよい").
func TestCompareResponse_AnyOf_UsesSameCodePath(t *testing.T) {
	s := oneOfFixtureSpec()
	schema := map[string]any{
		"anyOf": []any{
			map[string]any{"$ref": "#/components/schemas/Accepted"},
			map[string]any{"$ref": "#/components/schemas/Ignored"},
		},
	}
	accepted := map[string]any{"accepted": true, "user": "u1"}
	if mismatches := CompareResponse(s, schema, accepted, "root"); len(mismatches) != 0 {
		t.Fatalf("expected no mismatch for a matching anyOf branch, got %+v", mismatches)
	}
	neither := map[string]any{"totally_wrong_key": true}
	if mismatches := CompareResponse(s, schema, neither, "root"); len(mismatches) == 0 {
		t.Fatal("expected a non-empty mismatch for an anyOf actual matching no branch, got none")
	}
}

// --- ADR-0009 Decision A: ResponseObjectOperations / CoverageDiff --------
//
// Generic, algorithm-level proof (synthetic spec, no service fixture) that
// ResponseObjectOperations derives exactly the operations Decision A defines
// as in-scope, and that CoverageDiff's bidirectional comparison catches both
// mutation directions V(A)-1 requires. Each service's OWN
// apispec_parity_test.go additionally re-runs the same two directions
// against ITS real docs/openapi-*.yaml + real v5Coverage table (mirroring
// how V8's real-data proof sits alongside this file's synthetic one).

// responseObjectOpsFixtureSpec builds a *Spec whose `paths` exercise every
// ResponseObjectOperations decision point:
//
//	GET /object-ref       200 application/json $ref -> object w/ properties  (IN)
//	POST /object-ref-201  201 application/json $ref -> object w/ properties  (IN)
//	POST /oneof-object    200 application/json oneOf, both branches objects  (IN)
//	GET /no-properties    200 application/json {type: object} (no properties) (OUT)
//	GET /text-only        200 text/plain only, no application/json           (OUT)
//	POST /oneof-mixed     200 oneOf where one branch has no properties       (OUT)
//	GET /dangling-ref     200 application/json $ref to a schema that does
//	                       not exist in components.schemas                   (OUT)
func responseObjectOpsFixtureSpec() *Spec {
	return &Spec{raw: map[string]any{
		"paths": map[string]any{
			"/object-ref": map[string]any{
				"get": map[string]any{
					"responses": map[string]any{
						"200": map[string]any{"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/A"}},
						}},
					},
				},
			},
			"/object-ref-201": map[string]any{
				"post": map[string]any{
					"responses": map[string]any{
						"201": map[string]any{"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/A"}},
						}},
					},
				},
			},
			"/oneof-object": map[string]any{
				"post": map[string]any{
					"responses": map[string]any{
						"200": map[string]any{"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{
								"oneOf": []any{
									map[string]any{"$ref": "#/components/schemas/A"},
									map[string]any{"$ref": "#/components/schemas/D"},
								},
							}},
						}},
					},
				},
			},
			"/no-properties": map[string]any{
				"get": map[string]any{
					"responses": map[string]any{
						"200": map[string]any{"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"type": "object"}},
						}},
					},
				},
			},
			"/text-only": map[string]any{
				"get": map[string]any{
					"responses": map[string]any{
						"200": map[string]any{"content": map[string]any{
							"text/plain": map[string]any{},
						}},
					},
				},
			},
			"/oneof-mixed": map[string]any{
				"post": map[string]any{
					"responses": map[string]any{
						"200": map[string]any{"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{
								"oneOf": []any{
									map[string]any{"$ref": "#/components/schemas/A"},
									map[string]any{"type": "object"},
								},
							}},
						}},
					},
				},
			},
			"/dangling-ref": map[string]any{
				"get": map[string]any{
					"responses": map[string]any{
						"200": map[string]any{"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Missing"}},
						}},
					},
				},
			},
		},
		"components": map[string]any{"schemas": map[string]any{
			"A": map[string]any{"type": "object", "properties": map[string]any{"x": map[string]any{"type": "string"}}},
			"D": map[string]any{"type": "object", "properties": map[string]any{"y": map[string]any{"type": "string"}}},
		}},
	}}
}

// TestResponseObjectOperations_DerivesExactlyTheInScopeSet is V(A)-2's
// non-empty half plus the positive/negative shape decisions Decision A point
// 1 defines: object $ref (200 and 201), object-only oneOf are IN; a
// properties-less object, a text/plain-only response, a oneOf with a
// non-object branch, and a dangling $ref are all OUT.
func TestResponseObjectOperations_DerivesExactlyTheInScopeSet(t *testing.T) {
	got := ResponseObjectOperations(responseObjectOpsFixtureSpec())
	want := []string{"GET /object-ref", "POST /oneof-object", "POST /object-ref-201"}
	sort.Strings(want)
	if !slicesEqual(got, want) {
		t.Fatalf("ResponseObjectOperations() = %v, want %v", got, want)
	}
}

// TestResponseObjectOperations_EmptySpec_ReturnsEmpty is the OTHER end of
// V(A)-2: a spec with no paths at all must derive to an empty set (not
// silently panic or return something non-empty) — this is what makes the
// per-service "len(derived) == 0 -> Fatal" caller guard (V(A)-2's own text:
// "空を返したら fail する側の呼び出し") meaningful to have at all.
func TestResponseObjectOperations_EmptySpec_ReturnsEmpty(t *testing.T) {
	s := &Spec{raw: map[string]any{}}
	if got := ResponseObjectOperations(s); len(got) != 0 {
		t.Fatalf("expected empty spec to derive zero operations, got %v", got)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCoverageDiff_CleanIsEmpty pins the non-mutated baseline: a coverage
// table with EXACTLY the derived set's keys (all true) must report no diff.
func TestCoverageDiff_CleanIsEmpty(t *testing.T) {
	derived := []string{"GET /a", "POST /b"}
	coverage := map[string]bool{"GET /a": true, "POST /b": true}
	derivedOnly, coverageOnly := CoverageDiff(derived, coverage)
	if len(derivedOnly) != 0 || len(coverageOnly) != 0 {
		t.Fatalf("clean fixture must have no diff, got derivedOnly=%v coverageOnly=%v", derivedOnly, coverageOnly)
	}
}

// TestCoverageDiff_CatchesDerivedOnly is V(A)-1 mutation direction (a): an
// operation ResponseObjectOperations() derives but the table never mentions
// (or, equivalently, maps to false) must be reported as derivedOnly
// ("documented operation, no V5 coverage").
func TestCoverageDiff_CatchesDerivedOnly(t *testing.T) {
	derived := []string{"GET /a", "POST /b"}
	coverage := map[string]bool{"GET /a": true} // POST /b missing entirely
	derivedOnly, coverageOnly := CoverageDiff(derived, coverage)
	if len(derivedOnly) != 1 || derivedOnly[0] != "POST /b" {
		t.Fatalf("expected derivedOnly=[POST /b], got %v", derivedOnly)
	}
	if len(coverageOnly) != 0 {
		t.Fatalf("expected no coverageOnly entries, got %v", coverageOnly)
	}
}

// TestCoverageDiff_CatchesCoverageOnly is V(A)-1 mutation direction (b): a
// table entry ResponseObjectOperations() no longer derives (a stale entry —
// e.g. left behind after a schema lost its `properties` or a route was
// removed) must be reported as coverageOnly ("stale coverage entry").
func TestCoverageDiff_CatchesCoverageOnly(t *testing.T) {
	derived := []string{"GET /a"}
	coverage := map[string]bool{"GET /a": true, "DELETE /gone": true}
	derivedOnly, coverageOnly := CoverageDiff(derived, coverage)
	if len(derivedOnly) != 0 {
		t.Fatalf("expected no derivedOnly entries, got %v", derivedOnly)
	}
	if len(coverageOnly) != 1 || coverageOnly[0] != "DELETE /gone" {
		t.Fatalf("expected coverageOnly=[DELETE /gone], got %v", coverageOnly)
	}
}

// TestCoverageDiff_FalseTableEntryIsTreatedAsAbsent proves a table entry
// explicitly set to false (as opposed to omitted) is NOT treated as
// "covered" — CoverageDiff must fail closed on that shape too, matching
// StringExtParity/BoolExtParity's existing "absence, not an implicit
// default" discipline elsewhere in this package.
func TestCoverageDiff_FalseTableEntryIsTreatedAsAbsent(t *testing.T) {
	derived := []string{"GET /a"}
	coverage := map[string]bool{"GET /a": false}
	derivedOnly, _ := CoverageDiff(derived, coverage)
	if len(derivedOnly) != 1 || derivedOnly[0] != "GET /a" {
		t.Fatalf("expected a false table entry to be treated as uncovered, got derivedOnly=%v", derivedOnly)
	}
}
