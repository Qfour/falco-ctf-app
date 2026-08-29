package ingressparity

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// participantRoute is a small constructor for a synthetic
// AudienceParticipant apispec.Route — every field this package's covers()/
// CoverageDiff() reads is Method/Pattern/Audience, so the tests below only
// ever populate those three.
func participantRoute(method, pattern string) apispec.Route {
	return apispec.Route{Method: method, Pattern: pattern, Audience: apispec.AudienceParticipant}
}

func route(method, pattern string, audience apispec.Audience) apispec.Route {
	return apispec.Route{Method: method, Pattern: pattern, Audience: audience}
}

// TestCovers_D3BoundaryCases pins ADR-0021 D3's matching rule (the
// security-engineer HIGH-fixed version) against the 4 boundary cases
// security-engineer hand-verified during the ADR's advisory round. Each
// case name states the EXPECTED, POST-FIX behaviour — see
// TestCovers_D3InitialDraftWasWrong below for the companion regression
// guard proving the PRE-fix rule got case 4 backwards.
func TestCovers_D3BoundaryCases(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		path     string
		pathType string
		want     bool
	}{
		{
			name:     "param route covered by Prefix entry naming its exact static prefix",
			pattern:  "/api/users/{user}/journey",
			path:     "/api/users/",
			pathType: "Prefix",
			want:     true,
		},
		{
			name:     "param route NOT covered by an unrelated Prefix entry",
			pattern:  "/api/users/{user}/journey",
			path:     "/api/challenges/",
			pathType: "Prefix",
			want:     false,
		},
		{
			name:     "param route NEVER covered by Exact, even matching one concrete value",
			pattern:  "/api/users/{user}/journey",
			path:     "/api/users/alice/journey",
			pathType: "Exact",
			want:     false,
		},
		{
			// D3's HIGH fix: k8s Prefix pathType ignores the DECLARED path's
			// trailing slash — `path: /api/users/` (Prefix) matches a
			// request for the bare `/api/users` too. A bare, param-free
			// mux Pattern living exactly at the ingress path's trimmed form
			// must be covered.
			name:     "bare exact route covered by trailing-slash Prefix entry naming it (D3 HIGH fix)",
			pattern:  "/api/users",
			path:     "/api/users/",
			pathType: "Prefix",
			want:     true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := covers(c.pattern, c.path, c.pathType)
			if got != c.want {
				t.Errorf("covers(%q, %q, %q) = %v, want %v", c.pattern, c.path, c.pathType, got, c.want)
			}
		})
	}
}

// coversPreFixHIGH reproduces the INITIAL (buggy) D3 draft's Prefix rule:
// it applied the param-carrying formula (staticPrefix == P2 ||
// HasPrefix(staticPrefix, P2)) UNIFORMLY, with no separate branch for a
// param-free Pattern — which is exactly the bug security-engineer's HIGH
// advisory flagged. Every other combination (Exact, or a param-carrying
// Pattern under Prefix) behaved identically before and after the fix — the
// fix's ONLY behavioural delta is the param-free-Pattern-under-Prefix case
// — so this fixture delegates everything else to covers() itself and only
// reimplements that one case with the pre-fix (missing-branch) formula.
// Kept here ONLY as a regression fixture for
// TestCovers_D3InitialDraftWasWrong — never called from production logic.
func coversPreFixHIGH(pattern, path, pathType string) bool {
	staticPfx, hasParam := staticPrefix(pattern)
	if pathType != "Prefix" || hasParam {
		return covers(pattern, path, pathType)
	}
	p2 := normalize(path) + "/"
	// The bug: no "pattern == normalize(path)" disjunct for the param-free
	// case, so a staticPrefix SHORTER than p2 (any bare route sitting
	// exactly at the ingress path's own normalized form) can never satisfy
	// HasPrefix and is wrongly judged uncovered.
	return staticPfx == p2 || strings.HasPrefix(staticPfx, p2)
}

// TestCovers_D3InitialDraftWasWrong is ADR-0021 D3's own regression guard
// (Verification V(I15)-5 case 5): a bare, param-free route
// (`GET /api/users`) against a trailing-slash Prefix entry
// (`path: /api/users/`) must be judged COVERED by the fixed rule, and would
// have been judged UNCOVERED by the pre-fix rule — proving the fix actually
// changed this specific case's outcome, not just that the fixed rule
// "looks right" in isolation. If this test ever fails on the FIRST
// assertion, the fix has regressed; if it fails on the SECOND, the
// fixture (coversPreFixHIGH) stopped reproducing the bug and needs
// re-deriving from ADR-0021 D3's "初版の記述" paragraph.
func TestCovers_D3InitialDraftWasWrong(t *testing.T) {
	const pattern = "/api/users"
	const path = "/api/users/"
	const pathType = "Prefix"

	if got := covers(pattern, path, pathType); !got {
		t.Errorf("fixed covers(%q, %q, %q) = %v, want true (D3 HIGH fix)", pattern, path, pathType, got)
	}
	if got := coversPreFixHIGH(pattern, path, pathType); got {
		t.Errorf("pre-fix draft rule covers(%q, %q, %q) = %v, want false (fixture no longer reproduces the HIGH bug — re-derive it from ADR-0021 D3)", pattern, path, pathType, got)
	}
}

func sortedOrNil(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// TestCoverageDiff_MutationCases implements ADR-0021 V(I15)-5's cases 2-4
// (case 1, the real-chart green baseline, and case 5's route-table
// integration live in internal/scoreboard's ADR-0021 test — this file only
// needs synthetic input, never helm/a real chart, per D4's extraction/
// comparison split).
func TestCoverageDiff_MutationCases(t *testing.T) {
	t.Run("case 2: dropping a participant route from the ingress surfaces it in uncovered", func(t *testing.T) {
		routes := []apispec.Route{
			participantRoute("GET", "/portal"),
			participantRoute("GET", "/api/users/{user}/journey"),
		}
		paths := []IngressEntry{
			{Path: "/portal", PathType: "Exact"},
			// /api/users/ deliberately OMITTED — this is the mutation.
		}
		uncovered, foreign := CoverageDiff(routes, paths)
		wantUncovered := []string{"GET /api/users/{user}/journey"}
		if !reflect.DeepEqual(sortedOrNil(uncovered), wantUncovered) {
			t.Errorf("uncovered = %v, want %v", uncovered, wantUncovered)
		}
		if len(foreign) != 0 {
			t.Errorf("foreign = %v, want empty", foreign)
		}
	})

	t.Run("case 3: an operator route reachable via a participant Prefix entry surfaces in foreign", func(t *testing.T) {
		routes := []apispec.Route{
			participantRoute("GET", "/api/users/{user}/journey"),
			// The mutation: an operator-audience route living under the SAME
			// prefix the participant allow-list opens.
			route("GET", "/api/users/admin-summary", apispec.AudienceOperator),
		}
		paths := []IngressEntry{
			{Path: "/api/users/", PathType: "Prefix"},
		}
		uncovered, foreign := CoverageDiff(routes, paths)
		if len(uncovered) != 0 {
			t.Errorf("uncovered = %v, want empty", uncovered)
		}
		if len(foreign) != 1 {
			t.Fatalf("foreign = %v, want exactly 1 entry", foreign)
		}
		const want = "GET /api/users/admin-summary (audience=operator, via ingress Prefix /api/users/)"
		if foreign[0] != want {
			t.Errorf("foreign[0] = %q, want %q", foreign[0], want)
		}
	})

	t.Run("case 4: swapping a Prefix entry to Exact drops coverage for the param route underneath it", func(t *testing.T) {
		routes := []apispec.Route{
			participantRoute("GET", "/api/users/{user}/journey"),
		}
		paths := []IngressEntry{
			// The mutation: Prefix -> Exact. Exact can never cover a
			// param-carrying Pattern (D3's asymmetry) even though the
			// literal string here is the same "/api/users/" a Prefix entry
			// would have covered it with.
			{Path: "/api/users/", PathType: "Exact"},
		}
		uncovered, _ := CoverageDiff(routes, paths)
		wantUncovered := []string{"GET /api/users/{user}/journey"}
		if !reflect.DeepEqual(sortedOrNil(uncovered), wantUncovered) {
			t.Errorf("uncovered = %v, want %v", uncovered, wantUncovered)
		}
	})
}

// TestCoverageDiff_GreenOnMatchedInput is the non-mutated control for the
// cases above: a matched, minimal (routes, paths) pair must report BOTH
// slices empty, so a future change to CoverageDiff can't pass the mutation
// tests above vacuously by always returning non-empty results.
func TestCoverageDiff_GreenOnMatchedInput(t *testing.T) {
	routes := []apispec.Route{
		participantRoute("GET", "/portal"),
		participantRoute("GET", "/api/users/{user}/journey"),
		route("GET", "/api/state", apispec.AudienceOperator),
	}
	paths := []IngressEntry{
		{Path: "/portal", PathType: "Exact"},
		{Path: "/api/users/", PathType: "Prefix"},
	}
	uncovered, foreign := CoverageDiff(routes, paths)
	if len(uncovered) != 0 {
		t.Errorf("uncovered = %v, want empty", uncovered)
	}
	if len(foreign) != 0 {
		t.Errorf("foreign = %v, want empty", foreign)
	}
}

// TestDeadExact_Advisory covers V(I15)-3's pure-function half: an Exact
// entry with no literally-matching mux Route is reported; a matched one is
// not.
func TestDeadExact_Advisory(t *testing.T) {
	routes := []apispec.Route{
		participantRoute("GET", "/portal"),
	}
	paths := []IngressEntry{
		{Path: "/portal", PathType: "Exact"},
		{Path: "/csp-report", PathType: "Exact"},  // no matching route — dead.
		{Path: "/api/users/", PathType: "Prefix"}, // Prefix, never "dead".
	}
	dead := DeadExact(routes, paths)
	want := []string{"/csp-report"}
	if !reflect.DeepEqual(dead, want) {
		t.Errorf("DeadExact = %v, want %v", dead, want)
	}
}
