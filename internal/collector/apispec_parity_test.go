package collector

// ADR-0005 parity tests for the collector binary: keeps
// docs/openapi-collector.yaml honest against the ACTUAL registered route
// table (Handler.Routes(), table-driven — see route registration in
// collector.go's New()). This file is `package collector` (internal, not
// `collector_test`), matching collector_test.go's existing convention, so
// it can construct a Handler exactly like the rest of this package's tests
// do (New() does no network I/O at construction time — the upstream URL
// only needs to parse, never needs to be reachable, for these checks).

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

func loadCollectorSpec(t *testing.T) *apispec.Spec {
	t.Helper()
	spec, err := apispec.LoadSpec(filepath.Join("..", "..", "docs", "openapi-collector.yaml"))
	if err != nil {
		t.Fatalf("load docs/openapi-collector.yaml: %v", err)
	}
	return spec
}

func loadScoreboardSpecForCollector(t *testing.T) *apispec.Spec {
	t.Helper()
	spec, err := apispec.LoadSpec(filepath.Join("..", "..", "docs", "openapi-scoreboard.yaml"))
	if err != nil {
		t.Fatalf("load docs/openapi-scoreboard.yaml: %v", err)
	}
	return spec
}

func newParityFixtureHandler(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// The upstream URL only needs to PARSE (New does no network I/O at
	// construction), so a non-resolvable host is fine for structural checks.
	h, err := New("http://scoreboard.invalid", logger)
	if err != nil {
		t.Fatalf("collector.New: %v", err)
	}
	return h
}

func TestAPISpec_V1_RouteSetMatchesSpec(t *testing.T) {
	spec := loadCollectorSpec(t)
	h := newParityFixtureHandler(t)
	routes := h.Routes()

	if len(routes) == 0 {
		t.Fatal("collector Handler.Routes() returned zero routes — extraction is broken, not clean")
	}
	specOps := spec.Operations()
	if len(specOps) == 0 {
		t.Fatal("docs/openapi-collector.yaml parsed to zero operations — spec loading is broken, not clean")
	}

	specOnly, implOnly := apispec.RouteSetDiff(specOps, routes)
	if len(specOnly) > 0 {
		t.Errorf("documented but not implemented: %v", specOnly)
	}
	if len(implOnly) > 0 {
		t.Errorf("implemented but undocumented: %v", implOnly)
	}
	// ADR-0005 C1's real-world count: 3 forwarded participant routes + 2
	// local infra routes = 5.
	if len(routes) != 5 {
		t.Errorf("expected 5 registered routes (ADR-0005 C1), got %d: %v", len(routes), routes)
	}
}

// TestAPISpec_V1_MeIsNotRegistered pins the collector package doc's most
// security-relevant negative: GET /api/users/{user}/me must NEVER be
// registered here (it would be a self-scope bypass, P18) — a positive
// route-set match alone (above) proves the DOCUMENTED set matches the
// IMPLEMENTED set, but it cannot by itself prove neither side accidentally
// grew a route nobody intended, if both files were mutated in tandem. This
// is that extra, independent tripwire.
func TestAPISpec_V1_MeIsNotRegistered(t *testing.T) {
	h := newParityFixtureHandler(t)
	for _, rt := range h.Routes() {
		if rt.Pattern == "/api/users/{user}/me" {
			t.Fatalf("collector must never register GET /api/users/{user}/me (self-scope bypass, P18) — found: %+v", rt)
		}
	}
}

func TestAPISpec_V3_OriginGuardAndCollectorForwardParity(t *testing.T) {
	spec := loadCollectorSpec(t)
	h := newParityFixtureHandler(t)
	routes := h.Routes()
	specOps := spec.Operations()

	missingKey, onlyImpl, onlySpec := apispec.BoolExtParity(specOps, routes, "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
	if len(missingKey) > 0 || len(onlyImpl) > 0 || len(onlySpec) > 0 {
		t.Errorf("x-ctf-origin-guard parity failed: missingKey=%v onlyImpl=%v onlySpec=%v", missingKey, onlyImpl, onlySpec)
	}

	missingKey, onlyImpl, onlySpec = apispec.BoolExtParity(specOps, routes, "x-ctf-collector-forward", func(rt apispec.Route) bool { return rt.CollectorForward })
	if len(missingKey) > 0 || len(onlyImpl) > 0 || len(onlySpec) > 0 {
		t.Errorf("x-ctf-collector-forward parity failed: missingKey=%v onlyImpl=%v onlySpec=%v", missingKey, onlyImpl, onlySpec)
	}
}

// --- V4 ------------------------------------------------------------------

// TestAPISpec_V4_CollectorForwardBijection is ADR-0005 V4's core check: a
// pure spec-to-spec comparison between the collector and scoreboard specs
// (no Handler needed for this half — see CollectorForwardBijection's doc).
func TestAPISpec_V4_CollectorForwardBijection(t *testing.T) {
	collectorSpec := loadCollectorSpec(t)
	scoreboardSpec := loadScoreboardSpecForCollector(t)

	problems := apispec.CollectorForwardBijection(collectorSpec.Operations(), scoreboardSpec.Operations())
	for _, p := range problems {
		t.Error(p)
	}
	if got := apispec.ResetDirtySpecViolation(scoreboardSpec.Operations()); got != "" {
		t.Error(got)
	}
}

// TestAPISpec_V8_MutationsFailAgainstRealData re-runs the V8 mutation
// classes against today's real collector spec + real route table.
func TestAPISpec_V8_MutationsFailAgainstRealData(t *testing.T) {
	spec := loadCollectorSpec(t)
	h := newParityFixtureHandler(t)
	routes := h.Routes()
	specOps := spec.Operations()

	t.Run("route_removed", func(t *testing.T) {
		mutated := make([]apispec.Route, 0, len(routes)-1)
		for _, rt := range routes {
			if rt.MuxPattern() == "POST /api/challenges/{cid}/exfil" {
				continue
			}
			mutated = append(mutated, rt)
		}
		specOnly, _ := apispec.RouteSetDiff(specOps, mutated)
		if len(specOnly) != 1 || specOnly[0] != "POST /api/challenges/{cid}/exfil" {
			t.Fatalf("expected specOnly=[POST /api/challenges/{cid}/exfil], got %v", specOnly)
		}
	})

	t.Run("collector_forward_flipped", func(t *testing.T) {
		mutated := append([]apispec.Route(nil), routes...)
		flippedAny := false
		for i := range mutated {
			if mutated[i].MuxPattern() == "POST /api/challenges/{cid}/submit" {
				mutated[i].CollectorForward = false // real value is true
				flippedAny = true
			}
		}
		if !flippedAny {
			t.Fatal("test bug: submit route not found in the real route table")
		}
		_, _, onlySpec := apispec.BoolExtParity(specOps, mutated, "x-ctf-collector-forward", func(rt apispec.Route) bool { return rt.CollectorForward })
		found := false
		for _, k := range onlySpec {
			if k == "POST /api/challenges/{cid}/submit" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected onlySpec to flag POST /api/challenges/{cid}/submit, got %v", onlySpec)
		}
	})

	t.Run("forward_target_renamed", func(t *testing.T) {
		// Simulate the spec's x-ctf-forward-target drifting from the
		// scoreboard route it names (e.g. a scoreboard path rename that
		// forgot to update the collector spec).
		mutatedOps := map[string]map[string]any{}
		for k, v := range specOps {
			cp := map[string]any{}
			for kk, vv := range v {
				cp[kk] = vv
			}
			mutatedOps[k] = cp
		}
		submitOp := mutatedOps["POST /api/challenges/{cid}/submit"]
		submitOp["x-ctf-forward-target"] = "POST /api/challenges/{cid}/submit-RENAMED"

		scoreboardSpec := loadScoreboardSpecForCollector(t)
		problems := apispec.CollectorForwardBijection(mutatedOps, scoreboardSpec.Operations())
		if len(problems) == 0 {
			t.Fatal("expected a renamed x-ctf-forward-target to be flagged, got no problems")
		}
	})
}
