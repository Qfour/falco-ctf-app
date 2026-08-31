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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
)

func loadCollectorSpec(t *testing.T) *specparity.Spec {
	t.Helper()
	spec, err := specparity.LoadSpec(filepath.Join("..", "..", "docs", "openapi-collector.yaml"))
	if err != nil {
		t.Fatalf("load docs/openapi-collector.yaml: %v", err)
	}
	return spec
}

func loadScoreboardSpecForCollector(t *testing.T) *specparity.Spec {
	t.Helper()
	spec, err := specparity.LoadSpec(filepath.Join("..", "..", "docs", "openapi-scoreboard.yaml"))
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

	specOnly, implOnly := specparity.RouteSetDiff(specOps, routes)
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

	missingKey, onlyImpl, onlySpec := specparity.BoolExtParity(specOps, routes, "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
	if len(missingKey) > 0 || len(onlyImpl) > 0 || len(onlySpec) > 0 {
		t.Errorf("x-ctf-origin-guard parity failed: missingKey=%v onlyImpl=%v onlySpec=%v", missingKey, onlyImpl, onlySpec)
	}

	missingKey, onlyImpl, onlySpec = specparity.BoolExtParity(specOps, routes, "x-ctf-collector-forward", func(rt apispec.Route) bool { return rt.CollectorForward })
	if len(missingKey) > 0 || len(onlyImpl) > 0 || len(onlySpec) > 0 {
		t.Errorf("x-ctf-collector-forward parity failed: missingKey=%v onlyImpl=%v onlySpec=%v", missingKey, onlyImpl, onlySpec)
	}
}

// TestAPISpec_V3b_StringExtParity is HIGH 4 (5x review): x-ctf-audience /
// x-ctf-authz / x-ctf-rate-limit were declared mandatory (ADR-0005 Decision
// 2(b)) but had zero real value-comparison coverage before
// specparity.StringExtParity existed — only presence (V2's mandatory-field
// discipline), never content, was checked.
func TestAPISpec_V3b_StringExtParity(t *testing.T) {
	spec := loadCollectorSpec(t)
	h := newParityFixtureHandler(t)
	routes := h.Routes()
	specOps := spec.Operations()

	cases := []struct {
		key   string
		value func(apispec.Route) string
	}{
		{"x-ctf-audience", func(rt apispec.Route) string { return string(rt.Audience) }},
		{"x-ctf-authz", func(rt apispec.Route) string { return string(rt.Authz) }},
		{"x-ctf-rate-limit", func(rt apispec.Route) string { return rt.RateLimit }},
	}
	for _, c := range cases {
		missingKey, mismatched := specparity.StringExtParity(specOps, routes, c.key, c.value)
		if len(missingKey) > 0 {
			t.Errorf("%s: missing on spec operations: %v", c.key, missingKey)
		}
		if len(mismatched) > 0 {
			t.Errorf("%s parity failed: %v", c.key, mismatched)
		}
	}
}

// --- V4 ------------------------------------------------------------------

// TestAPISpec_V4_CollectorForwardBijection is ADR-0005 V4's core check: a
// pure spec-to-spec comparison between the collector and scoreboard specs
// (no Handler needed for this half — see CollectorForwardBijection's doc).
func TestAPISpec_V4_CollectorForwardBijection(t *testing.T) {
	collectorSpec := loadCollectorSpec(t)
	scoreboardSpec := loadScoreboardSpecForCollector(t)

	problems := specparity.CollectorForwardBijection(collectorSpec.Operations(), scoreboardSpec.Operations())
	for _, p := range problems {
		t.Error(p)
	}
	if got := specparity.ResetDirtySpecViolation(scoreboardSpec.Operations()); got != "" {
		t.Error(got)
	}
}

// --- ADR-0009 Decision A: machine-derived V5 coverage ---------------------

// v5Coverage is ADR-0009 Decision A point 2 for the collector binary:
// specparity.ResponseObjectOperations() derives exactly ONE operation from
// docs/openapi-collector.yaml (GET /healthz — the two forward routes have no
// `schema` under their `application/json: {}` content, since the relayed
// scoreboard body is out of this spec's scope, and /metrics is text/plain).
var v5Coverage = map[string]bool{
	"GET /healthz": true, // TestAPISpec_V5_HealthzFieldsMatchSpec
}

// TestAPISpec_VA1_ResponseObjectCoverageBidirectional is ADR-0009
// Verification V(A)-1 against the collector's real spec + real v5Coverage
// table.
func TestAPISpec_VA1_ResponseObjectCoverageBidirectional(t *testing.T) {
	spec := loadCollectorSpec(t)
	derived := specparity.ResponseObjectOperations(spec)

	if len(derived) == 0 {
		t.Fatal("specparity.ResponseObjectOperations() returned zero operations for docs/openapi-collector.yaml — derivation is broken, not clean")
	}
	derivedOnly, coverageOnly := specparity.CoverageDiff(derived, v5Coverage)
	if len(derivedOnly) > 0 {
		t.Errorf("documented operation(s) with NO V5 field-comparison test: %v", derivedOnly)
	}
	if len(coverageOnly) > 0 {
		t.Errorf("stale v5Coverage entr(y/ies) (operation no longer derived from the spec): %v", coverageOnly)
	}
	if len(derived) != 1 {
		t.Errorf("expected 1 response-object operation (ADR-0009 C2), got %d: %v", len(derived), derived)
	}
}

// TestAPISpec_VA1_MutationsFailBothDirections re-runs V(A)-1's mutation
// proof against the collector's real derived set (see the scoreboard
// package's identically-purposed test for the full reasoning).
func TestAPISpec_VA1_MutationsFailBothDirections(t *testing.T) {
	spec := loadCollectorSpec(t)
	derived := specparity.ResponseObjectOperations(spec)

	t.Run("derived_only_documented_no_coverage", func(t *testing.T) {
		derivedOnly, _ := specparity.CoverageDiff(derived, map[string]bool{}) // simulate: table never populated
		found := false
		for _, k := range derivedOnly {
			if k == "GET /healthz" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected derivedOnly to flag GET /healthz against an empty table, got %v", derivedOnly)
		}
	})

	t.Run("coverage_only_stale_entry", func(t *testing.T) {
		mutated := map[string]bool{"GET /healthz": true, "GET /api/does-not-exist": true}
		_, coverageOnly := specparity.CoverageDiff(derived, mutated)
		found := false
		for _, k := range coverageOnly {
			if k == "GET /api/does-not-exist" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected coverageOnly to flag GET /api/does-not-exist, got %v", coverageOnly)
		}
	})
}

// TestAPISpec_V5_HealthzFieldsMatchSpec is the field-comparison test
// v5Coverage above declares for GET /healthz.
func TestAPISpec_V5_HealthzFieldsMatchSpec(t *testing.T) {
	spec := loadCollectorSpec(t)
	h := newParityFixtureHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: status=%d body=%s", w.Code, w.Body)
	}
	var actual map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &actual); err != nil {
		t.Fatalf("decode JSON: %v (body=%s)", err, w.Body)
	}

	op, ok := spec.Operations()["GET /healthz"]
	if !ok {
		t.Fatal("spec has no GET /healthz operation")
	}
	schema := spec.OperationResponseSchema(op, "200")
	if schema == nil {
		t.Fatal("GET /healthz 200 has no application/json schema")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "healthz") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
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
		specOnly, _ := specparity.RouteSetDiff(specOps, mutated)
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
		_, _, onlySpec := specparity.BoolExtParity(specOps, mutated, "x-ctf-collector-forward", func(rt apispec.Route) bool { return rt.CollectorForward })
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
		problems := specparity.CollectorForwardBijection(mutatedOps, scoreboardSpec.Operations())
		if len(problems) == 0 {
			t.Fatal("expected a renamed x-ctf-forward-target to be flagged, got no problems")
		}
	})
}
