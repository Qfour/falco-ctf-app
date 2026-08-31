package authpolicy_test

// ADR-0005 parity tests for the auth-policy binary: keeps
// docs/openapi-auth-policy.yaml honest against the ACTUAL registered route
// table (authpolicy.Handler.Routes(), table-driven — see route
// registration in server.go's NewHandler()). Reuses this package's existing
// newHandler helper (server_test.go, same package) — NewHandler does no
// network I/O at construction time, so the upstream URL only needs to parse.

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
)

func loadAuthPolicySpec(t *testing.T) *specparity.Spec {
	t.Helper()
	spec, err := specparity.LoadSpec(filepath.Join("..", "..", "docs", "openapi-auth-policy.yaml"))
	if err != nil {
		t.Fatalf("load docs/openapi-auth-policy.yaml: %v", err)
	}
	return spec
}

func TestAPISpec_V1_RouteSetMatchesSpec(t *testing.T) {
	spec := loadAuthPolicySpec(t)
	h := newHandler("http://oauth2-proxy.invalid")
	routes := h.Routes()

	if len(routes) == 0 {
		t.Fatal("authpolicy Handler.Routes() returned zero routes — extraction is broken, not clean")
	}
	specOps := spec.Operations()
	if len(specOps) == 0 {
		t.Fatal("docs/openapi-auth-policy.yaml parsed to zero operations — spec loading is broken, not clean")
	}

	specOnly, implOnly := specparity.RouteSetDiff(specOps, routes)
	if len(specOnly) > 0 {
		t.Errorf("documented but not implemented: %v", specOnly)
	}
	if len(implOnly) > 0 {
		t.Errorf("implemented but undocumented: %v", implOnly)
	}
	// ADR-0005 C1's real-world count: /healthz, /metrics, /check, /check-admin.
	if len(routes) != 4 {
		t.Errorf("expected 4 registered routes (ADR-0005 C1), got %d: %v", len(routes), routes)
	}
}

func TestAPISpec_V3_OriginGuardAndCollectorForwardParity(t *testing.T) {
	spec := loadAuthPolicySpec(t)
	h := newHandler("http://oauth2-proxy.invalid")
	routes := h.Routes()
	specOps := spec.Operations()

	// auth-policy declares x-ctf-origin-guard / x-ctf-collector-forward as
	// false on every operation (it has no browser-CSRF surface and is never
	// fronted by the collector), so this parity check is a fixed point today
	// — but it must stay wired so a future operation added WITHOUT these
	// extensions fails loudly rather than silently defaulting.
	for _, key := range []string{"x-ctf-origin-guard", "x-ctf-collector-forward"} {
		missingKey, onlyImpl, onlySpec := specparity.BoolExtParity(specOps, routes, key, func(rt apispec.Route) bool {
			if key == "x-ctf-origin-guard" {
				return rt.OriginGuarded
			}
			return rt.CollectorForward
		})
		if len(missingKey) > 0 || len(onlyImpl) > 0 || len(onlySpec) > 0 {
			t.Errorf("%s parity failed: missingKey=%v onlyImpl=%v onlySpec=%v", key, missingKey, onlyImpl, onlySpec)
		}
	}
}

// TestAPISpec_V3b_StringExtParity is HIGH 4 (5x review): x-ctf-audience /
// x-ctf-authz / x-ctf-rate-limit were declared mandatory (ADR-0005 Decision
// 2(b)) but, before specparity.StringExtParity existed, nothing ever
// compared their VALUES between docs/openapi-auth-policy.yaml and
// Handler.Routes() — only their presence was checked elsewhere (V2's
// mandatory-field discipline). A reversed x-ctf-authz (e.g. GET /check
// declared "admin" while the route stays self-or-admin) would have passed
// `make test` silently. This wires the value comparison in for real.
func TestAPISpec_V3b_StringExtParity(t *testing.T) {
	spec := loadAuthPolicySpec(t)
	h := newHandler("http://oauth2-proxy.invalid")
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

// --- ADR-0009 Decision A: machine-derived V5 coverage ---------------------

// v5Coverage is ADR-0009 Decision A point 2 for the auth-policy binary:
// specparity.ResponseObjectOperations() derives exactly ONE operation from
// docs/openapi-auth-policy.yaml (GET /healthz — /check and /check-admin's
// 200 responses carry only `headers`, no `content` at all, and /metrics is
// text/plain).
var v5Coverage = map[string]bool{
	"GET /healthz": true, // TestAPISpec_V5_HealthzFieldsMatchSpec
}

// TestAPISpec_VA1_ResponseObjectCoverageBidirectional is ADR-0009
// Verification V(A)-1 against auth-policy's real spec + real v5Coverage
// table.
func TestAPISpec_VA1_ResponseObjectCoverageBidirectional(t *testing.T) {
	spec := loadAuthPolicySpec(t)
	derived := specparity.ResponseObjectOperations(spec)

	if len(derived) == 0 {
		t.Fatal("specparity.ResponseObjectOperations() returned zero operations for docs/openapi-auth-policy.yaml — derivation is broken, not clean")
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
// proof against auth-policy's real derived set (see the scoreboard
// package's identically-purposed test for the full reasoning).
func TestAPISpec_VA1_MutationsFailBothDirections(t *testing.T) {
	spec := loadAuthPolicySpec(t)
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
	spec := loadAuthPolicySpec(t)
	h := newHandler("http://oauth2-proxy.invalid")

	resp := do(t, h, "/healthz", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", resp.StatusCode)
	}
	var actual map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&actual); err != nil {
		t.Fatalf("decode JSON: %v", err)
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
// classes against today's real auth-policy spec + real route table.
func TestAPISpec_V8_MutationsFailAgainstRealData(t *testing.T) {
	spec := loadAuthPolicySpec(t)
	h := newHandler("http://oauth2-proxy.invalid")
	routes := h.Routes()
	specOps := spec.Operations()

	t.Run("route_removed", func(t *testing.T) {
		mutated := make([]apispec.Route, 0, len(routes)-1)
		for _, rt := range routes {
			if rt.MuxPattern() == "GET /check-admin" {
				continue
			}
			mutated = append(mutated, rt)
		}
		specOnly, _ := specparity.RouteSetDiff(specOps, mutated)
		if len(specOnly) != 1 || specOnly[0] != "GET /check-admin" {
			t.Fatalf("expected specOnly=[GET /check-admin], got %v", specOnly)
		}
	})

	// LOW (5x review): this subtest's name previously said
	// "authz_key_removed_from_spec" while its body actually deleted
	// x-ctf-origin-guard — a name/behaviour mismatch that made HIGH 4's gap
	// (x-ctf-authz having zero real parity coverage) look "tested" in a
	// test-name grep when it was not. Renamed to match what it actually
	// deletes; TestAPISpec_V3b_StringExtParity above is the real x-ctf-authz
	// coverage.
	t.Run("origin_guard_key_removed_from_spec", func(t *testing.T) {
		mutatedOps := map[string]map[string]any{}
		for k, v := range specOps {
			cp := map[string]any{}
			for kk, vv := range v {
				cp[kk] = vv
			}
			mutatedOps[k] = cp
		}
		delete(mutatedOps["GET /check"], "x-ctf-origin-guard")
		missingKey, _, _ := specparity.BoolExtParity(mutatedOps, routes, "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
		found := false
		for _, k := range missingKey {
			if k == "GET /check" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected missingKey to flag GET /check, got %v", missingKey)
		}
	})

	// HIGH 4's motivating mutation, run against the real spec: reversing
	// x-ctf-authz for GET /check-admin (admin -> none) WITHOUT touching the
	// route table must be caught.
	t.Run("authz_reversed_in_spec", func(t *testing.T) {
		mutatedOps := map[string]map[string]any{}
		for k, v := range specOps {
			cp := map[string]any{}
			for kk, vv := range v {
				cp[kk] = vv
			}
			mutatedOps[k] = cp
		}
		mutatedOps["GET /check-admin"]["x-ctf-authz"] = "none" // real Route.Authz stays admin
		_, mismatched := specparity.StringExtParity(mutatedOps, routes, "x-ctf-authz", func(rt apispec.Route) string { return string(rt.Authz) })
		found := false
		for _, m := range mismatched {
			if m == `GET /check-admin: impl="admin" spec="none"` {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a mismatch entry for GET /check-admin, got %v", mismatched)
		}
	})
}
