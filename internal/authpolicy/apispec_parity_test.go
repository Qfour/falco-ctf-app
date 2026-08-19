package authpolicy_test

// ADR-0005 parity tests for the auth-policy binary: keeps
// docs/openapi-auth-policy.yaml honest against the ACTUAL registered route
// table (authpolicy.Handler.Routes(), table-driven — see route
// registration in server.go's NewHandler()). Reuses this package's existing
// newHandler helper (server_test.go, same package) — NewHandler does no
// network I/O at construction time, so the upstream URL only needs to parse.

import (
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

func loadAuthPolicySpec(t *testing.T) *apispec.Spec {
	t.Helper()
	spec, err := apispec.LoadSpec(filepath.Join("..", "..", "docs", "openapi-auth-policy.yaml"))
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

	specOnly, implOnly := apispec.RouteSetDiff(specOps, routes)
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
		missingKey, onlyImpl, onlySpec := apispec.BoolExtParity(specOps, routes, key, func(rt apispec.Route) bool {
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
		specOnly, _ := apispec.RouteSetDiff(specOps, mutated)
		if len(specOnly) != 1 || specOnly[0] != "GET /check-admin" {
			t.Fatalf("expected specOnly=[GET /check-admin], got %v", specOnly)
		}
	})

	t.Run("authz_key_removed_from_spec", func(t *testing.T) {
		mutatedOps := map[string]map[string]any{}
		for k, v := range specOps {
			cp := map[string]any{}
			for kk, vv := range v {
				cp[kk] = vv
			}
			mutatedOps[k] = cp
		}
		delete(mutatedOps["GET /check"], "x-ctf-origin-guard")
		missingKey, _, _ := apispec.BoolExtParity(mutatedOps, routes, "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
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
}
