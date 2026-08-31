package authpolicy_test

// Issue #160: this is internal/scoreboard/authz_test.go's
// TestAuthz_AllDeclaredGatesEnforced pattern, ported to auth-policy — the
// service that owns I8 (prefix-exact `<host>@` binding). Before this file,
// docs/openapi-auth-policy.yaml's x-ctf-authz was only compared as a
// DECLARED string (apispec_parity_test.go's TestAPISpec_V3b_StringExtParity)
// against apispec.Route.Authz, itself just a hand-set field on a
// hand-written table — neither side ever issued a request, so "declared
// admin" and "actually gated" could drift apart with zero test failures
// (the exact shape scoreboard's authz_test.go package doc describes).
//
// Structural difference from scoreboard's version: auth-policy's "self"
// binding is NOT a {user} path segment — GET /check reads a `?host=`
// QUERY PARAMETER and compares it against the identity oauth2-proxy's
// /oauth2/auth subrequest returns (never a header on the incoming
// request itself). So this file derives its case table from
// h.Routes() exactly like scoreboard's, but drives the "identity" axis
// through a fake upstream (server_test.go's fakeOAuth2Proxy) instead of
// X-Auth-Request-Email, and builds each route's target with authzTarget
// (appending ?host=alice only for /check) instead of scoreboard's
// {name}-substitution.
//
// This file adds NO new production code and does not touch server.go's
// gate logic — additive tests only, same discipline the issue asked for.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// authzSelfHost is the ?host= value every /check-shaped case in this file
// uses. authzMismatchedEmail below is deliberately NEITHER "alice@..." NOR
// in the admin allowlist, so it satisfies neither half of /check's
// disjunction (I8 prefix-exact OR admin override) and neither half of
// /check-admin's allowlist check.
const authzSelfHost = "alice"

// authzMismatchedEmail is what the fake oauth2-proxy upstream returns for
// every request this file issues. It must fail BOTH gates so every
// Authz: admin / self-or-admin case in the derived table produces the same
// expected 403 without per-route bespoke identities.
const authzMismatchedEmail = "mallory@ctf.local"

// authzAdminAllowlist is the ADMIN_EMAILS entry configured on the fixture
// handler. authzMismatchedEmail is deliberately NOT a member.
const authzAdminAllowlist = "admin@ctf.local"

// authzTarget builds a concrete httptest target for rt. /check is the only
// route in this service whose "self" binding lives in a query string rather
// than a mux path segment (auth-policy's routes carry no {name} path
// parameters at all today), so this is a simpler, single-case version of
// scoreboard authz_test.go's authzConcretePath.
func authzTarget(rt apispec.Route) string {
	if rt.Pattern == "/check" {
		return rt.Pattern + "?host=" + authzSelfHost
	}
	return rt.Pattern
}

// authzCheck issues rt's request against srv with a Cookie header (so /check
// and /check-admin's callUpstream reaches the fake oauth2-proxy instead of
// short-circuiting on a missing session — an absent Cookie would 401, which
// is a DIFFERENT, unrelated failure mode this file is not testing), and
// reports "" when the observed status is consistent with rt.Authz, or a
// failure description otherwise. Factored out (mirrors scoreboard authz_
// test.go's authzCheck) so TestAuthz_CatchesUnenforcedGate below can run the
// exact same judgment against a synthetic, deliberately-broken route.
func authzCheck(t *testing.T, srv http.Handler, rt apispec.Route) string {
	t.Helper()
	r := httptest.NewRequest(rt.Method, authzTarget(rt), nil)
	r.Header.Set("Cookie", "_oauth2_proxy=fake-session")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	switch rt.Authz {
	case apispec.AuthzAdmin, apispec.AuthzSelfOrAdmin, apispec.AuthzSelfOrAdminWrite:
		if w.Code != http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, want 403 (Authz: %s — %s satisfies neither host=%s nor the admin allowlist)",
				rt.MuxPattern(), w.Code, w.Body, rt.Authz, authzMismatchedEmail, authzSelfHost)
		}
	case apispec.AuthzNone, apispec.AuthzClaimedIdentity:
		if w.Code == http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, must NOT be 403 (Authz: %s — an unrelated identity must never be gated here)",
				rt.MuxPattern(), w.Code, w.Body, rt.Authz)
		}
	default:
		return fmt.Sprintf("%s: unrecognised Authz value %q — authzCheck needs a new case before this route can be trusted", rt.MuxPattern(), rt.Authz)
	}
	return ""
}

// TestAuthz_AllDeclaredGatesEnforced derives its case table from h.Routes()
// (authpolicy.Handler's actually-installed route set), symmetric to
// scoreboard's TestAuthz_AllDeclaredGatesEnforced. See the package-level doc
// above for the drift shape this closes.
func TestAuthz_AllDeclaredGatesEnforced(t *testing.T) {
	upstream := fakeOAuth2Proxy(t, func(*http.Request) (int, string) {
		return http.StatusAccepted, authzMismatchedEmail
	})
	defer upstream.Close()
	h := newAdminHandler(upstream.URL, authzAdminAllowlist)

	var adminGated, selfGated, openGated int
	for _, rt := range h.Routes() {
		rt := rt
		switch rt.Authz {
		case apispec.AuthzAdmin:
			adminGated++
		case apispec.AuthzSelfOrAdmin, apispec.AuthzSelfOrAdminWrite:
			selfGated++
		case apispec.AuthzNone, apispec.AuthzClaimedIdentity:
			openGated++
		}
		t.Run(string(rt.Authz)+"/"+rt.MuxPattern(), func(t *testing.T) {
			if violation := authzCheck(t, h, rt); violation != "" {
				t.Fatal(violation)
			}
		})
	}

	// Non-vacuous count guards (mirrors scoreboard authz_test.go's V8-2
	// discipline): pin the per-class counts to ADR-0005 C1's real-world
	// canon (4 routes total) so a route silently losing its classification
	// — or the derivation breaking outright — shows up as a numeric
	// assertion failure, not a shrinking, easy-to-miss subtest count.
	if adminGated != 1 {
		t.Fatalf("expected exactly 1 Authz: admin route (GET /check-admin), got %d", adminGated)
	}
	if selfGated != 1 {
		t.Fatalf("expected exactly 1 Authz: self-or-admin route (GET /check), got %d", selfGated)
	}
	if openGated != 2 {
		t.Fatalf("expected exactly 2 Authz: none routes (GET /healthz, GET /metrics), got %d", openGated)
	}
}

// TestAuthz_CatchesUnenforcedGate is ADR-0005 V8's "prove the detector isn't
// vacuous" discipline, applied to this file's authzCheck — mirrors
// scoreboard authz_test.go's test of the same name. Both directions are
// proven against a synthetic *http.ServeMux, independent of the real
// authpolicy.Handler (that half is TestAuthz_AllDeclaredGatesEnforced's
// job), so this test's pass/fail does not depend on auth-policy's current
// route set staying exactly as it is today.
func TestAuthz_CatchesUnenforcedGate(t *testing.T) {
	t.Run("declared_admin_but_never_enforced", func(t *testing.T) {
		// A route declaring Authz: admin whose handler never checks the
		// caller's identity at all — the exact defect shape
		// scoreboard's PR #149 review-5x R1 finding described, ported here
		// for auth-policy's own route table.
		rt := apispec.Route{
			Method:  "GET",
			Pattern: "/check-admin-audit",
			Authz:   apispec.AuthzAdmin,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK) // BUG: never checks the caller's identity.
			}),
		}
		mux, _ := apispec.NewMux([]apispec.Route{rt})
		if violation := authzCheck(t, mux, rt); violation == "" {
			t.Fatal("expected authzCheck to flag a declared-admin route whose handler never enforces it, got no violation — the detector would be a permanent no-op")
		}
	})

	t.Run("declared_open_but_over_gated", func(t *testing.T) {
		// The negative branch matters equally: a route declared Authz: none
		// whose handler mistakenly gates on identity anyway (e.g. a
		// copy-pasted admin check left on a route meant to be open).
		rt := apispec.Route{
			Method:  "GET",
			Pattern: "/healthz-audit",
			Authz:   apispec.AuthzNone,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden) // BUG: over-gates a route declared open.
			}),
		}
		mux, _ := apispec.NewMux([]apispec.Route{rt})
		if violation := authzCheck(t, mux, rt); violation == "" {
			t.Fatal("expected authzCheck to flag a declared-open route whose handler over-gates, got no violation — the negative branch would be a permanent no-op")
		}
	})
}
