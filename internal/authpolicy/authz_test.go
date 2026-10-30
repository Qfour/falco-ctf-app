package authpolicy_test

// Issue #160: this is internal/scoreboard/authz_test.go's
// TestAuthz_AllDeclaredGatesEnforced pattern, ported to auth-policy — the
// service that owns I8 (the roster identity table and the exact seat match). Before this file,
// docs/openapi-auth-policy.yaml's x-ctf-authz was only compared as a
// DECLARED string (apispec_parity_test.go's TestAPISpec_V3b_StringExtParity)
// against apispec.Route.Authz, itself just a hand-set field on a
// hand-written table — neither side ever issued a request, so "declared
// admin" and "actually gated" could drift apart with zero test failures
// (the exact shape scoreboard's authz_test.go package doc describes).
//
// Structural difference from scoreboard's version: auth-policy's "self"
// binding is NOT a {user} path segment — GET /check-workspace reads a `?host=`
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
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// authzSelfHost is the ?host= value every /check-workspace case in this file
// uses. authzMismatchedEmail below is deliberately NEITHER a rostered
// identity NOR in the admin allowlist, so it satisfies neither half of
// /check-participant's disjunction (roster seat OR admin override), nor
// /check-workspace's roster seat (which admits no admin, ADR-0050), nor
// /check-admin's allowlist check.
const authzSelfHost = "alice"

// authzMismatchedEmail is what the fake oauth2-proxy upstream returns for
// every request this file issues. It must fail BOTH gates so every
// Authz: admin / self / rostered case in the derived table produces the same
// expected 403 without per-route bespoke identities.
const authzMismatchedEmail = "mallory@ctf.local" // not in fixtureRoster

// authzAdminAllowlist is the ADMIN_EMAILS entry configured on the fixture
// handler. authzMismatchedEmail is deliberately NOT a member.
const authzAdminAllowlist = "admin@ctf.local"

// authzTarget builds a concrete httptest target for rt. /check-workspace is the only
// route in this service whose "self" binding lives in a query string rather
// than a mux path segment (auth-policy's routes carry no {name} path
// parameters at all today), so this is a simpler, single-case version of
// scoreboard authz_test.go's authzConcretePath.
func authzTarget(rt apispec.Route) string {
	if rt.Pattern == "/check-workspace" {
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
	case apispec.AuthzAdmin, apispec.AuthzSelf, apispec.AuthzRostered:
		if w.Code != http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, want 403 (Authz: %s — %s satisfies neither the roster (host=%s) nor the admin allowlist)",
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

	var adminGated, selfGated, selfOrAdminGated, rosteredGated int
	var none, claimed []string
	for _, rt := range h.Routes() {
		rt := rt
		switch rt.Authz {
		case apispec.AuthzAdmin:
			adminGated++
		case apispec.AuthzSelf:
			selfGated++
		case apispec.AuthzSelfOrAdmin:
			selfOrAdminGated++
		case apispec.AuthzRostered:
			rosteredGated++
		}
		src, ok := apispec.IdentitySourceOf(rt.Authz)
		if !ok {
			t.Errorf("%s: Authz %q is not classified in apispec.AuthzIdentitySources", rt.MuxPattern(), rt.Authz)
		}
		switch src {
		case apispec.IdentityNone:
			none = append(none, rt.MuxPattern())
		case apispec.IdentityClaimed:
			claimed = append(claimed, string(rt.Authz)+" "+rt.MuxPattern())
		}
		t.Run(string(rt.Authz)+"/"+rt.MuxPattern(), func(t *testing.T) {
			if violation := authzCheck(t, h, rt); violation != "" {
				t.Fatal(violation)
			}
		})
	}

	// Non-vacuous count guards (mirrors scoreboard authz_test.go's V8-2
	// discipline): pin the per-class counts to ADR-0005 C1's real-world
	// canon (5 routes total, ADR-0034 D3) so a route silently losing its classification
	// — or the derivation breaking outright — shows up as a numeric
	// assertion failure, not a shrinking, easy-to-miss subtest count.
	if adminGated != 1 {
		t.Fatalf("expected exactly 1 Authz: admin route (GET /check-admin), got %d", adminGated)
	}
	if selfGated != 1 {
		t.Fatalf("expected exactly 1 Authz: self route (GET /check-workspace), got %d", selfGated)
	}
	// ADR-0050: auth-policy has no self-or-admin route (the workspace door has
	// no operator override). selfOrAdminGated is counted apart so a route that
	// slips back to the old word fails here by name.
	if selfOrAdminGated != 0 {
		t.Fatalf("expected 0 Authz: self-or-admin routes (ADR-0050: /check-workspace admits no operator), got %d", selfOrAdminGated)
	}
	if rosteredGated != 1 {
		t.Fatalf("expected exactly 1 Authz: rostered route (GET /check-participant), got %d", rosteredGated)
	}
	// app#393: none and the claimed words are pinned apart, as literal sets
	// selected by apispec.AuthzIdentitySources. auth-policy accepts no
	// claimed identity at all.
	sort.Strings(none)
	if strings.Join(none, ",") != "GET /healthz,GET /metrics" {
		t.Errorf("identity source none routes = %q, want exactly GET /healthz and GET /metrics", none)
	}
	if len(claimed) != 0 {
		t.Errorf("identity source claimed routes = %q, want none (auth-policy authorises from the oauth2-proxy subrequest only)", claimed)
	}
}

// TestAuthz_SelfRoutesRefuseAdmin pins what makes a route `self` and not
// `self-or-admin` (ADR-0050): the ADMIN_EMAILS identity is refused with a 403
// on every route classified self, with no identity header in the response.
// The routes are derived from h.Routes(), so a second self route is covered
// too, and a route that falls back to a 200 for the operator fails by name.
func TestAuthz_SelfRoutesRefuseAdmin(t *testing.T) {
	upstream := fakeOAuth2Proxy(t, func(*http.Request) (int, string) {
		return http.StatusAccepted, authzAdminAllowlist
	})
	defer upstream.Close()
	h := newAdminHandler(upstream.URL, authzAdminAllowlist)
	n := 0
	for _, rt := range h.Routes() {
		if rt.Authz != apispec.AuthzSelf {
			continue
		}
		n++
		r := httptest.NewRequest(rt.Method, authzTarget(rt), nil)
		r.Header.Set("Cookie", "_oauth2_proxy=fake-session")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status=%d body=%s, want 403 for an ADMIN_EMAILS identity (Authz: self has no operator override)", rt.MuxPattern(), w.Code, w.Body)
		}
		for k := range w.Header() {
			if strings.HasPrefix(k, "X-Auth-Request-") {
				t.Errorf("%s: refused response carries %s", rt.MuxPattern(), k)
			}
		}
	}
	if n != 1 {
		t.Fatalf("self routes = %d, want 1 (GET /check-workspace)", n)
	}
}

// TestAuthz_EveryProvenRouteRejectsUnproven is auth-policy's check of the
// "proven" row of apispec.AuthzIdentitySources (app#393), the counterpart of
// scoreboard's TestAuthz_EveryProvenRouteRejectsHeaderless. Here the proof is
// the /oauth2/auth subrequest, so a route whose word is classified proven
// answers 401 when oauth2-proxy authenticates nobody and 403 when it answers
// 202 without an identity — never 2xx. The routes are selected by the table,
// so rostered is covered with admin and self, and so is any word
// classified proven later.
func TestAuthz_EveryProvenRouteRejectsUnproven(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream int // the fake oauth2-proxy's status; it never sends an email
		want     int
	}{
		{"oauth2-proxy says not authenticated", http.StatusUnauthorized, http.StatusUnauthorized},
		{"oauth2-proxy authenticates without an identity", http.StatusAccepted, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := fakeOAuth2Proxy(t, func(*http.Request) (int, string) { return tc.upstream, "" })
			defer upstream.Close()
			h := newAdminHandler(upstream.URL, authzAdminAllowlist)
			words := map[apispec.Authz]bool{}
			for _, rt := range h.Routes() {
				src, ok := apispec.IdentitySourceOf(rt.Authz)
				if !ok {
					t.Errorf("%s: Authz %q is not classified in apispec.AuthzIdentitySources", rt.MuxPattern(), rt.Authz)
					continue
				}
				if src != apispec.IdentityProven {
					continue
				}
				words[rt.Authz] = true
				if v := unprovenViolation(h, rt, tc.want); v != "" {
					t.Error(v)
				}
			}
			want := map[apispec.Authz]bool{apispec.AuthzAdmin: true, apispec.AuthzSelf: true, apispec.AuthzRostered: true}
			if !reflect.DeepEqual(words, want) {
				t.Fatalf("proven words exercised = %v, want %v (the derivation is broken, or a word changed class)", words, want)
			}
		})
	}
}

// unprovenViolation sends rt's request with a session cookie (so the handler
// asks oauth2-proxy, whose answer the test fixes) and reports any status but
// want.
func unprovenViolation(h http.Handler, rt apispec.Route, want int) string {
	r := httptest.NewRequest(rt.Method, authzTarget(rt), nil)
	r.Header.Set("Cookie", "_oauth2_proxy=fake-session")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != want {
		return fmt.Sprintf("%s: status=%d body=%s, want %d (Authz: %s is classified proven)", rt.MuxPattern(), w.Code, w.Body, want, rt.Authz)
	}
	return ""
}

// The detector is not vacuous (ADR-0005 V8, as scoreboard's
// TestAuthz_HeaderlessDetectorCatchesClaimedFallback): a proven route whose
// handler answers 200 without asking oauth2-proxy is flagged for both
// unproven answers.
func TestAuthz_UnprovenDetectorCatchesUngatedRoute(t *testing.T) {
	rt := apispec.Route{Method: "GET", Pattern: "/check-participant-audit", Authz: apispec.AuthzRostered,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK) // BUG: never asks oauth2-proxy.
		})}
	mux, _ := apispec.NewMux([]apispec.Route{rt})
	for _, want := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		if v := unprovenViolation(mux, rt, want); v == "" {
			t.Errorf("a 200 on a proven route was not flagged (want %d)", want)
		}
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
