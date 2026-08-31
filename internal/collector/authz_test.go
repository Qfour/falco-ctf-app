package collector

// Issue #160: this is internal/scoreboard/authz_test.go's
// TestAuthz_AllDeclaredGatesEnforced pattern, ported to the collector.
//
// The collector is a THIN FORWARDER by design (package doc, collector.go):
// it does no identity checking of its own — every route it registers today
// declares Authz: none or Authz: claimed-identity (never admin /
// self-or-admin), because caller identity is either irrelevant (healthz/
// metrics) or claimed-in-body-and-never-proven (submit/display-name/exfil;
// the scoreboard downstream is the one that ever proves anything). So the
// POSITIVE direction of this file's derived table (an Authz: admin /
// self-or-admin route MUST 403 a mismatched identity) has zero real cases
// to walk today — that is the correct, intentional state, not a gap. What
// this file still buys:
//
//  1. The NEGATIVE direction has real coverage: every registered route
//     (declared none/claimed-identity) must never spuriously 403 an
//     unrelated identity — proving the collector does not accidentally
//     grow an identity check of its own outside the scoreboard's gates.
//  2. TestAuthz_CatchesUnenforcedGate proves the detection MECHANISM
//     itself would catch a future route that declared Authz: admin /
//     self-or-admin without actually enforcing it — so if a later change
//     ever adds such a route to the collector, this file's machinery (not
//     a fresh PR) is what notices a missing gate.
//
// package collector (not collector_test) to reuse testLogger/
// upstreamRecorder (helpers_test.go / collector_test.go, same package),
// matching apispec_parity_test.go's existing convention in this directory.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// authzMismatchedEmail mirrors authpolicy/authz_test.go's constant of the
// same name — an arbitrary, unrelated identity. The collector never reads
// this header at all (by design), so its only job here is to prove that
// fact: no registered route's status changes because of it.
const authzMismatchedEmail = "mallory@ctf.local"

var authzPathParamPattern = regexp.MustCompile(`\{([^}]+)\}`)

// authzPathParamValues mirrors scoreboard authz_test.go's authzConcretePath
// map — fixed placeholder values good enough to satisfy http.ServeMux's
// pattern match. The collector never inspects {cid}/{user} for identity
// purposes (it forwards verbatim or claims-and-forwards), so these values
// only need to route, not be "real" in a catalog sense.
var authzPathParamValues = map[string]string{
	"user": "alice",
	"cid":  "02-evade",
}

func authzConcretePath(pattern string) string {
	return authzPathParamPattern.ReplaceAllStringFunc(pattern, func(seg string) string {
		name := seg[1 : len(seg)-1]
		if v, ok := authzPathParamValues[name]; ok {
			return v
		}
		return "x"
	})
}

// authzCheck issues rt's request against srv carrying an unrelated identity
// header, and reports "" when the observed status is consistent with
// rt.Authz, or a failure description otherwise. Mirrors scoreboard/
// authpolicy authz_test.go's function of the same name and purpose, so
// TestAuthz_CatchesUnenforcedGate below can reuse it against a synthetic
// route exactly the same way those two files do.
func authzCheck(t *testing.T, srv http.Handler, rt apispec.Route) string {
	t.Helper()
	target := authzConcretePath(rt.Pattern)
	r := httptest.NewRequest(rt.Method, target, nil)
	r.Header.Set("X-Auth-Request-Email", authzMismatchedEmail)
	// Distinct RemoteAddr per call keeps this file's own requests from
	// tripping the collector's unrelated per-IP rate limiter (1 req/s burst
	// 10) — a 429 would be a false negative for this test's "must not be
	// 403" assertion's INTENT even though 429 != 403 numerically.
	r.RemoteAddr = "198.51.100.1:1"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	switch rt.Authz {
	case apispec.AuthzAdmin, apispec.AuthzSelfOrAdmin, apispec.AuthzSelfOrAdminWrite:
		if w.Code != http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, want 403 (Authz: %s — %s must not be granted)",
				rt.MuxPattern(), w.Code, w.Body, rt.Authz, authzMismatchedEmail)
		}
	case apispec.AuthzNone, apispec.AuthzClaimedIdentity:
		if w.Code == http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, must NOT be 403 (Authz: %s — the collector does not check identity; a 403 means something started gating this route)",
				rt.MuxPattern(), w.Code, w.Body, rt.Authz)
		}
	default:
		return fmt.Sprintf("%s: unrecognised Authz value %q — authzCheck needs a new case before this route can be trusted", rt.MuxPattern(), rt.Authz)
	}
	return ""
}

// TestAuthz_AllDeclaredGatesEnforced derives its case table from h.Routes()
// (collector.Handler's actually-installed route set), symmetric to
// scoreboard's and auth-policy's tests of the same name. See the
// package-level doc above for what this file can and cannot prove for the
// collector specifically.
func TestAuthz_AllDeclaredGatesEnforced(t *testing.T) {
	up := &upstreamRecorder{}
	upSrv := httptest.NewServer(up.handler())
	defer upSrv.Close()

	h, err := New(upSrv.URL, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

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

	// Non-vacuous count guards (mirrors scoreboard/auth-policy authz_test.go's
	// discipline): pin the per-class counts to ADR-0005 C1's real-world
	// canon (5 routes total: 3 forwarded participant writes +
	// healthz/metrics). adminGated/selfGated are pinned to 0 DELIBERATELY —
	// see the package-level doc above; a nonzero value here means a future
	// route declared Authz: admin/self-or-admin on the collector, which is
	// itself worth a second look (the collector is meant to stay a thin
	// forwarder with no gates of its own).
	if adminGated != 0 {
		t.Fatalf("expected zero Authz: admin routes on the collector (thin-forwarder design), got %d", adminGated)
	}
	if selfGated != 0 {
		t.Fatalf("expected zero Authz: self-or-admin route on the collector (thin-forwarder design), got %d", selfGated)
	}
	if openGated != 5 {
		t.Fatalf("expected exactly 5 Authz: none/claimed-identity routes (POST submit, POST display-name, POST exfil, GET healthz, GET metrics), got %d", openGated)
	}
}

// TestAuthz_CatchesUnenforcedGate is ADR-0005 V8's "prove the detector
// isn't vacuous" discipline, applied to this file's authzCheck — mirrors
// scoreboard/auth-policy authz_test.go's test of the same name. Run against
// a synthetic *http.ServeMux, independent of collector.Handler, so this
// test's pass/fail does not depend on the collector ever actually growing
// an Authz: admin/self-or-admin route (which TestAuthz_AllDeclaredGates
// Enforced's count guards above pin at zero today).
func TestAuthz_CatchesUnenforcedGate(t *testing.T) {
	t.Run("declared_admin_but_never_enforced", func(t *testing.T) {
		rt := apispec.Route{
			Method:  "GET",
			Pattern: "/internal-audit",
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
		rt := apispec.Route{
			Method:  "GET",
			Pattern: "/healthz-audit",
			Authz:   apispec.AuthzNone,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Auth-Request-Email") != "admin@ctf.local" { // BUG: over-gates a route declared open.
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusOK)
			}),
		}
		mux, _ := apispec.NewMux([]apispec.Route{rt})
		if violation := authzCheck(t, mux, rt); violation == "" {
			t.Fatal("expected authzCheck to flag a declared-open route whose handler over-gates, got no violation — the negative branch would be a permanent no-op")
		}
	})
}
