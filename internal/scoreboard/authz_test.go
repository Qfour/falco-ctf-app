package scoreboard_test

// Requirement 1 (final review round): TestAuthz_AllDeclaredGatesEnforced is
// TestOriginGuard_AllProtectedRoutesEnforced's (origin_guard_test.go) exact
// counterpart for x-ctf-authz, closing the SAME defect shape security-
// engineer found for a second field on apispec.Route.
//
// security-engineer's proof: add `GET /api/admin/audit` to
// api.Handler.Routes() declaring `Authz: apispec.AuthzAdmin`, with a handler
// that never calls isAdmin (or any other gate) at all; add the matching
// operation to docs/openapi-scoreboard.yaml with `x-ctf-authz: admin`; bump
// the route-count pin from 20 to 21 — the edit a developer adds a route
// would naturally make. `make test` stayed fully green, and an anonymous
// `GET /api/admin/audit` returned 200 with the store's contents. Every
// existing ADR-0005 check (V1/V3b's StringExtParity) only compares the
// DECLARED apispec.Route.Authz string against the spec's DECLARED
// x-ctf-authz string — neither side ever issues a request, so "declared
// admin" and "actually gated" can drift apart with zero test failures. This
// is exactly BLOCKING 2's shape from the ROUND BEFORE this one
// (OriginGuarded), reopened one field over.
//
// The fix is structurally identical to origin_guard_test.go's: derive the
// case table from srv.Routes() itself (never a hand-maintained list, which
// is how BLOCKING 2 escaped detection the first time — origin_guard_test.go's
// OWN doc comment on TestOriginGuard_AllProtectedRoutesEnforced), and assert
// the OBSERVED HTTP status, not the declared string.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/qa"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// authzSelfUser is the "self" identity embedded in every request this file
// issues — as the {user} path segment for every AuthzSelfOrAdmin(Write)
// route that carries one, and (for the one route that doesn't — see
// authzGenericBody's doc) as the JSON body's "user" field instead.
const authzSelfUser = "alice"

// authzMismatchedEmail is a valid, non-admin, non-"alice" participant
// identity: every positive-branch case in this file sends this as
// X-Auth-Request-Email and expects a 403 (it satisfies neither "is admin"
// nor "is alice"), and every negative-branch case sends the SAME identity
// and expects NOT-403 (an unrelated identity must never be gated on a route
// declared Authz: none/claimed-identity).
const authzMismatchedEmail = "mallory@ctf.local"

// authzAdminEmail matches newAuthzFixture's ADMIN_EMAILS entry. Not used by
// TestAuthz_AllDeclaredGatesEnforced itself (every case there deliberately
// uses a NON-admin identity), but shared with any future positive-admin
// case and kept next to the other two identities for discoverability.
const authzAdminEmail = "admin@ctf.local"

// authzGenericBody is sent as the JSON body of every non-GET request this
// file issues. It is deliberately a superset of every write handler's
// expected shape (submitDetect's `user`+`condition`, stepCheck's `checked`,
// setDisplayName's `name`, releaseHint's `mission`+`hint`+`released`) —
// encoding/json's Decoder ignores object keys a given target struct does not
// declare, so one fixed body is safe to reuse across every route in the
// derived table without per-route bodies.
//
// The "user":"alice" key matters for exactly ONE route in the whole table:
// POST /api/challenges/{cid}/submit-detect is the only Authz-gated route
// whose caller identity comes from the REQUEST BODY rather than a {user}
// path segment (api.go's submitDetect reads `user := req.User`, never
// r.PathValue) — every other AuthzSelfOrAdmin(Write) route gets its "self"
// value from authzConcretePath substituting {user} in the URL instead. Using
// the SAME authzSelfUser value in both places keeps "the self identity under
// test" consistent across the whole derived table, whichever way a given
// route happens to read it.
const authzGenericBody = `{"user":"alice","name":"alice","checked":true,"condition":"evt.type=execve","mission":"02-evade","hint":1,"released":false}`

// authzCID picks the {cid} path substitution for rt. Every Authz-gated route
// except submit-detect runs its authz gate BEFORE ever looking at the
// challenge catalog (see each handler's own doc in api.go: isAdmin/
// selfOrAdmin/selfOrAdminWrite are all checked first), so "02-evade" — a
// plain evade challenge — is a safe universal default for them. submit-
// detect is the ONE exception: api.go's submitDetect checks
// `h.detectRunner != nil` and `ch.Type != "detect"` BEFORE it ever reaches
// the authz gate this file is testing, so it needs its own detect-type
// catalog entry to reach the gate at all (a wrong cid here would make the
// route 400/503 before the gate runs, which would silently turn this file's
// "want 403" assertion into a false negative rather than a true positive).
func authzCID(rt apispec.Route) string {
	if strings.Contains(rt.Pattern, "submit-detect") {
		return "03-detect"
	}
	return "02-evade"
}

// authzConcretePath is concretePath's (origin_guard_test.go, same package)
// sibling: same {name}-substitution mechanism via pathParamPattern, but with
// a PER-ROUTE {cid} value (authzCID) instead of one fixed value for every
// route — see authzCID's doc for why submit-detect needs a different one.
func authzConcretePath(rt apispec.Route) string {
	values := map[string]string{
		"user": authzSelfUser,
		"cid":  authzCID(rt),
		"idx":  "0",
		"qid":  "deadbeef",
	}
	return pathParamPattern.ReplaceAllStringFunc(rt.Pattern, func(seg string) string {
		name := seg[1 : len(seg)-1]
		if v, ok := values[name]; ok {
			return v
		}
		return "x"
	})
}

// noopDetectRunner satisfies scoring.DetectRunner (structurally — this file
// never imports the scoring package, since Grade's signature uses only
// stdlib types) purely so POST /api/challenges/{cid}/submit-detect's
// pre-authz guard (`h.detectRunner != nil`) passes. Grade's return value
// never matters here: api.go's submitDetect reads the body and checks
// selfOrAdminWrite BEFORE it ever calls h.grader.SubmitDetect (which is the
// only caller of the runner) — the authz gate under test in this file always
// resolves (pass or 403) before Grade would run.
type noopDetectRunner struct{}

func (noopDetectRunner) Grade(_ context.Context, _, _ string) (int, int, bool, error) {
	return 0, 0, false, nil
}

func newAuthzFixture(t *testing.T) *scoreboard.Handler {
	t.Helper()
	cat := catalog.Catalog{
		"02-evade":  {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"},
		"03-detect": {ID: "03-detect", Type: "detect"},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "authz.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	qaSt, err := qa.Open(filepath.Join(t.TempDir(), "authz-qa.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { qaSt.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithAdminEmails([]string{authzAdminEmail}),
		scoreboard.WithAllowedOrigins([]string{allowedOrigin}),
		scoreboard.WithDetect(api.DetectConfig{Runner: noopDetectRunner{}}),
		scoreboard.WithQA(qaSt),
	)
}

// authzCheck issues the request rt's Authz declaration calls for — an
// allowed Origin (so the origin guard, a DIFFERENT mechanism that also
// returns 403, can never masquerade as "the authz gate worked"; the mirror
// image of origin_guard_test.go's own admin-identity discipline), the
// generic write body for non-GET methods, and X-Auth-Request-Email:
// authzMismatchedEmail — and reports "" when the observed status is
// consistent with rt.Authz, or a failure description otherwise.
//
// Factored out of TestAuthz_AllDeclaredGatesEnforced's loop body (rather
// than inlined with t.Fatalf, the way origin_guard_test.go's positive/
// negative branches are) specifically so
// TestAuthz_CatchesUnenforcedGate below can run the EXACT same check
// against a synthetic, deliberately-broken route without duplicating the
// per-Authz-class branching — a t.Fatalf inline in the main test's loop
// cannot be reused as a value-returning predicate the way this can.
func authzCheck(t *testing.T, srv http.Handler, rt apispec.Route) string {
	t.Helper()
	target := authzConcretePath(rt)
	var body io.Reader
	if rt.Method != http.MethodGet {
		body = strings.NewReader(authzGenericBody)
	}
	r := httptest.NewRequest(rt.Method, target, body)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Origin", allowedOrigin)
	r.Header.Set("X-Auth-Request-Email", authzMismatchedEmail)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	switch rt.Authz {
	case apispec.AuthzAdmin, apispec.AuthzSelfOrAdmin, apispec.AuthzSelfOrAdminWrite:
		if w.Code != http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, want 403 (Authz: %s — %s does not satisfy it)",
				rt.MuxPattern(), w.Code, w.Body, rt.Authz, authzMismatchedEmail)
		}
	case apispec.AuthzNone, apispec.AuthzClaimedIdentity:
		if w.Code == http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, must NOT be 403 (Authz: %s — an unrelated identity must never be gated here; a 403 means a future change over-gated this route)",
				rt.MuxPattern(), w.Code, w.Body, rt.Authz)
		}
	default:
		return fmt.Sprintf("%s: unrecognised Authz value %q — authzCheck (and this test's count guards) need a new case before this route can be trusted", rt.MuxPattern(), rt.Authz)
	}
	return ""
}

// TestAuthz_AllDeclaredGatesEnforced derives its case table from
// srv.Routes() (scoreboard.Handler's flattened, ACTUALLY-installed route
// set — see server.go's Routes() doc), symmetric to
// TestOriginGuard_AllProtectedRoutesEnforced (origin_guard_test.go). See the
// package-level doc above for the exploit this closes.
func TestAuthz_AllDeclaredGatesEnforced(t *testing.T) {
	srv := newAuthzFixture(t)

	var adminGated, selfGated, openGated int
	for _, rt := range srv.Routes() {
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
			if violation := authzCheck(t, srv, rt); violation != "" {
				t.Fatal(violation)
			}
		})
	}

	// V8-2 non-vacuous count guards (mirrors origin_guard_test.go's own
	// `guarded != wantOriginGuardedRouteCount` discipline), one PER Authz
	// class rather than one combined total — a single combined count could
	// hide, e.g., every AuthzAdmin route losing its classification to
	// AuthzNone by mistake behind AuthzNone's count silently absorbing the
	// difference. 7 admin + 11 self(-write) + 9 none/claimed-identity = 27,
	// matching ADR-0005/ADR-0006/app#116/app#84/app#95's real-world
	// route-count canon (apispec_parity_test.go's
	// TestAPISpec_V1_RouteSetMatchesSpec).
	if adminGated != 7 {
		t.Fatalf("expected exactly 7 Authz: admin routes (ADR-0005 canon: GET /, GET /api/state, POST /api/admin/reset, POST /api/admin/users/{user}/display-name; ADR-0006 P25: GET /api/admin/questions, GET /api/admin/questions/{qid}, POST /api/admin/questions/{qid}/reply), got %d", adminGated)
	}
	if selfGated != 11 {
		t.Fatalf("expected exactly 11 Authz: self-or-admin(-write) routes (GET /api/users/{user}/me, GET /api/users/{user}/journey, POST /api/challenges/{cid}/submit-detect, POST /api/users/{user}/challenges/{cid}/steps/{idx}/check, POST /api/users/{user}/challenges/{cid}/hints/{idx}, POST /api/users/{user}/challenges/{cid}/reset-dirty, POST /api/users/{user}/display-name; ADR-0006 P25: GET /api/users/{user}/questions, POST /api/users/{user}/questions, GET /api/users/{user}/questions/{qid}, POST /api/users/{user}/questions/{qid}/messages), got %d", selfGated)
	}
	if openGated != 9 {
		t.Fatalf("expected exactly 9 Authz: none/claimed-identity routes (GET /portal, GET the cybercore css asset, GET the design-tokens css asset (app#116), POST /falco/events, GET /healthz, GET /metrics, POST /api/challenges/{cid}/submit, POST /internal/exfil/{cid}; Issue #95: POST /csp-report), got %d", openGated)
	}
}

// TestAuthz_CatchesUnenforcedGate is ADR-0005 V8's "prove the detector isn't
// vacuous" discipline (Requirement 1's own verification, final review
// round), applied to authzCheck. Both directions security-engineer's finding
// and this Requirement's text call out are proven here, against a
// synthetic *http.ServeMux — no scoreboard.Handler needed, since the point
// is authzCheck's OWN judgment, not the real route table (that half is
// TestAuthz_AllDeclaredGatesEnforced's job).
func TestAuthz_CatchesUnenforcedGate(t *testing.T) {
	t.Run("declared_admin_but_never_enforced", func(t *testing.T) {
		// Reproduces security-engineer's exact finding: a route declaring
		// Authz: admin whose handler never calls any gate at all.
		rt := apispec.Route{
			Method:  "GET",
			Pattern: "/api/admin/audit",
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
		// whose handler mistakenly DOES gate on identity (e.g. a
		// copy-pasted admin check left on a route that should be open) is
		// an over-gating regression, not a security hole, but it is still a
		// declared-vs-enforced mismatch this check must catch.
		rt := apispec.Route{
			Method:  "GET",
			Pattern: "/api/example-open-route",
			Authz:   apispec.AuthzNone,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Auth-Request-Email") != authzAdminEmail { // BUG: over-gates a route declared open.
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
