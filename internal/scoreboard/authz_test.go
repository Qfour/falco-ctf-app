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
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// authzSelfUser is the "self" identity embedded in every request this file
// issues — as the {user} path segment for every AuthzSelfOrAdmin
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
// r.PathValue) — every other AuthzSelfOrAdmin route gets its "self"
// value from authzConcretePath substituting {user} in the URL instead. Using
// the SAME authzSelfUser value in both places keeps "the self identity under
// test" consistent across the whole derived table, whichever way a given
// route happens to read it.
const authzGenericBody = `{"user":"alice","name":"alice","checked":true,"condition":"evt.type=execve","mission":"02-evade","hint":1,"released":false}`

// authzCID picks the {cid} path substitution for rt. Every Authz-gated route
// except submit-detect runs its authz gate BEFORE ever looking at the
// challenge catalog (see each handler's own doc in api.go: isAdmin/
// selfOrAdmin are all checked first), so "02-evade" — a
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
		"tid":  "00000000000000000000000000000000",
		"mid":  "00000000000000000000000000000000",
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
// selfOrAdmin BEFORE it ever calls h.grader.SubmitDetect (which is the
// only caller of the runner) — the authz gate under test in this file always
// resolves (pass or 403) before Grade would run. One exception:
// submit_detect_authz_test.go's 200 rows DO run Grade and depend on this
// (0, 0, false) "missed" verdict being a 200 response.
type noopDetectRunner struct{}

func (noopDetectRunner) Grade(_ context.Context, _, _ string) (int, int, bool, error) {
	return 0, 0, false, nil
}

func newAuthzFixture(t *testing.T) *scoreboard.Handler {
	t.Helper()
	return newAuthzFixtureRunner(t, noopDetectRunner{})
}

// newAuthzFixtureRunner is newAuthzFixture with the given grader Job runner.
func newAuthzFixtureRunner(t *testing.T, runner scoring.DetectRunner) *scoreboard.Handler {
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
	boardSt, err := board.Open(filepath.Join(t.TempDir(), "authz-board.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { boardSt.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain),
		scoreboard.WithAdminEmails([]string{authzAdminEmail}),
		scoreboard.WithAllowedOrigins([]string{allowedOrigin}),
		scoreboard.WithDetect(api.DetectConfig{Runner: runner}),
		scoreboard.WithBoard(boardSt),
	)
}

// authzDo issues rt's request (allowed Origin, generic write body for non-GET)
// with X-Auth-Request-Email: email when withHeader, or with NO identity header
// at all when !withHeader.
func authzDo(srv http.Handler, rt apispec.Route, email string, withHeader bool) *httptest.ResponseRecorder {
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
	if withHeader {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
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
	w := authzDo(srv, rt, authzMismatchedEmail, true)

	switch rt.Authz {
	case apispec.AuthzAdmin, apispec.AuthzSelfOrAdmin:
		if w.Code != http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, want 403 (Authz: %s — %s does not satisfy it)",
				rt.MuxPattern(), w.Code, w.Body, rt.Authz, authzMismatchedEmail)
		}
	case apispec.AuthzInternalClaimedIdentity:
		// Collector-only (ADR-0034 D12 S1): ANY X-Auth-Request-* header is
		// refused, whoever it claims to be, and a header-less request is NOT
		// refused. The mismatched-identity 403 above alone cannot tell this
		// class from self-or-admin (both 403 a stranger), so the two
		// extra probes below are what pin the distinction: an ADMIN header (or
		// the {user} owner's) still 403s here, which self-or-admin
		// would let through; and no header at all passes, which self-or-admin
		// (read) would 403.
		if w.Code != http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, want 403 (Authz: %s — any X-Auth-Request-* header is refused)",
				rt.MuxPattern(), w.Code, w.Body, rt.Authz)
		}
		for _, email := range []string{authzAdminEmail, authzSelfUser + "@ctf.local"} {
			if wa := authzDo(srv, rt, email, true); wa.Code != http.StatusForbidden {
				return fmt.Sprintf("%s: status=%d body=%s with X-Auth-Request-Email: %s, want 403 (Authz: %s — a proven admin/owner identity must be refused too; a 200 means the route fell back to a self-or-admin-shaped gate)",
					rt.MuxPattern(), wa.Code, wa.Body, email, rt.Authz)
			}
		}
		if wn := authzDo(srv, rt, "", false); wn.Code == http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s with NO identity header, must NOT be 403 (Authz: %s — the collector path carries no header and must keep working)",
				rt.MuxPattern(), wn.Code, wn.Body, rt.Authz)
		}
	case apispec.AuthzNone, apispec.AuthzClaimedIdentity:
		if w.Code == http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, must NOT be 403 (Authz: %s — an unrelated identity must never be gated here; a 403 means a future change over-gated this route)",
				rt.MuxPattern(), w.Code, w.Body, rt.Authz)
		}
	case apispec.AuthzAuthenticated:
		// app#292 Phase 2 (QA Board): unlike self-or-admin, this
		// gate performs NO username match against a {user} path segment —
		// any proven identity, related or not, may proceed. A mismatched
		// (but valid) identity like authzMismatchedEmail must NEVER be
		// 403'd here; TestAuthz_EveryProvenRouteRejectsHeaderless below
		// is this case's other half (missing header -> 403), which this
		// helper cannot express since it always sends an identity header.
		if w.Code == http.StatusForbidden {
			return fmt.Sprintf("%s: status=%d body=%s, must NOT be 403 (Authz: authenticated — an unrelated-but-valid identity must never be gated here; a 403 means a future change wrongly added a self-or-admin-shaped username check to a route that carries no {user} segment)",
				rt.MuxPattern(), w.Code, w.Body)
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

	var adminGated, selfGated, authenticatedGated int
	var none, claimed []string
	for _, rt := range srv.Routes() {
		rt := rt
		switch rt.Authz {
		case apispec.AuthzAdmin:
			adminGated++
		case apispec.AuthzSelfOrAdmin:
			selfGated++
		case apispec.AuthzAuthenticated:
			authenticatedGated++
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
	// difference. app#292 Phase 2: P25's 7 QA routes (3 admin, 4
	// self-or-admin) are gone (internal/qa removed wholesale);
	// the QA Board's 11 routes replace them under a FOURTH bucket for the
	// 6 participant ones (authz=authenticated has no {user}-path
	// self-match, so it is not "self-or-admin" — see authzCheck's own
	// doc) plus 5 admin routes (4 from the initial Phase 2 landing + 1
	// post-review gap-close: boardAdminGetThread). 9 admin + 7 self(-write) +
	// 15 none/claimed-identity + 6 authenticated = 37; ADR-0028 then folded the
	// 8 static-asset routes into one (none): 9 + 7 + 8 + 6 = 30; ADR-0034 D12 S1
	// then moved display-name out of self(-write) into its own
	// internal-claimed-identity class: 9 + 6 + 1 + 8 + 6 = 30; closing the
	// browser path of POST /falco/events and POST /internal/exfil/{cid} moves
	// both out of the none/claimed-identity bucket (their Authz was
	// claimed-identity, counted with none at the time) into
	// internal-claimed-identity: 9 + 6 + 3 + 6 + 6 = 30; ADR-0034 S1 then removed
	// the participant display-name route (internal-claimed-identity 3 -> 2) and
	// added the two profile routes (+1 admin, +1 self-or-admin):
	// 10 + 7 + 2 + 6 + 6 = 31, matching
	// apispec_parity_test.go's TestAPISpec_V1_RouteSetMatchesSpec.
	// ADR-0034 S1 (D8): +1 admin (POST /api/admin/users/{user}/profile-reset) and
	// +1 self-or-admin (POST /api/users/{user}/profile).
	// app#346: the self-or-admin-write class (submit-detect, its only user)
	// is gone — submit-detect is plain self-or-admin, so the combined self
	// count stays 7 (6 + 1) but the vocabulary has no "write" member.
	// app#393: none and the claimed words are no longer one bucket. A route
	// that accepts a claimed identity relabelled none moved between two
	// counts that summed the same; now both are literal sets (selected by
	// apispec.AuthzIdentitySources, like the collector's forward set), so a
	// route entering or leaving either is a named diff.
	if adminGated != 10 {
		t.Fatalf("expected exactly 10 Authz: admin routes (ADR-0005 canon: GET /, GET /api/state, POST /api/admin/reset, POST /api/admin/users/{user}/display-name; app#292 QA Board: GET /api/admin/board/threads, GET /api/admin/board/threads/{tid}, POST /api/admin/board/threads/{tid}/reply, POST /api/admin/board/threads/{tid}/state, POST /api/admin/board/messages/{mid}/state; ADR-0034: POST /api/admin/users/{user}/profile-reset), got %d", adminGated)
	}
	if selfGated != 7 {
		t.Fatalf("expected exactly 7 Authz: self-or-admin routes (GET /api/users/{user}/me, GET /api/users/{user}/journey, POST /api/challenges/{cid}/submit-detect, POST /api/users/{user}/challenges/{cid}/steps/{idx}/check, POST /api/users/{user}/challenges/{cid}/hints/{idx}, POST /api/users/{user}/challenges/{cid}/reset-dirty, ADR-0034: POST /api/users/{user}/profile — P25's 4 QA self-or-admin(-write) routes are gone, cutover), got %d", selfGated)
	}
	// GET /static/{asset} is ADR-0028's single static route; POST
	// /csp-report is Issue #95.
	pinRouteSet(t, "identity source none", none, []string{
		"GET /healthz", "GET /metrics", "GET /portal", "GET /static/{asset}", "POST /csp-report",
	})
	// internal-claimed-identity is internal-only (browser path closed); the
	// collector-only participant display-name route went in ADR-0034 D12 S1.
	pinRouteSet(t, "identity source claimed", claimed, []string{
		"claimed-identity POST /api/challenges/{cid}/submit",
		"internal-claimed-identity POST /falco/events",
		"internal-claimed-identity POST /internal/exfil/{cid}",
	})
	if authenticatedGated != 6 {
		t.Fatalf("expected exactly 6 Authz: authenticated routes (app#292 QA Board participant routes: GET /api/board/threads, GET /api/board/threads/{tid}, POST /api/board/threads, POST /api/board/threads/{tid}/messages, POST /api/board/threads/{tid}/like, POST /api/board/threads/{tid}/unlike), got %d", authenticatedGated)
	}
}

// pinRouteSet fails unless got (in any order) is exactly want.
func pinRouteSet(t *testing.T, what string, got, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s routes = %q, want exactly %q", what, got, want)
	}
}

// headerlessViolation sends rt's request with an ALLOWED Origin (so the
// origin guard cannot be what answers 403) and NO identity header, and
// reports anything but 403.
func headerlessViolation(srv http.Handler, rt apispec.Route) string {
	if w := authzDo(srv, rt, "", false); w.Code != http.StatusForbidden {
		return fmt.Sprintf("%s: header-less status=%d body=%s, want 403 (Authz: %s is classified proven, so it requires the identity header)", rt.MuxPattern(), w.Code, w.Body, rt.Authz)
	}
	return ""
}

// TestAuthz_EveryProvenRouteRejectsHeaderless is the scoreboard's check of
// the "proven" row of apispec.AuthzIdentitySources (app#393): every route
// whose word is classified proven answers a request with no identity header
// with 403. The routes are selected by the table, not by word, so admin,
// self-or-admin, authenticated and any word classified proven later are all
// covered, and a claimed word mis-classified proven is red here (its route
// lets the header-less request through). TestAuthz_AllDeclaredGatesEnforced
// sends a MISMATCHED identity, which a header-less-allowing handler also
// rejects, so it cannot tell the two gates apart; this test can. Replaces
// TestProfile_V1_EverySelfOrAdminRouteRejectsHeaderless (self-or-admin only)
// and TestAuthz_AuthenticatedGate_MissingHeaderDenied (authenticated only).
func TestAuthz_EveryProvenRouteRejectsHeaderless(t *testing.T) {
	srv := newAuthzFixture(t)
	words := map[apispec.Authz]bool{}
	for _, rt := range srv.Routes() {
		src, ok := apispec.IdentitySourceOf(rt.Authz)
		if !ok {
			t.Errorf("%s: Authz %q is not classified in apispec.AuthzIdentitySources", rt.MuxPattern(), rt.Authz)
			continue
		}
		if src != apispec.IdentityProven {
			continue
		}
		words[rt.Authz] = true
		rt := rt
		t.Run(string(rt.Authz)+"/"+rt.MuxPattern(), func(t *testing.T) {
			if v := headerlessViolation(srv, rt); v != "" {
				t.Fatal(v)
			}
		})
	}
	// Non-vacuous: every proven word the scoreboard declares was exercised
	// (rostered is auth-policy's; per-word route counts are pinned above).
	want := map[apispec.Authz]bool{apispec.AuthzAdmin: true, apispec.AuthzSelfOrAdmin: true, apispec.AuthzAuthenticated: true}
	if !reflect.DeepEqual(words, want) {
		t.Fatalf("proven words exercised = %v, want %v (the derivation is broken, or a word changed class)", words, want)
	}
}

// The detector is not vacuous: a proven route backed by a handler that falls
// back to a claimed identity when the header is missing (the removed
// selfOrAdminWrite's shape) is flagged.
func TestAuthz_HeaderlessDetectorCatchesClaimedFallback(t *testing.T) {
	rt := apispec.Route{Method: "POST", Pattern: "/api/users/{user}/profile", Authz: apispec.AuthzSelfOrAdmin,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Auth-Request-Email") == "" {
				w.WriteHeader(http.StatusOK) // BUG: no header -> allow.
				return
			}
			w.WriteHeader(http.StatusForbidden)
		})}
	mux, _ := apispec.NewMux([]apispec.Route{rt})
	if v := headerlessViolation(mux, rt); v == "" {
		t.Fatal("a header-less 200 on a proven route was not flagged")
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

	t.Run("declared_internal_claimed_identity_but_dual_path_gate_shaped", func(t *testing.T) {
		// The shape display-name had before the collector-only fix, and the
		// one the removed self-or-admin-write class implemented (app#346) — a
		// stranger's header is 403, but an admin's (or the
		// owner's) passes and a header-less request passes. authzCheck must
		// flag it for a route declaring internal-claimed-identity, which a
		// "mismatched email gets 403" probe alone cannot (the same 403).
		rt := apispec.Route{
			Method:  "POST",
			Pattern: "/api/users/{user}/example-internal",
			Authz:   apispec.AuthzInternalClaimedIdentity,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if email := r.Header.Get("X-Auth-Request-Email"); email != "" &&
					email != authzAdminEmail && !strings.HasPrefix(email, r.PathValue("user")+"@") {
					w.WriteHeader(http.StatusForbidden) // BUG: header-bearing admin/owner requests are accepted.
					return
				}
				w.WriteHeader(http.StatusOK)
			}),
		}
		mux, _ := apispec.NewMux([]apispec.Route{rt})
		if violation := authzCheck(t, mux, rt); violation == "" {
			t.Fatal("expected authzCheck to flag an internal-claimed-identity route that is really dual-path-gate shaped (header-less passes, admin/owner pass), got no violation — the class would be indistinguishable from self-or-admin")
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

// internalAudienceViolations returns every route that is declared
// Audience: internal yet not Authz: internal-claimed-identity. An "internal"
// route is one only the cluster-internal callers (collector, falcosidekick)
// may reach; any other Authz class (none, claimed-identity, ...) lets a
// browser-path request through, which is how POST /falco/events and
// POST /internal/exfil/{cid} stayed reachable from a participant's browser.
// If a future internal-only class is added, extend the allowed set HERE.
func internalAudienceViolations(routes []apispec.Route) (violations []string, internalCount int) {
	for _, rt := range routes {
		if rt.Audience != apispec.AudienceInternal {
			continue
		}
		internalCount++
		if rt.Authz != apispec.AuthzInternalClaimedIdentity {
			violations = append(violations, fmt.Sprintf("%s: Audience internal but Authz %q (want %q)", rt.MuxPattern(), rt.Authz, apispec.AuthzInternalClaimedIdentity))
		}
	}
	return violations, internalCount
}

// TestAuthz_InternalAudienceRoutesAreInternalClaimedIdentity pins the
// invariant "every scoreboard route with x-ctf-audience: internal is gated
// internal-claimed-identity". authzCheck only enforces what a route
// DECLARES, so an internal route declared Authz: none would pass every other
// check here while being reachable from the browser path.
func TestAuthz_InternalAudienceRoutesAreInternalClaimedIdentity(t *testing.T) {
	violations, internalCount := internalAudienceViolations(newAuthzFixture(t).Routes())
	if internalCount == 0 {
		t.Fatal("found zero Audience: internal routes — the derivation is broken (or every internal route lost its audience label), not \"nothing to check\"")
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// TestAuthz_InternalAudienceInvariantCatchesOpenRoute proves the detector is
// not vacuous: an Audience: internal route declared Authz: none is flagged.
func TestAuthz_InternalAudienceInvariantCatchesOpenRoute(t *testing.T) {
	routes := []apispec.Route{
		{Method: "POST", Pattern: "/internal/ok", Audience: apispec.AudienceInternal, Authz: apispec.AuthzInternalClaimedIdentity},
		{Method: "POST", Pattern: "/internal/leaky", Audience: apispec.AudienceInternal, Authz: apispec.AuthzNone},
	}
	violations, internalCount := internalAudienceViolations(routes)
	if internalCount != 2 || len(violations) != 1 || !strings.Contains(violations[0], "/internal/leaky") {
		t.Fatalf("want exactly the open internal route flagged, got count=%d violations=%v", internalCount, violations)
	}
}
