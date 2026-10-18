package scoreboard_test

// P23-2: origin guard integration tests. These exercise the middleware
// end-to-end through scoreboard.NewHandler (not the originguard package
// directly) so the assertions match what a real deployment sees: the exact
// set of routes wrapped in internal/scoreboard/api.Register, wired via
// scoreboard.WithAllowedOrigins.

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/originguard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// newOriginFixture builds a handler carrying an evade + exfil-required
// challenge (so /submit and /internal/exfil/{cid} are both exercisable) and
// an admin identity, with the given allowed origins wired in. opts are applied
// after those (e.g. scoreboard.WithNow to freeze the rate limiters' clock).
func newOriginFixture(t *testing.T, allowedOrigins []string, opts ...scoreboard.Option) *scoreboard.Handler {
	t.Helper()
	cat := catalog.Catalog{
		"02-evade": {
			ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"},
			ExpectedFlag: "FALCO{ok}",
		},
		"03-exfil": {
			ID: "03-exfil", Type: "evade", ForbiddenRules: []string{"r"},
			ExpectedFlag: "FALCO{boss}", RequireExfil: true,
		},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "og.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	boardSt, err := board.Open(filepath.Join(t.TempDir(), "og-board.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { boardSt.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return scoreboard.NewHandler(cat, st, logger, append([]scoreboard.Option{
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain),
		scoreboard.WithAdminEmails([]string{"admin@ctf.local"}),
		scoreboard.WithAllowedOrigins(allowedOrigins),
		scoreboard.WithBoard(boardSt),
	}, opts...)...)
}

// ogReq issues a request against srv with optional Origin/Referer/auth
// headers. body may be nil (several protected routes, like /api/admin/reset,
// take no body at all — the mitigation's core case).
func ogReq(t *testing.T, srv http.Handler, method, target string, origin, referer, authEmail string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, body)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if referer != "" {
		r.Header.Set("Referer", referer)
	}
	if authEmail != "" {
		r.Header.Set("X-Auth-Request-Email", authEmail)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

const allowedOrigin = "https://scoreboard.ctf.example.com"

// wantOriginGuardedRouteCount is ADR-0005 Decision 4's current-truth count
// of OriginGuarded routes. Requirement 6.4 (final review round): this used
// to be the literal `7` duplicated independently in THIS file's
// TestOriginGuard_AllProtectedRoutesEnforced AND in apispec_parity_test.go's
// TestAPISpec_V3_OriginGuardParity — two copies of the same canon, one of
// which could be bumped on a route-count change while the other was missed
// (they are in different files, so a diff review of one does not surface
// the other going stale). Both now pin against this single constant.
//
// app#292 Phase 2: P25's 3 QA origin-guarded routes (questions POST,
// questions/{qid}/messages POST, admin/questions/{qid}/reply) are gone
// (cutover — internal/qa removed wholesale), replaced by the QA Board's 7
// (participant: boardCreateThread, boardAppendMessage, boardLikeThread,
// boardUnlikeThread; operator: boardAdminReply, boardAdminSetThreadState,
// boardAdminSetMessageState). 9 - 3 + 7 = 13. ADR-0034 S1 (D8) adds the two
// profile routes — setProfile (participant) and adminResetProfile (operator),
// both browser-only and both guarded: 13 + 2 = 15.
const wantOriginGuardedRouteCount = 15

// TestOriginGuard_ResetFormCSRF is the mitigation's headline case: a
// body-less POST /api/admin/reset (the route a CSRF <form> auto-submit can
// hit without any CORS preflight) must be rejected when the request carries
// a foreign Origin, even though the caller also presents a valid admin
// identity header — an attacker riding a victim admin's session cookie would
// still supply that header via the browser, so the Origin check must be the
// thing that stops it.
func TestOriginGuard_ResetFormCSRF(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})

	w := ogReq(t, srv, "POST", "/api/admin/reset", "https://evil.example.com", "", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin reset: status=%d body=%s, want 403", w.Code, w.Body)
	}

	w = ogReq(t, srv, "POST", "/api/admin/reset", allowedOrigin, "", "admin@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("same-origin reset: status=%d body=%s, want 200", w.Code, w.Body)
	}
}

// TestOriginGuard_MissingOriginAndReferer covers the fail-closed default: a
// protected POST with neither Origin nor Referer is denied, even carrying a
// valid admin identity.
func TestOriginGuard_MissingOriginAndReferer(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})
	w := ogReq(t, srv, "POST", "/api/admin/reset", "", "", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", w.Code, w.Body)
	}
}

// TestOriginGuard_EmptyAllowlistDeniesAll asserts the fail-closed default
// (ALLOWED_ORIGINS unset): every guarded route denies even a same-origin-
// looking request, because nothing is in the allowlist to match against.
func TestOriginGuard_EmptyAllowlistDeniesAll(t *testing.T) {
	srv := newOriginFixture(t, nil)
	w := ogReq(t, srv, "POST", "/api/admin/reset", allowedOrigin, "", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403 (empty allowlist must deny)", w.Code, w.Body)
	}
}

// TestOriginGuard_RefererFallback: browsers that omit Origin on some
// navigations still send Referer; the guard must derive the origin from it
// and apply the same allowlist check.
func TestOriginGuard_RefererFallback(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})

	// Allowed referer origin (path/query beyond the origin must be ignored).
	w := ogReq(t, srv, "POST", "/api/admin/reset", "", allowedOrigin+"/admin/panel?x=1", "admin@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("allowed referer: status=%d body=%s, want 200", w.Code, w.Body)
	}

	// Disallowed referer origin → 403.
	w = ogReq(t, srv, "POST", "/api/admin/reset", "", "https://evil.example.com/x", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("disallowed referer: status=%d body=%s, want 403", w.Code, w.Body)
	}
}

// TestOriginGuard_OriginWinsOverReferer: when both headers are present,
// Origin is authoritative — a mismatched Referer must not save (or sink) the
// request if Origin itself passes (or fails) the allowlist.
func TestOriginGuard_OriginWinsOverReferer(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})

	// Origin allowed, Referer would fail on its own — request still passes.
	w := ogReq(t, srv, "POST", "/api/admin/reset", allowedOrigin, "https://evil.example.com/x", "admin@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("origin allowed despite bad referer: status=%d body=%s, want 200", w.Code, w.Body)
	}
}

// TestOriginGuard_MultipleAllowedOrigins: the CSV allowlist supports more
// than one entry (future portal origin alongside the existing scoreboard
// host), and each is matched independently/exactly.
func TestOriginGuard_MultipleAllowedOrigins(t *testing.T) {
	const portalOrigin = "https://portal.ctf.example.com"
	srv := newOriginFixture(t, []string{allowedOrigin, portalOrigin})

	for _, origin := range []string{allowedOrigin, portalOrigin} {
		w := ogReq(t, srv, "POST", "/api/admin/reset", origin, "", "admin@ctf.local", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("origin %s: status=%d body=%s, want 200", origin, w.Code, w.Body)
		}
	}
	// A third, unlisted origin is still denied.
	w := ogReq(t, srv, "POST", "/api/admin/reset", "https://unlisted.example.com", "", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unlisted origin: status=%d body=%s, want 403", w.Code, w.Body)
	}
}

// pathParamValues maps the {name} path-param segments used across
// scoreboard's route table to a fixed value good enough to satisfy
// http.ServeMux's pattern match. The origin guard runs BEFORE any
// handler-level use of the substituted value (it wraps the handler, and
// http.ServeMux dispatches on the pattern shape, not the concrete value), so
// these values only need to route — they do not need to be "real" in a
// catalog sense. "02-evade" is nonetheless a real fixture catalog id (see
// newOriginFixture) so the small number of UNGUARDED POST routes exercised
// below (which DO reach handler code — see
// TestOriginGuard_AllProtectedRoutesEnforced's negative branch) hit a normal
// business-logic response (400/404/200) rather than an unrelated panic.
var pathParamValues = map[string]string{
	"user": "alice",
	"cid":  "02-evade",
	"idx":  "0",
	"tid":  "00000000000000000000000000000000",
	"mid":  "00000000000000000000000000000000",
}

var pathParamPattern = regexp.MustCompile(`\{([^}]+)\}`)

// concretePath substitutes every {name} segment in an apispec.Route.Pattern
// with pathParamValues' fixed value (or "x" for a name not in that map, so a
// future path-param name doesn't panic the test — it just gets a
// less-meaningful substitution), producing a URL usable as an httptest
// target.
func concretePath(pattern string) string { return concretePathAs(pattern, pathParamValues["user"]) }

// concretePathAs is concretePath with {user} = user, so a request can target
// the caller's own seat whoever the caller is.
func concretePathAs(pattern, user string) string {
	return pathParamPattern.ReplaceAllStringFunc(pattern, func(seg string) string {
		name := seg[1 : len(seg)-1]
		if name == "user" {
			return user
		}
		if v, ok := pathParamValues[name]; ok {
			return v
		}
		return "x"
	})
}

// TestOriginGuard_AllProtectedRoutesEnforced is the behavioural half of
// ADR-0005's origin-guard contract, and DERIVES its case table from
// srv.Routes() — the same declarative table api.Handler.Routes() (and
// scoreboard.Handler.Routes(), which flattens it together with
// ingest/view's) exposes to the ADR-0005 V1-V4 spec-parity tests — instead
// of a hand-maintained list of route names.
//
// This closes a real gap the 5x review found: a hand-written 6-entry table
// here had ZERO coverage of POST
// /api/users/{user}/challenges/{cid}/reset-dirty, even though
// api.Handler.Routes() declares it OriginGuarded: true (ADR-0003 A2-2's
// destructive self-scoped taint reset). Because this test built its case
// list independently of Routes(), a mutation that dropped reset-dirty's
// h.og(...) wrapper WHILE LEAVING OriginGuarded: true in the table (exactly
// what security-engineer's 5x mutation test did) made `make test` fully
// green: nothing here ever exercised that route. Deriving the case table
// from Routes() itself means any route currently — or in the future — marked
// OriginGuarded: true is automatically walked here; there is no second,
// independently-maintained list to silently drift out of sync with it again.
//
// For every route:
//   - OriginGuarded: true → a cross-origin POST (Origin: evil, no matching
//     entry in the allowlist) MUST be rejected 403. This is the guard's
//     entire job.
//   - OriginGuarded: false AND Method == "POST" → the SAME cross-origin
//     request MUST NOT be rejected 403 by the guard (it may still fail for
//     an unrelated business reason — wrong flag, bad body, unknown
//     challenge — none of which is 403 in this codebase's routes; see the
//     per-route handler doc comments in api.go). This is the negative branch
//     that would catch the opposite mutation: a future route accidentally
//     wrapped in h.og(...) despite being a collector-forwarded write (which
//     would silently break scoring the same way P23-2's original bug did).
//
// Every request carries X-Auth-Request-Email: admin@ctf.local (the fixture's
// admin) so a 403 from isAdmin/selfOrAdmin — a DIFFERENT
// mechanism that also returns 403, unrelated to the origin guard — can never
// masquerade as "the guard worked": admin bypasses all three of those checks
// regardless of the substituted {user} value, isolating the origin guard as
// the only thing that can produce a 403 in this test.
//
// GET routes are not exercised here (the origin guard is a CSRF mitigation
// for state-changing requests; ADR-0005's table has no GET route marked
// OriginGuarded: true today, and a GET being added with the flag set would
// still be caught by the positive branch above — the loop keys off
// OriginGuarded, not Method).
func TestOriginGuard_AllProtectedRoutesEnforced(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})
	const evilOrigin = "https://evil.example.com"

	var guarded, unguardedWrites int
	for _, rt := range srv.Routes() {
		rt := rt
		target := concretePath(rt.Pattern)
		switch {
		case rt.OriginGuarded:
			guarded++
			t.Run("guarded/"+rt.MuxPattern(), func(t *testing.T) {
				w := ogReq(t, srv, rt.Method, target, evilOrigin, "", "admin@ctf.local", strings.NewReader("{}"))
				if w.Code != http.StatusForbidden {
					t.Fatalf("%s: status=%d body=%s, want 403 (OriginGuarded: true — cross-origin must be denied)", rt.MuxPattern(), w.Code, w.Body)
				}
			})
		case rt.Method == "POST":
			unguardedWrites++
			t.Run("unguarded/"+rt.MuxPattern(), func(t *testing.T) {
				email := "admin@ctf.local"
				if rt.Authz == apispec.AuthzInternalClaimedIdentity {
					// Collector-only routes refuse ANY X-Auth-Request-* header
					// with their own 403 (ADR-0034 D12 S1), which is not the
					// origin guard. Send the header-less shape the collector
					// forward actually has, so a 403 here still means "the
					// origin guard wrongly wraps this route".
					email = ""
				}
				w := ogReq(t, srv, rt.Method, target, evilOrigin, "", email, strings.NewReader("{}"))
				if w.Code == http.StatusForbidden {
					t.Fatalf("%s: status=%d body=%s, must NOT be 403 (OriginGuarded: false — a deliberately unguarded write, e.g. collector-forwarded)", rt.MuxPattern(), w.Code, w.Body)
				}
			})
		}
	}

	// V8 exact-count guard (mirrors ADR-0005's own "prove the detector isn't
	// vacuous" discipline): pin the number of OriginGuarded routes to the
	// canon in falco-api's skill index / api.go's Routes() comment, so a
	// route silently losing OriginGuarded: true — or the derivation itself
	// breaking (e.g. Routes() returning nil) — shows up as a numeric
	// assertion failure, not a shrinking, easy-to-miss subtest count.
	if guarded != wantOriginGuardedRouteCount {
		t.Fatalf("expected exactly %d OriginGuarded routes (ADR-0005 canon: api.go's admin/reset, admin/display-name, submit-detect, steps/check, hints/{idx}, reset-dirty — admin/hints removed as dead code, app#84; app#292 Phase 2 QA Board: boardCreateThread, boardAppendMessage, boardLikeThread, boardUnlikeThread, boardAdminReply, boardAdminSetThreadState, boardAdminSetMessageState — P25's QA routes are gone, cutover), got %d", wantOriginGuardedRouteCount, guarded)
	}
	if unguardedWrites == 0 {
		t.Fatal("expected at least one unguarded POST route to exercise the negative branch — the derivation might be broken")
	}
}

// TestOriginGuard_SubmitBypassesGuard is the collector-forward
// regression fence for the P23-2 follow-up fix: POST
// /api/challenges/{cid}/submit must succeed with NEITHER Origin NOR Referer
// present — the exact shape of the collector's verbatim forward of a
// participant's curl request (internal/collector/collector.go "Routes
// fronted"; curl never sends either header). (POST
// /api/users/{user}/display-name used to be covered here too; it was removed
// with `setname` in ADR-0034 S1.) Before this fix the route was wrapped in h.og(...), so a
// fail-closed empty-both-headers request 403'd unconditionally — which is
// exactly the "ingest/collector path gets Origin-gated and scoring breaks"
// failure mode the guard must never cause. Uses an empty allowlist too,
// mirroring TestOriginGuard_ExfilBypassesGuard, to prove these paths work
// even before ALLOWED_ORIGINS is configured at all.
//
// submit-detect is NOT covered here: unlike submit, the
// collector's forward allowlist does not include it (its only caller is the
// journey UI's browser fetch), so it IS origin-guarded — see
// TestOriginGuard_AllProtectedRoutesEnforced's derived
// "guarded/POST /api/challenges/{cid}/submit-detect" case and
// TestOriginGuard_SubmitDetectRequiresOrigin below.
func TestOriginGuard_SubmitBypassesGuard(t *testing.T) {
	for _, allowlist := range [][]string{{allowedOrigin}, nil} {
		srv := newOriginFixture(t, allowlist)

		w := ogReq(t, srv, "POST", "/api/challenges/02-evade/submit", "", "", "",
			strings.NewReader(`{"user":"alice","flag":"FALCO{ok}"}`))
		if w.Code != http.StatusOK {
			t.Fatalf("submit without Origin/Referer (allowlist=%v): status=%d body=%s, want 200", allowlist, w.Code, w.Body)
		}
	}
}

// TestOriginGuard_SubmitDetectRequiresOrigin is the positive-path counterpart
// to the derived "guarded/POST /api/challenges/{cid}/submit-detect" case in
// TestOriginGuard_AllProtectedRoutesEnforced: a
// same-origin request must reach the handler (and get evaluated on its own
// terms — here a 503 because no DetectRunner is wired in this fixture) rather
// than being 403'd, proving the guard is allowlist-driven and not a blanket
// deny. A request with neither Origin nor Referer must be 403'd fail-closed,
// unlike submit above — submit-detect has no collector caller to
// protect.
func TestOriginGuard_SubmitDetectRequiresOrigin(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})

	// Send a proven identity but neither Origin nor Referer: detectMW answers
	// 403 for a request with NO identity header too, so an identity-less probe
	// would pass even if the origin guard were removed. With an identity, the
	// 403 below can only come from the guard.
	w := ogReq(t, srv, "POST", "/api/challenges/02-evade/submit-detect", "", "", "alice@ctf.local",
		strings.NewReader(`{"user":"alice","condition":"x"}`))
	if w.Code != http.StatusForbidden {
		t.Fatalf("submit-detect without Origin/Referer: status=%d body=%s, want 403 (no collector caller to protect, must be origin-gated)", w.Code, w.Body)
	}

	// app#328: a proven identity is required past the guard (detectMW), so send
	// one — otherwise the 403 below would be detectMW's, not the guard's.
	w = ogReq(t, srv, "POST", "/api/challenges/02-evade/submit-detect", allowedOrigin, "", "alice@ctf.local",
		strings.NewReader(`{"user":"alice","condition":"x"}`))
	// No DetectRunner is wired in this fixture, so the handler itself returns
	// 503 (feature off) — the point here is only that a same-origin request
	// reaches the handler instead of being 403'd by the guard.
	if w.Code == http.StatusForbidden {
		t.Fatalf("submit-detect with allowed Origin: status=%d body=%s, must not be 403 (allowlisted origin must pass the guard)", w.Code, w.Body)
	}
}

// TestOriginGuard_SubmitStillBlocksCrossOriginBrowserPOST is the other half
// of the dual-path story: the portal's Journey pane's browser fetch DOES
// carry an Origin header (templates/portal.html's fetch(
// '/api/challenges/'+cid+'/submit', {method:'POST',...})). Even though
// /submit is no longer wrapped by
// h.og(...), removing that wrapper must not silently make it accept an
// attacker's cross-origin state-changing request when a real Origin header
// IS present — the route's own handler-side trust model (claimed identity,
// per-IP rate limit) is unchanged and unaffected by the guard's absence
// either way, but this test pins the actual observed behaviour: a
// browser-shaped cross-origin POST reaches the handler and is evaluated on
// its own terms (flag correctness), not blocked or specially allowed by
// Origin. This documents that the residual CSRF exposure accepted in
// api.Register's comment is real (a forged cross-origin submit DOES reach
// the grader) — it is not silently mitigated by some other layer.
func TestOriginGuard_SubmitStillBlocksCrossOriginBrowserPOST(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})
	const evilOrigin = "https://evil.example.com"

	// Wrong flag from a cross-origin browser POST: rejected on flag mismatch
	// (200 + correct:false), not by the origin guard (confirms /submit is no
	// longer origin-gated — a pre-fix 403 here would indicate a regression).
	w := ogReq(t, srv, "POST", "/api/challenges/02-evade/submit", evilOrigin, "", "",
		strings.NewReader(`{"user":"alice","flag":"FALCO{wrong}"}`))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"correct":false`) {
		t.Fatalf("cross-origin submit: status=%d body=%s, want 200 with correct:false (evaluated by the grader, not origin-gated)", w.Code, w.Body)
	}
}

// TestOriginGuard_ExfilBypassesGuard is the collector-only server-to-server
// sink regression fence: POST /internal/exfil/{cid} must NOT be gated by the
// origin guard — it has no browser Origin/Referer, and gating it would
// silently break the boss-capstone scoring path (exfil receipts would 403
// forever regardless of ALLOWED_ORIGINS).
func TestOriginGuard_ExfilBypassesGuard(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin}) // non-empty allowlist, still no Origin sent below

	body := strings.NewReader(`{"user":"alice","flag":"FALCO{boss}"}`)
	w := ogReq(t, srv, "POST", "/internal/exfil/03-exfil", "", "", "", body)
	if w.Code != http.StatusOK {
		t.Fatalf("exfil without Origin/Referer: status=%d body=%s, want 200 (server-to-server sink must not be origin-gated)", w.Code, w.Body)
	}

	// Also true with an EMPTY allowlist — exfil must keep working even before
	// an operator has configured ALLOWED_ORIGINS at all.
	srv2 := newOriginFixture(t, nil)
	w2 := ogReq(t, srv2, "POST", "/internal/exfil/03-exfil", "", "", "", strings.NewReader(`{"user":"bob","flag":"FALCO{boss}"}`))
	if w2.Code != http.StatusOK {
		t.Fatalf("exfil with empty allowlist: status=%d body=%s, want 200", w2.Code, w2.Body)
	}
}

// --- og -> rate limiter order, derived from Routes() (app#389) ---------------

// foreignOrigin is an Origin that is not in any fixture's ALLOWED_ORIGINS.
const foreignOrigin = "https://evil.example.com"

// declaresRateLimit reports whether rt declares a rate-limit bucket. A route
// without one declares x-ctf-rate-limit "none", optionally followed by the
// reason ("none (the limit lives on the collector front)"). Anything else,
// the empty string included, counts as a bucket, so a blank declaration is
// pulled into the checks below instead of being skipped.
func declaresRateLimit(rt apispec.Route) bool {
	return rt.RateLimit != "none" && !strings.HasPrefix(rt.RateLimit, "none ")
}

// guardedRateLimitedRoutes is TestOriginGuardRunsBeforeRateLimiter's case
// table: every route that is origin-guarded AND rate-limited.
func guardedRateLimitedRoutes(routes []apispec.Route) []apispec.Route {
	var out []apispec.Route
	for _, rt := range routes {
		if rt.OriginGuarded && declaresRateLimit(rt) {
			out = append(out, rt)
		}
	}
	return out
}

// testClock is a settable clock for the rate limiters (scoreboard.WithNow).
// It does not move unless a test advances it, so a bucket never refills
// mid-test and a burst is an exact count.
type testClock struct{ ns atomic.Int64 }

func newTestClock() *testClock {
	c := &testClock{}
	c.ns.Store(time.Unix(1_700_000_000, 0).UnixNano())
	return c
}

func (c *testClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// newLimiterFixture is newOriginFixture with the limiters on clock.
func newLimiterFixture(t *testing.T, clock *testClock) *scoreboard.Handler {
	t.Helper()
	return newOriginFixture(t, []string{allowedOrigin}, scoreboard.WithNow(clock.now))
}

// limiterReq sends rt from origin as user's own seat: {user} = user and
// X-Auth-Request-Email = user@<fixture domain>; user "" sends no identity
// header (and the default seat). The body is "{}" for every route: the rate
// limiters run before any handler reads it, and every outcome the handler
// gives it (400 / 404 / 503 / 2xx) is equally "not limited".
func limiterReq(t *testing.T, srv http.Handler, rt apispec.Route, origin, user string) *httptest.ResponseRecorder {
	t.Helper()
	seat, email := pathParamValues["user"], ""
	if user != "" {
		seat, email = user, user+"@"+fixtureEmailDomain
	}
	return ogReq(t, srv, rt.Method, concretePathAs(rt.Pattern, seat), origin, "", email, strings.NewReader("{}"))
}

// limited reports whether w is a rate limiter's 429. A 429 with any other
// body (submit-detect's in-flight grader cap) fails the test: it is not the
// bucket being measured.
func limited(t *testing.T, rt apispec.Route, w *httptest.ResponseRecorder) bool {
	t.Helper()
	if w.Code != http.StatusTooManyRequests {
		return false
	}
	if !strings.Contains(w.Body.String(), `"rate limit exceeded"`) {
		t.Fatalf("%s: a 429 that is not the rate limiter's: %s", rt.MuxPattern(), w.Body)
	}
	return true
}

const maxBurstProbe = 64

// burstOf sends rt as user from the allowed origin until the limiter answers
// 429 and returns how many requests got past it (-1: never limited within
// maxBurstProbe).
func burstOf(t *testing.T, srv http.Handler, rt apispec.Route, user string) int {
	t.Helper()
	for n := 0; n < maxBurstProbe; n++ {
		if limited(t, rt, limiterReq(t, srv, rt, allowedOrigin, user)) {
			return n
		}
	}
	return -1
}

// ogBeforeLimiterViolation reports how rt breaks "the origin guard runs
// before the rate limiter", or "" when it does not. fresh must return a new
// handler (full buckets, frozen clock) on every call.
//
// Cookies are SameSite=None, so another site's page can make a victim's
// browser POST with the victim's identity header. The guard must 403 that
// before the limiter spends a token; otherwise the flood drains the victim's
// bucket and their own same-origin requests 429 (security review of app#379,
// L1). The control burst (no flood) is measured first: a route that never
// 429s cannot show the order either way, so that is a violation too.
func ogBeforeLimiterViolation(t *testing.T, fresh func() http.Handler, rt apispec.Route) string {
	t.Helper()
	burst := burstOf(t, fresh(), rt, "alice")
	if burst <= 0 {
		return fmt.Sprintf("%s declares RateLimit %q, but from the allowed origin alice's burst is %d (-1: no 429 in %d requests), so the order cannot be observed", rt.MuxPattern(), rt.RateLimit, burst, maxBurstProbe)
	}
	srv := fresh()
	for i := 1; i <= burst+1; i++ { // one past the burst
		if w := limiterReq(t, srv, rt, foreignOrigin, "alice"); w.Code != http.StatusForbidden {
			return fmt.Sprintf("%s: cross-origin request #%d carrying alice's identity: status=%d body=%s, want 403 (a 429 means the limiter runs before the origin guard)", rt.MuxPattern(), i, w.Code, w.Body)
		}
	}
	if got := burstOf(t, srv, rt, "alice"); got != burst {
		return fmt.Sprintf("%s: alice's burst after a cross-origin flood is %d, want the untouched %d (the flood spent her tokens: the limiter runs before the origin guard)", rt.MuxPattern(), got, burst)
	}
	return ""
}

// TestOriginGuardRunsBeforeRateLimiter (app#389) checks og -> limiter ->
// handler on EVERY route that is OriginGuarded and declares a RateLimit,
// derived from srv.Routes() the way TestOriginGuard_AllProtectedRoutesEnforced
// derives its table. It replaces a hand-written list of 2 of those routes
// (submit-detect, reset-dirty), which a new guarded, rate-limited route would
// not have joined.
func TestOriginGuardRunsBeforeRateLimiter(t *testing.T) {
	routes := guardedRateLimitedRoutes(newOriginFixture(t, []string{allowedOrigin}).Routes())
	if len(routes) == 0 {
		t.Fatal("derived 0 origin-guarded, rate-limited routes: the derivation is broken, not clean")
	}
	for _, rt := range routes {
		t.Run(rt.MuxPattern(), func(t *testing.T) {
			fresh := func() http.Handler { return newLimiterFixture(t, newTestClock()) }
			if v := ogBeforeLimiterViolation(t, fresh, rt); v != "" {
				t.Fatal(v)
			}
		})
	}
}

// syntheticMux serves one route per handler, all built fresh, from the real
// originguard and ratelimit packages (the same pieces api.Routes() composes).
func syntheticMux(routes ...apispec.Route) http.Handler {
	mux, _ := apispec.NewMux(routes)
	return mux
}

func syntheticOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// The order check is not vacuous: limiter -> og, and a declared limit that is
// not wired at all, are both flagged; og -> limiter passes.
func TestOriginGuardRunsBeforeRateLimiter_DetectorCatchesSwappedOrder(t *testing.T) {
	rt := apispec.Route{Method: "POST", Pattern: "/api/users/{user}/example", OriginGuarded: true, RateLimit: "identity 1 req/s burst 10"}
	for _, tc := range []struct {
		name      string
		wire      func(og, lim func(http.Handler) http.Handler) http.Handler
		wantFlags bool
	}{
		{"og -> limiter (api.Routes()' order)", func(og, lim func(http.Handler) http.Handler) http.Handler { return og(lim(syntheticOK())) }, false},
		{"limiter -> og (swapped)", func(og, lim func(http.Handler) http.Handler) http.Handler { return lim(og(syntheticOK())) }, true},
		{"og only (declared limit not wired)", func(og, _ func(http.Handler) http.Handler) http.Handler { return og(syntheticOK()) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fresh := func() http.Handler {
				og := originguard.New([]string{allowedOrigin}, slog.New(slog.NewTextHandler(io.Discard, nil))).Middleware
				lim := ratelimit.New(1, 10).WithNow(newTestClock().now).MiddlewareStrict("example", ratelimit.IdentityKeyed, strictObs())
				r := rt
				r.Handler = tc.wire(og, lim)
				return syntheticMux(r)
			}
			if v := ogBeforeLimiterViolation(t, fresh, rt); (v != "") != tc.wantFlags {
				t.Fatalf("violation = %q, want flagged=%v", v, tc.wantFlags)
			}
		})
	}
}

// The derivation picks up a NEW guarded, rate-limited route with no edit to
// the test, and leaves out the routes the order does not apply to.
func TestGuardedRateLimitedRoutes_DerivesNewRoutes(t *testing.T) {
	routes := append(newOriginFixture(t, []string{allowedOrigin}).Routes(),
		apispec.Route{Method: "POST", Pattern: "/new/guarded-limited", OriginGuarded: true, RateLimit: "identity 1 req/s burst 5"},
		apispec.Route{Method: "POST", Pattern: "/new/guarded-blank", OriginGuarded: true, RateLimit: ""},
		apispec.Route{Method: "POST", Pattern: "/new/guarded-none", OriginGuarded: true, RateLimit: "none (no bucket)"},
		apispec.Route{Method: "POST", Pattern: "/new/unguarded-limited", OriginGuarded: false, RateLimit: "per-IP 1 req/s burst 10"},
	)
	got := map[string]bool{}
	for _, rt := range guardedRateLimitedRoutes(routes) {
		got[rt.Pattern] = true
	}
	for pattern, want := range map[string]bool{
		"/new/guarded-limited": true, "/new/guarded-blank": true,
		"/new/guarded-none": false, "/new/unguarded-limited": false,
		"/api/challenges/{cid}/submit-detect": true, "/api/challenges/{cid}/submit": false, "/api/admin/reset": false,
	} {
		if got[pattern] != want {
			t.Errorf("%s derived = %v, want %v", pattern, got[pattern], want)
		}
	}
}
