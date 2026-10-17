package scoreboard_test

// app#389: the identity-keyed rate-limit buckets as ONE table. A row is one
// limiter behind api.Routes() (actionMW, detectMW, boardPostMW, boardLikeMW):
// its declared rate and burst, whether it is fail-closed (MiddlewareStrict),
// and every route on it. The table is checked against Routes() (every route
// declaring an "identity ..." rate limit is on exactly one row, with that
// declaration) and against the live handler:
//
//   - burst and rate: exactly `burst` requests pass, and one token comes back
//     after `refill`, not before;
//   - identity-keyed: behind one IP (httptest sends one RemoteAddr, i.e. the
//     venue-NAT case) another identity keeps its full burst;
//   - header-less: never gets through and spends no identity's token; on a
//     strict bucket it is 403 every time (no token taken, no IP fallback);
//   - sharing: draining a route 429s exactly the routes on its own row and
//     nothing else, not another identity bucket and not submit's per-IP one.
//
// x-ctf-rate-limit is free text, so the rows cannot be derived from it yet: a
// new identity bucket is a new row here. Route-specific claims stay with the
// route (submit_detect_gate_test.go: never reads the body, never reaches the
// grader); the og -> limiter order is TestOriginGuardRunsBeforeRateLimiter.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

type identityBucket struct {
	name     string        // the bucket (metric label, or the limiter's name)
	declared string        // prefix of every member's RateLimit declaration
	burst    int           // requests that pass from a full bucket
	refill   time.Duration // time for one token to come back
	strict   bool          // MiddlewareStrict: header-less is 403, no token, no IP fallback
	members  []string      // MuxPattern of every route on the bucket
}

var identityBuckets = []identityBucket{
	{
		name: "detect", declared: "identity 1 req/s burst 10", burst: 10, refill: time.Second, strict: true,
		members: []string{"POST /api/challenges/{cid}/submit-detect"},
	},
	{
		name: "participant_action", declared: "identity 1 req/s burst 10", burst: 10, refill: time.Second, strict: true,
		members: []string{
			"POST /api/users/{user}/challenges/{cid}/steps/{idx}/check",
			"POST /api/users/{user}/challenges/{cid}/hints/{idx}",
			"POST /api/users/{user}/challenges/{cid}/reset-dirty",
			"POST /api/users/{user}/profile",
		},
	},
	{
		// Not strict: boardIdentityKeyed falls back to a client-IP key when the
		// header is missing, and requireAuthenticated (in the handler) is the
		// 403. Past that IP key's burst a header-less request is 429 instead.
		name: "board_post", declared: "identity 1 req/10s burst 3", burst: 3, refill: 10 * time.Second, strict: false,
		members: []string{"POST /api/board/threads", "POST /api/board/threads/{tid}/messages"},
	},
	{
		name: "board_like", declared: "identity 1 req/s burst 10", burst: 10, refill: time.Second, strict: false,
		members: []string{"POST /api/board/threads/{tid}/like", "POST /api/board/threads/{tid}/unlike"},
	},
}

// submitIPRoute is the per-IP bucket every identity bucket must stay apart
// from: under a venue NAT one participant's actions must not 429 anyone's
// flag submission (app#315, app#328).
const submitIPRoute = "POST /api/challenges/{cid}/submit"

func routeByPattern(t *testing.T, routes []apispec.Route, pattern string) apispec.Route {
	t.Helper()
	for _, rt := range routes {
		if rt.MuxPattern() == pattern {
			return rt
		}
	}
	t.Fatalf("%s is not in Routes()", pattern)
	return apispec.Route{}
}

func TestIdentityBuckets_TableMatchesRoutes(t *testing.T) {
	routes := newOriginFixture(t, []string{allowedOrigin}).Routes()
	rowOf := map[string]string{}
	for _, b := range identityBuckets {
		for _, m := range b.members {
			if prev, dup := rowOf[m]; dup {
				t.Errorf("%s is on two rows (%s, %s)", m, prev, b.name)
			}
			rowOf[m] = b.name
			if rt := routeByPattern(t, routes, m); !strings.HasPrefix(rt.RateLimit, b.declared) {
				t.Errorf("%s (row %s) declares RateLimit %q, want the prefix %q", m, b.name, rt.RateLimit, b.declared)
			}
		}
	}
	derived := 0
	for _, rt := range routes {
		if !strings.HasPrefix(rt.RateLimit, "identity ") {
			continue
		}
		derived++
		if _, ok := rowOf[rt.MuxPattern()]; !ok {
			t.Errorf("%s declares an identity rate limit (%q) but is on no row of identityBuckets", rt.MuxPattern(), rt.RateLimit)
		}
	}
	if derived == 0 {
		t.Fatal("derived 0 identity rate-limited routes: the derivation is broken, not clean")
	}
	if rt := routeByPattern(t, routes, submitIPRoute); !strings.HasPrefix(rt.RateLimit, "per-IP ") {
		t.Errorf("%s declares RateLimit %q, want a per-IP bucket", submitIPRoute, rt.RateLimit)
	}
}

// bucketPropertyViolation checks one member route of b on a fresh handler
// whose limiters run on clock, and reports the first broken property or "".
func bucketPropertyViolation(t *testing.T, srv http.Handler, clock *testClock, rt apispec.Route, b identityBucket) string {
	t.Helper()
	p := rt.MuxPattern()
	if n := burstOf(t, srv, rt, "alice"); n != b.burst {
		return fmt.Sprintf("%s: alice's burst = %d, want %d", p, n, b.burst)
	}
	if n := burstOf(t, srv, rt, "bob"); n != b.burst {
		return fmt.Sprintf("%s: bob (same IP) got burst %d after alice drained hers, want %d: the bucket is not identity-keyed", p, n, b.burst)
	}
	for i := 1; i <= 3*b.burst+1; i++ {
		blank := "" // no header; every other request a whitespace-only one, which is the same
		if i%2 == 0 {
			blank = "   "
		}
		w := ogReq(t, srv, rt.Method, concretePath(rt.Pattern), allowedOrigin, "", blank, strings.NewReader("{}"))
		if w.Code == http.StatusForbidden || (!b.strict && limited(t, rt, w)) {
			continue
		}
		want := "403 every time (no token taken, never an IP-keyed 429)"
		if !b.strict {
			want = "403 or the limiter's 429, never through"
		}
		return fmt.Sprintf("%s: header-less request #%d (X-Auth-Request-Email %q): status=%d body=%s, want %s", p, i, blank, w.Code, w.Body, want)
	}
	if n := burstOf(t, srv, rt, "carol"); n != b.burst {
		return fmt.Sprintf("%s: carol's burst after a header-less flood = %d, want %d (the flood spent an identity's tokens)", p, n, b.burst)
	}
	if n := burstOf(t, srv, rt, "dave"); n != b.burst {
		return fmt.Sprintf("%s: dave's burst = %d, want %d", p, n, b.burst)
	}
	// carol and dave are both empty now. Just before one refill period dave
	// is still limited; at exactly one period carol gets one token, no more.
	clock.advance(b.refill - time.Millisecond)
	if !limited(t, rt, limiterReq(t, srv, rt, allowedOrigin, "dave")) {
		return fmt.Sprintf("%s: a token came back before %s (want one per %s)", p, b.refill-time.Millisecond, b.refill)
	}
	clock.advance(time.Millisecond)
	if n := burstOf(t, srv, rt, "carol"); n != 1 {
		return fmt.Sprintf("%s: %d tokens came back after %s, want exactly 1", p, n, b.refill)
	}
	return ""
}

func TestIdentityBuckets_Properties(t *testing.T) {
	for _, b := range identityBuckets {
		for _, m := range b.members {
			t.Run(b.name+"/"+m, func(t *testing.T) {
				clock := newTestClock()
				srv := newLimiterFixture(t, clock)
				if v := bucketPropertyViolation(t, srv, clock, routeByPattern(t, srv.Routes(), m), b); v != "" {
					t.Fatal(v)
				}
			})
		}
	}
}

// bucketSharingViolations drains each route (as alice) on a fresh handler and
// probes each other route once on that handler: the limiter's 429 on the
// probe means the two share a bucket. Every ordered pair gets its own handler,
// so an earlier probe can never have spent the probed bucket. It reports
// every pair where that disagrees with bucketOf (MuxPattern -> bucket name).
func bucketSharingViolations(t *testing.T, fresh func() http.Handler, routes []apispec.Route, bucketOf map[string]string) []string {
	t.Helper()
	var out []string
	for _, a := range routes {
		for _, b := range routes {
			if a.MuxPattern() == b.MuxPattern() {
				continue
			}
			srv := fresh()
			if n := burstOf(t, srv, a, "alice"); n <= 0 {
				out = append(out, fmt.Sprintf("%s never 429s (burst %d): sharing cannot be measured", a.MuxPattern(), n))
				break
			}
			shared := limited(t, b, limiterReq(t, srv, b, allowedOrigin, "alice"))
			if want := bucketOf[a.MuxPattern()] == bucketOf[b.MuxPattern()]; shared != want {
				out = append(out, fmt.Sprintf("draining %s (%s): %s limited=%v, want %v (%s)", a.MuxPattern(), bucketOf[a.MuxPattern()], b.MuxPattern(), shared, want, bucketOf[b.MuxPattern()]))
			}
		}
	}
	return out
}

func TestIdentityBuckets_ShareExactlyTheirRow(t *testing.T) {
	routes := newOriginFixture(t, []string{allowedOrigin}).Routes()
	bucketOf := map[string]string{submitIPRoute: "submit (per-IP)"}
	cases := []apispec.Route{routeByPattern(t, routes, submitIPRoute)}
	for _, b := range identityBuckets {
		for _, m := range b.members {
			bucketOf[m] = b.name
			cases = append(cases, routeByPattern(t, routes, m))
		}
	}
	fresh := func() http.Handler { return newLimiterFixture(t, newTestClock()) }
	for _, v := range bucketSharingViolations(t, fresh, cases, bucketOf) {
		t.Error(v)
	}
}

// The sharing check is not vacuous: two routes on ONE limiter declared as two
// buckets, and two limiters declared as one bucket, are both flagged.
func TestIdentityBuckets_SharingDetectorCatchesMismatch(t *testing.T) {
	a := apispec.Route{Method: "POST", Pattern: "/example/a"}
	b := apispec.Route{Method: "POST", Pattern: "/example/b"}
	wire := func(oneLimiter bool) func() http.Handler {
		return func() http.Handler {
			la := ratelimit.New(1, 10).WithNow(newTestClock().now)
			lb := la
			if !oneLimiter {
				lb = ratelimit.New(1, 10).WithNow(newTestClock().now)
			}
			ra, rb := a, b
			ra.Handler = la.MiddlewareStrict("a", ratelimit.IdentityKeyed)(syntheticOK())
			rb.Handler = lb.MiddlewareStrict("b", ratelimit.IdentityKeyed)(syntheticOK())
			return syntheticMux(ra, rb)
		}
	}
	for _, tc := range []struct {
		name       string
		oneLimiter bool
		bucketOf   map[string]string
		wantFlags  bool
	}{
		{"separate limiters, declared separate", false, map[string]string{a.MuxPattern(): "x", b.MuxPattern(): "y"}, false},
		{"one limiter, declared separate (a shared bucket)", true, map[string]string{a.MuxPattern(): "x", b.MuxPattern(): "y"}, true},
		{"separate limiters, declared shared", false, map[string]string{a.MuxPattern(): "x", b.MuxPattern(): "x"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := bucketSharingViolations(t, wire(tc.oneLimiter), []apispec.Route{a, b}, tc.bucketOf)
			if (len(v) > 0) != tc.wantFlags {
				t.Fatalf("violations = %v, want flagged=%v", v, tc.wantFlags)
			}
		})
	}
}
