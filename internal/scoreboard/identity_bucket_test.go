package scoreboard_test

// app#389: the scoreboard's rate-limit buckets as ONE table. A row of
// identityBuckets is one identity-keyed limiter behind api.Routes() (actionMW,
// detectMW, boardPostMW, boardLikeMW): its burst, its refill (one token per
// refill), whether it is fail-closed (MiddlewareStrict), and every route on
// it. submitIPBucket is the per-IP bucket on POST /submit. The rows are
// checked against Routes() (every route declaring an "identity ..." rate
// limit is on exactly one row, and declares exactly the row's numbers) and
// against the live handler:
//
//   - burst and rate: exactly `burst` requests pass, and one token comes back
//     after `refill`, not before;
//   - identity-keyed: behind one IP (httptest sends one RemoteAddr, i.e. the
//     venue-NAT case) another identity keeps its full burst;
//   - header-less: never gets through and spends no identity's token; on a
//     strict row the limiter ITSELF answers every one (its no_identity
//     counter moves by the number sent), never an IP-keyed 429;
//   - sharing: draining a route 429s exactly the routes on its own row and
//     nothing else, not another identity bucket and not submit's per-IP one;
//   - submit: the collector forward's shape (no identity header, no Origin)
//     is limited at exactly its burst, per IP, without limiting any
//     identity row.
//
// A NEW row is strict: true (MiddlewareStrict, the app#315 shape).
// strict: false is board_post and board_like only (TableMatchesRoutes
// asserts that set; whether to make them strict too is #390 / #397).
//
// x-ctf-rate-limit is free text, so the rows cannot be derived from it yet: a
// new identity bucket is a new row here. Route-specific claims stay with the
// route (submit_detect_gate_test.go: never reads the body, never reaches the
// grader); the og -> limiter order is TestOriginGuardRunsBeforeRateLimiter.

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

type rateBucket struct {
	name    string        // the bucket; for a strict row, its ratelimit.IdentityRequestsTotal label
	burst   int           // requests that pass from a full bucket
	refill  time.Duration // time for one token to come back
	strict  bool          // MiddlewareStrict: header-less is the limiter's 403, no token, no IP fallback
	members []string      // MuxPattern of every route on the bucket
}

var identityBuckets = []rateBucket{
	{
		name: "detect", burst: 10, refill: time.Second, strict: true,
		members: []string{"POST /api/challenges/{cid}/submit-detect"},
	},
	{
		name: "participant_action", burst: 10, refill: time.Second, strict: true,
		members: []string{
			"POST /api/users/{user}/challenges/{cid}/steps/{idx}/check",
			"POST /api/users/{user}/challenges/{cid}/hints/{idx}",
			"POST /api/users/{user}/challenges/{cid}/reset-dirty",
			"POST /api/users/{user}/profile",
		},
	},
	{
		// Not strict: boardIdentityKeyed falls back to a client-IP key when the
		// header is missing, and the 403 comes from requireAuthenticated in the
		// handler, after that key has spent a token. Past the IP key's burst a
		// header-less request is 429 instead.
		name: "board_post", burst: 3, refill: 10 * time.Second, strict: false,
		members: []string{"POST /api/board/threads", "POST /api/board/threads/{tid}/messages"},
	},
	{
		name: "board_like", burst: 10, refill: time.Second, strict: false,
		members: []string{"POST /api/board/threads/{tid}/like", "POST /api/board/threads/{tid}/unlike"},
	},
}

// submitIPBucket is the per-IP bucket every identity bucket must stay apart
// from: under a venue NAT one participant's actions must not 429 anyone's
// flag submission (app#315, app#328).
var submitIPBucket = rateBucket{
	name: "submit (per-IP)", burst: 10, refill: time.Second,
	members: []string{"POST /api/challenges/{cid}/submit"},
}

// declaredRate is the x-ctf-rate-limit wording for a bucket of the given
// keying, so the numbers in a row are the only source of the declaration:
// "identity 1 req/s burst 10", "identity 1 req/10s burst 3", "per-IP 1 req/s
// burst 10".
func declaredRate(keying string, b rateBucket) string {
	per := "s"
	if b.refill != time.Second {
		per = strconv.Itoa(int(b.refill/time.Second)) + "s"
	}
	return fmt.Sprintf("%s 1 req/%s burst %d", keying, per, b.burst)
}

// declares reports whether a RateLimit string declares exactly `declared`,
// optionally followed by a space and more text ("... (shared with ...)").
// "burst 10" does not match "burst 100".
func declares(rateLimit, declared string) bool {
	return rateLimit == declared || strings.HasPrefix(rateLimit, declared+" ")
}

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
	var lenient []string
	for _, b := range identityBuckets {
		if !b.strict {
			lenient = append(lenient, b.name)
		}
		for _, m := range b.members {
			if prev, dup := rowOf[m]; dup {
				t.Errorf("%s is on two rows (%s, %s)", m, prev, b.name)
			}
			rowOf[m] = b.name
			if rt, want := routeByPattern(t, routes, m), declaredRate("identity", b); !declares(rt.RateLimit, want) {
				t.Errorf("%s (row %s) declares RateLimit %q, want %q (from the row's burst and refill)", m, b.name, rt.RateLimit, want)
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
	sort.Strings(lenient)
	if got := strings.Join(lenient, ","); got != "board_like,board_post" {
		t.Errorf("rows with strict: false = [%s], want [board_like,board_post]: a new identity bucket is MiddlewareStrict (#390)", got)
	}
	if declares("identity 1 req/s burst 100", "identity 1 req/s burst 10") {
		t.Error(`declares matched "burst 10" inside "burst 100": the match has no word boundary`)
	}
	sub := submitIPBucket.members[0]
	if rt, want := routeByPattern(t, routes, sub), declaredRate("per-IP", submitIPBucket); !declares(rt.RateLimit, want) {
		t.Errorf("%s declares RateLimit %q, want %q", sub, rt.RateLimit, want)
	}
}

// bucketPropertyViolation checks one member route of b on a fresh handler
// whose limiters run on clock, and reports the first broken property or "".
func bucketPropertyViolation(t *testing.T, srv http.Handler, clock *testClock, rt apispec.Route, b rateBucket) string {
	t.Helper()
	p := rt.MuxPattern()
	if n := burstOf(t, srv, rt, "alice"); n != b.burst {
		return fmt.Sprintf("%s: alice's burst = %d, want %d", p, n, b.burst)
	}
	if n := burstOf(t, srv, rt, "bob"); n != b.burst {
		return fmt.Sprintf("%s: bob (same IP) got burst %d after alice drained hers, want %d: the bucket is not identity-keyed", p, n, b.burst)
	}
	// A 403 alone cannot tell the limiter's answer from the handler's gate, so
	// on a strict row the limiter's own no_identity counter must move by
	// exactly the number of header-less requests sent.
	noIdentity := func() float64 {
		if !b.strict {
			return 0
		}
		return testutil.ToFloat64(ratelimit.IdentityRequestsTotal.WithLabelValues(b.name, "no_identity"))
	}
	before := noIdentity()
	sent := 3*b.burst + 1
	for i := 1; i <= sent; i++ {
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
	if got := noIdentity() - before; b.strict && got != float64(sent) {
		return fmt.Sprintf("%s: the limiter answered %v of %d header-less requests itself (ratelimit_identity_requests_total{bucket=%q,outcome=\"no_identity\"}); the other 403s came from behind it, so the bucket is not MiddlewareStrict", p, got, sent, b.name)
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

// identityOrEmpty is the keying a strict bucket must not regress to: the
// identity when there is one, and otherwise "" — which ratelimit.Middleware
// lets through without spending a token.
func identityOrEmpty(r *http.Request) string {
	k, _ := ratelimit.IdentityKeyed(r)
	return k
}

// gate403 stands in for a handler's own identity gate (selfOrAdmin): no
// header is 403, anything else is 200.
func gate403() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ratelimit.IdentityKeyed(r); !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// The property check is not vacuous: a strict row whose limiter lets an empty
// key through (the handler behind it still answers 403) is flagged, while a
// real MiddlewareStrict passes every property.
func TestIdentityBuckets_PropertyDetectorCatchesPassThrough(t *testing.T) {
	rt := apispec.Route{Method: "POST", Pattern: "/api/users/{user}/example"}
	for _, tc := range []struct {
		name      string
		wire      func(l *ratelimit.Limiter, bucket string) http.Handler
		wantFlags bool
	}{
		{"MiddlewareStrict", func(l *ratelimit.Limiter, bucket string) http.Handler {
			return l.MiddlewareStrict(bucket, ratelimit.IdentityKeyed)(gate403())
		}, false},
		{"empty-key pass-through Middleware behind a 403 gate", func(l *ratelimit.Limiter, _ string) http.Handler {
			return l.Middleware(identityOrEmpty)(gate403())
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := rateBucket{name: "example_proof_" + strconv.FormatBool(tc.wantFlags), burst: 10, refill: time.Second, strict: true}
			clock := newTestClock()
			r := rt
			r.Handler = tc.wire(ratelimit.New(1, 10).WithNow(clock.now), b.name)
			if v := bucketPropertyViolation(t, syntheticMux(r), clock, rt, b); (v != "") != tc.wantFlags {
				t.Fatalf("violation = %q, want flagged=%v", v, tc.wantFlags)
			}
		})
	}
}

// submitIPBucketViolation checks the per-IP bucket on rt: requests in the
// collector forward's shape (no identity header, no Origin) are limited at
// exactly b.burst; after that a request carrying an identity from the same
// IP is limited too (the key is the IP, not the identity); and none of
// others (the identity routes) is limited by the drain.
func submitIPBucketViolation(t *testing.T, srv http.Handler, rt apispec.Route, b rateBucket, others []apispec.Route) string {
	t.Helper()
	p := rt.MuxPattern()
	n := 0
	for ; n < maxBurstProbe && !limited(t, rt, limiterReq(t, srv, rt, "", "")); n++ {
	}
	if n != b.burst {
		return fmt.Sprintf("%s: requests with no identity header and no Origin (the collector forward) got %d past the limiter (%d = never limited), want %d", p, n, maxBurstProbe, b.burst)
	}
	for _, user := range []string{"alice", "bob"} {
		if !limited(t, rt, limiterReq(t, srv, rt, allowedOrigin, user)) {
			return fmt.Sprintf("%s: %s (same IP, identity header) is not limited after the header-less drain: the bucket is not keyed by IP", p, user)
		}
	}
	for _, o := range others {
		if limited(t, o, limiterReq(t, srv, o, allowedOrigin, "alice")) {
			return fmt.Sprintf("draining %s with header-less requests 429s %s: the per-IP bucket is shared with an identity route", p, o.MuxPattern())
		}
	}
	return ""
}

func TestSubmitBucket_PerIPInTheCollectorForwardShape(t *testing.T) {
	srv := newLimiterFixture(t, newTestClock())
	routes := srv.Routes()
	var others []apispec.Route
	for _, b := range identityBuckets {
		for _, m := range b.members {
			others = append(others, routeByPattern(t, routes, m))
		}
	}
	if v := submitIPBucketViolation(t, srv, routeByPattern(t, routes, submitIPBucket.members[0]), submitIPBucket, others); v != "" {
		t.Fatal(v)
	}
}

// The submit check is not vacuous: a bucket keyed by identity that lets an
// empty key through (header-less = unlimited), and one keyed by identity
// with an IP fallback (bob is not limited by the IP drain), are both flagged;
// a client-IP key passes.
func TestSubmitBucket_DetectorCatchesIdentityKeying(t *testing.T) {
	rt := apispec.Route{Method: "POST", Pattern: "/example/submit"}
	for _, tc := range []struct {
		name      string
		keyFn     func(*http.Request) string
		wantFlags bool
	}{
		{"client IP (api.Routes()' submitMW)", ratelimit.ClientIP, false},
		{"identity, empty key passes", identityOrEmpty, true},
		{"identity, IP fallback", func(r *http.Request) string {
			if k := identityOrEmpty(r); k != "" {
				return k
			}
			return "ip:" + ratelimit.ClientIP(r)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rt
			r.Handler = ratelimit.New(1, 10).WithNow(newTestClock().now).Middleware(tc.keyFn)(syntheticOK())
			if v := submitIPBucketViolation(t, syntheticMux(r), rt, submitIPBucket, nil); (v != "") != tc.wantFlags {
				t.Fatalf("violation = %q, want flagged=%v", v, tc.wantFlags)
			}
		})
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
	bucketOf := map[string]string{}
	var cases []apispec.Route
	for _, b := range append([]rateBucket{submitIPBucket}, identityBuckets...) {
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

// --- the x-ctf-rate-limit vocabulary (until it is structured, #390) ---------

// rateLimitKeying classifies a RateLimit declaration: "none" (with or
// without a "(reason)"), or a bucket keyed per identity, per IP or per
// participant. Anything else is "" — an unknown wording fails
// TestRateLimitDeclarations_ClosedVocabulary rather than being read as
// either a bucket or none.
func rateLimitKeying(rateLimit string) string {
	if !declaresRateLimit(apispec.Route{RateLimit: rateLimit}) {
		return "none"
	}
	for _, k := range []string{"identity", "per-IP", "per-participant"} {
		if strings.HasPrefix(rateLimit, k+" ") {
			return k
		}
	}
	return ""
}

func TestRateLimitDeclarations_ClosedVocabulary(t *testing.T) {
	seen := map[string]int{}
	for _, rt := range newOriginFixture(t, []string{allowedOrigin}).Routes() {
		k := rateLimitKeying(rt.RateLimit)
		if k == "" {
			t.Errorf("%s declares RateLimit %q, which starts with none of: none, identity, per-IP, per-participant", rt.MuxPattern(), rt.RateLimit)
		}
		seen[k]++
	}
	for _, k := range []string{"none", "identity", "per-IP", "per-participant"} {
		if seen[k] == 0 {
			t.Errorf("no route declares a %q rate limit: the classification is broken (counts %v)", k, seen)
		}
	}
	if k := rateLimitKeying("bursty 5"); k != "" {
		t.Errorf("an unknown wording classified as %q, want unknown", k)
	}
}

// A route that declares "none" has no limiter: maxBurstProbe requests from
// an identity that passes its gate (admin; none on the collector-only
// internal routes, which refuse any identity header) never meet the
// limiter's 429.
func TestRateLimitDeclarations_NoneMeansNoLimiter(t *testing.T) {
	var none int
	for _, rt := range newOriginFixture(t, []string{allowedOrigin}).Routes() {
		if declaresRateLimit(rt) {
			continue
		}
		none++
		t.Run(rt.MuxPattern(), func(t *testing.T) {
			user := "admin"
			if rt.Authz == apispec.AuthzInternalClaimedIdentity {
				user = ""
			}
			if n := burstOf(t, newLimiterFixture(t, newTestClock()), rt, user); n != -1 {
				t.Fatalf("%s declares RateLimit %q but the limiter answered 429 after %d requests", rt.MuxPattern(), rt.RateLimit, n)
			}
		})
	}
	if none == 0 {
		t.Fatal("derived 0 routes declaring none: the derivation is broken, not clean")
	}
}
