// Package ratelimit provides a small in-memory token-bucket limiter keyed
// by an arbitrary string (the requester's IP, or a proven identity).
//
// What this is, honestly: a per-pod limiter, and the only rate control this
// repository itself configures (no chart sets an ingress-nginx rate-limit
// annotation). Any edge limit in front of it (ingress-nginx, Cloudflare) is a
// deployment setting that lives outside this repo and is not relied on here.
// /falco/events is NOT keyed by IP: its single sender would make one shared
// bucket, so internal/scoreboard/ingest keys by participant (app#359).
//
// The state is bounded (app#463): a bucket whose tokens have refilled to the
// burst and that has been idle past the eviction TTL is dropped, and the map
// never holds more than the configured maximum number of buckets. Past that
// maximum the LEAST RECENTLY USED bucket is evicted to make room, never the new
// key refused: refusing a new key would let anyone who can mint keys (a forged
// ns on /falco/events, a forged X-Forwarded-For) lock honest participants out,
// and on the scoring path would drop a real forbidden-rule fire (app#359 "a
// scoring rule is never dropped"). The cost of evicting instead is bounded and
// fail-open for the evicted key only: it restarts with a full bucket, so a
// flood of more than the maximum distinct keys can reset other keys' buckets to
// their burst. That is the price of never denying a new key; it does not let
// anyone exceed the burst allowance of their own bucket by more than the reset.
package ratelimit

import (
	"container/list"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
)

// DefaultMaxBuckets is the bucket-count cap a Limiter starts with. Each bucket
// is on the order of 100 bytes, so the cap bounds the state at roughly a
// megabyte while being far above the key population of a real event (a few
// hundred participants).
const DefaultMaxBuckets = 10000

// Limiter implements per-key token-bucket rate limiting. Buckets evict
// themselves once unused for the eviction TTL (and refilled); keep that larger
// than the fill interval so legitimate clients aren't reset between calls.
type Limiter struct {
	rate       float64       // tokens per second
	burst      float64       // bucket capacity
	eviction   time.Duration // idle time after which a refilled bucket is dropped
	maxBuckets int           // hard cap on len(buckets)

	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*list.Element // key -> element of order, Value is *bucket
	order   *list.List               // front = most recently used, back = least
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// New returns a limiter that allows `burst` requests instantly, then
// refills at `rate` tokens per second.
func New(rate, burst float64) *Limiter {
	return &Limiter{
		rate:       rate,
		burst:      burst,
		eviction:   5 * time.Minute,
		maxBuckets: DefaultMaxBuckets,
		now:        time.Now,
		buckets:    make(map[string]*list.Element),
		order:      list.New(),
	}
}

// WithNow swaps the clock for tests.
func (l *Limiter) WithNow(now func() time.Time) *Limiter {
	l.now = now
	return l
}

// WithMaxBuckets sets the cap on the number of buckets (n < 1 is treated as 1:
// a limiter must be able to hold the bucket it is using).
func (l *Limiter) WithMaxBuckets(n int) *Limiter {
	if n < 1 {
		n = 1
	}
	l.maxBuckets = n
	return l
}

// WithEviction sets the idle TTL after which a refilled bucket is dropped.
func (l *Limiter) WithEviction(d time.Duration) *Limiter {
	l.eviction = d
	return l
}

// Len is the number of buckets currently held (for tests and diagnostics).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// refilled is the bucket's token count at `now`, capped at the burst. The
// stored count is only updated on a use, so "full" must be judged on this
// value, not on b.tokens (judging on the stale stored value is what kept a
// partly-drained, long-idle bucket in the map forever: app#463).
func (l *Limiter) refilled(b *bucket, now time.Time) float64 {
	return math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
}

// expired reports whether b can be dropped without changing any answer: it has
// been idle past the TTL and would be full again anyway, so a fresh bucket for
// the key behaves identically.
func (l *Limiter) expired(b *bucket, now time.Time) bool {
	return now.Sub(b.last) > l.eviction && l.refilled(b, now) >= l.burst
}

func (l *Limiter) remove(e *list.Element) {
	delete(l.buckets, e.Value.(*bucket).key)
	l.order.Remove(e)
}

// Allow consumes one token from `key`'s bucket and returns whether the
// request should be permitted.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Drop expired buckets from the cold end. The list is ordered by last use,
	// so this stops at the first bucket that is still live or not yet refilled:
	// O(1) amortized, no scan of the map. (A not-yet-refilled bucket at the back
	// can shield a newer expired one, but the cap below bounds the map anyway.)
	for e := l.order.Back(); e != nil; e = l.order.Back() {
		if !l.expired(e.Value.(*bucket), now) {
			break
		}
		l.remove(e)
	}

	var b *bucket
	if e, ok := l.buckets[key]; ok {
		b = e.Value.(*bucket)
		b.tokens = l.refilled(b, now)
		b.last = now
		l.order.MoveToFront(e)
	} else {
		// Make room by evicting the least recently used bucket; never refuse a
		// new key (see the package doc).
		for len(l.buckets) >= l.maxBuckets {
			l.remove(l.order.Back())
		}
		b = &bucket{key: key, tokens: l.burst, last: now}
		l.buckets[key] = l.order.PushFront(b)
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Middleware wraps `next` and rejects requests whose `keyFn(r)` exceeds
// the rate. Rejected requests get 429 Too Many Requests, JSON-encoded via
// httpx.WriteJSON (Issue #159 / ADR-0005 follow-up F1 — this used to be
// http.Error's text/plain, the only non-2xx deviation from the "{"error":
// string}" contract besides view.portal's 500; see that package for the
// other half).
//
// Keying an identity bucket through this function (an identity key that falls
// back to the client IP, or to "" = unlimited when the header is missing) is
// retired as of app#397: no route does it any more, and every identity-keyed
// bucket is MiddlewareStrict. What remains here is the per-IP keying
// (ClientIPKeyed, ClientIP, collector's remoteIP), where an empty key "cannot
// happen". ADR-0037 S1a will replace the choice of key kind by a declaration;
// until then, do not add an identity-keyed caller of Middleware. (This is not
// a "Deprecated:" marker because the per-IP callers are live.)
func (l *Limiter) Middleware(keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" || l.Allow(key) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Retry-After", "1")
			httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
		})
	}
}

// clientIP is the pure ADR-0023 extraction logic shared by ClientIP and
// ClientIPKeyed. It has NO side effects (no metric emission) — callers
// decide separately whether/how to record the source, so that computing the
// IP more than once for the same request (e.g. once in a rate-limit
// Middleware keyFn and again in a log line) never double-counts a metric
// (ADR-0023 review R5-F2). Priority order:
//
//  1. CF-Connecting-IP, when non-empty and a syntactically valid IP
//     (net.ParseIP). Cloudflare's edge sets this header itself, overwriting
//     any client-supplied value — unlike X-Forwarded-For, which Cloudflare
//     forwards append-only, leaving the attacker-controlled leftmost entry
//     intact. The validity check keeps a malformed/unexpected value (e.g. a
//     misconfigured upstream) from becoming an unbounded bucket key.
//  2. X-Forwarded-For's leftmost entry, when (1) is absent or invalid
//     (pre-ADR-0023 behavior, unchanged — ingress-nginx populates this).
//  3. RemoteAddr, when neither header is present.
//
// prod/vm-prod run behind Cloudflare, so CF-Connecting-IP is expected to be
// present on essentially every request there; local/dev and the
// non-Cloudflare-routed POST /falco/events path fall through to (2)/(3) by
// design (ADR-0023 D3/D5) and are not a signal of anything wrong on their
// own — see ClientIPKeyed's doc for why that distinction needs a caller
// label, not just a source label.
//
// ADR-0023 D1b: internal/collector strips CF-Connecting-IP (alongside
// X-Forwarded-For/X-Real-IP) from participant-controlled forwards before
// they can reach any caller of this function, so a workspace pod cannot use
// this new priority tier to forge a rate-limit key over the collector's
// ClusterIP-direct path. Any future addition of a new trusted header here
// MUST be mirrored by a strip in collector.go's Director (ADR-0023
// Signpost 5) — forgetting that pairing is exactly the regression D1b
// fixed.
func clientIP(r *http.Request) (ip, source string) {
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" && net.ParseIP(cf) != nil {
		return cf, "cf_connecting_ip"
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i]), "x_forwarded_for"
		}
		return strings.TrimSpace(xff), "x_forwarded_for"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr, "remote_addr"
	}
	return host, "remote_addr"
}

// ClientIP extracts the remote IP for rate-limit keying (ADR-0023) without
// recording it to ClientIPSourceTotal. Use this when the IP value is needed but a
// V5 counter increment already happened (or will happen) elsewhere for the
// same request — e.g. csp_report.go computes it once per request for its log
// line, separately from the ClientIPKeyed call the rate-limit Middleware
// already made (ADR-0023 review R5-F2: calling this in a loop over a batched
// report no longer risks inflating ClientIPSourceTotal, because this function
// never touches it).
//
// See clientIP's doc for the full CF-Connecting-IP / XFF / RemoteAddr
// priority order and the ADR-0023 D1b dependency on internal/collector.
func ClientIP(r *http.Request) string {
	ip, _ := clientIP(r)
	return ip
}

// ClientIPKeyed returns a rate-limit Middleware keyFn that behaves exactly
// like ClientIP but additionally records ADR-0023 V5 observability: each
// call increments ClientIPSourceTotal labelled by BOTH which header tier won
// (source) and which route family is asking (caller). The caller label
// exists because /falco/events (ADR-0023 D5) never goes through Cloudflare
// and therefore ALWAYS falls back past CF-Connecting-IP — without
// distinguishing it, its high, constant request volume drowns out the
// signal ADR-0023 Signpost 2 depends on ("a sustained non-cf_connecting_ip
// rate on a Cloudflare-fronted route means the contract drifted"): an
// operator graphing the unlabelled counter could never tell a real
// CF-Connecting-IP outage on prod/vm-prod's submit/display-name/questions
// traffic apart from ordinary /falco/events noise (ADR-0023 review R5-F1).
// With the caller label, that query becomes "any caller other than
// falco_events" — trivial to express and graph.
//
// Each of this function's callers passes a caller name that identifies the
// limiter/route family it wires into a rate-limit Middleware, so the
// increment happens exactly once per incoming HTTP request (inside the
// Middleware's keyFn), never once per downstream log line or loop
// iteration.
func ClientIPKeyed(caller string) func(*http.Request) string {
	return func(r *http.Request) string {
		ip, source := clientIP(r)
		ClientIPSourceTotal.WithLabelValues(caller, source).Inc()
		return ip
	}
}

// KeyFunc extracts a rate-limit key from a request, reporting ok=false when
// the request carries no usable key. MiddlewareStrict treats !ok (and an empty
// key) as a DENY, never as "unlimited" — the opposite of Middleware's
// `key == ""` pass-through, which exists for legacy IP keying where an empty
// IP "cannot happen". Use this shape for every NEW identity-keyed bucket
// (app#315, ADR-0027 Consequences, ADR-0032 D3): the key function is the only
// thing a route family chooses, the fail-closed behaviour is not optional.
type KeyFunc func(*http.Request) (key string, ok bool)

// IdentityHeader is the proven-identity header oauth2-proxy / auth-policy
// inject on the participant (journey) host. The ingress overwrites any
// client-supplied value; cluster-internal Service paths do not carry it at all.
const IdentityHeader = "X-Auth-Request-Email"

// IdentityKeyed is the KeyFunc for identity-keyed buckets: the lower-cased,
// trimmed X-Auth-Request-Email. A missing or blank header is ok=false. It does
// NOT fall back to the client IP — that fallback is exactly what let one NAT'd
// venue share a single bucket (app#315).
func IdentityKeyed(r *http.Request) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(r.Header.Get(IdentityHeader)))
	return email, email != ""
}

// identityOutcomes are the IdentityRequestsTotal outcome label values that
// MiddlewareStrict emits; each is pre-created per bucket when it wraps a handler.
// "no_identity" is not one of them: a header-less 403 is counted by the caller's
// NoIdentityObserver (scoreboard_identity_denials_total{gate="strict"}), so the
// same refusal is not counted by two metrics (app#404, ADR-0038 D1).
var identityOutcomes = []string{"allowed", "limited"}

// NoIdentityObserver is told about every request MiddlewareStrict refuses for
// lack of an identity, right before it writes the 403. It is the only way the
// refusal is observed (count, log): this package neither counts nor logs it, and
// does not import the package that does (internal/scoreboard/identityobs). The
// collector links and COPYs this package by name but not that one (app#404,
// ADR-0038 C6 (a), D3), so an import in that direction would build on the host
// and in CI and break only the collector image.
type NoIdentityObserver func(r *http.Request)

// MiddlewareStrict is Middleware's fail-closed sibling for identity-keyed
// buckets. `bucket` names the bucket for the IdentityRequestsTotal metric (use
// a small fixed set of constants — it is a label). onNoIdentity is REQUIRED: a
// nil observer panics when the middleware is assembled (not on the first
// request), so a wiring that forgets it can never ship a gate that refuses
// silently. Outcomes:
//
//   - keyFn !ok or key == "" -> onNoIdentity(r), then 403 {"error":"forbidden"};
//     NO token is consumed (so an anonymous flood cannot drain anyone's bucket)
//     and the handler never runs. Not counted in IdentityRequestsTotal.
//   - bucket empty           -> 429 {"error":"rate limit exceeded"}, Retry-After: 1
//   - otherwise              -> next
//
// Place it AFTER the origin guard and BEFORE the handler's own authz gate.
func (l *Limiter) MiddlewareStrict(bucket string, keyFn KeyFunc, onNoIdentity NoIdentityObserver) func(http.Handler) http.Handler {
	if onNoIdentity == nil {
		panic("ratelimit: MiddlewareStrict needs a NoIdentityObserver (bucket " + bucket + ")")
	}
	return func(next http.Handler) http.Handler {
		// Create every outcome series at 0 now (no Inc), so the first real
		// "limited" is an increase from an existing 0 and Prometheus' increase()
		// counts it (a series born at 1 contributes no increase). app#387.
		for _, o := range identityOutcomes {
			IdentityRequestsTotal.WithLabelValues(bucket, o)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, ok := keyFn(r)
			if !ok || key == "" {
				onNoIdentity(r)
				httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
				return
			}
			if !l.Allow(key) {
				IdentityRequestsTotal.WithLabelValues(bucket, "limited").Inc()
				w.Header().Set("Retry-After", "1")
				httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
				return
			}
			IdentityRequestsTotal.WithLabelValues(bucket, "allowed").Inc()
			next.ServeHTTP(w, r)
		})
	}
}
