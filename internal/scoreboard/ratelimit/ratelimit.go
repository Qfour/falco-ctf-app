// Package ratelimit provides a small in-memory token-bucket limiter keyed
// by an arbitrary string (typically the requester's IP). Defense-in-depth
// against /submit brute-forcing and /falco/events flooding — the primary
// controls are the NetworkPolicy (limiting /falco/events to the falco ns)
// and per-IP ingress-nginx rate limits, but a per-pod fallback here keeps
// the scoreboard responsive even if those upstream controls drift.
package ratelimit

import (
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
)

// Limiter implements per-key token-bucket rate limiting. Buckets evict
// themselves once unused for the eviction TTL; keep this larger than the
// fill interval so legitimate clients aren't reset between calls.
type Limiter struct {
	rate     float64       // tokens per second
	burst    float64       // bucket capacity
	eviction time.Duration // bucket TTL once `tokens == burst`

	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter that allows `burst` requests instantly, then
// refills at `rate` tokens per second.
func New(rate, burst float64) *Limiter {
	return &Limiter{
		rate:     rate,
		burst:    burst,
		eviction: 5 * time.Minute,
		now:      time.Now,
		buckets:  make(map[string]*bucket),
	}
}

// WithNow swaps the clock for tests.
func (l *Limiter) WithNow(now func() time.Time) *Limiter {
	l.now = now
	return l
}

// Allow consumes one token from `key`'s bucket and returns whether the
// request should be permitted.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		delta := now.Sub(b.last).Seconds()
		b.tokens = math.Min(l.burst, b.tokens+delta*l.rate)
		b.last = now
	}

	// Evict full buckets older than the TTL so the map doesn't grow unbounded
	// on bursty traffic from many distinct keys.
	if len(l.buckets) > 1024 {
		for k, v := range l.buckets {
			if v.tokens >= l.burst && now.Sub(v.last) > l.eviction {
				delete(l.buckets, k)
			}
		}
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
