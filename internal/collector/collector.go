// Package collector is the participant-facing front for the CTF workspace
// (P11.5 full one-pipe). Once ctf-user egress lockdown is on, a workspace pod
// can reach *only* the collector — never the scoreboard directly. The collector
// therefore fronts the participant WRITE route (submit) and,
// for the boss capstone, receives the exfil drop and forwards it to the
// scoreboard's internal-only sink. Progress READ (GET /me) is NOT fronted here:
// participant progress is viewed on the browser journey host (authenticated,
// self-scoped), so exposing an anonymous, self-claimed /me read through the
// collector would be a self-scope bypass (P18).
//
// Design constraints (see REFACTORING.md P11.5):
//   - No catalog, no flags, no persistence. The collector holds no CTF state
//     (catalog / flags / DB); it is an allowlisted forwarder that checks one
//     thing itself, the challenge-id grammar (ADR-0041). Solve/exfil truth
//     lives in the scoreboard (HasExfil at submit time is the only scoring gate).
//     The one thing it knows about challenge ids is their grammar
//     (internal/catalog/challengeid, standard library only): that is syntax, not
//     a catalog, and it keeps yaml.v3 and the catalog parser out of this image.
//   - net/http only (repo convention — no chi/echo).
//   - Per-IP rate limit identical to /submit (1 req/s, burst 10). A workspace
//     that scraped another flag must not be able to flood submit/exfil.
//   - The default-deny surface (a request no route matches: 404 / 405) has its
//     own per-IP bucket of the same size, keyed on RemoteAddr, and the request
//     duration metric's method label is a closed set (app#485). That budget
//     covers ONLY such requests: /healthz, /metrics and the normalising
//     redirect are outside it, so it is not a cap on the collector's total
//     request volume.
//   - Default-deny routing: only the explicitly-listed participant routes are
//     forwarded. /internal/*, /api/admin/*, /metrics, /falco/events are never
//     reachable through the collector.
//   - Identity-header strip (ADR-0034 D6). A workspace is not behind
//     ingress-nginx, so every request header named X-Auth-Request-* is forged;
//     the collector deletes ALL of them before forwarding, whatever the route.
//     A request the scoreboard receives over this path therefore never carries
//     a proven identity (the claimed-identity routes' premise).
//   - XFF-spoof resistance. Unlike the scoreboard (which sits behind
//     ingress-nginx/Cloudflare and can trust an injected X-Forwarded-For or
//     CF-Connecting-IP, ADR-0023), the collector is hit directly by workspace
//     pods over the ClusterIP. A workspace could therefore send an arbitrary
//     X-Forwarded-For / CF-Connecting-IP to dodge a per-IP limit. So the
//     collector keys its own limiter on r.RemoteAddr (the real workspace
//     pod IP) and STRIPS inbound X-Forwarded-For / X-Real-IP / CF-Connecting-IP
//     before forwarding, so the downstream scoreboard limiter also sees only
//     the real connection.
//
// Routes fronted (method + path → upstream):
//
//	POST /api/challenges/{cid}/exfil       → scoreboard POST /internal/exfil/{cid}
//	POST /api/challenges/{cid}/submit      → scoreboard (verbatim once {cid} is inside the grammar)
//	GET  /healthz                          collector liveness (local)
//	GET  /metrics                          collector Prometheus exposition
//
// Progress read (GET /api/users/{user}/me) is intentionally NOT fronted — see
// the package comment above. It is served only on the browser journey host,
// which reaches the scoreboard directly (self-scope gated by X-Auth-Request-Email).
package collector

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

// The per-IP budget of the submit/exfil routes and of the default-deny surface:
// one pair, so the two limiters and docs/openapi-collector.yaml (`x-ctf-rate-limit`,
// compared by the ADR-0005 parity test and by TestRateLimitConstantsMatchSpec)
// cannot drift apart.
const (
	budgetRate  = 1  // sustained requests per second
	budgetBurst = 10 // bucket size
)

// rateLimitDesc is the `x-ctf-rate-limit` text of the two rate-limited routes.
var rateLimitDesc = fmt.Sprintf("per-IP (RemoteAddr) %d req/s burst %d", budgetRate, budgetBurst)

// Handler fronts the participant HTTP surface and forwards to the scoreboard.
type Handler struct {
	logger  *slog.Logger
	mux     *http.ServeMux
	proxy   *httputil.ReverseProxy
	limiter *ratelimit.Limiter
	// denyLimiter is the per-IP budget of the default-deny surface (a request no
	// declared route matched: 404 / 405). A separate Limiter, so that probing
	// the wrong URL cannot spend the submit/exfil budget of the same pod (and
	// the reverse); the same rate and key (remoteIP).
	denyLimiter *ratelimit.Limiter
	now         func() time.Time
	// routes is the declarative route table (ADR-0005 V2) this Handler
	// registers onto mux. Stored so Routes() can hand it back to the
	// ADR-0005 parity tests unchanged from what New() actually installed.
	routes []apispec.Route
}

// Option customizes a Handler.
type Option func(*Handler)

// WithNow swaps the clock (tests + rate-limit determinism).
func WithNow(f func() time.Time) Option { return func(h *Handler) { h.now = f } }

// New builds a collector Handler forwarding to upstream (the scoreboard base
// URL, e.g. http://scoreboard.scoreboard.svc:80). It returns an error if
// upstream is not a valid absolute URL.
func New(upstream string, logger *slog.Logger, opts ...Option) (*Handler, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	h := &Handler{
		logger: logger,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(h)
	}
	// Same per-IP budget as /submit — the collector is now the only place a
	// workspace can flood submit/exfil, so the limit must live here.
	h.limiter = ratelimit.New(budgetRate, budgetBurst).WithNow(h.now)
	h.denyLimiter = ratelimit.New(budgetRate, budgetBurst).WithNow(h.now)

	h.proxy = httputil.NewSingleHostReverseProxy(u)
	// Explicit upstream transport: the default one's 90s idle-connection time
	// would be longer than some server idle deadlines. Idle upstream connections
	// are closed after 30s, shorter than the scoreboard's IdleTimeout
	// (serverutil), so the collector side closes first.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.IdleConnTimeout = 30 * time.Second
	h.proxy.Transport = tr
	// Strip participant-controlled forwarding headers before forwarding. The
	// workspace connects directly (no trusted ingress-nginx in front), so any
	// inbound X-Forwarded-For / X-Real-IP / CF-Connecting-IP is
	// attacker-chosen and must not reach the scoreboard, whose limiter
	// (ratelimit.ClientIP) trusts CF-Connecting-IP first, then XFF's leftmost
	// entry (ADR-0023). We delete them after NewSingleHostReverseProxy's
	// Director runs; ReverseProxy then appends its own X-Forwarded-For = the
	// real RemoteAddr, so downstream sees the genuine connection IP.
	// (X-Real-IP and CF-Connecting-IP are not re-added by ReverseProxy.)
	//
	// CF-Connecting-IP (ADR-0023 D1b): this collector is never reached
	// through Cloudflare (it fronts the ClusterIP-direct workspace path), so
	// any CF-Connecting-IP a workspace sends is always forged. Without this
	// strip, ratelimit.ClientIP's new CF-Connecting-IP-first priority would
	// let a workspace mint an arbitrary rate-limit key per request and
	// bypass the scoreboard's per-route submit budget
	// entirely (security-engineer HIGH finding, ADR-0023). Any future
	// addition of a new trusted header to ratelimit.ClientIP MUST be
	// mirrored here (ADR-0023 Signpost 5).
	baseDirector := h.proxy.Director
	h.proxy.Director = func(req *http.Request) {
		baseDirector(req)
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Real-IP")
		req.Header.Del("CF-Connecting-IP")
		stripAuthRequestHeaders(req.Header)
	}
	// Fail closed on upstream errors: a proxy dial failure must not leak a
	// Go default 502 body or the upstream address into the participant shell.
	h.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// r.Pattern, not r.URL.Path: the path carries the participant-chosen
		// {cid} (and, on exfil, was rewritten), the pattern is a constant.
		h.logger.Error("upstream forward failed", "pattern", r.Pattern, "err", err)
		httpx.WriteJSON(w, http.StatusBadGateway, map[string]any{"error": "scoreboard unavailable"})
	}

	// Key the limiter on the real connection IP (r.RemoteAddr), never on the
	// participant-supplied X-Forwarded-For — otherwise a workspace could rotate
	// XFF values to bypass the per-IP budget. Deliberately NOT ratelimit.ClientIP
	// (which trusts XFF; correct only behind ingress-nginx, i.e. the scoreboard).
	rl := h.limiter.Middleware(remoteIP)

	// Participant WRITE routes — forwarded to the scoreboard once {cid} is
	// inside the challenge-id grammar (outside it the collector itself answers
	// 404 and stops, ADR-0041; it still holds no CTF state) — plus the
	// exfil-drop rewrite and this binary's own local
	// liveness/metrics, as a declarative table (ADR-0005 V2). NOTE: the
	// progress READ route (GET /api/users/{user}/me) is deliberately NOT in
	// this table. An anonymous, client-chosen {user} read through the
	// collector is a self-scope bypass; progress is viewed only on the browser
	// journey host (authenticated + self-scope gated). With this route absent
	// the mux default-denies it → 404 (see ServeHTTP below), which is the
	// intent — and it is also why docs/openapi-collector.yaml does not
	// document this route at all (no exclusion list; see that spec's info
	// description).
	// declared is the DESIRED table; h.mux/h.routes below become apispec.
	// NewMux's RETURN values, not a pre-built mux + this slice itself
	// (MEDIUM 1, 5x review — see route.go's NewMux doc): that is what makes
	// Routes() report exactly what the mux serves, never a route a future
	// edit left Handler: nil on. NewMux (task #146) also owns mux
	// construction, so there is no separately-constructed mux variable this
	// declared table could be pointed at instead of the real one.
	declared := []apispec.Route{
		{
			Method: "POST", Pattern: "/api/challenges/{cid}/submit",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzClaimedIdentity,
			OriginGuarded: false, CollectorForward: true,
			RateLimit: rateLimitDesc,
			Handler:   rl(http.HandlerFunc(h.submit)),
		},
		{
			// Exfil drop → rewrite to the scoreboard's internal-only sink (see
			// h.exfil). The public /api/challenges/{cid}/exfil path stays the
			// participant-facing contract (curl target in the Mission 10
			// brief); only the upstream path changes.
			Method: "POST", Pattern: "/api/challenges/{cid}/exfil",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzClaimedIdentity,
			OriginGuarded: false, CollectorForward: true,
			RateLimit: rateLimitDesc,
			Handler:   rl(http.HandlerFunc(h.exfil)),
		},
		{
			// Collector's own liveness. NOT forwarded — this is local.
			Method: "GET", Pattern: "/healthz",
			Audience: apispec.AudienceInfra, Authz: apispec.AuthzNone,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.healthz),
		},
		{
			// Collector's own Prometheus exposition. NOT forwarded — this is local.
			Method: "GET", Pattern: "/metrics",
			Audience: apispec.AudienceInfra, Authz: apispec.AuthzNone,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: promhttp.Handler(),
		},
	}
	h.mux, h.routes = apispec.NewMux(declared)

	return h, nil
}

// authRequestPrefix is the prefix of every identity header auth-policy /
// oauth2-proxy stamp on a request that came through ingress-nginx
// (X-Auth-Request-Email, -User, -Preferred-Username, -Groups, …).
const authRequestPrefix = "x-auth-request-"

// stripAuthRequestHeaders deletes EVERY header whose name starts with
// "X-Auth-Request-" (case-insensitively), unconditionally (ADR-0034 D6, the same
// class of duty as ADR-0023 D1b). A workspace connects to the collector
// directly, so any such header is forged. Forwarded to the scoreboard it would
// either (a) turn a header-less claimed-identity write into a proven-identity
// one — letting a workspace impersonate an admin or any seat — or (b) make the
// scoreboard's 200/403 answer depend on a forged identity (the ADMIN_EMAILS
// oracle the display-name hotfix closed). The match is by PREFIX over every
// header, not a list of known names: a new X-Auth-Request-* header added to
// auth-response-headers later is covered without anyone remembering to add it
// here. Keys are compared lower-cased because a hand-built request (tests,
// future callers) may carry a non-canonical key that Header.Del would miss.
func stripAuthRequestHeaders(h http.Header) {
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), authRequestPrefix) {
			delete(h, k)
		}
	}
}

// Routes returns the route set this Handler ACTUALLY registered onto its mux
// (ADR-0005 V2) — exactly apispec.NewMux's second return value from New(), for
// the parity tests (collector_test.go) to compare against
// docs/openapi-collector.yaml. Returns a copy (MEDIUM 5, 5x review): callers
// must not be able to mutate this Handler's live route table by mutating an
// element of the returned slice in place.
func (h *Handler) Routes() []apispec.Route {
	return append([]apispec.Route(nil), h.routes...)
}

// ServeHTTP records request duration then dispatches. Any path not registered
// above (e.g. /falco/events, /internal/*, /api/admin/*, /api/state, and the
// deliberately-unfronted GET /api/users/{user}/me) 404s at the mux —
// default-deny, so the collector can never be used to reach the ingest, admin,
// internal, or progress-read surface of the scoreboard.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, route := h.mux.Handler(r)
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	start := h.now()
	var next http.Handler = h.mux
	if route == "" {
		// No declared route matched: the default-deny surface answers 404 / 405
		// and sits outside every route's limiter, so it gets the per-IP budget
		// here (app#485). The 429 is recorded like any answer: route "", method
		// "other", status 429.
		next = h.denyLimiter.Middleware(remoteIP)(h.mux)
	}
	next.ServeHTTP(sw, r)
	forwardDuration.
		WithLabelValues(route, httpx.MethodLabel(route, r.Method), strconv.Itoa(sw.status)).
		Observe(h.now().Sub(start).Seconds())
}

// unknownChallengeBody is the one body the collector answers an id outside the
// grammar with. It is byte-for-byte the scoreboard's answer for an id it does
// not know (docs/openapi-scoreboard.yaml, the `404` of every {cid} route): one
// rule for the participant, "an id that is not a challenge is 404". The input
// is never echoed.
const unknownChallengeBody = "unknown challenge"

// rejectUnknownCID answers 404 and reports true when cid is outside the
// challenge-id grammar; the caller must then not forward (ADR-0041).
func rejectUnknownCID(w http.ResponseWriter, cid string) bool {
	if challengeid.Valid(cid) {
		return false
	}
	httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": unknownChallengeBody})
	return true
}

// submit forwards POST /api/challenges/{cid}/submit verbatim once {cid} is
// inside the challenge-id grammar. An id outside it is answered here (404) and
// never reaches the scoreboard. An id inside it is forwarded even when the
// scoreboard has no such challenge: the collector holds no catalog, so the
// scoreboard's 404 is what answers it (platform verify (a-2) relies on this
// with the verify probe id of ADR-0041).
func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	if rejectUnknownCID(w, r.PathValue("cid")) {
		return
	}
	h.proxy.ServeHTTP(w, r)
}

// exfil rewrites the participant drop POST /api/challenges/{cid}/exfil to the
// scoreboard's POST /internal/exfil/{cid} and forwards the body unchanged. The
// collector does not parse or validate the payload — the scoreboard owns the
// receipt and HasExfil is the only scoring gate. {cid} is checked against the
// challenge-id grammar so a crafted path can't be reflected into the upstream
// URL; outside it the answer is the same 404 as submit's (ADR-0041).
func (h *Handler) exfil(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	// Guards the value reflected into the upstream /internal/exfil/{cid} path.
	if rejectUnknownCID(w, cid) {
		return
	}
	r.URL.Path = "/internal/exfil/" + cid
	r.URL.RawPath = ""
	h.logger.Info("exfil_forward", "cid", cid, "remote_addr", r.RemoteAddr)
	h.proxy.ServeHTTP(w, r)
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// remoteIP is the collector's rate-limit key: the real connection IP from
// r.RemoteAddr with the port stripped. It intentionally ignores any inbound
// X-Forwarded-For / X-Real-IP — the collector is reached directly by workspace
// pods, so those headers are participant-controlled and would let a caller
// forge a fresh key per request to escape the per-IP budget. Falls back to the
// raw RemoteAddr if it has no host:port shape.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
