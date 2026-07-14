// Package collector is the participant-facing front for the CTF workspace
// (P11.5 full one-pipe). Once ctf-user egress lockdown is on, a workspace pod
// can reach *only* the collector — never the scoreboard directly. The collector
// therefore fronts the participant WRITE routes (submit / display-name) and,
// for the boss capstone, receives the exfil drop and forwards it to the
// scoreboard's internal-only sink. Progress READ (GET /me) is NOT fronted here:
// participant progress is viewed on the browser journey host (authenticated,
// self-scoped), so exposing an anonymous, self-claimed /me read through the
// collector would be a self-scope bypass (P18).
//
// Design constraints (see REFACTORING.md P11.5):
//   - No catalog, no flags, no persistence. The collector holds no CTF state;
//     it is a thin, allowlisted forwarder. Solve/exfil truth lives in the
//     scoreboard (HasExfil at submit time is the only scoring gate).
//   - net/http only (repo convention — no chi/echo).
//   - Per-IP rate limit identical to /submit (1 req/s, burst 10). A workspace
//     that scraped another flag must not be able to flood submit/exfil.
//   - Default-deny routing: only the explicitly-listed participant routes are
//     forwarded. /internal/*, /api/admin/*, /metrics, /falco/events are never
//     reachable through the collector.
//   - XFF-spoof resistance. Unlike the scoreboard (which sits behind
//     ingress-nginx and can trust an injected X-Forwarded-For), the collector
//     is hit directly by workspace pods over the ClusterIP. A workspace could
//     therefore send an arbitrary X-Forwarded-For to dodge a per-IP limit. So
//     the collector keys its own limiter on r.RemoteAddr (the real workspace
//     pod IP) and STRIPS inbound X-Forwarded-For / X-Real-IP before forwarding,
//     so the downstream scoreboard limiter also sees only the real connection.
//
// Routes fronted (method + path → upstream):
//
//	POST /api/challenges/{cid}/exfil       → scoreboard POST /internal/exfil/{cid}
//	POST /api/challenges/{cid}/submit      → scoreboard (transparent)
//	POST /api/users/{user}/display-name    → scoreboard (transparent)
//	GET  /healthz                          collector liveness (local)
//	GET  /metrics                          collector Prometheus exposition
//
// Progress read (GET /api/users/{user}/me) is intentionally NOT fronted — see
// the package comment above. It is served only on the browser journey host,
// which reaches the scoreboard directly (self-scope gated by X-Auth-Request-Email).
package collector

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

// Handler fronts the participant HTTP surface and forwards to the scoreboard.
type Handler struct {
	logger  *slog.Logger
	mux     *http.ServeMux
	proxy   *httputil.ReverseProxy
	limiter *ratelimit.Limiter
	now     func() time.Time
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
		mux:    http.NewServeMux(),
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(h)
	}
	// Same per-IP budget as /submit — the collector is now the only place a
	// workspace can flood submit/exfil, so the limit must live here.
	h.limiter = ratelimit.New(1 /* req/s */, 10 /* burst */).WithNow(h.now)

	h.proxy = httputil.NewSingleHostReverseProxy(u)
	// Strip participant-controlled forwarding headers before forwarding. The
	// workspace connects directly (no trusted ingress-nginx in front), so any
	// inbound X-Forwarded-For / X-Real-IP is attacker-chosen and must not reach
	// the scoreboard, whose limiter trusts XFF's leftmost entry. We delete them
	// after NewSingleHostReverseProxy's Director runs; ReverseProxy then appends
	// its own X-Forwarded-For = the real RemoteAddr, so downstream sees the
	// genuine connection IP. (X-Real-IP is not re-added by ReverseProxy.)
	baseDirector := h.proxy.Director
	h.proxy.Director = func(req *http.Request) {
		baseDirector(req)
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Real-IP")
	}
	// Fail closed on upstream errors: a proxy dial failure must not leak a
	// Go default 502 body or the upstream address into the participant shell.
	h.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		h.logger.Error("upstream forward failed", "path", r.URL.Path, "err", err)
		httpx.WriteJSON(w, http.StatusBadGateway, map[string]any{"error": "scoreboard unavailable"})
	}

	// Key the limiter on the real connection IP (r.RemoteAddr), never on the
	// participant-supplied X-Forwarded-For — otherwise a workspace could rotate
	// XFF values to bypass the per-IP budget. Deliberately NOT ratelimit.ClientIP
	// (which trusts XFF; correct only behind ingress-nginx, i.e. the scoreboard).
	rl := h.limiter.Middleware(remoteIP)

	// Transparent participant WRITE routes — forwarded verbatim to the scoreboard.
	// NOTE: the progress READ route (GET /api/users/{user}/me) is deliberately
	// NOT registered. An anonymous, client-chosen {user} read through the
	// collector is a self-scope bypass; progress is viewed only on the browser
	// journey host (authenticated + self-scope gated). With this route absent the
	// mux default-denies it → 404 (see ServeHTTP below), which is the intent.
	h.mux.Handle("POST /api/challenges/{cid}/submit", rl(h.proxy))
	h.mux.Handle("POST /api/users/{user}/display-name", rl(h.proxy))

	// Exfil drop → rewrite to the scoreboard's internal-only sink. The public
	// /api/challenges/{cid}/exfil path stays the participant-facing contract
	// (curl target in the Mission 10 brief); only the upstream path changes.
	h.mux.Handle("POST /api/challenges/{cid}/exfil", rl(http.HandlerFunc(h.exfil)))

	// Collector's own liveness + metrics. NOT forwarded — these are local.
	h.mux.HandleFunc("GET /healthz", h.healthz)
	h.mux.Handle("GET /metrics", promhttp.Handler())

	return h, nil
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
	h.mux.ServeHTTP(sw, r)
	forwardDuration.
		WithLabelValues(route, r.Method, strconv.Itoa(sw.status)).
		Observe(h.now().Sub(start).Seconds())
}

// exfil rewrites the participant drop POST /api/challenges/{cid}/exfil to the
// scoreboard's POST /internal/exfil/{cid} and forwards the body unchanged. The
// collector does not parse or validate the payload — the scoreboard owns the
// receipt and HasExfil is the only scoring gate. {cid} is validated as a slug
// so a crafted path can't be reflected into the upstream URL.
func (h *Handler) exfil(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	if !validCID.MatchString(cid) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid challenge id"})
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
