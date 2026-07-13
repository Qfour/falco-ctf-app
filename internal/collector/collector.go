// Package collector is the participant-facing front for the CTF workspace
// (P11.5 full one-pipe). Once ctf-user egress lockdown is on, a workspace pod
// can reach *only* the collector — never the scoreboard directly. The collector
// therefore fronts every participant route (submit / me / display-name) and,
// for the boss capstone, receives the exfil drop and forwards it to the
// scoreboard's internal-only sink.
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
//
// Routes fronted (method + path → upstream):
//
//	POST /api/challenges/{cid}/exfil       → scoreboard POST /internal/exfil/{cid}
//	POST /api/challenges/{cid}/submit      → scoreboard (transparent)
//	GET  /api/users/{user}/me              → scoreboard (transparent)
//	POST /api/users/{user}/display-name    → scoreboard (transparent)
//	GET  /healthz                          collector liveness (local)
//	GET  /metrics                          collector Prometheus exposition
package collector

import (
	"log/slog"
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
	// Fail closed on upstream errors: a proxy dial failure must not leak a
	// Go default 502 body or the upstream address into the participant shell.
	h.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		h.logger.Error("upstream forward failed", "path", r.URL.Path, "err", err)
		httpx.WriteJSON(w, http.StatusBadGateway, map[string]any{"error": "scoreboard unavailable"})
	}

	rl := h.limiter.Middleware(ratelimit.ClientIP)

	// Transparent participant routes — forwarded verbatim to the scoreboard.
	h.mux.Handle("POST /api/challenges/{cid}/submit", rl(h.proxy))
	h.mux.Handle("GET /api/users/{user}/me", rl(h.proxy))
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
// above (e.g. /falco/events, /internal/*, /api/admin/*, /api/state) 404s at the
// mux — default-deny, so the collector can never be used to reach the ingest,
// admin, or internal surface of the scoreboard.
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

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
