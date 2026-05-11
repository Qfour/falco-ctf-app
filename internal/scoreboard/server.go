// Package scoreboard wires the ingest / api / view sub-handlers + /healthz
// + /metrics into a single http.Handler.
//
// Routes:
//
//	GET  /healthz                          liveness/readiness
//	GET  /metrics                          Prometheus exposition
//	POST /falco/events                     (ingest)
//	POST /api/challenges/{cid}/submit      (api)
//	GET  /api/state                        (api)
//	GET  /                                 (view: embedded HTML dashboard)
package scoreboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ingest"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/view"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

type Handler struct {
	cat    catalog.Catalog
	store  *store.Store
	logger *slog.Logger
	mux    *http.ServeMux
	dbPath string
	now    func() time.Time
}

type Option func(*Handler)

func WithNow(f func() time.Time) Option { return func(h *Handler) { h.now = f } }
func WithDBPath(p string) Option        { return func(h *Handler) { h.dbPath = p } }

func NewHandler(cat catalog.Catalog, s *store.Store, logger *slog.Logger, opts ...Option) *Handler {
	h := &Handler{
		cat:    cat,
		store:  s,
		logger: logger,
		mux:    http.NewServeMux(),
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(h)
	}

	h.mux.HandleFunc("GET /healthz", h.healthz)
	h.mux.Handle("GET /metrics", promhttp.Handler())

	ingest.New(cat, s, logger, h.now).Register(h.mux)
	api.New(cat, s, logger, h.now).Register(h.mux)
	view.New().Register(h.mux)

	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, route := h.mux.Handler(r)
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()
	h.mux.ServeHTTP(sw, r)
	metrics.HTTPRequestDuration.
		WithLabelValues(route, r.Method, strconv.Itoa(sw.status)).
		Observe(time.Since(start).Seconds())
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":            true,
		"challenges":    h.cat.IDs(),
		"db":            h.dbPath,
		"solved_loaded": h.store.SolvedCount(),
	})
}
