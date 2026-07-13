// Package scoreboard wires the ingest / api / view sub-handlers + /healthz
// + /metrics into a single http.Handler.
//
// Routes:
//
//	GET  /healthz                                                 liveness/readiness
//	GET  /metrics                                                 Prometheus exposition
//	POST /falco/events                                            (ingest)
//	POST /api/challenges/{cid}/submit                             (api)
//	POST /internal/exfil/{cid}                                    (api: collector-only exfil sink)
//	GET  /api/state                                               (api)
//	GET  /api/users/{user}/me                                     (api)
//	GET  /api/users/{user}/journey                                (api: Journey projection)
//	POST /api/users/{user}/challenges/{cid}/steps/{idx}/check     (api: Journey step self-check)
//	POST /api/users/{user}/challenges/{cid}/hints/{idx}           (api: Journey progressive hint reveal)
//	GET  /                                                        (view: embedded HTML dashboard)
//	GET  /journey                                                 (view: guided Journey UI)
package scoreboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ingest"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/view"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

type Handler struct {
	cat         catalog.Catalog
	store       *store.Store
	logger      *slog.Logger
	mux         *http.ServeMux
	dbPath      string
	now         func() time.Time
	adminEmails []string
	journeys    catalog.Journeys
	order       []string
	docsBaseURL string
	sweeper     *scoring.Sweeper
}

type Option func(*Handler)

func WithNow(f func() time.Time) Option { return func(h *Handler) { h.now = f } }
func WithDBPath(p string) Option        { return func(h *Handler) { h.dbPath = p } }

// WithAdminEmails sets the allowlist for admin-only endpoints (POST
// /api/admin/reset). Empty = nobody (fail-closed).
func WithAdminEmails(e []string) Option { return func(h *Handler) { h.adminEmails = e } }

// WithJourneys supplies the /journey UI narrative content (challengeId ->
// Journey). Optional; a missing entry means "no briefing authored yet" and the
// UI degrades gracefully.
func WithJourneys(j catalog.Journeys) Option {
	return func(h *Handler) { h.journeys = j }
}

// WithOrder sets the mission progression order (scenario order when pinned,
// else catalog sorted ids). Drives sequential unlock in the Journey UI.
func WithOrder(order []string) Option { return func(h *Handler) { h.order = order } }

// WithDocsBaseURL sets the participant docs-site origin used to absolutise each
// mission's relative docsUrl (see api.JourneyConfig.DocsBaseURL). Empty = keep
// the relative path.
func WithDocsBaseURL(u string) Option { return func(h *Handler) { h.docsBaseURL = u } }

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

	// Single Grader shared by the ingest handler, the api handler, AND the
	// auto-solve sweeper. One instance = one clock and one MarkSolved caller,
	// preserving the single-writer discipline (conventions I1) across all three
	// entry points (this also resolves the prior double-instantiation, R4).
	grader := scoring.New(cat, s, h.now)
	// The sweeper bumps the same evade solve metric a manual submit would, so an
	// auto-solve is indistinguishable from a manual one on the dashboard.
	h.sweeper = scoring.NewSweeper(grader, scoring.DefaultSweepCadence, logger, func(r scoring.SweepResult) {
		metrics.SolvesTotal.WithLabelValues(r.Challenge, "evade").Inc()
	})

	ingest.New(grader, s, logger, h.now).Register(h.mux)
	api.New(cat, grader, s, logger, h.now, h.adminEmails, api.JourneyConfig{
		Journeys:    h.journeys,
		Order:       h.order,
		DocsBaseURL: h.docsBaseURL,
	}).Register(h.mux)
	view.New().Register(h.mux)

	return h
}

// Sweeper returns the auto-solve sweeper wired to this handler's shared Grader.
// The command layer runs it (Sweeper.Run) in its own goroutine bound to the
// server's lifecycle context, so it stops on shutdown. Always non-nil after
// NewHandler.
func (h *Handler) Sweeper() *scoring.Sweeper { return h.sweeper }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Reject an empty {user} path segment under /api/users/ explicitly, before
	// ServeMux gets to it. ServeMux would otherwise issue an unclean-path
	// redirect ("/api/users//me" -> "/api/users/me"), whose status is both
	// ambiguous and Go-version-dependent (301 on go1.25, 307 on go1.26). We
	// prefer an explicit 400 over relying on that implicit redirect — the user
	// segment carries identity, so a blank one is a bad request, not something
	// to silently rewrite. Scoped to the /api/users/ display+display-name paths;
	// does not touch ingest scoring or auth-policy.
	if strings.HasPrefix(r.URL.Path, "/api/users//") {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "user required"})
		return
	}

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
