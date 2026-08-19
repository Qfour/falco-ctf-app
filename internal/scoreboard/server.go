// Package scoreboard wires the ingest / api / view sub-handlers + /healthz
// + /metrics into a single http.Handler.
//
// The complete, current route set is docs/openapi-scoreboard.yaml (ADR-0005
// canon) — NOT the list that used to live in this comment. That list had
// already drifted (it still named the P19-2b-removed GET /journey page
// route, confusing it with the still-live GET /api/users/{user}/journey API
// route) by the time ADR-0005 audited it, which is exactly the kind of
// hand-maintained-comment drift ADR-0005's machine-checked parity gate
// (internal/apispec, this package's Routes()) exists to replace: a doc
// comment cannot go stale in a way that fails `make test`, but the route
// table can.
package scoreboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
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
	falcoRules  catalog.FalcoRuleExcerpts
	order       []string
	docsBaseURL string
	// points is a WIRING-TIME TRANSFER ONLY: WithPoints stashes the operator's
	// policy here so NewHandler can pass it into the single Grader (below). It is
	// never read at request time — the runtime score/penalty are always sourced
	// via grader.Points() (the api handler asks the Grader), so the Grader stays
	// the single owner of the points arithmetic (R4-F8 / #39). nil = the Grader
	// keeps its placeholder DefaultPointsPolicy.
	points         *scoring.PointsPolicy
	sweeper        *scoring.Sweeper
	detect         api.DetectConfig
	allowedOrigins []string
	// ttydSuffix (P23-4) feeds the portal Terminal pane's iframe src builder
	// (view.New / portal.ttydURLFor) — see WithTtydSuffix.
	ttydSuffix string
	// routes is the FULL, flattened route table this binary registers —
	// this package's own /healthz + /metrics rows, plus ingest's, api's and
	// view's Routes() (ADR-0005 V2). Stored so Routes() can return it to the
	// parity tests without re-deriving it or re-wiring a second handler.
	routes []apispec.Route
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

// WithFalcoRules supplies the Story tab's display-only Falco rule excerpt
// (challengeId -> List/Macro/Rule, from challenges/<NN>-<slug>/rule.yaml —
// P23 Story-as-docs). Optional; a missing entry means "no rule.yaml authored
// for this challenge" and the UI omits the Falco Rule panel for that mission
// (same fail-soft posture as WithJourneys).
func WithFalcoRules(r catalog.FalcoRuleExcerpts) Option {
	return func(h *Handler) { h.falcoRules = r }
}

// WithOrder sets the mission progression order (scenario order when pinned,
// else catalog sorted ids). Drives sequential unlock in the Journey UI.
func WithOrder(order []string) Option { return func(h *Handler) { h.order = order } }

// WithDocsBaseURL sets the participant docs-site origin used to absolutise each
// mission's relative docsUrl (see api.JourneyConfig.DocsBaseURL). Empty = keep
// the relative path.
func WithDocsBaseURL(u string) Option { return func(h *Handler) { h.docsBaseURL = u } }

// WithDetect supplies the detect-challenge grading config (runner + in-flight
// cap). Omitted / nil runner = /submit-detect returns 503 (feature off, e.g.
// local dev without falco). The runner is the port that shells out to Falco (a
// local-exec docker runner for dev/colima, a K8s-Job runner for prod), so the
// scoreboard image itself stays distroless and falco-free.
func WithDetect(dc api.DetectConfig) Option {
	return func(h *Handler) { h.detect = dc }
}

// WithPoints sets the scoring points policy (base award per solve + per-hint
// reveal penalty, #40). Unset = the placeholder DefaultPointsPolicy. The same
// policy feeds the shared Grader (score computation) and the api handler (which
// surfaces the per-hint penalty to the UI), so both agree on the values.
func WithPoints(p scoring.PointsPolicy) Option {
	return func(h *Handler) { h.points = &p }
}

// WithAllowedOrigins sets the ALLOWED_ORIGINS allowlist (P23-2) the api
// handler's origin guard checks browser-facing state-changing requests
// against (Origin, falling back to Referer's origin). Empty = every guarded
// request is denied (fail-closed) — see cmd/scoreboard/main.go for the
// deploy-time default and rationale.
func WithAllowedOrigins(origins []string) Option {
	return func(h *Handler) { h.allowedOrigins = origins }
}

// WithTtydSuffix sets the DNS suffix (PORTAL_TTYD_SUFFIX) the portal
// Terminal pane uses to build each caller's OWN ttyd iframe src:
// `https://<derived-username>.<suffix>` — matching charts/ctf-user's
// `<username>.<dnsSuffix>` per-user Ingress host pattern exactly, so the
// portal's guess always resolves to the SAME workspace `deploy-user.sh`
// already stood up. Empty (default) = the Terminal pane renders its
// fail-safe "not configured" placeholder instead of an iframe (see
// view.renderPortal / portal.ttydURLFor). The real value is P19-dependent
// (single participant-facing origin design) — see cmd/scoreboard/main.go's
// PORTAL_TTYD_SUFFIX doc for the local-vs-prod distinction.
func WithTtydSuffix(suffix string) Option {
	return func(h *Handler) { h.ttydSuffix = suffix }
}

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

	// Single Grader shared by the ingest handler, the api handler, AND the
	// auto-solve sweeper. One instance = one clock and one MarkSolved caller,
	// preserving the single-writer discipline (conventions I1) across all three
	// entry points (this also resolves the prior double-instantiation, R4).
	//
	// WithOrder(h.order) wires the SAME progression order into the Grader
	// that api.New below receives via JourneyConfig.Order (ADR-0003 A1): the
	// Grader's attempt-scope taint gate and the Journey projection MUST agree
	// on "current" — two different orders would silently reintroduce the "two
	// definitions of current" drift the ADR warns against.
	grader := scoring.New(cat, s, h.now).WithOrder(h.order)
	if h.points != nil {
		grader.WithPoints(*h.points)
	}
	// The sweeper bumps the same evade solve metric a manual submit would, so an
	// auto-solve is indistinguishable from a manual one on the dashboard.
	h.sweeper = scoring.NewSweeper(grader, scoring.DefaultSweepCadence, logger, func(r scoring.SweepResult) {
		metrics.SolvesTotal.WithLabelValues(r.Challenge, "evade").Inc()
	})

	ih := ingest.New(grader, s, logger, h.now)
	ah := api.New(cat, grader, s, logger, h.now, h.adminEmails, h.allowedOrigins, api.JourneyConfig{
		Journeys:    h.journeys,
		FalcoRules:  h.falcoRules,
		Order:       h.order,
		DocsBaseURL: h.docsBaseURL,
	}, h.detect)
	// The operator index page (GET /) is admin-gated in the app layer too
	// (P18-1 defense-in-depth) using the same ADMIN_EMAILS rule the api handler
	// enforces. The participant journey/me pages are served ungated as static
	// shells (they carry no data; their per-user API is self-scoped). GET
	// /portal (P23-1) is served to any authenticated caller — see
	// view.renderPortal's doc for why that is safe (no admin data is ever
	// embedded; the api.NewAdminGate/api.DeriveUsername results feed only
	// display hints, and every pane's actual data fetch stays gated in api.Handler).
	vh := view.New(api.NewAdminGate(h.adminEmails), api.DeriveUsername, h.ttydSuffix, logger)

	// This binary's OWN two routes (liveness + metrics), table-driven like
	// every sub-handler's (ADR-0005 V2) so the static "no direct
	// mux.Handle outside the table" check (internal/apispec) covers this
	// file too, not just the sub-packages.
	h.routes = append(h.routes, apispec.Route{
		Method: "GET", Pattern: "/healthz",
		Audience: apispec.AudienceInfra, Authz: apispec.AuthzNone,
		OriginGuarded: false, CollectorForward: false, RateLimit: "none",
		Handler: http.HandlerFunc(h.healthz),
	})
	h.routes = append(h.routes, apispec.Route{
		Method: "GET", Pattern: "/metrics",
		Audience: apispec.AudienceInfra, Authz: apispec.AuthzNone,
		OriginGuarded: false, CollectorForward: false, RateLimit: "none",
		Handler: promhttp.Handler(),
	})
	h.routes = append(h.routes, ih.Routes()...)
	h.routes = append(h.routes, ah.Routes()...)
	h.routes = append(h.routes, vh.Routes()...)
	apispec.Register(h.mux, h.routes)

	return h
}

// Routes returns this binary's FULL, flattened declarative route table
// (this package's own healthz/metrics rows plus ingest's, api's and view's —
// ADR-0005 V2/V1). It is exactly what was installed onto the mux in
// NewHandler, via the same apispec.Register call, so a parity test reading
// this back sees the actual registered set, not a second hand-maintained
// copy of it.
func (h *Handler) Routes() []apispec.Route { return h.routes }

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
