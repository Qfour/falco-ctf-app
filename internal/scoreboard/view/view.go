// Package view serves the embedded HTML dashboards at GET /, GET /me,
// GET /journey, and GET /portal.
//
// The legacy pages (/, /me, /journey) are static — they fetch live state via
// /api/state, /api/users/{user}/me, and /api/users/{user}/journey
// respectively. The HTML / CSS / JS is shipped via go:embed so the binary
// needs no filesystem assets at runtime.
//
// /portal (P23-1) is the unified admin/participant shell: one page, a
// client-side hash-tab router, and a small amount of SERVER-INJECTED
// DISPLAY STATE (role + derived username — see portal.go). It is still not
// server-rendering any admin/participant DATA: every pane fetches its own
// data from the same already-gated APIs the legacy pages use. See portal.go
// for the security rationale in full.
package view

import (
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
)

//go:embed templates/index.html
var indexHTML string

//go:embed templates/me.html
var meHTML string

//go:embed templates/journey.html
var journeyHTML string

//go:embed templates/portal.html
var portalHTMLSrc string

// portalTmpl is parsed once at init from the embedded source. html/template
// (not text/template) is load-bearing here: it auto-escapes {{.RoleJSON}} /
// {{.UserJSON}} / {{.TtydURLJSON}} for their JS-string context, so even
// though portal.go feeds them pre-marshalled template.JS (already-safe
// JSON), a future edit that forgets to use template.JS still can't reopen an
// XSS hole — html/template would HTML/JS-escape a plain string instead of
// trusting it verbatim.
var portalTmpl = template.Must(template.New("portal").Parse(portalHTMLSrc))

type Handler struct {
	// isAdmin gates the operator dashboard index page (GET /). It mirrors the
	// api handler's identity check (X-Auth-Request-Email ∈ ADMIN_EMAILS). Nil =
	// no gate (kept for tests / callers that don't supply an allowlist); the
	// production wiring always supplies it.
	isAdmin func(*http.Request) bool
	// deriveUser derives the DISPLAY-ONLY username the portal shell pre-fills
	// into the Journey/Me panes (api.DeriveUsername — see that function's doc
	// for why this is never an authorization decision). Nil = "" always (the
	// portal falls back to its "could not determine" empty state, same as a
	// blank ?user= does today on /journey and /me).
	deriveUser func(*http.Request) string
	// ttydSuffix (P23-4) is the PORTAL_TTYD_SUFFIX deploy-time value used to
	// build the Terminal pane's own-ttyd iframe src
	// (`https://<deriveUser(r)>.<ttydSuffix>`, see portal.go's ttydURLFor).
	// "" (default) = the Terminal pane renders its fail-safe "not
	// configured" placeholder instead of an iframe. The real value is
	// P19-dependent (single participant-facing origin) — see
	// cmd/scoreboard/main.go's PORTAL_TTYD_SUFFIX doc.
	ttydSuffix string
	logger     *slog.Logger
}

// New builds the view handler. isAdmin, when non-nil, gates GET / (the
// full-event operator dashboard) to admins only — defense-in-depth (P18-1)
// behind the already-admin-gated ingress host — and also drives the GET
// /portal role injection (P23-1: which tab/pane the shell shows by default).
// Pass nil to leave / ungated (tests). deriveUser supplies the /portal
// username hint (api.DeriveUsername); nil = no hint. ttydSuffix (P23-4)
// supplies the Terminal pane's iframe host suffix; "" = no iframe (fail-safe
// placeholder). logger may be nil (tests); production wiring always
// supplies one so a template-render failure on GET /portal is observable.
func New(isAdmin func(*http.Request) bool, deriveUser func(*http.Request) string, ttydSuffix string, logger *slog.Logger) *Handler {
	return &Handler{isAdmin: isAdmin, deriveUser: deriveUser, ttydSuffix: ttydSuffix, logger: logger}
}

// Register wires all view routes. P23-1 is additive: legacy GET /, /me, and
// /journey stay registered as-is alongside the new /portal shell. Portal only
// becomes the sole participant/operator entrypoint once P23-4/-5/-6 (cookie
// SameSite, iframe embedding, docs/cybercore integration) land — that cutover
// is a separate, cross-repo change that will remove the legacy routes, repoint
// the ingress paths (see charts/scoreboard/templates/ingress*.yaml), and
// update operations.md. Do not remove the legacy routes before then.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.index)
	mux.HandleFunc("GET /me", h.me)
	mux.HandleFunc("GET /journey", h.journey)
	mux.HandleFunc("GET /portal", h.portal)
	// P23-6: the vendored, self-hosted cybercore-css stylesheet the portal
	// shell links to (see vendorassets.go's cybercoreCSSPath / PROVENANCE.md
	// for the pin). Served same-origin — never a CDN — so this asset never
	// leaves the deploy's own origin (P12).
	mux.HandleFunc("GET "+cybercoreCSSPath, serveCybercoreCSS)
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	// `GET /` in Go 1.22+ mux matches everything under /, so we reject
	// non-root paths explicitly to surface 404 for unknown routes.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Defense-in-depth (P18-1): the operator dashboard is admin-only. The
	// ingress admin host already gates this via auth-policy /check-admin, but we
	// re-check at the app layer so a misrouted request from the participant
	// journey host can't render the full-field leaderboard shell. The page's
	// data source (/api/state) is independently admin-gated too; this gate stops
	// the HTML from being served at all to a non-admin. Fail-closed: a missing
	// or non-admin identity gets 403 (the isAdmin predicate returns false for a
	// blank header and for an empty allowlist).
	if h.isAdmin != nil && !h.isAdmin(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<!doctype html><meta charset=utf-8><title>403</title><p>forbidden"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// me serves the participant self-service page. The HTML reads `?user=<name>`
// client-side and calls /api/users/<name>/me; the route itself is permissive
// so an empty / missing user just renders an instructional landing screen.
func (h *Handler) me(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(meHTML))
}

// journey serves the guided Journey UI. Like /me it is static: it reads
// `?user=<name>` client-side and polls /api/users/<name>/journey. A missing
// user renders an instructional landing screen.
func (h *Handler) journey(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(journeyHTML))
}

// portal serves the unified admin/participant shell (P23-1). See portal.go
// for renderPortal / the security rationale of the role+user injection.
func (h *Handler) portal(w http.ResponseWriter, r *http.Request) {
	if err := renderPortal(w, r, h.isAdmin, h.deriveUser, h.ttydSuffix); err != nil {
		if h.logger != nil {
			h.logger.Error("portal render failed", "err", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}
