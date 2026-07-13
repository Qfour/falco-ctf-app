// Package view serves the embedded HTML dashboards at GET /, GET /me, and
// GET /journey.
//
// All pages are static — they fetch live state via /api/state,
// /api/users/{user}/me, and /api/users/{user}/journey respectively. The
// HTML / CSS / JS is shipped via go:embed so the binary needs no filesystem
// assets at runtime.
package view

import (
	_ "embed"
	"net/http"
)

//go:embed templates/index.html
var indexHTML string

//go:embed templates/me.html
var meHTML string

//go:embed templates/journey.html
var journeyHTML string

type Handler struct {
	// isAdmin gates the operator dashboard index page (GET /). It mirrors the
	// api handler's identity check (X-Auth-Request-Email ∈ ADMIN_EMAILS). Nil =
	// no gate (kept for tests / callers that don't supply an allowlist); the
	// production wiring always supplies it.
	isAdmin func(*http.Request) bool
}

// New builds the view handler. isAdmin, when non-nil, gates GET / (the
// full-event operator dashboard) to admins only — defense-in-depth (P18-1)
// behind the already-admin-gated ingress host. Pass nil to leave / ungated.
func New(isAdmin func(*http.Request) bool) *Handler { return &Handler{isAdmin: isAdmin} }

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.index)
	mux.HandleFunc("GET /me", h.me)
	mux.HandleFunc("GET /journey", h.journey)
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
