// Package view serves the embedded HTML dashboards at GET / and GET /me.
//
// Both pages are static — they fetch live state via /api/state and
// /api/users/{user}/me respectively. The HTML / CSS / JS is shipped via
// go:embed so the binary needs no filesystem assets at runtime.
package view

import (
	_ "embed"
	"net/http"
)

//go:embed templates/index.html
var indexHTML string

//go:embed templates/me.html
var meHTML string

type Handler struct{}

func New() *Handler { return &Handler{} }

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.index)
	mux.HandleFunc("GET /me", h.me)
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	// `GET /` in Go 1.22+ mux matches everything under /, so we reject
	// non-root paths explicitly to surface 404 for unknown routes.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
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
