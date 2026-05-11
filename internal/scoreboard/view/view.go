// Package view serves the embedded HTML dashboard at GET /.
//
// The HTML/CSS/JS is shipped via go:embed so the binary needs no
// filesystem assets at runtime.
package view

import (
	_ "embed"
	"net/http"
)

//go:embed templates/index.html
var indexHTML string

type Handler struct{}

func New() *Handler { return &Handler{} }

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.index)
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
