// Package view serves the embedded HTML dashboards at GET / and GET /portal.
//
// GET / (the legacy operator dashboard) is static — it fetches live state via
// /api/state. The HTML / CSS / JS is shipped via go:embed so the binary needs
// no filesystem assets at runtime.
//
// GET /portal (P23-1) is the unified admin/participant shell: one page, a
// client-side hash-tab router, and a small amount of SERVER-INJECTED
// DISPLAY STATE (role + derived username — see portal.go). It is still not
// server-rendering any admin/participant DATA: every pane fetches its own
// data from the same already-gated APIs GET / uses. See portal.go for the
// security rationale in full.
//
// P19-2b cutover: the legacy GET /me and GET /journey routes (and their
// templates/{me,journey}.html) have been REMOVED. The portal's Journey (#journey)
// and Me (#me) tabs already fetched the exact same /api/users/{user}/{journey,me}
// endpoints these pages used, so no participant-facing capability is lost —
// see the portal.html pane-journey / pane-me sections for the equivalent
// client-side logic. GET / (the admin-gated operator dashboard) is
// DELIBERATELY KEPT (P19-1 design: "/" stays admin dashboard-only to avoid
// colliding authorization profiles with /portal, which is open to any
// authenticated login). Do not resurrect /me or /journey as aliases for
// /portal#me / /portal#journey — redirect via a link (see index.html's
// journey-link), not a server route, to keep the route surface matching the
// two Ingress objects' path allow-lists exactly (charts/scoreboard/templates/
// ingress*.yaml).
package view

import (
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
)

//go:embed templates/index.html
var indexHTML string

// indexTmpl is parsed once at init from the embedded source (Issue #114 /
// P23-6 parity fixup). Previously GET / wrote indexHTML verbatim via
// w.Write and carried NO nonce for its single inline <script> (line ~284),
// which meant writeSecurityHeaders (below) had nothing to thread through —
// the admin dashboard's CSP either had to omit script-src's nonce-source
// entirely (falling back to 'unsafe-inline', defeating the point) or the
// inline script would silently stop executing. Parsing as html/template and
// injecting {{.Nonce}} (indexData below) mirrors portalTmpl exactly, so the
// admin dashboard — the single highest-privilege page in this service — now
// gets the SAME strict script-src 'nonce-<per-response>' contract the
// participant portal already had, instead of a weaker one just because it
// predates P23-6.
var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

// indexData is GET /'s template payload — deliberately just the nonce.
// Unlike portalData, the admin dashboard embeds no per-viewer display hints
// (role/user/ttyd) at all; it is a static shell that fetches everything via
// /api/state client-side (see the package doc above), so there is nothing
// else to thread through.
type indexData struct {
	// Nonce (Issue #114) is the CSP script-src nonce generated fresh for
	// THIS response by writeSecurityHeaders and simultaneously stamped onto
	// the Content-Security-Policy response header — see portalData.Nonce's
	// doc (portal.go) for the full rationale, which applies identically
	// here. templates/index.html's <script> tag MUST carry
	// nonce="{{.Nonce}}".
	Nonce string
}

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
	// portal falls back to its "could not determine" empty state — the same
	// empty state the removed legacy /journey and /me pages used to show for
	// a blank ?user=).
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

// Routes returns the view package's declarative route table (ADR-0005 V2).
// GET / (admin dashboard), GET /portal (P23-1 unified shell), the vendored
// cybercore-css stylesheet, and the design-tokens stylesheet (app#116) are
// the only four routes left after the P19-2b cutover removed GET /me and
// GET /journey (see the package doc above).
//
// The cybercore-css and tokens-css routes' Pattern fields are the
// cybercoreCSSPath / tokensCSSPath CONSTANTS (vendorassets.go), not a string
// built by concatenating "GET "+path at the mux.HandleFunc call site the way
// the pre-ADR-0005 code did — that concatenation is exactly what defeated a
// literal-grep route extraction (ADR-0005 V2's motivating example). Reading
// Pattern back through this method gives the parity test the actual runtime
// string, however it was computed.
func (h *Handler) Routes() []apispec.Route {
	return []apispec.Route{
		{
			Method:           "GET",
			Pattern:          "/",
			Audience:         apispec.AudienceOperator,
			Authz:            apispec.AuthzAdmin,
			OriginGuarded:    false,
			CollectorForward: false,
			RateLimit:        "none",
			Handler:          http.HandlerFunc(h.index),
		},
		{
			Method:           "GET",
			Pattern:          "/portal",
			Audience:         apispec.AudienceParticipant,
			Authz:            apispec.AuthzNone,
			OriginGuarded:    false,
			CollectorForward: false,
			RateLimit:        "none",
			Handler:          http.HandlerFunc(h.portal),
		},
		{
			Method:           "GET",
			Pattern:          cybercoreCSSPath,
			Audience:         apispec.AudienceParticipant,
			Authz:            apispec.AuthzNone,
			OriginGuarded:    false,
			CollectorForward: false,
			RateLimit:        "none",
			Handler:          http.HandlerFunc(serveCybercoreCSS),
		},
		{
			Method:           "GET",
			Pattern:          tokensCSSPath,
			Audience:         apispec.AudienceParticipant,
			Authz:            apispec.AuthzNone,
			OriginGuarded:    false,
			CollectorForward: false,
			RateLimit:        "none",
			Handler:          http.HandlerFunc(serveTokensCSS),
		},
	}
}

// This package deliberately has no Register(mux) method of its own (LOW,
// 5x review: one used to exist here, calling apispec.Register(mux,
// h.Routes()) directly, but nothing — production or test — ever called it;
// scoreboard.Handler's NewHandler always collects every sub-package's
// Routes() into one table and calls apispec.Register exactly once). Keeping
// an unused second registration entry point around contradicted I14's
// "single registration path" claim on its face; removed rather than
// documented as test-only, since it had no test either.

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	// `GET /` in Go 1.22+ mux matches everything under /, so we reject
	// non-root paths explicitly to surface 404 for unknown routes.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// writeSecurityHeaders (Issue #114 — previously wired only into
	// GET /portal, see csp.go's doc) MUST run before any Content-Type /
	// WriteHeader / Write below — headers cannot be added after the first
	// Write. "" for ttydSuffix: the admin dashboard embeds no iframe (unlike
	// the portal's Terminal pane), so frame-src stays 'none' — the
	// strictest value portalCSP can produce — rather than opening up
	// frame-src for a page that has no legitimate use for it.
	nonce, err := writeSecurityHeaders(w, "")
	if err != nil {
		if h.logger != nil {
			h.logger.Error("index security headers failed", "err", err)
		}
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
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
	if err := indexTmpl.Execute(w, indexData{Nonce: nonce}); err != nil {
		if h.logger != nil {
			h.logger.Error("index render failed", "err", err)
		}
		// Best-effort like portal()'s error path below: indexTmpl.Execute
		// streams as it renders, so a failure here likely happened after
		// some bytes already flushed — this WriteJSON is a no-op in that
		// case (net/http silently drops writes after the first one wins
		// the status code) and a genuine 500 body only in the rare case
		// the failure happened before any byte was written.
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
	}
}

// portal serves the unified admin/participant shell (P23-1). See portal.go
// for renderPortal / the security rationale of the role+user injection.
func (h *Handler) portal(w http.ResponseWriter, r *http.Request) {
	if err := renderPortal(w, r, h.isAdmin, h.deriveUser, h.ttydSuffix); err != nil {
		if h.logger != nil {
			h.logger.Error("portal render failed", "err", err)
		}
		// Issue #159 / ADR-0005 follow-up F1: JSON-encoded via httpx.WriteJSON,
		// not http.Error's text/plain — this was the second of the two
		// documented non-2xx deviations (the other was ratelimit.Middleware's
		// 429, now also unified). renderPortal has already written a partial
		// text/html body up to the point of failure in the common case
		// (html/template streams as it executes), so this WriteHeader is best-
		// effort like the http.Error it replaces — it is not reachable once
		// bytes have actually flushed, same as before.
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
}
