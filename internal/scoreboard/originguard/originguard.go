// Package originguard provides a CSRF-mitigation middleware that validates
// the Origin (falling back to Referer) of browser-issued state-changing
// requests against an explicit allowlist.
//
// Why (P23-2): the portal work (P23) plans to relax the oauth2-proxy session
// cookie from SameSite=Lax to SameSite=None so it can be embedded in an
// iframe (P23-4). SameSite=Lax already blocks the classic cross-site
// form-POST CSRF for most state-changing routes today, but that protection
// disappears once SameSite=None lands. Some routes need no request body at
// all (e.g. POST /api/admin/reset) — an attacker can trigger those with a
// bare auto-submitting <form> from any origin, which bypasses CORS
// preflight entirely (no custom header, no non-simple content-type
// required). This middleware closes that gap NOW, while SameSite=Lax still
// covers the rest, so the guard is proven correct before the cookie
// attribute changes. Cookies themselves are untouched here.
//
// Guard is fail-closed: Host / X-Forwarded-Host are never consulted (both
// are attacker-controllable and would reintroduce the same-origin bypass
// this package exists to close). The allowed set is supplied explicitly by
// the caller (ALLOWED_ORIGINS), never inferred from the request.
package originguard

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
)

// Guard validates the Origin/Referer of state-changing requests against an
// explicit allowlist of origins (scheme://host[:port], no trailing slash,
// no path). A zero-value Guard (empty Allowed) denies every request it
// guards (fail-closed) — construct via New so callers see the tradeoff.
type Guard struct {
	allowed map[string]struct{}
	logger  *slog.Logger
}

// New builds a Guard from a list of allowed origins (e.g.
// "https://ctf.example.com", "https://portal.ctf.example.com:8443"). Entries
// are trimmed and matched verbatim (case-sensitive host is fine — browsers
// lower-case Origin/Referer host already; scheme is always lower-case).
// A nil logger falls back to slog.Default().
func New(allowedOrigins []string, logger *slog.Logger) *Guard {
	if logger == nil {
		logger = slog.Default()
	}
	set := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o = strings.TrimSpace(o); o != "" {
			set[o] = struct{}{}
		}
	}
	return &Guard{allowed: set, logger: logger}
}

// Middleware wraps next and enforces the origin check on every request it
// receives (callers mount it only on the protected, state-changing routes —
// see internal/scoreboard/api.Register). Semantics:
//
//   - Origin header present: must exactly match an allowed origin. No
//     Referer fallback is consulted in this case (Origin is the stronger,
//     purpose-built signal — a browser overrides it deliberately, so it wins
//     outright rather than being combined with Referer).
//   - Origin absent, Referer present: the Referer URL's scheme://host[:port]
//     is derived and must exactly match an allowed origin.
//   - Both absent: denied. Modern browsers always send Origin on
//     state-changing (POST/PUT/PATCH/DELETE) fetches/form-submits; a
//     same-site navigation also carries Referer. Only legacy/non-browser
//     clients omit both, and this middleware is mounted solely on
//     browser-facing routes (server-to-server paths like
//     POST /internal/exfil/{cid} are never wrapped with it), so failing
//     closed here does not break any known legitimate caller.
//
// A denial writes 403 via httpx.WriteJSON and logs the rejected value (never
// trusts Host/X-Forwarded-Host — see package doc).
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			if _, ok := g.allowed[origin]; ok {
				next.ServeHTTP(w, r)
				return
			}
			g.deny(w, r, "origin", origin)
			return
		}

		if referer := r.Header.Get("Referer"); referer != "" {
			if refOrigin, ok := originOf(referer); ok {
				if _, allowedOK := g.allowed[refOrigin]; allowedOK {
					next.ServeHTTP(w, r)
					return
				}
				g.deny(w, r, "referer_origin", refOrigin)
				return
			}
			// Unparseable Referer is treated the same as an absent one below —
			// fail closed rather than guess.
		}

		g.deny(w, r, "origin", "")
	})
}

// originOf extracts scheme://host[:port] from a Referer URL. Returns ok=false
// for a malformed or relative (no scheme/host) value.
func originOf(referer string) (string, bool) {
	u, err := url.Parse(referer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

func (g *Guard) deny(w http.ResponseWriter, r *http.Request, field, value string) {
	g.logger.Warn("origin guard denied",
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"path", r.URL.Path,
		field, value,
	)
	httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
}
