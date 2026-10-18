// Package authpolicy implements a small HTTP service that combines
// oauth2-proxy authentication with the ADR-0034 identity roster.
//
// Three ingress-nginx auth-url targets. Each calls oauth2-proxy's
// /oauth2/auth, normalises the returned email (NormalizeEmail) and decides:
//
//	GET /check-participant            (portal / scoreboard participant routes)
//	  ├ email ∈ ADMIN_EMAILS          → 200 (identity headers passed through)
//	  ├ email resolves to a seat      → 200, headers REWRITTEN to the canonical
//	  │                                 <seat>@<EXPECTED_EMAIL_DOMAIN>
//	  ├ anything else                 → 403 (body carries no email)
//	  └ no auth at all                → 401
//
//	GET /check-workspace?host=<seat>  (per-seat ttyd workspace)
//	  same, except a resolved seat must EQUAL host (exact match)
//
//	GET /check-admin                  (operator-only hosts)
//	  ├ email ∈ ADMIN_EMAILS env → 200
//	  ├ otherwise                → 403
//	  └ no auth at all           → 401
//
// There is no prefix, suffix or substring rule anywhere: the roster is the one
// table that says which identity is which seat (I8). The old `/check` route is
// gone on purpose — an old binary behind a new chart (or the reverse) answers
// the auth subrequest with 404, which ingress-nginx turns into a 500: closed.
package authpolicy

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/identity"
)

type Config struct {
	OAuth2ProxyURL      string
	ExpectedEmailDomain string
	UpstreamTimeout     time.Duration
	// AdminEmails is the allowlist consulted by /check-admin. An empty list
	// denies everyone — fail-closed so a misconfigured deployment cannot
	// accidentally expose admin endpoints.
	AdminEmails []string
	// Roster is the ADR-0034 D2 identity table. A nil Roster resolves nobody:
	// participant and workspace routes answer 403 to everyone but admins
	// (fail-closed). cmd/auth-policy refuses to start without one.
	Roster *Roster
}

type Handler struct {
	cfg      Config
	logger   *slog.Logger
	client   *http.Client
	mux      *http.ServeMux
	adminSet map[string]struct{}
	// routes is the declarative route table (ADR-0005 V2) this Handler
	// registers onto mux, retained so Routes() can hand it back to the
	// ADR-0005 parity test (server_test.go) unchanged from what NewHandler
	// actually installed.
	routes []apispec.Route
}

func NewHandler(cfg Config, logger *slog.Logger) *Handler {
	h := &Handler{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{
			Timeout: cfg.UpstreamTimeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 64,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
			},
		},
		adminSet: make(map[string]struct{}, len(cfg.AdminEmails)),
	}
	for _, e := range cfg.AdminEmails {
		// Same normaliser as the request side. An entry that does not
		// normalise (blank, non-ASCII, malformed) can never match anyone.
		if n, ok := NormalizeEmail(e); ok {
			h.adminSet[n] = struct{}{}
		}
	}
	// declared is the DESIRED table; h.mux/h.routes below become apispec.
	// NewMux's RETURN values, not a pre-built mux + this slice itself
	// (MEDIUM 1, 5x review — see route.go's NewMux doc): that is what makes
	// Routes() report exactly what the mux serves, never a route a future
	// edit left Handler: nil on. NewMux (task #146) also owns mux
	// construction, so there is no separately-constructed mux variable this
	// declared table could be pointed at instead of the real one.
	declared := []apispec.Route{
		{
			Method: "GET", Pattern: "/healthz",
			Audience: apispec.AudienceInfra, Authz: apispec.AuthzNone,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.healthz),
		},
		{
			Method: "GET", Pattern: "/metrics",
			Audience: apispec.AudienceInfra, Authz: apispec.AuthzNone,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: promhttp.Handler(),
		},
		{
			Method: "GET", Pattern: "/check-workspace",
			Audience: apispec.AudienceInternal, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.checkWorkspace),
		},
		{
			Method: "GET", Pattern: "/check-participant",
			Audience: apispec.AudienceInternal, Authz: apispec.AuthzRostered,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.checkParticipant),
		},
		{
			Method: "GET", Pattern: "/check-admin",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.checkAdmin),
		},
	}
	h.mux, h.routes = apispec.NewMux(declared)
	return h
}

// Routes returns the route set this Handler ACTUALLY registered onto its
// mux (ADR-0005 V2) — exactly apispec.NewMux's second return value from
// NewHandler, for the parity test (server_test.go) to compare against
// docs/openapi-auth-policy.yaml. Returns a copy (MEDIUM 5, 5x review):
// callers must not be able to mutate this Handler's live route table by
// mutating an element of the returned slice in place.
func (h *Handler) Routes() []apispec.Route {
	return append([]apispec.Route(nil), h.routes...)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// WithClient swaps the upstream HTTP client (intended for tests).
func (h *Handler) WithClient(c *http.Client) *Handler {
	h.client = c
	return h
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("content-type", "application/json")
	// roster_seats is what the S3 preflight reads (ADR-0034 V15): a binary
	// that predates the roster has no such key, and 0 means "nobody can enter".
	// Counts only — never an address.
	var seats, external int
	if h.cfg.Roster != nil {
		seats, external = h.cfg.Roster.SeatCount(), h.cfg.Roster.ExternalCount()
	}
	_, _ = fmt.Fprintf(w, `{"ok":true,"oauth2_proxy":%q,"domain":%q,"admin_count":%d,"roster_seats":%d,"roster_external":%d}`,
		h.cfg.OAuth2ProxyURL, h.cfg.ExpectedEmailDomain, len(h.adminSet), seats, external)
}

// upstreamResult communicates the outcome of an oauth2-proxy /oauth2/auth
// subrequest. On the happy path `status == 0` and `email` carries the
// authenticated identity; otherwise `status`+`body` describe the response
// the caller must forward unmodified.
type upstreamResult struct {
	email   string
	headers http.Header
	status  int
	body    string
}

// callUpstream issues the oauth2-proxy /oauth2/auth subrequest and classifies
// the response. Shared by every check endpoint so all of them honor the
// same error-masking and metrics behavior.
func (h *Handler) callUpstream(r *http.Request) upstreamResult {
	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.cfg.OAuth2ProxyURL, nil)
	if err != nil {
		h.logger.Error("build oauth2-proxy request", "err", err)
		return upstreamResult{status: http.StatusInternalServerError, body: "internal error"}
	}
	if c := r.Header.Get("Cookie"); c != "" {
		upstream.Header.Set("Cookie", c)
	}
	if a := r.Header.Get("Authorization"); a != "" {
		upstream.Header.Set("Authorization", a)
	}

	start := time.Now()
	resp, err := h.client.Do(upstream)
	upstreamDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		h.logger.Warn("oauth2-proxy unreachable", "err", err)
		return upstreamResult{status: http.StatusBadGateway, body: "oauth2-proxy unreachable"}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		// Let ingress-nginx auth-signin redirect to /oauth2/start.
		return upstreamResult{status: http.StatusUnauthorized, body: "not authenticated"}
	case http.StatusAccepted:
		// happy path
	default:
		// Don't leak upstream status / body. Anything other than 200/401/202
		// from oauth2-proxy is an internal failure mode that should look
		// like a generic 502 to the outside.
		h.logger.Warn("oauth2-proxy unexpected status", "status", resp.StatusCode)
		return upstreamResult{status: http.StatusBadGateway, body: "upstream error"}
	}
	return upstreamResult{email: resp.Header.Get("X-Auth-Request-Email"), headers: resp.Header}
}

// upstreamFailed answers a non-happy-path subrequest. It reports whether it
// wrote a response.
func (h *Handler) upstreamFailed(w http.ResponseWriter, up upstreamResult, count func(result string)) bool {
	if up.status == 0 {
		return false
	}
	label := "upstream_error"
	if up.status == http.StatusUnauthorized {
		label = "unauthenticated"
	}
	count(label)
	http.Error(w, up.body, up.status)
	return true
}

// propagateIdentity copies the standard auth-request headers from the
// upstream response into the response back to ingress-nginx. It is used for
// ADMIN_EMAILS only (their identity is already a reserved-domain static
// account); everyone else gets stampCanonical.
func propagateIdentity(w http.ResponseWriter, src http.Header) {
	w.Header().Set("X-Auth-Request-Email", src.Get("X-Auth-Request-Email"))
	if v := src.Get("X-Auth-Request-User"); v != "" {
		w.Header().Set("X-Auth-Request-User", v)
	}
	if v := src.Get("X-Auth-Request-Preferred-Username"); v != "" {
		w.Header().Set("X-Auth-Request-Preferred-Username", v)
	}
}

// stampCanonical is ADR-0034 D3: for a resolved seat, the three identity
// headers ingress-nginx forwards downstream are set to the canonical form
// ONLY, whatever oauth2-proxy returned. The IdP's real email and sub never
// leave this process, so the scoreboard's self check can be a plain equality
// against <user>@<EXPECTED_EMAIL_DOMAIN>.
func (h *Handler) stampCanonical(w http.ResponseWriter, seat string) {
	w.Header().Set("X-Auth-Request-Email", identity.Canonical(seat, h.cfg.Roster.Domain()))
	w.Header().Set("X-Auth-Request-User", seat)
	w.Header().Set("X-Auth-Request-Preferred-Username", seat)
}

// isAdmin reports whether the (raw) upstream email is in ADMIN_EMAILS after
// normalisation. A non-ASCII or malformed email is never an admin.
func (h *Handler) isAdmin(email string) bool {
	n, ok := NormalizeEmail(email)
	if !ok {
		return false
	}
	_, in := h.adminSet[n]
	return in
}

// deny answers 403 with a fixed body. The body NEVER carries an email or a
// seat (ADR-0034 D3). The one thing logged with the raw email is an identity
// that is not in the roster at all — what an operator needs on the day to fix
// the table; a rostered identity is logged by seat only.
func (h *Handler) deny(w http.ResponseWriter, endpoint, rawEmail, seat string, resolved bool, attrs ...any) {
	if resolved {
		h.logger.Warn("identity denied", append([]any{"endpoint", endpoint, "seat", seat}, attrs...)...)
	} else {
		h.logger.Warn("identity not in roster", append([]any{"endpoint", endpoint, "email", rawEmail}, attrs...)...)
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

func (h *Handler) countCheck(endpoint string) func(string) {
	return func(result string) { checksTotal.WithLabelValues(endpoint, result).Inc() }
}

// checkWorkspace gates a per-seat workspace: admin, or the roster seat the
// identity resolves to equals ?host= exactly.
func (h *Handler) checkWorkspace(w http.ResponseWriter, r *http.Request) {
	count := h.countCheck("workspace")
	host := r.URL.Query().Get("host")
	if host == "" {
		count("bad_request")
		http.Error(w, "missing ?host= query param", http.StatusBadRequest)
		return
	}
	if !identity.ValidSeat(host) {
		count("bad_request")
		http.Error(w, "invalid ?host= value", http.StatusBadRequest)
		return
	}

	up := h.callUpstream(r)
	if h.upstreamFailed(w, up, count) {
		return
	}

	// Admins reach any workspace (operator override). This is the one
	// intentional exception to the roster binding below — gated by the same
	// ADMIN_EMAILS allowlist as /check-admin (fail-closed when empty).
	if h.isAdmin(up.email) {
		propagateIdentity(w, up.headers)
		count("ok_admin")
		w.WriteHeader(http.StatusOK)
		return
	}

	seat, ok := h.cfg.Roster.Resolve(up.email)
	if !ok {
		count("forbidden")
		h.deny(w, "workspace", up.email, "", false, "host", host)
		return
	}
	if seat != host {
		count("forbidden")
		h.deny(w, "workspace", up.email, seat, true, "host", host)
		return
	}
	h.stampCanonical(w, seat)
	count("ok")
	w.WriteHeader(http.StatusOK)
}

// checkParticipant gates the participant portal and its API: admin, or any
// identity the roster resolves to a seat. It is the door that replaces
// "any authenticated login".
func (h *Handler) checkParticipant(w http.ResponseWriter, r *http.Request) {
	count := h.countCheck("participant")
	up := h.callUpstream(r)
	if h.upstreamFailed(w, up, count) {
		return
	}
	if h.isAdmin(up.email) {
		propagateIdentity(w, up.headers)
		count("ok_admin")
		w.WriteHeader(http.StatusOK)
		return
	}
	seat, ok := h.cfg.Roster.Resolve(up.email)
	if !ok {
		count("forbidden")
		h.deny(w, "participant", up.email, "", false)
		return
	}
	h.stampCanonical(w, seat)
	count("ok")
	w.WriteHeader(http.StatusOK)
}

// checkAdmin gates operator-only hosts (scoreboard dashboard, /me page,
// any admin views). Returns 200 only if the authenticated email is in the
// ADMIN_EMAILS allowlist (case-insensitive). An empty allowlist denies
// everyone — fail-closed.
func (h *Handler) checkAdmin(w http.ResponseWriter, r *http.Request) {
	count := func(result string) { adminChecksTotal.WithLabelValues(result).Inc() }
	up := h.callUpstream(r)
	if h.upstreamFailed(w, up, count) {
		return
	}
	if !h.isAdmin(up.email) {
		count("forbidden")
		seat, resolved := h.cfg.Roster.Resolve(up.email)
		h.deny(w, "admin", up.email, seat, resolved)
		return
	}
	propagateIdentity(w, up.headers)
	count("ok")
	w.WriteHeader(http.StatusOK)
}
