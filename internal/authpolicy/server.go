// Package authpolicy implements a small HTTP service that combines
// oauth2-proxy authentication with authorization checks.
//
// Two ingress-nginx auth-url targets:
//
//	GET /check?host=<expected-username>
//	  ingress ──► oauth2-proxy /oauth2/auth ──► X-Auth-Request-Email
//	         ├ email starts with "<host>@" → 200
//	         ├ email ∈ ADMIN_EMAILS        → 200 (admins reach any workspace)
//	         ├ email otherwise            → 403
//	         └ no auth at all             → 401
//
//	GET /check-admin
//	  ingress ──► oauth2-proxy /oauth2/auth ──► X-Auth-Request-Email
//	         ├ email ∈ ADMIN_EMAILS env → 200
//	         ├ email otherwise         → 403
//	         └ no auth at all          → 401
//
// `/check` gates per-user workspaces (`userN.<domain>` → 200 only if the
// logged-in email is `userN@…`). `/check-admin` gates operator-only hosts
// like the scoreboard dashboard.
package authpolicy

import (
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// validHost matches the username slugs Dex / oauth2-proxy emit. Restricting
// the `host` query param to this shape rejects garbled inputs (containing
// `@`, `/`, whitespace, etc.) before they reach the upstream-status branch
// and avoids confusing metrics labels.
var validHost = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type Config struct {
	OAuth2ProxyURL      string
	ExpectedEmailDomain string
	UpstreamTimeout     time.Duration
	// AdminEmails is the allowlist consulted by /check-admin. An empty list
	// denies everyone — fail-closed so a misconfigured deployment cannot
	// accidentally expose admin endpoints.
	AdminEmails []string
}

type Handler struct {
	cfg      Config
	logger   *slog.Logger
	client   *http.Client
	mux      *http.ServeMux
	adminSet map[string]struct{}
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
		mux:      http.NewServeMux(),
		adminSet: make(map[string]struct{}, len(cfg.AdminEmails)),
	}
	for _, e := range cfg.AdminEmails {
		e = strings.TrimSpace(strings.ToLower(e))
		if e == "" {
			continue
		}
		h.adminSet[e] = struct{}{}
	}
	h.mux.HandleFunc("GET /healthz", h.healthz)
	h.mux.Handle("GET /metrics", promhttp.Handler())
	h.mux.HandleFunc("GET /check", h.check)
	h.mux.HandleFunc("GET /check-admin", h.checkAdmin)
	return h
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
	_, _ = fmt.Fprintf(w, `{"ok":true,"oauth2_proxy":%q,"domain":%q,"admin_count":%d}`,
		h.cfg.OAuth2ProxyURL, h.cfg.ExpectedEmailDomain, len(h.adminSet))
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
// the response. Shared between /check and /check-admin so both honor the
// same error-masking and metrics behavior.
func (h *Handler) callUpstream(r *http.Request) upstreamResult {
	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.cfg.OAuth2ProxyURL, nil)
	if err != nil {
		return upstreamResult{status: http.StatusInternalServerError, body: fmt.Sprintf("build request: %v", err)}
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

// propagateIdentity copies the standard auth-request headers from the
// upstream response into the response back to ingress-nginx, which then
// forwards them to the protected backend (ttyd / scoreboard).
func propagateIdentity(w http.ResponseWriter, src http.Header) {
	w.Header().Set("X-Auth-Request-Email", src.Get("X-Auth-Request-Email"))
	if v := src.Get("X-Auth-Request-User"); v != "" {
		w.Header().Set("X-Auth-Request-User", v)
	}
	if v := src.Get("X-Auth-Request-Preferred-Username"); v != "" {
		w.Header().Set("X-Auth-Request-Preferred-Username", v)
	}
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		checksTotal.WithLabelValues("bad_request").Inc()
		http.Error(w, "missing ?host= query param", http.StatusBadRequest)
		return
	}
	if !validHost.MatchString(host) {
		checksTotal.WithLabelValues("bad_request").Inc()
		http.Error(w, "invalid ?host= value", http.StatusBadRequest)
		return
	}

	up := h.callUpstream(r)
	if up.status != 0 {
		label := "upstream_error"
		if up.status == http.StatusUnauthorized {
			label = "unauthenticated"
		}
		checksTotal.WithLabelValues(label).Inc()
		http.Error(w, up.body, up.status)
		return
	}

	// Admins reach any workspace (operator override). This is the one
	// intentional exception to the <host>@ binding below — gated by the same
	// ADMIN_EMAILS allowlist as /check-admin (fail-closed when empty).
	if _, isAdmin := h.adminSet[strings.ToLower(up.email)]; isAdmin {
		propagateIdentity(w, up.headers)
		checksTotal.WithLabelValues("ok_admin").Inc()
		w.WriteHeader(http.StatusOK)
		return
	}

	// Boundary: require "<host>@" exact prefix so `alice2@...` does not
	// satisfy host=alice.
	if !strings.HasPrefix(up.email, host+"@") {
		checksTotal.WithLabelValues("forbidden").Inc()
		http.Error(w,
			fmt.Sprintf("forbidden: %q does not match host %q", up.email, host),
			http.StatusForbidden,
		)
		return
	}

	propagateIdentity(w, up.headers)
	checksTotal.WithLabelValues("ok").Inc()
	w.WriteHeader(http.StatusOK)
}

// checkAdmin gates operator-only hosts (scoreboard dashboard, /me page,
// any admin views). Returns 200 only if the authenticated email is in the
// ADMIN_EMAILS allowlist (case-insensitive). An empty allowlist denies
// everyone — fail-closed.
func (h *Handler) checkAdmin(w http.ResponseWriter, r *http.Request) {
	up := h.callUpstream(r)
	if up.status != 0 {
		label := "upstream_error"
		if up.status == http.StatusUnauthorized {
			label = "unauthenticated"
		}
		adminChecksTotal.WithLabelValues(label).Inc()
		http.Error(w, up.body, up.status)
		return
	}

	if _, ok := h.adminSet[strings.ToLower(up.email)]; !ok {
		adminChecksTotal.WithLabelValues("forbidden").Inc()
		http.Error(w,
			fmt.Sprintf("forbidden: %q is not in admin allowlist", up.email),
			http.StatusForbidden,
		)
		return
	}

	propagateIdentity(w, up.headers)
	adminChecksTotal.WithLabelValues("ok").Inc()
	w.WriteHeader(http.StatusOK)
}
