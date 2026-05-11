// Package authpolicy implements a small HTTP service that combines
// oauth2-proxy authentication with a host↔email binding check.
//
//	ingress ── /check?host=<expected-username> ──►  authpolicy
//	                                                  │
//	                                                  └─► oauth2-proxy /oauth2/auth
//	                                                         (cookie forwarded)
//	                                                      returns X-Auth-Request-Email
//	                                                  │
//	                                                  ├ email startswith "<host>@" → 200
//	                                                  ├ email otherwise            → 403
//	                                                  └ no auth at all             → 401
//
// Plain `auth-url: oauth2-proxy/oauth2/auth` would let any logged-in user
// reach any user's workspace. This service closes that gap without requiring
// ingress-nginx snippet annotations (which the admission webhook blocks).
package authpolicy

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Config struct {
	OAuth2ProxyURL      string
	ExpectedEmailDomain string
	UpstreamTimeout     time.Duration
}

type Handler struct {
	cfg    Config
	logger *slog.Logger
	client *http.Client
	mux    *http.ServeMux
}

func NewHandler(cfg Config, logger *slog.Logger) *Handler {
	h := &Handler{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: cfg.UpstreamTimeout},
		mux:    http.NewServeMux(),
	}
	h.mux.HandleFunc("GET /healthz", h.healthz)
	h.mux.Handle("GET /metrics", promhttp.Handler())
	h.mux.HandleFunc("GET /check", h.check)
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
	_, _ = fmt.Fprintf(w, `{"ok":true,"oauth2_proxy":%q,"domain":%q}`,
		h.cfg.OAuth2ProxyURL, h.cfg.ExpectedEmailDomain)
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		checksTotal.WithLabelValues("bad_request").Inc()
		http.Error(w, "missing ?host= query param", http.StatusBadRequest)
		return
	}

	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.cfg.OAuth2ProxyURL, nil)
	if err != nil {
		checksTotal.WithLabelValues("upstream_error").Inc()
		http.Error(w, fmt.Sprintf("build request: %v", err), http.StatusInternalServerError)
		return
	}
	// Forward the original request's cookie and authorization to oauth2-proxy.
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
		checksTotal.WithLabelValues("upstream_error").Inc()
		h.logger.Warn("oauth2-proxy unreachable", "err", err)
		http.Error(w, fmt.Sprintf("oauth2-proxy unreachable: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		// Let ingress-nginx auth-signin redirect to /oauth2/start.
		checksTotal.WithLabelValues("unauthenticated").Inc()
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	case http.StatusAccepted:
		// authenticated — identity headers are populated; fall through to email check.
	default:
		checksTotal.WithLabelValues("upstream_error").Inc()
		http.Error(w,
			fmt.Sprintf("oauth2-proxy returned %d", resp.StatusCode),
			resp.StatusCode,
		)
		return
	}

	email := resp.Header.Get("X-Auth-Request-Email")
	// Boundary: require "<host>@" exact prefix so `alice2@...` does not satisfy host=alice.
	if !strings.HasPrefix(email, host+"@") {
		checksTotal.WithLabelValues("forbidden").Inc()
		http.Error(w,
			fmt.Sprintf("forbidden: %q does not match host %q", email, host),
			http.StatusForbidden,
		)
		return
	}

	// Propagate identity headers so the upstream (ttyd) can read them too.
	w.Header().Set("X-Auth-Request-Email", email)
	if v := resp.Header.Get("X-Auth-Request-User"); v != "" {
		w.Header().Set("X-Auth-Request-User", v)
	}
	if v := resp.Header.Get("X-Auth-Request-Preferred-Username"); v != "" {
		w.Header().Set("X-Auth-Request-Preferred-Username", v)
	}
	checksTotal.WithLabelValues("ok").Inc()
	w.WriteHeader(http.StatusOK)
}
