package authpolicy_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/authpolicy"
)

func fakeOAuth2Proxy(t *testing.T, behavior func(r *http.Request) (status int, email string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, email := behavior(r)
		if email != "" {
			w.Header().Set("X-Auth-Request-Email", email)
			w.Header().Set("X-Auth-Request-User", strings.SplitN(email, "@", 2)[0])
		}
		w.WriteHeader(status)
	}))
}

func newHandler(upstreamURL string) *authpolicy.Handler {
	cfg := authpolicy.Config{
		OAuth2ProxyURL:      upstreamURL,
		ExpectedEmailDomain: "ctf.local",
		UpstreamTimeout:     2 * time.Second,
	}
	return authpolicy.NewHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func do(t *testing.T, h http.Handler, target string, headers map[string]string) *http.Response {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

func TestHealthz(t *testing.T) {
	h := newHandler("http://example.invalid")
	resp := do(t, h, "/healthz", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", resp.StatusCode)
	}
}

func TestCheck_MissingHost(t *testing.T) {
	h := newHandler("http://example.invalid")
	resp := do(t, h, "/check", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 when host missing, got %d", resp.StatusCode)
	}
}

func TestCheck_NotAuthenticated_Returns401(t *testing.T) {
	upstream := fakeOAuth2Proxy(t, func(_ *http.Request) (int, string) {
		return http.StatusUnauthorized, ""
	})
	defer upstream.Close()
	h := newHandler(upstream.URL)
	resp := do(t, h, "/check?host=alice", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 (let auth-signin redirect), got %d", resp.StatusCode)
	}
}

func TestCheck_AuthenticatedWrongUser_Returns403(t *testing.T) {
	upstream := fakeOAuth2Proxy(t, func(_ *http.Request) (int, string) {
		return http.StatusAccepted, "bob@ctf.local"
	})
	defer upstream.Close()
	h := newHandler(upstream.URL)
	resp := do(t, h, "/check?host=alice", map[string]string{"Cookie": "_oauth2_proxy=foo"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-user access, got %d", resp.StatusCode)
	}
}

func TestCheck_AuthenticatedSameUser_Returns200(t *testing.T) {
	upstream := fakeOAuth2Proxy(t, func(r *http.Request) (int, string) {
		if got := r.Header.Get("Cookie"); got != "_oauth2_proxy=foo" {
			t.Errorf("upstream did not receive forwarded cookie: %q", got)
		}
		return http.StatusAccepted, "alice@ctf.local"
	})
	defer upstream.Close()
	h := newHandler(upstream.URL)
	resp := do(t, h, "/check?host=alice", map[string]string{"Cookie": "_oauth2_proxy=foo"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-Request-Email"); got != "alice@ctf.local" {
		t.Fatalf("expected email header propagated, got %q", got)
	}
	if got := resp.Header.Get("X-Auth-Request-User"); got != "alice" {
		t.Fatalf("expected user header propagated, got %q", got)
	}
}

// Boundary: an email of `alice2@...` MUST NOT satisfy host=alice. Pins the
// `<host>@` exact-prefix rule against future "startswith" relaxations.
func TestCheck_EmailPrefixBoundary(t *testing.T) {
	upstream := fakeOAuth2Proxy(t, func(_ *http.Request) (int, string) {
		return http.StatusAccepted, "alice2@ctf.local"
	})
	defer upstream.Close()
	h := newHandler(upstream.URL)
	resp := do(t, h, "/check?host=alice", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice2@... must NOT satisfy host=alice; got %d", resp.StatusCode)
	}
}

func TestCheck_UpstreamUnreachable_Returns502(t *testing.T) {
	// Port 1 reliably refuses connections immediately.
	h := newHandler("http://127.0.0.1:1/oauth2/auth")
	resp := do(t, h, "/check?host=alice", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 when upstream is down, got %d", resp.StatusCode)
	}
}

func TestCheck_UpstreamUnexpectedStatus_PassesThrough(t *testing.T) {
	upstream := fakeOAuth2Proxy(t, func(_ *http.Request) (int, string) {
		return http.StatusInternalServerError, ""
	})
	defer upstream.Close()
	h := newHandler(upstream.URL)
	resp := do(t, h, "/check?host=alice", nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 passed through, got %d", resp.StatusCode)
	}
}
