package originguard

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestGuard(allowed ...string) *Guard {
	return New(allowed, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func serve(g *Guard, method, target, origin, referer string) *httptest.ResponseRecorder {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest(method, target, nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if referer != "" {
		r.Header.Set("Referer", referer)
	}
	w := httptest.NewRecorder()
	g.Middleware(next).ServeHTTP(w, r)
	return w
}

func TestMiddleware_AllowedOrigin(t *testing.T) {
	g := newTestGuard("https://a.example.com")
	w := serve(g, "POST", "/x", "https://a.example.com", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", w.Code)
	}
}

func TestMiddleware_DisallowedOrigin(t *testing.T) {
	g := newTestGuard("https://a.example.com")
	w := serve(g, "POST", "/x", "https://b.example.com", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403", w.Code)
	}
}

func TestMiddleware_RefererFallback(t *testing.T) {
	g := newTestGuard("https://a.example.com")
	w := serve(g, "POST", "/x", "", "https://a.example.com/some/path?q=1")
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", w.Code)
	}
}

func TestMiddleware_RefererWrongOrigin(t *testing.T) {
	g := newTestGuard("https://a.example.com")
	w := serve(g, "POST", "/x", "", "https://b.example.com/some/path")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403", w.Code)
	}
}

func TestMiddleware_NoOriginNoReferer(t *testing.T) {
	g := newTestGuard("https://a.example.com")
	w := serve(g, "POST", "/x", "", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403", w.Code)
	}
}

func TestMiddleware_MalformedReferer(t *testing.T) {
	g := newTestGuard("https://a.example.com")
	// A relative/schemeless value has no origin to extract → deny.
	w := serve(g, "POST", "/x", "", "/just/a/path")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403", w.Code)
	}
}

func TestMiddleware_EmptyAllowlistDeniesEverything(t *testing.T) {
	g := newTestGuard() // no allowed origins at all
	w := serve(g, "POST", "/x", "https://a.example.com", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403 (empty allowlist must fail closed)", w.Code)
	}
}

func TestMiddleware_OriginTakesPrecedenceOverReferer(t *testing.T) {
	g := newTestGuard("https://a.example.com")
	// Origin allowed; Referer alone would fail — Origin wins, request passes.
	w := serve(g, "POST", "/x", "https://a.example.com", "https://evil.example.com/x")
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", w.Code)
	}
}

func TestNew_NilLoggerDoesNotPanic(t *testing.T) {
	g := New([]string{"https://a.example.com"}, nil)
	w := serve(g, "POST", "/x", "https://b.example.com", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403", w.Code)
	}
}

func TestOriginOf(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"https://a.example.com/path?q=1", "https://a.example.com", true},
		{"https://a.example.com:8443/", "https://a.example.com:8443", true},
		{"/relative/path", "", false},
		{"not a url at all \x7f", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := originOf(c.in)
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("originOf(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}
