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

// TestOriginOf_CaseNormalization pins the case-folding behavior documented
// on originOf: scheme and host are lower-cased so a mixed-case Origin/Referer
// still compares equal against a lower-cased allowlist entry.
func TestOriginOf_CaseNormalization(t *testing.T) {
	got, ok := originOf("HTTPS://A.Example.COM")
	if !ok {
		t.Fatalf("originOf: ok=false, want true")
	}
	if got != "https://a.example.com" {
		t.Fatalf("originOf(%q) = %q, want %q", "HTTPS://A.Example.COM", got, "https://a.example.com")
	}
}

// TestMiddleware_CaseInsensitiveAllowlistMatch exercises the same
// case-normalization end to end: an allowlist entry supplied in mixed case
// must still match a lower-case request Origin, because both sides go
// through originOf's lower-casing.
func TestMiddleware_CaseInsensitiveAllowlistMatch(t *testing.T) {
	g := newTestGuard("HTTPS://Foo.Example.COM")
	w := serve(g, "POST", "/x", "https://foo.example.com", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d want 200 (case-insensitive allowlist match)", w.Code)
	}
}

// TestNew_AllowlistEntryWithTrailingSlashAndPath verifies that an allowlist
// entry supplied with a trailing slash (or a path) is normalised down to
// scheme://host by the same originOf parser New uses, so it still matches a
// bare-origin request.
func TestNew_AllowlistEntryWithTrailingSlashAndPath(t *testing.T) {
	g := newTestGuard("https://foo.example.com/")
	w := serve(g, "POST", "/x", "https://foo.example.com", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d want 200 (trailing-slash allowlist entry should still match)", w.Code)
	}

	g2 := newTestGuard("https://foo.example.com/some/path")
	w2 := serve(g2, "POST", "/x", "https://foo.example.com", "")
	if w2.Code != http.StatusOK {
		t.Fatalf("code=%d want 200 (allowlist entry with a path should still match on origin only)", w2.Code)
	}
}

// TestMiddleware_PortMismatchDenied is a regression guard: an allowed origin
// and a request Origin that differ only by port must NOT be treated as
// equal. scheme://host[:port] is compared as a whole string, so a missing
// vs. present (or differing) port must deny.
func TestMiddleware_PortMismatchDenied(t *testing.T) {
	g := newTestGuard("https://a.example.com")
	w := serve(g, "POST", "/x", "https://a.example.com:8443", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d want 403 (port-only mismatch must not be allowed)", w.Code)
	}
}
