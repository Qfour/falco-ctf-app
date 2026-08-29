package ratelimit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

func TestAllow_Burst(t *testing.T) {
	var now time.Time
	l := ratelimit.New(0.1 /* tokens/s */, 3 /* burst */).WithNow(func() time.Time { return now })
	now = time.Unix(0, 0)
	// 3 instant requests should pass (burst).
	for i := 0; i < 3; i++ {
		if !l.Allow("ip1") {
			t.Fatalf("burst[%d] should be allowed", i)
		}
	}
	// 4th immediately is denied.
	if l.Allow("ip1") {
		t.Fatal("4th request must be denied")
	}
}

func TestAllow_RefillsAtRate(t *testing.T) {
	var now time.Time
	l := ratelimit.New(1 /* token/s */, 1 /* burst */).WithNow(func() time.Time { return now })
	now = time.Unix(0, 0)
	if !l.Allow("ip1") {
		t.Fatal("first call should consume the only token")
	}
	if l.Allow("ip1") {
		t.Fatal("second call (no refill) must be denied")
	}
	now = now.Add(2 * time.Second) // 2 tokens added, capped to burst=1
	if !l.Allow("ip1") {
		t.Fatal("after refill, call should succeed")
	}
}

func TestAllow_KeysIndependent(t *testing.T) {
	var now time.Time
	l := ratelimit.New(0.1, 1).WithNow(func() time.Time { return now })
	now = time.Unix(0, 0)
	if !l.Allow("ip1") {
		t.Fatal("ip1 first call should be allowed")
	}
	if !l.Allow("ip2") {
		t.Fatal("ip2 first call must be allowed independently")
	}
}

func TestMiddleware_Returns429OnExceeded(t *testing.T) {
	var now time.Time
	l := ratelimit.New(0.1, 1).WithNow(func() time.Time { return now })
	now = time.Unix(0, 0)
	keyFn := func(*http.Request) string { return "single-ip" }
	called := 0
	h := l.Middleware(keyFn)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(204) }))

	// First passes.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != 204 || called != 1 {
		t.Fatalf("first call: code=%d called=%d", w.Code, called)
	}

	// Second blocked.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second call: expected 429, got %d", w.Code)
	}
	if called != 1 {
		t.Fatalf("inner handler should not have been called again, was %d", called)
	}
	if w.Header().Get("Retry-After") != "1" {
		t.Fatal("Retry-After must be set")
	}
}

// TestMiddleware_Returns429JSON proves the 429 body is JSON-encoded via
// httpx.WriteJSON (Issue #159 / ADR-0005 Decision 5 point 4 — this used to
// be http.Error's text/plain, the only other non-2xx deviation from the
// scoreboard's "{"error": string}" contract besides view.portal's 500,
// which view_test.go's TestHandlerPortal_RenderFailureIsJSON now covers).
func TestMiddleware_Returns429JSON(t *testing.T) {
	var now time.Time
	l := ratelimit.New(0.1, 1).WithNow(func() time.Time { return now })
	now = time.Unix(0, 0)
	keyFn := func(*http.Request) string { return "single-ip" }
	h := l.Middleware(keyFn)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil)) // consume the burst

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status: got %d, want 429", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type: got %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v (body=%s)", err, w.Body.String())
	}
	if _, ok := body["error"]; !ok {
		t.Fatalf(`expected an "error" key in the body, got %v`, body)
	}
}

func TestClientIP_XForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.4, 10.0.0.1")
	if got := ratelimit.ClientIP(r); got != "203.0.113.4" {
		t.Fatalf("XFF leftmost: got %q", got)
	}
}

func TestClientIP_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.5.5.5:12345"
	if got := ratelimit.ClientIP(r); got != "10.5.5.5" {
		t.Fatalf("got %q", got)
	}
}

// TestClientIP_PriorityOrder is the ADR-0023 V1 table: CF-Connecting-IP
// (valid) wins over everything, an invalid/absent CF-Connecting-IP falls
// back to XFF leftmost (pre-ADR-0023 behavior, unchanged), and with neither
// present it falls back to RemoteAddr (also unchanged).
func TestClientIP_PriorityOrder(t *testing.T) {
	tests := []struct {
		name       string
		cfConnIP   string // "" = header not set
		xff        string // "" = header not set
		remoteAddr string
		want       string
	}{
		{
			name:       "valid CF-Connecting-IP alone wins",
			cfConnIP:   "198.51.100.9",
			remoteAddr: "10.0.0.1:1234",
			want:       "198.51.100.9",
		},
		{
			name:       "valid CF-Connecting-IP wins over XFF when both present",
			cfConnIP:   "198.51.100.9",
			xff:        "203.0.113.4, 10.0.0.1",
			remoteAddr: "10.0.0.1:1234",
			want:       "198.51.100.9",
		},
		{
			name:       "CF-Connecting-IP present but empty falls back to XFF",
			cfConnIP:   "",
			xff:        "203.0.113.4, 10.0.0.1",
			remoteAddr: "10.0.0.1:1234",
			want:       "203.0.113.4",
		},
		{
			name:       "CF-Connecting-IP syntactically invalid falls back to XFF",
			cfConnIP:   "not-an-ip",
			xff:        "203.0.113.4, 10.0.0.1",
			remoteAddr: "10.0.0.1:1234",
			want:       "203.0.113.4",
		},
		{
			name:       "CF-Connecting-IP whitespace-only falls back to XFF",
			cfConnIP:   "   ",
			xff:        "203.0.113.4, 10.0.0.1",
			remoteAddr: "10.0.0.1:1234",
			want:       "203.0.113.4",
		},
		{
			name:       "neither CF-Connecting-IP nor XFF falls back to RemoteAddr",
			remoteAddr: "10.5.5.5:12345",
			want:       "10.5.5.5",
		},
		{
			name:       "invalid CF-Connecting-IP and absent XFF falls back to RemoteAddr",
			cfConnIP:   "999.999.999.999",
			remoteAddr: "10.5.5.5:12345",
			want:       "10.5.5.5",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.cfConnIP != "" {
				r.Header.Set("CF-Connecting-IP", tc.cfConnIP)
			}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			r.RemoteAddr = tc.remoteAddr
			if got := ratelimit.ClientIP(r); got != tc.want {
				t.Fatalf("ClientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}
