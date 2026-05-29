package ratelimit_test

import (
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
