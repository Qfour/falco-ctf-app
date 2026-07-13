package collector

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// upstreamRecorder is a stand-in scoreboard that records the method + path it
// was called with and returns a canned body, so tests can assert exactly what
// the collector forwarded.
type upstreamRecorder struct {
	mu    sync.Mutex
	calls []string // "METHOD PATH"
}

func (u *upstreamRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.calls = append(u.calls, r.Method+" "+r.URL.Path)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"upstream":true,"path":"`+r.URL.Path+`"}`)
	})
}

func (u *upstreamRecorder) last() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.calls) == 0 {
		return ""
	}
	return u.calls[len(u.calls)-1]
}

// newTestCollector wires a collector at a fixed clock (rate-limit burst never
// refills mid-test) in front of a recording upstream.
func newTestCollector(t *testing.T) (*httptest.Server, *upstreamRecorder) {
	t.Helper()
	up := &upstreamRecorder{}
	upSrv := httptest.NewServer(up.handler())
	t.Cleanup(upSrv.Close)

	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	h, err := New(upSrv.URL, testLogger(), WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cSrv := httptest.NewServer(h)
	t.Cleanup(cSrv.Close)
	return cSrv, up
}

func do(t *testing.T, method, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	// Distinct source IP per subtest run keeps the shared burst budget clean.
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, url, err)
	}
	return resp
}

func TestExfil_RewrittenToInternalSink(t *testing.T) {
	c, up := newTestCollector(t)
	resp := do(t, "POST", c.URL+"/api/challenges/10-final-exfil/exfil", `{"user":"alice","flag":"FALCO{x}"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got, want := up.last(), "POST /internal/exfil/10-final-exfil"; got != want {
		t.Fatalf("upstream call = %q, want %q", got, want)
	}
}

func TestExfil_InvalidCID_Rejected(t *testing.T) {
	c, up := newTestCollector(t)
	// Path-traversal attempt must not reach the upstream at all.
	resp := do(t, "POST", c.URL+"/api/challenges/..%2f..%2finternal/exfil", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 400/404", resp.StatusCode)
	}
	if up.last() != "" {
		t.Fatalf("upstream should not have been called, got %q", up.last())
	}
}

func TestSubmit_ForwardedTransparently(t *testing.T) {
	c, up := newTestCollector(t)
	resp := do(t, "POST", c.URL+"/api/challenges/10-final-exfil/submit", `{"user":"alice","flag":"FALCO{x}"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got, want := up.last(), "POST /api/challenges/10-final-exfil/submit"; got != want {
		t.Fatalf("upstream call = %q, want %q", got, want)
	}
}

func TestMeAndDisplayName_Forwarded(t *testing.T) {
	c, up := newTestCollector(t)
	r1 := do(t, "GET", c.URL+"/api/users/alice/me", "")
	r1.Body.Close()
	if got := up.last(); got != "GET /api/users/alice/me" {
		t.Fatalf("me forward = %q", got)
	}
	r2 := do(t, "POST", c.URL+"/api/users/alice/display-name", `{"name":"Alice"}`)
	r2.Body.Close()
	if got := up.last(); got != "POST /api/users/alice/display-name" {
		t.Fatalf("display-name forward = %q", got)
	}
}

// TestDefaultDeny_BlockedRoutes ensures the collector never forwards the
// ingest, admin, internal, or state surface of the scoreboard.
func TestDefaultDeny_BlockedRoutes(t *testing.T) {
	c, up := newTestCollector(t)
	blocked := []struct {
		method, path string
	}{
		{"POST", "/falco/events"},
		{"POST", "/internal/exfil/10-final-exfil"},
		{"POST", "/api/admin/reset"},
		{"POST", "/api/admin/hints"},
		{"GET", "/api/state"},
		{"GET", "/api/hints"},
		{"GET", "/"},
	}
	for _, b := range blocked {
		resp := do(t, b.method, c.URL+b.path, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status = %d, want 404/405 (default-deny)", b.method, b.path, resp.StatusCode)
		}
	}
	if up.last() != "" {
		t.Fatalf("no blocked route may reach upstream, got %q", up.last())
	}
}

func TestHealthz_LocalNotForwarded(t *testing.T) {
	c, up := newTestCollector(t)
	resp := do(t, "GET", c.URL+"/healthz", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	if up.last() != "" {
		t.Fatalf("healthz must be served locally, upstream got %q", up.last())
	}
}

// TestRateLimit_PerIP confirms the collector enforces the same 1req/s burst-10
// budget as /submit: the 11th request from one IP within the frozen clock is
// throttled.
func TestRateLimit_PerIP(t *testing.T) {
	up := &upstreamRecorder{}
	upSrv := httptest.NewServer(up.handler())
	defer upSrv.Close()

	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	h, err := New(upSrv.URL, testLogger(), WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := httptest.NewServer(h)
	defer c.Close()

	var got429 bool
	for i := 0; i < 12; i++ {
		req, _ := http.NewRequest("POST", c.URL+"/api/challenges/10-final-exfil/submit", strings.NewReader(`{}`))
		req.Header.Set("X-Forwarded-For", "10.9.9.9")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("expected a 429 after exceeding burst 10")
	}
}

func TestNew_BadUpstream(t *testing.T) {
	if _, err := New("http://[::1]:namedport", testLogger()); err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
}
