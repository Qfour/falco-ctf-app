package collector

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// upstreamRecorder is a stand-in scoreboard that records the method + path it
// was called with and returns a canned body, so tests can assert exactly what
// the collector forwarded.
type upstreamRecorder struct {
	mu       sync.Mutex
	calls    []string // "METHOD PATH"
	lastXFF  string   // X-Forwarded-For as seen by the upstream on the last call
	lastReal string   // X-Real-IP as seen by the upstream on the last call
	lastCFIP string   // CF-Connecting-IP as seen by the upstream on the last call
	lastCT   string   // Content-Type as seen by the upstream on the last call
	lastAuth []string // X-Auth-Request-* header names as seen by the upstream on the last call
}

func (u *upstreamRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.calls = append(u.calls, r.Method+" "+r.URL.Path)
		u.lastXFF = r.Header.Get("X-Forwarded-For")
		u.lastReal = r.Header.Get("X-Real-IP")
		u.lastCFIP = r.Header.Get("CF-Connecting-IP")
		u.lastCT = r.Header.Get("Content-Type")
		u.lastAuth = nil
		for k := range r.Header {
			if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Auth-Request-") {
				u.lastAuth = append(u.lastAuth, k)
			}
		}
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

func (u *upstreamRecorder) forwardedHeaders() (xff, real string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastXFF, u.lastReal
}

func (u *upstreamRecorder) lastCFConnectingIP() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastCFIP
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

// TestExfil_ForwardAddsNoProxyIdentity pins the collector side of the
// scoreboard's internal-only exfil sink: the sink 403s any request carrying an
// X-Auth-Request-* header and 415s a non-JSON body, so the collector must never
// ADD an identity header on the rewritten forward and must pass the
// participant curl's Content-Type through untouched.
func TestExfil_ForwardAddsNoProxyIdentity(t *testing.T) {
	c, up := newTestCollector(t)
	resp := do(t, "POST", c.URL+"/api/challenges/10-final-exfil/exfil", `{"user":"alice","flag":"FALCO{x}"}`)
	resp.Body.Close()
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.lastAuth) != 0 {
		t.Fatalf("collector forwarded X-Auth-Request-* headers %v on a header-less exfil", up.lastAuth)
	}
	if up.lastCT != "application/json" {
		t.Fatalf("upstream Content-Type = %q, want application/json passed through", up.lastCT)
	}
}

// outOfGrammarCIDs are path segments outside the challenge-id grammar that a
// client can still put in a URL (percent-encoded where needed).
func outOfGrammarCIDs() map[string]string {
	return map[string]string{
		"4096 characters":   strings.Repeat("a", 4096),
		"upper case":        "01-Recon",
		"dot":               "01-a.b",
		"encoded space":     "01-a%20b",
		"no digits":         "verify-probe",
		"one digit":         "9-verify-probe",
		"61-char slug":      "01-" + strings.Repeat("a", 61),
		"path traversal":    "..%2f..%2finternal",
		"encoded slash":     "01-a%2fb",
		"non-UTF-8 bytes":   "%ff%fe",
		"trailing newline":  "01-a%0a",
		"internal prefix":   "internal",
		"unrelated segment": "%00",
	}
}

// assertFixedUnknown holds the collector's own answer for an id outside the
// grammar: 404 and the fixed body, nothing of the input echoed.
func assertFixedUnknown(t *testing.T, name string, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("%s: status = %d body=%.120s, want 404", name, resp.StatusCode, b)
	}
	if got, want := strings.TrimSpace(string(b)), `{"error":"unknown challenge"}`; got != want {
		t.Fatalf("%s: body = %.120s, want the fixed %s", name, got, want)
	}
}

// An id outside the grammar is answered 404 by the collector and never reaches
// the scoreboard, on exfil as on submit (ADR-0041: one rule for both).
func TestExfil_OutOfGrammarCID_Fixed404NotForwarded(t *testing.T) {
	for name, cid := range outOfGrammarCIDs() {
		// A collector per case: the per-IP budget (burst 10) must not turn a
		// later case into a 429 that hides what is being pinned.
		c, up := newTestCollector(t)
		assertFixedUnknown(t, "exfil "+name, do(t, "POST", c.URL+"/api/challenges/"+cid+"/exfil", `{}`))
		if up.last() != "" {
			t.Fatalf("exfil %s: upstream should not have been called, got %q", name, up.last())
		}
	}
}

func TestSubmit_OutOfGrammarCID_Fixed404NotForwarded(t *testing.T) {
	for name, cid := range outOfGrammarCIDs() {
		// A collector per case: the per-IP budget (burst 10) must not turn a
		// later case into a 429 that hides what is being pinned.
		c, up := newTestCollector(t)
		assertFixedUnknown(t, "submit "+name, do(t, "POST", c.URL+"/api/challenges/"+cid+"/submit", `{"user":"user1","flag":"FALCO{x}"}`))
		if up.last() != "" {
			t.Fatalf("submit %s: upstream should not have been called, got %q", name, up.last())
		}
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

// TestDisplayName_NotForwarded pins ADR-0034 D12 / S1: the participant
// display-name write (the workspace's `setname`) is no longer fronted, so the
// collector default-denies it — 404/405 at the mux, never reaching the
// upstream — for every shape `setname` used (JSON body, header-less) and for a
// forged X-Auth-Request-Email. A participant now sets display name and avatar
// through the authenticated profile route on the portal origin.
func TestDisplayName_NotForwarded(t *testing.T) {
	c, up := newTestCollector(t)
	for _, hdr := range []map[string]string{nil, {"X-Auth-Request-Email": "admin@ctf.local"}} {
		req, _ := http.NewRequest("POST", c.URL+"/api/users/alice/display-name", strings.NewReader(`{"name":"Alice"}`))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST display-name (headers %v): status = %d, want 404/405 (default-deny)", hdr, resp.StatusCode)
		}
	}
	if up.last() != "" {
		t.Fatalf("display-name must not reach upstream, got %q", up.last())
	}
}

// TestMeRead_NotForwarded proves the progress READ route is default-denied at
// the collector (P18): GET /api/users/{user}/me is anonymous + self-claimed, so
// it must NOT be fronted here. It 404s at the mux and never reaches the upstream.
// Progress is viewed only on the browser journey host (self-scope gated).
func TestMeRead_NotForwarded(t *testing.T) {
	c, up := newTestCollector(t)
	resp := do(t, "GET", c.URL+"/api/users/alice/me", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /me status = %d, want 404/405 (route removed, default-deny)", resp.StatusCode)
	}
	if up.last() != "" {
		t.Fatalf("GET /me must not reach upstream, got %q", up.last())
	}
}

// TestDefaultDeny_BlockedRoutes ensures the collector never forwards the
// ingest, admin, internal, or state surface of the scoreboard.
func TestDefaultDeny_BlockedRoutes(t *testing.T) {
	h, up := newMethodHandler(t)
	blocked := []struct {
		method, path string
	}{
		{"POST", "/falco/events"},
		{"POST", "/internal/exfil/10-final-exfil"},
		{"POST", "/api/admin/reset"},
		{"GET", "/api/state"},
		{"GET", "/"},
		{"GET", "/api/users/alice/me"},            // progress read is not fronted (P18)
		{"POST", "/api/users/alice/display-name"}, // setname's forward, removed in ADR-0034 S1
	}
	for i, b := range blocked {
		// One connection address per entry: the default-deny surface has a per-IP
		// budget (burst 10), and this test is about what is refused, not about how
		// many refusals fit in the burst. Sharing one address would turn an 11th
		// entry into a 429 and fail with an unrelated message.
		w := serve(h, b.method, b.path, fmt.Sprintf("10.70.0.%d", i+1))
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status = %d, want 404/405 (default-deny)", b.method, b.path, w.Code)
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

// TestRateLimit_XFFSpoofDoesNotBypass proves the [MED] finding is fixed: a
// caller rotating X-Forwarded-For on every request (a fresh forged IP each time)
// must NOT escape the per-IP budget, because the collector keys on r.RemoteAddr
// (the real connection), not the participant-supplied XFF. All 12 requests come
// from the same loopback connection, so the 11th+ still 429s.
func TestRateLimit_XFFSpoofDoesNotBypass(t *testing.T) {
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
		// A different forged source IP on each request — if the limiter trusted
		// XFF this would mint a fresh bucket every time and never throttle.
		req.Header.Set("X-Forwarded-For", "203.0.113."+strconv.Itoa(i))
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
		t.Fatal("XFF rotation bypassed the per-IP limit — limiter must key on RemoteAddr, not XFF")
	}
}

// TestForward_StripsInboundForwardingHeaders proves the collector removes
// participant-controlled X-Forwarded-For / X-Real-IP before forwarding, so the
// downstream scoreboard limiter can't be fooled either. The upstream must NOT
// see the spoofed values; ReverseProxy re-adds XFF = the real RemoteAddr.
func TestForward_StripsInboundForwardingHeaders(t *testing.T) {
	c, up := newTestCollector(t)
	req, _ := http.NewRequest("POST", c.URL+"/api/challenges/10-final-exfil/submit", strings.NewReader(`{}`))
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Real-IP", "203.0.113.7")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	xff, real := up.forwardedHeaders()
	if strings.Contains(xff, "203.0.113.7") {
		t.Errorf("spoofed X-Forwarded-For leaked to upstream: %q", xff)
	}
	if real != "" {
		t.Errorf("X-Real-IP must be stripped, upstream saw %q", real)
	}
	// ReverseProxy appends the genuine connection IP (loopback in the test).
	if xff == "" {
		t.Error("expected ReverseProxy to set X-Forwarded-For to the real RemoteAddr")
	}
}

// TestForward_StripsCFConnectingIP proves the ADR-0023 D1b fix: the collector
// removes a participant-controlled CF-Connecting-IP before forwarding. Without
// this strip, a workspace could send an arbitrary CF-Connecting-IP on every
// request through the collector's submit/exfil forward and — since
// ratelimit.ClientIP now trusts CF-Connecting-IP first (ADR-0023 D1) — mint a
// fresh rate-limit key per request, bypassing the scoreboard's per-route
// submit budget entirely (security-engineer HIGH finding).
//
// Mutation check (ADR-0023 V4, V8-style, reported not committed): commenting
// out the `req.Header.Del("CF-Connecting-IP")` line in collector.go's
// Director turns this test red — the upstream then observes the spoofed
// value verbatim, proving the assertion actually exercises the strip.
func TestForward_StripsCFConnectingIP(t *testing.T) {
	c, up := newTestCollector(t)
	req, _ := http.NewRequest("POST", c.URL+"/api/challenges/10-final-exfil/submit", strings.NewReader(`{}`))
	req.Header.Set("CF-Connecting-IP", "198.51.100.42")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if got := up.lastCFConnectingIP(); got != "" {
		t.Fatalf("spoofed CF-Connecting-IP leaked to upstream: %q", got)
	}
}

// TestForward_StripsCFConnectingIP_Exfil is the same assertion as
// TestForward_StripsCFConnectingIP but for the other participant forward: the
// exfil drop is rewritten to the scoreboard's internal sink but still goes
// through the same proxy Director, and a forged CF-Connecting-IP there would
// mint a rate-limit key per request just like on submit. (Before ADR-0034 S1
// this slot covered the display-name forward, which no longer exists.)
func TestForward_StripsCFConnectingIP_Exfil(t *testing.T) {
	c, up := newTestCollector(t)
	req, _ := http.NewRequest("POST", c.URL+"/api/challenges/10-final-exfil/exfil", strings.NewReader(`{"user":"alice","flag":"FALCO{x}"}`))
	req.Header.Set("CF-Connecting-IP", "198.51.100.42")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if got := up.lastCFConnectingIP(); got != "" {
		t.Fatalf("spoofed CF-Connecting-IP leaked to upstream: %q", got)
	}
	if got, want := up.last(), "POST /internal/exfil/10-final-exfil"; got != want {
		t.Fatalf("upstream call = %q, want %q (the strip test must actually reach the exfil rewrite)", got, want)
	}
}

// TestRateLimit_CFConnectingIPSpoofDoesNotBypass is the CF-Connecting-IP
// analogue of TestRateLimit_XFFSpoofDoesNotBypass: rotating CF-Connecting-IP
// on every request must not let a caller escape the collector's own per-IP
// budget, because the collector's limiter is keyed on remoteIP (RemoteAddr),
// a function independent of ratelimit.ClientIP (ADR-0023 V4 point 3 — this
// also regression-covers that remoteIP itself was not accidentally changed
// to consult CF-Connecting-IP).
func TestRateLimit_CFConnectingIPSpoofDoesNotBypass(t *testing.T) {
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
		// A different forged CF-Connecting-IP on each request — if the
		// collector's own limiter trusted it, this would mint a fresh bucket
		// every time and never throttle.
		req.Header.Set("CF-Connecting-IP", "198.51.100."+strconv.Itoa(i))
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
		t.Fatal("CF-Connecting-IP rotation bypassed the collector's per-IP limit — remoteIP must ignore it")
	}
}

func TestNew_BadUpstream(t *testing.T) {
	if _, err := New("http://[::1]:namedport", testLogger()); err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
}
