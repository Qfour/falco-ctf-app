package ratelimit_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

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
		name string
		// setCF distinguishes "header not sent at all" from "header sent
		// with an empty value" (R2-F1, /review-5x — a prior version of this
		// table had a case NAMED "present but empty" that in fact never
		// called r.Header.Set at all, so it silently tested the same
		// absent-header path as the true absent case below it). Only
		// meaningful together with cfConnIP: setCF=true, cfConnIP="" sends
		// `CF-Connecting-IP: ` explicitly; setCF=false never touches the
		// header regardless of cfConnIP's value.
		setCF      bool
		cfConnIP   string
		xff        string // "" = header not set
		remoteAddr string
		want       string
	}{
		{
			name:       "valid CF-Connecting-IP alone wins",
			setCF:      true,
			cfConnIP:   "198.51.100.9",
			remoteAddr: "10.0.0.1:1234",
			want:       "198.51.100.9",
		},
		{
			name:       "valid CF-Connecting-IP wins over XFF when both present",
			setCF:      true,
			cfConnIP:   "198.51.100.9",
			xff:        "203.0.113.4, 10.0.0.1",
			remoteAddr: "10.0.0.1:1234",
			want:       "198.51.100.9",
		},
		{
			name:       "CF-Connecting-IP absent falls back to XFF",
			setCF:      false,
			xff:        "203.0.113.4, 10.0.0.1",
			remoteAddr: "10.0.0.1:1234",
			want:       "203.0.113.4",
		},
		{
			name:       "CF-Connecting-IP header present but empty falls back to XFF",
			setCF:      true,
			cfConnIP:   "",
			xff:        "203.0.113.4, 10.0.0.1",
			remoteAddr: "10.0.0.1:1234",
			want:       "203.0.113.4",
		},
		{
			name:       "CF-Connecting-IP syntactically invalid falls back to XFF",
			setCF:      true,
			cfConnIP:   "not-an-ip",
			xff:        "203.0.113.4, 10.0.0.1",
			remoteAddr: "10.0.0.1:1234",
			want:       "203.0.113.4",
		},
		{
			name:       "CF-Connecting-IP whitespace-only falls back to XFF",
			setCF:      true,
			cfConnIP:   "   ",
			xff:        "203.0.113.4, 10.0.0.1",
			remoteAddr: "10.0.0.1:1234",
			want:       "203.0.113.4",
		},
		{
			name:       "neither CF-Connecting-IP nor XFF falls back to RemoteAddr",
			setCF:      false,
			remoteAddr: "10.5.5.5:12345",
			want:       "10.5.5.5",
		},
		{
			name:       "invalid CF-Connecting-IP and absent XFF falls back to RemoteAddr",
			setCF:      true,
			cfConnIP:   "999.999.999.999",
			remoteAddr: "10.5.5.5:12345",
			want:       "10.5.5.5",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.setCF {
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

// TestClientIP_DoesNotRecordMetric proves ADR-0023 review R5-F2's fix: the
// plain ClientIP function (no Middleware wiring) must NOT touch
// ClientIPSourceTotal, since its whole purpose is to let a caller (e.g.
// csp_report.go's per-batch-entry log line) recompute the same value
// multiple times per request without inflating the counter that
// ClientIPKeyed's Middleware wiring already incremented once for that
// request.
func TestClientIP_DoesNotRecordMetric(t *testing.T) {
	before := testutil.ToFloat64(ratelimit.ClientIPSourceTotal.WithLabelValues("test-no-record", "cf_connecting_ip"))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "198.51.100.9")
	for i := 0; i < 5; i++ {
		if got := ratelimit.ClientIP(r); got != "198.51.100.9" {
			t.Fatalf("ClientIP() = %q, want 198.51.100.9", got)
		}
	}

	if after := testutil.ToFloat64(ratelimit.ClientIPSourceTotal.WithLabelValues("test-no-record", "cf_connecting_ip")); after != before {
		t.Fatalf("ClientIP must not record to ClientIPSourceTotal: before=%v after=%v", before, after)
	}
}

// TestClientIPKeyed_RecordsCallerAndSource is the ADR-0023 V5 minimal assert
// (review "F1 の label 追加後、counter が caller 別に増分することのテストを 1
// 本追加"): ClientIPKeyed(caller) must increment ClientIPSourceTotal exactly
// once per call, labelled with BOTH the caller name passed in and the
// source tier ClientIP actually used — proving the two labels are wired to
// the right dimensions, not swapped or dropped.
func TestClientIPKeyed_RecordsCallerAndSource(t *testing.T) {
	tests := []struct {
		name       string
		caller     string
		setCF      bool
		cfConnIP   string
		xff        string
		remoteAddr string
		wantIP     string
		wantSource string
	}{
		{
			name:       "cf_connecting_ip source",
			caller:     "test-caller-cf",
			setCF:      true,
			cfConnIP:   "198.51.100.10",
			remoteAddr: "10.0.0.1:1234",
			wantIP:     "198.51.100.10",
			wantSource: "cf_connecting_ip",
		},
		{
			name:       "x_forwarded_for source (falco_events-style fallback)",
			caller:     "test-caller-xff",
			xff:        "203.0.113.5",
			remoteAddr: "10.0.0.1:1234",
			wantIP:     "203.0.113.5",
			wantSource: "x_forwarded_for",
		},
		{
			name:       "remote_addr source",
			caller:     "test-caller-remote",
			remoteAddr: "10.5.5.6:12345",
			wantIP:     "10.5.5.6",
			wantSource: "remote_addr",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := testutil.ToFloat64(ratelimit.ClientIPSourceTotal.WithLabelValues(tc.caller, tc.wantSource))

			r := httptest.NewRequest("GET", "/", nil)
			if tc.setCF {
				r.Header.Set("CF-Connecting-IP", tc.cfConnIP)
			}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			r.RemoteAddr = tc.remoteAddr

			keyFn := ratelimit.ClientIPKeyed(tc.caller)
			if got := keyFn(r); got != tc.wantIP {
				t.Fatalf("ClientIPKeyed(%q)(r) = %q, want %q", tc.caller, got, tc.wantIP)
			}

			after := testutil.ToFloat64(ratelimit.ClientIPSourceTotal.WithLabelValues(tc.caller, tc.wantSource))
			if after != before+1 {
				t.Fatalf("ClientIPSourceTotal{caller=%q,source=%q}: before=%v after=%v, want +1", tc.caller, tc.wantSource, before, after)
			}

			// A DIFFERENT caller/source label pair must not have moved —
			// proves the labels are attributed to the right series, not
			// just "some" series incrementing.
			other := testutil.ToFloat64(ratelimit.ClientIPSourceTotal.WithLabelValues(tc.caller, "unused-source-for-this-case"))
			if other != 0 {
				t.Fatalf("unrelated label combination must stay at 0, got %v", other)
			}
		})
	}
}

// --- app#315: identity-keyed, fail-closed buckets (MiddlewareStrict) ---------

func identityReq(email string) *http.Request {
	r := httptest.NewRequest("POST", "/", nil)
	if email != "" {
		r.Header.Set(ratelimit.IdentityHeader, email)
	}
	return r
}

func TestIdentityKeyed(t *testing.T) {
	for _, c := range []struct {
		name, header string
		want         string
		wantOK       bool
	}{
		{"plain email", "alice@ctf.local", "alice@ctf.local", true},
		{"lower-cased and trimmed", "  Alice@CTF.local ", "alice@ctf.local", true},
		{"missing header", "", "", false},
		{"blank header is not an identity", "   ", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", nil)
			if c.header != "" {
				r.Header.Set(ratelimit.IdentityHeader, c.header)
			}
			got, ok := ratelimit.IdentityKeyed(r)
			if got != c.want || ok != c.wantOK {
				t.Fatalf("IdentityKeyed(%q) = (%q, %v), want (%q, %v)", c.header, got, ok, c.want, c.wantOK)
			}
		})
	}
}

// Two identities behind the SAME client IP get independent buckets: this is
// the whole point of app#315 (venue NAT).
func TestMiddlewareStrict_SameIPDifferentIdentitiesAreIndependent(t *testing.T) {
	now := time.Unix(0, 0)
	l := ratelimit.New(0.1, 2).WithNow(func() time.Time { return now })
	h := l.MiddlewareStrict("test_same_ip", ratelimit.IdentityKeyed)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	do := func(email string) int {
		r := identityReq(email)
		r.RemoteAddr = "203.0.113.7:1234" // the one shared NAT address
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 2; i++ {
		if c := do("alice@ctf.local"); c != 204 {
			t.Fatalf("alice burst[%d]: got %d, want 204", i, c)
		}
	}
	if c := do("alice@ctf.local"); c != http.StatusTooManyRequests {
		t.Fatalf("alice past burst: got %d, want 429", c)
	}
	if c := do("bob@ctf.local"); c != 204 {
		t.Fatalf("bob (same IP, other identity) must have his own bucket: got %d, want 204", c)
	}
}

// A request with no identity is 403, runs no handler, and consumes NO token —
// including from a bucket that another identity could otherwise be draining.
// It must never degrade to "unlimited" (Middleware's empty-key pass-through).
func TestMiddlewareStrict_NoIdentityIsDeniedAndConsumesNothing(t *testing.T) {
	now := time.Unix(0, 0)
	l := ratelimit.New(0.1, 1).WithNow(func() time.Time { return now })
	called := 0
	h := l.MiddlewareStrict("test_no_identity", ratelimit.IdentityKeyed)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(204) }))
	before := testutil.ToFloat64(ratelimit.IdentityRequestsTotal.WithLabelValues("test_no_identity", "no_identity"))
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, identityReq(""))
		if w.Code != http.StatusForbidden {
			t.Fatalf("header-less call %d: got %d, want 403 body=%s", i, w.Code, w.Body)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] == nil {
			t.Fatalf("403 body must be the {\"error\":...} JSON shape, got %q (%v)", w.Body, err)
		}
	}
	if called != 0 {
		t.Fatalf("handler ran %d times for header-less requests, want 0", called)
	}
	// The (only) token of a real identity is untouched by the anonymous flood.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, identityReq("alice@ctf.local"))
	if w.Code != 204 {
		t.Fatalf("alice after anonymous flood: got %d, want 204", w.Code)
	}
	if d := testutil.ToFloat64(ratelimit.IdentityRequestsTotal.WithLabelValues("test_no_identity", "no_identity")) - before; d != 50 {
		t.Fatalf("no_identity metric delta = %v, want 50", d)
	}
}

// An empty key with ok=true (a buggy KeyFunc) is still a deny, not unlimited.
func TestMiddlewareStrict_EmptyKeyIsDenied(t *testing.T) {
	l := ratelimit.New(1, 1)
	h := l.MiddlewareStrict("test_empty_key", func(*http.Request) (string, bool) { return "", true })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, identityReq("alice@ctf.local"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("empty key must be denied, got %d", w.Code)
	}
}

func TestMiddlewareStrict_429IsJSONWithRetryAfterAndMetric(t *testing.T) {
	now := time.Unix(0, 0)
	l := ratelimit.New(0.1, 1).WithNow(func() time.Time { return now })
	h := l.MiddlewareStrict("test_429", ratelimit.IdentityKeyed)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	// IdentityRequestsTotal is a process-global counter: assert deltas, not
	// absolutes, so the test survives -count>1 and other tests sharing a bucket.
	before := map[string]float64{}
	for _, outcome := range []string{"allowed", "limited"} {
		before[outcome] = testutil.ToFloat64(ratelimit.IdentityRequestsTotal.WithLabelValues("test_429", outcome))
	}
	h.ServeHTTP(httptest.NewRecorder(), identityReq("alice@ctf.local"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, identityReq("alice@ctf.local"))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "1" ||
		w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("429 shape: code=%d retry-after=%q ct=%q", w.Code, w.Header().Get("Retry-After"), w.Header().Get("Content-Type"))
	}
	for outcome, want := range map[string]float64{"allowed": 1, "limited": 1} {
		if got := testutil.ToFloat64(ratelimit.IdentityRequestsTotal.WithLabelValues("test_429", outcome)) - before[outcome]; got != want {
			t.Fatalf("metric bucket=test_429 outcome=%s delta = %v, want %v", outcome, got, want)
		}
	}
}

// --- app#387: sampled Warn line for no-identity denials ----------------------

// denyLogLines decodes the JSON log buffer into one map per emitted line.
func denyLogLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("log line is not JSON: %q (%v)", ln, err)
		}
		out = append(out, m)
	}
	return out
}

func denyReq(path, pattern, remote string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest("POST", path, nil)
	r.Pattern = pattern
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestMiddlewareStrict_NoIdentityLogsWarnWithoutIdentityOrPath(t *testing.T) {
	now := time.Unix(1000, 0)
	var buf bytes.Buffer
	l := ratelimit.New(1, 10).WithNow(func() time.Time { return now }).
		WithLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
	h := l.MiddlewareStrict("test_log", ratelimit.IdentityKeyed)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))

	// header absent
	h.ServeHTTP(httptest.NewRecorder(), denyReq("/api/users/victim/x", "POST /api/users/{user}/x", "10.1.2.3:51000", nil))
	lines := denyLogLines(t, &buf)
	if len(lines) != 1 {
		t.Fatalf("want 1 log line, got %d: %s", len(lines), buf.String())
	}
	got := lines[0]
	want := map[string]any{
		"level": "WARN", "bucket": "test_log", "route": "POST /api/users/{user}/x",
		"remote_addr": "10.1.2.3", "reason": "no_identity", "suppressed": float64(0),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("log[%q] = %v, want %v (line: %s)", k, got[k], v, buf.String())
		}
	}
	if strings.Contains(buf.String(), "victim") {
		t.Errorf("the URL path (participant name) leaked into the log: %s", buf.String())
	}

	// header present but blank -> empty_identity (after the sampling window)
	now = now.Add(denyWindow)
	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), denyReq("/", "", "[::1]:1", map[string]string{ratelimit.IdentityHeader: "   "}))
	lines = denyLogLines(t, &buf)
	if len(lines) != 1 || lines[0]["reason"] != "empty_identity" || lines[0]["route"] != "-" || lines[0]["remote_addr"] != "::1" {
		t.Fatalf("blank header: got %s", buf.String())
	}
}

// A keyFn that denies a request that DOES carry an identity header (e.g. a
// future stricter keyFn) must still never put the header value in the log.
func TestMiddlewareStrict_NoIdentityLogNeverContainsHeaderValue(t *testing.T) {
	var buf bytes.Buffer
	l := ratelimit.New(1, 10).WithLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
	h := l.MiddlewareStrict("test_leak", func(*http.Request) (string, bool) { return "", false })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	h.ServeHTTP(httptest.NewRecorder(), denyReq("/", "POST /p", "10.0.0.1:1",
		map[string]string{ratelimit.IdentityHeader: "secret.person@ctf.local", "Cookie": "sess=abc"}))
	if buf.Len() == 0 {
		t.Fatal("expected a log line")
	}
	for _, bad := range []string{"secret.person", "ctf.local", "sess=abc"} {
		if strings.Contains(buf.String(), bad) {
			t.Errorf("log contains %q: %s", bad, buf.String())
		}
	}
}

// denyWindow mirrors the package's 10s sampling interval (unexported); the
// sampling test below fails loudly if the two drift apart.
const denyWindow = 10 * time.Second

func TestMiddlewareStrict_NoIdentityLogIsSampledPerBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	var buf bytes.Buffer
	lg := slog.New(slog.NewJSONHandler(&buf, nil))
	clock := func() time.Time { return now }
	l := ratelimit.New(1, 10).WithNow(clock).WithLogger(lg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	a := l.MiddlewareStrict("bucket_a", ratelimit.IdentityKeyed)(next)
	b := l.MiddlewareStrict("bucket_b", ratelimit.IdentityKeyed)(next)
	deny := func(h http.Handler, n int) {
		for i := 0; i < n; i++ {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, denyReq("/", "POST /p", "10.0.0.1:1", nil))
			if w.Code != http.StatusForbidden {
				t.Fatalf("got %d, want 403", w.Code)
			}
		}
	}
	metricBefore := testutil.ToFloat64(ratelimit.IdentityRequestsTotal.WithLabelValues("bucket_a", "no_identity"))

	deny(a, 25) // 25 denials in one instant -> exactly one line
	if n := len(denyLogLines(t, &buf)); n != 1 {
		t.Fatalf("25 denials in the window: %d lines, want 1\n%s", n, buf.String())
	}
	now = now.Add(denyWindow - time.Second) // still inside the window
	deny(a, 5)
	if n := len(denyLogLines(t, &buf)); n != 1 {
		t.Fatalf("inside the window: %d lines, want 1", n)
	}
	deny(b, 1) // another bucket is not throttled by a's window
	if n := len(denyLogLines(t, &buf)); n != 2 {
		t.Fatalf("bucket_b first denial: %d lines, want 2", n)
	}
	now = now.Add(time.Second) // window elapsed for a
	deny(a, 1)
	lines := denyLogLines(t, &buf)
	if len(lines) != 3 {
		t.Fatalf("after the window: %d lines, want 3\n%s", len(lines), buf.String())
	}
	last := lines[2]
	if last["bucket"] != "bucket_a" || last["suppressed"] != float64(29) { // 24 + 5 swallowed
		t.Fatalf("resumed line = %v, want bucket_a suppressed=29", last)
	}
	// Sampling is log-only: the metric still counts every denial (25+5+1).
	if d := testutil.ToFloat64(ratelimit.IdentityRequestsTotal.WithLabelValues("bucket_a", "no_identity")) - metricBefore; d != 31 {
		t.Fatalf("metric delta = %v, want 31", d)
	}
}
