package collector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// durationSeries returns the series of collector_request_duration_seconds as
// "route|method|status" -> observation count, read through a fresh registry so
// the package-global vector is not touched.
func durationSeries(t *testing.T) map[string]uint64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(forwardDuration)
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]uint64{}
	for _, f := range fams {
		for _, m := range f.GetMetric() {
			l := map[string]string{}
			for _, p := range m.GetLabel() {
				l[p.GetName()] = p.GetValue()
			}
			out[l["route"]+"|"+l["method"]+"|"+l["status"]] += m.GetHistogram().GetSampleCount()
		}
	}
	return out
}

func newMethodHandler(t *testing.T) (*Handler, *upstreamRecorder) {
	h, up, _ := newMethodHandlerClock(t)
	return h, up
}

// newMethodHandlerClock also returns a function that advances the handler's clock.
func newMethodHandlerClock(t *testing.T) (*Handler, *upstreamRecorder, func(time.Duration)) {
	t.Helper()
	up := &upstreamRecorder{}
	upSrv := httptest.NewServer(up.handler())
	t.Cleanup(upSrv.Close)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	h, err := New(upSrv.URL, testLogger(), WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, up, func(d time.Duration) { now = now.Add(d) }
}

// serve runs one request through ServeHTTP. The request is built by hand
// because httptest.NewRequest panics on a method that is not a valid token,
// and the point is to hand the handler whatever a caller could name. ip is the
// connection address (the rate-limit key).
func serve(h *Handler, method, path, ip string) *httptest.ResponseRecorder {
	r := &http.Request{
		Method: method, URL: &url.URL{Path: path}, Host: "collector",
		Header: http.Header{}, Body: http.NoBody, RemoteAddr: ip + ":4000",
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// fiftyMethods: FOO1..FOO50, a method far longer than any real one, a
// non-ASCII one, and one that is not valid UTF-8 (the metrics client panics on
// an invalid label value, so the fold must keep it out of a label).
// tag keeps the methods of one subtest apart from another's: the vector is
// package-global, so a repeated name would reuse a series and hide a missing fold.
func fiftyMethods(tag string) []string {
	ms := make([]string, 0, 53)
	for i := 1; i <= 50; i++ {
		ms = append(ms, fmt.Sprintf("FOO%d%s", i, tag))
	}
	return append(ms, "LONG"+tag+strings.Repeat("X", 4096), "メソッド"+tag, "\xff\xfe"+tag)
}

func TestMethodLabel(t *testing.T) {
	tests := []struct {
		name, route, method, want string
	}{
		{"declared POST", "POST /api/challenges/{cid}/submit", "POST", "POST"},
		{"declared GET", "GET /healthz", "GET", "GET"},
		{"HEAD is served from a GET pattern and keeps its value", "GET /healthz", "HEAD", "HEAD"},
		{"a method the route does not declare", "GET /healthz", "FOO1", "other"},
		{"POST on a GET route (405)", "GET /healthz", "POST", "other"},
		{"HEAD on a POST route", "POST /api/challenges/{cid}/submit", "HEAD", "other"},
		{"nothing matched", "", "POST", "other"},
		{"nothing matched, invented method", "", "FOO1", "other"},
		{"invalid UTF-8 never reaches a label", "", "\xff\xfe", "other"},
		{"a pattern without a method is not trusted", "/healthz", "GET", "other"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := methodLabel(tc.route, tc.method); got != tc.want {
				t.Fatalf("methodLabel(%q, %q) = %q, want %q", tc.route, tc.method, got, tc.want)
			}
		})
	}
}

// Fifty-odd distinct methods, on the default-deny surface (404), on a known path
// with the wrong method (405) and on a known route with a method the route does
// not declare, add at most one series each: all of them fold into "other".
func TestRequestDurationMethodIsFoldedIntoOneLabelValue(t *testing.T) {
	surfaces := []struct {
		name, path string
		lo, hi     int // the status must be in [lo, hi)
	}{
		{"default-deny path (404)", "/api/state", 404, 405},
		{"known GET path, other method (405)", "/healthz", 405, 406},
		{"known POST route, other method (405)", "/api/challenges/10-final-exfil/submit", 405, 406},
		// net/http's redirect for a cleaned path: which 3xx it is depends on the
		// method and on the Go version, so the test takes the class.
		{"a path net/http would redirect, other method (3xx)", "//healthz", 300, 400},
	}
	for k, s := range surfaces {
		tag := strings.Repeat("T", k)
		t.Run(s.name, func(t *testing.T) {
			h, _ := newMethodHandler(t)
			before := durationSeries(t)
			for i, m := range fiftyMethods(tag) {
				// A distinct connection address per request keeps the default-deny
				// limiter out of the way: this test is about the label.
				w := serve(h, m, s.path, fmt.Sprintf("10.20.%d.%d", i/250, i%250+1))
				if w.Code < s.lo || w.Code >= s.hi {
					t.Fatalf("%.12q %s: status=%d body=%.80s, want [%d, %d)", m, s.path, w.Code, w.Body.String(), s.lo, s.hi)
				}
			}
			after := durationSeries(t)
			added := 0
			for k := range after {
				if _, ok := before[k]; ok {
					continue
				}
				added++
				if parts := strings.Split(k, "|"); len(parts) != 3 || parts[1] != "other" {
					t.Fatalf("a new series %.60q appeared; only method=other may", k)
				}
			}
			if added > 1 {
				t.Fatalf("%d new series for %d methods, want at most 1", added, len(fiftyMethods(tag)))
			}
		})
	}
}

// The label values of the routes the collector serves are unchanged.
func TestRequestDurationDeclaredMethodsKeepTheirLabels(t *testing.T) {
	h, _ := newMethodHandler(t)
	before := durationSeries(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/healthz"}, {"HEAD", "/healthz"}, {"POST", "/api/challenges/10-final-exfil/submit"},
		{"POST", "/api/challenges/10-final-exfil/exfil"},
	} {
		if w := serve(h, c.method, c.path, "10.30.0.1"); w.Code != http.StatusOK {
			t.Fatalf("%s %s: status=%d body=%.80s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	after := durationSeries(t)
	for _, k := range []string{
		"GET /healthz|GET|200", "GET /healthz|HEAD|200",
		"POST /api/challenges/{cid}/submit|POST|200", "POST /api/challenges/{cid}/exfil|POST|200",
	} {
		if after[k] != before[k]+1 {
			t.Fatalf("series %q rose by %d, want 1 (a declared route keeps its labels)", k, after[k]-before[k])
		}
	}
}

// The default-deny surface has a per-IP budget of its own (same rate and key as
// submit/exfil): the 11th unmatched request of one connection address is 429,
// forging X-Forwarded-For does not help, another address is unaffected, and it
// does not spend the submit budget (nor does submit spend it).
func TestDefaultDeny_PerIPLimit(t *testing.T) {
	h, _, advance := newMethodHandlerClock(t)
	const ip = "10.40.0.1"
	for i := 0; i < 10; i++ {
		if w := serve(h, "GET", "/api/state", ip); w.Code != http.StatusNotFound {
			t.Fatalf("request %d: status=%d, want 404 inside the burst", i+1, w.Code)
		}
	}
	for _, m := range []string{"GET", "FOO1", "POST"} {
		w := serve(h, m, "/api/state", ip)
		if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
			t.Fatalf("%s past the burst: status=%d Retry-After=%q body=%.80s, want 429", m, w.Code, w.Header().Get("Retry-After"), w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] == nil || len(body) != 1 {
			t.Fatalf("%s past the burst: body=%.80s (err=%v), want the one-key {\"error\": ...} JSON", m, w.Body.String(), err)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("%s past the burst: Content-Type=%q, want application/json", m, ct)
		}
	}
	// The bucket refills at the sustained rate: one second later, one request passes.
	advance(time.Second)
	if w := serve(h, "GET", "/api/state", ip); w.Code != http.StatusNotFound {
		t.Fatalf("one second after the burst: status=%d, want 404 (one token refilled)", w.Code)
	}
	if w := serve(h, "GET", "/api/state", ip); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request in that second: status=%d, want 429", w.Code)
	}
	// A forged forwarding header is not the key.
	r := &http.Request{Method: "GET", URL: &url.URL{Path: "/api/state"}, Host: "collector",
		Header: http.Header{"X-Forwarded-For": {"203.0.113.9"}}, Body: http.NoBody, RemoteAddr: ip + ":4001"}
	if w := httptest.NewRecorder(); func() int { h.ServeHTTP(w, r); return w.Code }() != http.StatusTooManyRequests {
		t.Fatal("rotating X-Forwarded-For escaped the default-deny budget; the key must be RemoteAddr")
	}
	if w := serve(h, "GET", "/api/state", "10.40.0.2"); w.Code != http.StatusNotFound {
		t.Fatalf("another address: status=%d, want 404 (the budget is per IP)", w.Code)
	}
	// The exhausted default-deny budget leaves submit and healthz alone.
	if w := serve(h, "POST", "/api/challenges/10-final-exfil/submit", ip); w.Code != http.StatusOK {
		t.Fatalf("submit after a default-deny flood: status=%d body=%.80s, want 200", w.Code, w.Body.String())
	}
	if w := serve(h, "GET", "/healthz", ip); w.Code != http.StatusOK {
		t.Fatalf("healthz after a default-deny flood: status=%d, want 200", w.Code)
	}
}

// The 429 of the default-deny budget is recorded as one more "other" series
// (route "", method "other", status 429), not as a raw method.
func TestDefaultDeny_RateLimitedMethodStaysFolded(t *testing.T) {
	h, _ := newMethodHandler(t)
	before := durationSeries(t)
	for i := 0; i < 15; i++ {
		serve(h, fmt.Sprintf("FOO%d", i), "/api/state", "10.50.0.1")
	}
	after := durationSeries(t)
	if got := after["|other|429"] - before["|other|429"]; got != 5 {
		t.Fatalf("|other|429 rose by %d, want 5 (15 requests, burst 10)", got)
	}
	for k := range after {
		if _, ok := before[k]; !ok && !strings.HasPrefix(k, "|other|") {
			t.Fatalf("a new series %.60q appeared; only method=other may", k)
		}
	}
}

// The default-deny budget and the submit/exfil budget are one pair of constants,
// and docs/openapi-collector.yaml says so: each rate-limited route declares
// that text (the ADR-0005 parity test compares it with the spec), and the
// spec's prose states the same numbers.
func TestRateLimitConstantsMatchSpec(t *testing.T) {
	h, _ := newMethodHandler(t)
	want := fmt.Sprintf("per-IP (RemoteAddr) %d req/s burst %d", budgetRate, budgetBurst)
	n := 0
	for _, rt := range h.Routes() {
		if rt.RateLimit == "none" {
			continue
		}
		n++
		if rt.RateLimit != want {
			t.Fatalf("%s %s: RateLimit=%q, want %q", rt.Method, rt.Pattern, rt.RateLimit, want)
		}
	}
	if n != 2 {
		t.Fatalf("%d rate-limited routes, want the 2 forward routes", n)
	}
	spec, err := os.ReadFile("../../docs/openapi-collector.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(spec), "the same "+fmt.Sprintf("%d req/s burst %d", budgetRate, budgetBurst)) {
		t.Fatal("the spec's default-deny prose does not state the budget constants")
	}
}
