package scoreboard_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
)

// Metric-label hygiene for the request's method (app#491, the scoreboard half of
// app#485): scoreboard_http_request_duration_seconds{method} is the declared
// method of the matched route, or "other", never the raw r.Method, which a caller
// chooses freely and which the unmatched surface (404 / 405, reachable through
// the ingress) would otherwise turn into one series per distinct value.

// requestDurationSeries returns the series of the histogram as
// "route|method|status" -> observation count, read through a fresh registry so
// the process-wide vector is not touched.
func requestDurationSeries(t *testing.T) map[string]uint64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.HTTPRequestDuration)
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

// serveRaw runs one request through ServeHTTP. It is built by hand because
// httptest.NewRequest panics on a method that is not a valid token, and the
// point is to hand the handler whatever a caller could name.
func (f *fixture) serveRaw(method, path string) *httptest.ResponseRecorder {
	r := &http.Request{
		Method: method, URL: &url.URL{Path: path}, Host: "scoreboard",
		Header: http.Header{}, Body: http.NoBody, RemoteAddr: "10.60.0.1:4000",
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

// manyMethods: FOO1..FOO50, a method far longer than any real one, a non-ASCII
// one, and one that is not valid UTF-8 (the metrics client panics on an invalid
// label value, so the fold must keep it out of a label). tag keeps the methods of
// one subtest apart from another's: the vector is process-wide, so a repeated
// name would reuse a series and hide a missing fold.
func manyMethods(tag string) []string {
	ms := make([]string, 0, 53)
	for i := 1; i <= 50; i++ {
		ms = append(ms, fmt.Sprintf("FOO%d%s", i, tag))
	}
	return append(ms, "LONG"+tag+strings.Repeat("X", 4096), "メソッド"+tag, "\xff\xfe"+tag)
}

// Fifty-odd distinct methods, on a path no route declares, on a known path with
// the wrong method (405) and on a known route with a method the route does not
// declare, add at most one series each: all of them fold into "other".
func TestRequestDurationMethodIsFoldedIntoOneLabelValue(t *testing.T) {
	surfaces := []struct {
		name, path string
		lo, hi     int // the status must be in [lo, hi)
	}{
		{"path no route declares (405)", "/api/no-such-route", 405, 406},
		{"known GET path, other method (405)", "/healthz", 405, 406},
		{"known POST route, other method (405)", "/api/challenges/02-evade/submit", 405, 406},
		// net/http's redirect for a cleaned path: which 3xx it is depends on the
		// method and on the Go version, so the test takes the class.
		{"a path net/http would redirect, other method (3xx)", "//healthz", 300, 400},
	}
	for k, s := range surfaces {
		tag := strings.Repeat("T", k)
		t.Run(s.name, func(t *testing.T) {
			f := newFixture(t, nil)
			before := requestDurationSeries(t)
			methods := manyMethods(tag)
			for _, m := range methods {
				w := f.serveRaw(m, s.path)
				if w.Code < s.lo || w.Code >= s.hi {
					t.Fatalf("%.12q %s: status=%d body=%.80s, want [%d, %d)", m, s.path, w.Code, w.Body.String(), s.lo, s.hi)
				}
			}
			after := requestDurationSeries(t)
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
				t.Fatalf("%d new series for %d methods, want at most 1", added, len(methods))
			}
		})
	}
}

// A declared route keeps its own method label (the fold must not hide real traffic).
func TestRequestDurationDeclaredMethodsKeepTheirLabels(t *testing.T) {
	f := newFixture(t, nil)
	before := requestDurationSeries(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/healthz"}, {"HEAD", "/healthz"},
	} {
		if w := f.serveRaw(c.method, c.path); w.Code != http.StatusOK {
			t.Fatalf("%s %s: status=%d body=%.80s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	after := requestDurationSeries(t)
	for _, k := range []string{"GET /healthz|GET|200", "GET /healthz|HEAD|200"} {
		if after[k] != before[k]+1 {
			t.Fatalf("series %q rose by %d, want 1 (a declared route keeps its labels)", k, after[k]-before[k])
		}
	}
}

// Real methods the surface does not declare (CONNECT included: net/http answers
// it without cleaning the path, and reports a request-derived pattern when it
// redirects to a trailing slash) never become a label value of their own.
func TestRequestDurationUndeclaredStandardMethodsAreNotLabels(t *testing.T) {
	f := newFixture(t, nil)
	for _, m := range []string{"CONNECT", "TRACE", "PATCH", "DELETE", "OPTIONS", "PUT"} {
		for _, path := range []string{"/healthz", "/api/no-such-route", "/api/challenges/02-evade/submit", "/static/x/", "/a b/"} {
			f.serveRaw(m, path)
		}
	}
	for k := range requestDurationSeries(t) {
		parts := strings.Split(k, "|")
		if len(parts) != 3 {
			t.Fatalf("series key %.60q is not route|method|status", k)
		}
		switch parts[1] {
		case "CONNECT", "TRACE", "PATCH", "DELETE", "OPTIONS", "PUT":
			t.Fatalf("series %.60q: an undeclared method became a label value", k)
		}
		// Whatever the route label is, it never leaks the request's path (a path
		// with a space, or a trailing slash, would show here).
		if strings.Contains(parts[0], "a b") {
			t.Fatalf("series %.60q: the route label carries a request-derived path", k)
		}
	}
}
