package collector

// ADR-0034 V13: the collector strips EVERY X-Auth-Request-* request header from
// a workspace's request, on EVERY forwarded route. The route set is derived from
// Routes() (CollectorForward), so a route added to the forward table is covered
// without editing this test; a hand-written list would silently skip it.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// concretePath fills a route pattern's {name} segments with fixed values.
func concretePath(pattern string) string {
	r := strings.NewReplacer("{cid}", "10-final-exfil", "{user}", "alice", "{idx}", "0")
	return r.Replace(pattern)
}

// headerRecorder records the full header set the upstream (the scoreboard
// stand-in) received on each call.
type headerRecorder struct {
	mu    sync.Mutex
	calls []http.Header
}

func (u *headerRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.calls = append(u.calls, r.Header.Clone())
	u.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func TestV13_StripsAuthRequestHeadersOnEveryForwardedRoute(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	probe, err := New("http://scoreboard.invalid", testLogger(), WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	var forwarded []string
	routeOf := map[string][2]string{}
	for _, rt := range probe.Routes() {
		if rt.CollectorForward {
			forwarded = append(forwarded, rt.MuxPattern())
			routeOf[rt.MuxPattern()] = [2]string{rt.Method, concretePath(rt.Pattern)}
		}
	}
	// Non-vacuous: the derivation must find the collector's real forward set.
	if len(forwarded) != 3 {
		t.Fatalf("derived %d forwarded routes %v, want 3 (submit, display-name, exfil); the derivation is broken, not clean", len(forwarded), forwarded)
	}

	// Named headers from the ADR plus an arbitrary one no list would contain,
	// and a lower-case key a hand-built request could carry.
	forged := []string{
		"X-Auth-Request-Email",
		"X-Auth-Request-User",
		"X-Auth-Request-Preferred-Username",
		"X-Auth-Request-Groups",
		"X-Auth-Request-Some-Future-Header",
		"x-auth-request-email", // non-canonical spelling, set by map assignment below
	}

	for _, mp := range forwarded {
		mp := mp
		t.Run(mp, func(t *testing.T) {
			up := &headerRecorder{}
			upSrv := httptest.NewServer(up)
			defer upSrv.Close()
			h, err := New(upSrv.URL, testLogger(), WithNow(func() time.Time { return now }))
			if err != nil {
				t.Fatal(err)
			}
			cSrv := httptest.NewServer(h)
			defer cSrv.Close()

			target := routeOf[mp]
			req, err := http.NewRequest(target[0], cSrv.URL+target[1], strings.NewReader(`{"name":"x"}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Probe-Survives", "yes") // control: the strip is targeted, not "drop everything"
			for _, k := range forged {
				if k == strings.ToLower(k) {
					req.Header[k] = []string{"forged-" + k}
				} else {
					req.Header.Set(k, "forged-"+k)
				}
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: status %d, want the upstream's 200 (the request must reach the upstream for this test to mean anything)", mp, resp.StatusCode)
			}
			up.mu.Lock()
			defer up.mu.Unlock()
			if len(up.calls) != 1 {
				t.Fatalf("%s: upstream saw %d calls, want 1", mp, len(up.calls))
			}
			got := up.calls[0]
			for k, v := range got {
				if strings.HasPrefix(strings.ToLower(k), "x-auth-request-") {
					t.Errorf("%s: upstream received %s=%q; every X-Auth-Request-* must be stripped", mp, k, v)
				}
			}
			if got.Get("X-Probe-Survives") != "yes" {
				t.Errorf("%s: an unrelated header did not survive (%v): the strip must not drop everything", mp, got)
			}
		})
	}
}

// Unit-level: the prefix match is case-insensitive and anchored at the start,
// and does not touch look-alikes that merely contain the string.
func TestStripAuthRequestHeaders(t *testing.T) {
	h := http.Header{}
	h["X-Auth-Request-Email"] = []string{"a"}
	h["x-auth-request-user"] = []string{"b"}
	h["X-AUTH-REQUEST-GROUPS"] = []string{"c"}
	h["X-Auth-Request-"] = []string{"d"} // the bare prefix is still in the namespace
	h["X-Not-Auth-Request-Email"] = []string{"keep1"}
	h["X-Auth-Requests"] = []string{"keep2"} // no trailing hyphen after "request"
	h["Authorization"] = []string{"keep3"}
	stripAuthRequestHeaders(h)
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-auth-request-") {
			t.Errorf("header %q survived", k)
		}
	}
	for _, k := range []string{"X-Not-Auth-Request-Email", "X-Auth-Requests", "Authorization"} {
		if len(h[k]) != 1 {
			t.Errorf("unrelated header %q was removed", k)
		}
	}
}
