package harness

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
)

// echoSite answers every request with the identity header it saw and a CSP, so
// a test can tell what the Proxy forwarded and what it left alone.
func echoSite(t *testing.T) *Site {
	t.Helper()
	site, err := NewSite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'nonce-abc'")
		w.Header().Set("X-Seen-Identity", r.Header.Get(IdentityHeader))
		w.Header().Set("X-Seen-XFF", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Seen-Forwarded", r.Header.Get("Forwarded"))
		_, _ = io.WriteString(w, "ok")
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(site.Close)
	return site
}

func newTestProxy(t *testing.T, up Upstream) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProxy(ln, up, "user1@e2e.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func do(t *testing.T, method, url string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestProxy_OverwritesIdentityAndLeavesHeadersAlone(t *testing.T) {
	p := newTestProxy(t, echoSite(t))
	resp := do(t, "GET", p.Origin()+"/x", map[string]string{
		IdentityHeader:    "admin@evil.test", // a client must not be able to pick its identity
		"X-Forwarded-For": "6.6.6.6",
		"Forwarded":       "for=6.6.6.6",
	})
	if got := resp.Header.Get("X-Seen-Identity"); got != "user1@e2e.test" {
		t.Errorf("upstream saw identity %q, want the proxy's user1@e2e.test", got)
	}
	if got := resp.Header.Get("X-Seen-XFF"); got != "" {
		t.Errorf("upstream saw X-Forwarded-For %q; the proxy must forward none", got)
	}
	if got := resp.Header.Get("X-Seen-Forwarded"); got != "" {
		t.Errorf("upstream saw Forwarded %q; the proxy must forward none", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "default-src 'self'; script-src 'nonce-abc'" {
		t.Errorf("CSP was rewritten on the way back: %q", got)
	}
}

func TestProxy_RecordsInArrivalOrderWithStatusAndWrites(t *testing.T) {
	p := newTestProxy(t, echoSite(t))
	mark := p.Mark()
	do(t, "GET", p.Origin()+"/a?x=1", nil)
	do(t, "POST", p.Origin()+"/b", nil)
	do(t, "GET", p.Origin()+"/c", nil)
	do(t, "DELETE", p.Origin()+"/d", nil)
	got := p.Since(mark)
	if len(got) != 4 {
		t.Fatalf("recorded %d entries, want 4:\n%s", len(got), FormatLog(got))
	}
	for i, want := range []string{"GET /a", "POST /b", "GET /c", "DELETE /d"} {
		if got[i].Op() != want || got[i].Seq != mark+i+1 || !got[i].Done || got[i].Status != 200 {
			t.Errorf("entry %d = %s, want %s done with 200", i, got[i], want)
		}
	}
	if got[0].Query != "x=1" {
		t.Errorf("query not recorded: %q", got[0].Query)
	}
	if w := p.Writes(mark); strings.Join(w, ",") != "POST /b,DELETE /d" {
		t.Errorf("Writes = %v, want the POST then the DELETE (everything but GET)", w)
	}
	if w := p.Writes(p.Mark()); len(w) != 0 {
		t.Errorf("Writes after the last entry = %v, want none", w)
	}
}

func TestProxy_InjectsFaults(t *testing.T) {
	p := newTestProxy(t, echoSite(t))
	match := func(method, path string) bool { return path == "/broken" }
	remove := p.InjectFault(match, Fault404)
	if got := do(t, "GET", p.Origin()+"/broken", nil).StatusCode; got != 404 {
		t.Errorf("Fault404 answered %d", got)
	}
	if got := do(t, "GET", p.Origin()+"/fine", nil).StatusCode; got != 200 {
		t.Errorf("a path the rule does not match answered %d, want the upstream's 200", got)
	}
	remove()
	remove = p.InjectFault(match, Fault500)
	if got := do(t, "GET", p.Origin()+"/broken", nil).StatusCode; got != 500 {
		t.Errorf("Fault500 answered %d", got)
	}
	remove()
	if got := do(t, "GET", p.Origin()+"/broken", nil).StatusCode; got != 200 {
		t.Errorf("after remove() the request answered %d, want the upstream's 200", got)
	}
	var faulted []string
	for _, e := range p.Entries() {
		if e.Fault != "" {
			faulted = append(faulted, e.Fault)
		}
	}
	if strings.Join(faulted, ",") != "404,500" {
		t.Errorf("faults recorded = %v, want [404 500]", faulted)
	}
}

func TestProxy_StallHoldsTheRequestUntilItIsCancelled(t *testing.T) {
	p := newTestProxy(t, echoSite(t))
	p.InjectFault(func(string, string) bool { return true }, FaultStall)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", p.Origin()+"/hang", nil)
	errc := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		errc <- err
	}()
	// The request is recorded, in flight, before anything answers it.
	wctx, wcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer wcancel()
	if err := p.Wait(wctx, "the stalled request to arrive", func(log []Entry) bool { return len(log) == 1 }); err != nil {
		t.Fatal(err)
	}
	if e := p.Entries()[0]; e.Done {
		t.Fatalf("a stalled request must stay in flight, got %s", e)
	}
	cancel()
	if err := <-errc; err == nil {
		t.Fatal("the cancelled request returned no error")
	}
	if err := p.Wait(wctx, "the cancelled request to be closed out", func(log []Entry) bool { return log[0].Done }); err != nil {
		t.Fatal(err)
	}
}

func TestProxy_WaitFailsAtTheDeadlineAndPrintsTheLog(t *testing.T) {
	p := newTestProxy(t, echoSite(t))
	do(t, "GET", p.Origin()+"/seen", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := p.Wait(ctx, "a request that never comes", func(log []Entry) bool { return len(log) > 5 })
	if err == nil {
		t.Fatal("Wait returned nil although the condition never held")
	}
	if !strings.Contains(err.Error(), "a request that never comes") || !strings.Contains(err.Error(), "GET /seen") {
		t.Errorf("the failure should name what it waited for and show the log, got: %v", err)
	}
}

func TestProxy_WaitWakesOnNewEntries(t *testing.T) {
	p := newTestProxy(t, echoSite(t))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	var werr error
	go func() {
		defer wg.Done()
		werr = p.Wait(ctx, "two POSTs", func(log []Entry) bool {
			n := 0
			for _, e := range log {
				if e.Method == "POST" {
					n++
				}
			}
			return n == 2
		})
	}()
	do(t, "POST", p.Origin()+"/1", nil)
	do(t, "POST", p.Origin()+"/2", nil)
	wg.Wait()
	if werr != nil {
		t.Fatal(werr)
	}
}

func TestSettledAfter(t *testing.T) {
	j := Matcher{Method: "GET", Path: "/j"}
	cases := []struct {
		name string
		log  []Entry
		mark int
		min  int
		want bool
	}{
		{"no request after the change yet", []Entry{{Seq: 1, Method: "GET", Path: "/j", Done: true}}, 1, 1, false},
		{"a request that began before the change is still in flight", []Entry{
			{Seq: 1, Method: "GET", Path: "/j"},
			{Seq: 2, Method: "GET", Path: "/j", Done: true},
		}, 1, 1, false},
		{"all earlier requests are out and one later request is done", []Entry{
			{Seq: 1, Method: "GET", Path: "/j", Done: true},
			{Seq: 2, Method: "GET", Path: "/j", Done: true},
		}, 1, 1, true},
		{"a later request is in flight only", []Entry{
			{Seq: 1, Method: "GET", Path: "/j", Done: true},
			{Seq: 2, Method: "GET", Path: "/j"},
		}, 1, 1, false},
		{"requests for another path do not count, and do not block", []Entry{
			{Seq: 1, Method: "GET", Path: "/other"},
			{Seq: 2, Method: "GET", Path: "/j", Done: true},
		}, 0, 1, true},
		{"min is a count of finished later requests", []Entry{
			{Seq: 2, Method: "GET", Path: "/j", Done: true},
			{Seq: 3, Method: "GET", Path: "/j", Done: true},
		}, 1, 3, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SettledAfter(c.log, c.mark, c.min, j); got != c.want {
				t.Errorf("SettledAfter = %v, want %v", got, c.want)
			}
		})
	}
}

func TestNewProxy_RejectsAnInjectableIdentity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	site := echoSite(t)
	for _, email := range []string{"", "a@e2e.test\r\nX-Evil: 1"} {
		if _, err := NewProxy(ln, site, email); err == nil {
			t.Errorf("NewProxy accepted the identity %q", email)
		}
	}
}

// countingSite counts what reaches it, so a test can tell "refused by the
// Proxy" from "forwarded and answered".
func countingSite(t *testing.T) (*Site, *int32) {
	t.Helper()
	var hits int32
	site, err := NewSite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "reached: "+r.Header.Get(IdentityHeader))
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(site.Close)
	return site, &hits
}

// rawDo sends a request with an explicit Host (the Go client takes it from
// req.Host, not from a header).
func rawDo(t *testing.T, method, url, host string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// The identity is a capability: the Proxy injects it on every request it
// forwards, so it must forward only the page's own requests (security review of
// ADR-0031 H1, MEDIUM-1). Each case is a deliberate break; none may reach the
// upstream, and each must be answered 403.
func TestProxy_RefusesRequestsThatAreNotThePagesOwn(t *testing.T) {
	site, hits := countingSite(t)
	p := newTestProxy(t, site)
	own := p.Origin()
	cases := []struct {
		name, method, path, host string
		hdr                      map[string]string
		fault                    string
	}{
		{"another Host (DNS rebinding)", "GET", "/portal", "attacker.example:" + strings.TrimPrefix(own, "http://127.0.0.1:"), nil, "refused-host"},
		{"localhost is not the served Host", "GET", "/portal", "localhost:" + strings.TrimPrefix(own, "http://127.0.0.1:"), nil, "refused-host"},
		{"right name, wrong port", "GET", "/portal", "127.0.0.1:1", nil, "refused-host"},
		{"Host without a port", "GET", "/portal", "127.0.0.1", nil, "refused-host"},
		{"text/plain POST from another page's origin", "POST", "/api/admin/hints", "", map[string]string{"Origin": "https://evil.example", "Content-Type": "text/plain"}, "refused-origin"},
		{"Origin of another port on 127.0.0.1", "POST", "/api/x", "", map[string]string{"Origin": "http://127.0.0.1:9"}, "refused-origin"},
		{"opaque Origin null", "POST", "/api/x", "", map[string]string{"Origin": "null"}, "refused-origin"},
		{"Sec-Fetch-Site cross-site", "GET", "/api/x", "", map[string]string{"Sec-Fetch-Site": "cross-site"}, "refused-fetch-site"},
		{"Sec-Fetch-Site same-site (another port)", "GET", "/api/x", "", map[string]string{"Sec-Fetch-Site": "same-site"}, "refused-fetch-site"},
		{"the webhook", "POST", "/falco/events", "", nil, "refused-path"},
		{"the webhook with a trailing path", "POST", "/falco/events/x", "", nil, "refused-path"},
		{"the internal surface", "POST", "/internal/exfil/11", "", nil, "refused-path"},
		{"the internal surface via dot segments", "POST", "/a/../internal/exfil/11", "", nil, "refused-path"},
		{"the webhook via a doubled slash", "POST", "//falco/events", "", nil, "refused-path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := atomic.LoadInt32(hits)
			mark := p.Mark()
			resp := rawDo(t, c.method, own+c.path, c.host, c.hdr)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 403 {
				t.Errorf("status = %d (%s), want 403", resp.StatusCode, body)
			}
			if got := atomic.LoadInt32(hits); got != before {
				t.Errorf("the upstream was reached (%d -> %d hits); the Proxy must not forward this", before, got)
			}
			if strings.Contains(string(body), "user1@") {
				t.Errorf("the injected identity leaked into the refusal: %s", body)
			}
			if es := p.Since(mark); len(es) != 1 || es[0].Fault != c.fault || es[0].Status != 403 || !es[0].Done {
				t.Errorf("log = %s, want one entry refused as %s with 403", FormatLog(es), c.fault)
			}
		})
	}
}

// The other direction: what the page itself sends must still pass, or the
// refusals above would be indistinguishable from a proxy that forwards nothing.
func TestProxy_ForwardsThePagesOwnRequests(t *testing.T) {
	site, hits := countingSite(t)
	p := newTestProxy(t, site)
	own := p.Origin()
	cases := []struct {
		name, method string
		hdr          map[string]string
	}{
		{"navigation typed in the address bar", "GET", map[string]string{"Sec-Fetch-Site": "none"}},
		{"same-origin fetch", "GET", map[string]string{"Sec-Fetch-Site": "same-origin"}},
		{"same-origin POST", "POST", map[string]string{"Origin": own, "Sec-Fetch-Site": "same-origin"}},
		{"a client with no browser headers", "GET", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := atomic.LoadInt32(hits)
			resp := rawDo(t, c.method, own+"/api/ok", "", c.hdr)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 || string(body) != "reached: user1@e2e.test" {
				t.Errorf("status %d body %q, want the upstream's 200 with the injected identity", resp.StatusCode, body)
			}
			if got := atomic.LoadInt32(hits); got != before+1 {
				t.Errorf("hits %d -> %d, want exactly one more", before, got)
			}
		})
	}
	// Names that merely start like a refused path are not refused.
	for _, path := range []string{"/falco/eventsx", "/internals", "/api/internal/x"} {
		if got := rawDo(t, "GET", own+path, "", nil).StatusCode; got != 200 {
			t.Errorf("GET %s = %d, want it forwarded (200)", path, got)
		}
	}
}

// `make e2e-serve` binds the proxy to every interface of its container (docker's
// publish is what keeps it on the host's loopback). The served Host and Origin
// must then still be the 127.0.0.1 form, not the listener's "[::]:port".
func TestProxy_OnAWildcardListenerServesOnlyTheLoopbackHost(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		// make test runs in Dockerfile.test (Linux): a wildcard bind failing
		// there is an environment defect, and a skip would hide it.
		t.Fatalf("no wildcard listener: %v", err)
	}
	site, hits := countingSite(t)
	p, err := NewProxy(ln, site, "user1@e2e.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if !strings.HasPrefix(p.Origin(), "http://127.0.0.1:") {
		t.Fatalf("Origin = %q, want the 127.0.0.1 form", p.Origin())
	}
	if got := rawDo(t, "GET", p.Origin()+"/x", "", nil).StatusCode; got != 200 {
		t.Errorf("GET via 127.0.0.1 = %d, want 200", got)
	}
	port := strings.TrimPrefix(p.Origin(), "http://127.0.0.1:")
	before := atomic.LoadInt32(hits)
	if got := rawDo(t, "GET", p.Origin()+"/x", "evil.example:"+port, nil).StatusCode; got != 403 {
		t.Errorf("GET with another Host = %d, want 403", got)
	}
	if atomic.LoadInt32(hits) != before {
		t.Error("a request with another Host reached the upstream")
	}
}

var pathParam = regexp.MustCompile(`\{[^}/]+\}`)

// refusalParityViolations compares the proxy's refusedPath with the spec's
// audience of every operation: an `x-ctf-audience: internal` route (the
// webhook, the collector's server-to-server calls) must be refused — the proxy
// would otherwise hand it the injected identity — and every other route must
// be forwarded, since the page's own requests go through. A missing audience
// is a violation too (ADR-0005: the x-ctf-* keys have no default).
func refusalParityViolations(ops map[string]map[string]any) (out []string, internal int) {
	for key, op := range ops {
		_, path, _ := strings.Cut(key, " ")
		concrete := pathParam.ReplaceAllString(path, "x")
		aud, ok := specparity.StringExt(op, "x-ctf-audience")
		switch {
		case !ok:
			out = append(out, key+": no x-ctf-audience")
		case aud == "internal":
			internal++
			if !refusedPath(concrete) {
				out = append(out, key+": internal in the spec, but the e2e proxy would forward it with an injected identity (add it to refusedPrefixes)")
			}
		case refusedPath(concrete):
			out = append(out, key+": audience "+aud+", but the e2e proxy refuses it (a page's own request must be forwarded)")
		}
	}
	sort.Strings(out)
	return out, internal
}

// review-5x T3 R4#5: refusedPrefixes is a hand copy of the spec's internal
// audience; this keeps the two equal, so a new internal route cannot be
// forwarded with the injected identity unnoticed.
func TestProxy_RefusesExactlyTheSpecsInternalRoutes(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := specparity.LoadSpec(filepath.Join(root, "docs", "openapi-scoreboard.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ops := spec.Operations()
	v, internal := refusalParityViolations(ops)
	if len(ops) == 0 || internal == 0 {
		t.Fatalf("the spec gave %d operations, %d internal — the extraction is broken, and a comparison over nothing proves nothing", len(ops), internal)
	}
	if len(v) > 0 {
		t.Fatalf("the e2e proxy's refused paths and the spec's internal audience differ:\n  %s", strings.Join(v, "\n  "))
	}
}

func TestRefusalParity_CatchesPlantedDrift(t *testing.T) {
	ext := func(aud string) map[string]any { return map[string]any{"x-ctf-audience": aud} }
	cases := map[string]map[string]map[string]any{
		"a new internal route outside refusedPrefixes": {"POST /hooks/new": ext("internal")},
		"a participant route the proxy would refuse":   {"GET /internal/me": ext("participant")},
		"an operation with no audience":                {"GET /api/x": {}},
	}
	for name, ops := range cases {
		if v, _ := refusalParityViolations(ops); len(v) != 1 {
			t.Errorf("%s: violations = %v, want exactly one", name, v)
		}
	}
	ok := map[string]map[string]any{
		"POST /falco/events":          ext("internal"),
		"POST /internal/exfil/{cid}":  ext("internal"),
		"GET /api/users/{user}/me":    ext("participant"),
		"GET /api/users/{user}/x/{y}": ext("participant"),
	}
	if v, internal := refusalParityViolations(ok); len(v) != 0 || internal != 2 {
		t.Errorf("the matching set gave %v (%d internal)", v, internal)
	}
}
