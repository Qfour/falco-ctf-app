package harness

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
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
