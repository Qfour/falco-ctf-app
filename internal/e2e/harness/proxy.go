// Package harness is the part of the ADR-0031 browser E2E harness that does not
// need a browser: the recording reverse proxy, the child-process launcher for
// the real cmd/scoreboard binary (with its env allowlist), the TLS stub that
// stands in for a participant's ttyd, the HTTP seeds, and the Chromium flag
// allowlist. It deliberately has no chromedp import and no build tag, so its
// unit tests run in `make test` (a required check) and not only in `make e2e`.
//
// Nothing in this tree may be imported by a production binary (V4:
// internal/apispec/e2e_boundary_test.go).
package harness

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strconv"
	"strings"
	"sync"
)

// IdentityHeader is the header the real ingress (oauth2-proxy / auth-policy)
// overwrites with the authenticated e-mail. The Proxy sets it on every request,
// whatever the client sent — the same direction as the ingress.
const IdentityHeader = "X-Auth-Request-Email"

// Upstream is a server the Proxy may forward to. The only implementations are
// *Scoreboard (the child this harness started) and *Site (a page server this
// harness started): the method is unexported, so nothing outside this package
// can hand the Proxy an arbitrary URL, and an env var or an argument cannot
// redirect it (ADR-0031 D1 (b), V8).
type Upstream interface {
	upstreamAddr() string
}

// Entry is one request the Proxy saw. Seq is the arrival order, starting at 1.
type Entry struct {
	Seq    int
	Method string
	Path   string
	Query  string
	// Status is the upstream's status (or the injected fault's), 0 until the
	// response head has been written.
	Status int
	// Done is true once the exchange has ended (the response was fully relayed,
	// the upstream failed, or the client went away). A stalled request stays
	// not-Done until it is cancelled.
	Done bool
	// Fault names the injected fault that answered instead of the upstream, or
	// "refused-<host|origin|fetch-site|path>" when the Proxy itself answered
	// 403 and forwarded nothing.
	Fault string
}

// IsWrite reports whether the request is anything but a GET. ADR-0031 D2: the
// "write requests" of a scenario are every non-GET request, so a HEAD or an
// OPTIONS the page starts to send counts too.
func (e Entry) IsWrite() bool { return e.Method != http.MethodGet }

// Op renders the entry as "METHOD /path" (no query): the form a scenario lists
// the writes it expects in.
func (e Entry) Op() string { return e.Method + " " + e.Path }

func (e Entry) String() string {
	s := fmt.Sprintf("#%d %s %s", e.Seq, e.Method, e.Path)
	if e.Query != "" {
		s += "?" + e.Query
	}
	switch {
	case e.Fault != "":
		s += " [fault " + e.Fault + "]"
	case !e.Done:
		s += " [in flight]"
	default:
		s += fmt.Sprintf(" -> %d", e.Status)
	}
	return s
}

// FaultKind is one of the three failures ADR-0031 H1 (e) asks the proxy to
// inject.
type FaultKind string

const (
	// Fault404 answers 404 with a JSON error body.
	Fault404 FaultKind = "404"
	// Fault500 answers 500 with a JSON error body.
	Fault500 FaultKind = "500"
	// FaultStall never answers: the request hangs until the client gives up or
	// the proxy is closed.
	FaultStall FaultKind = "stall"
)

type faultRule struct {
	match func(method, path string) bool
	kind  FaultKind
}

// Proxy is the reverse proxy in front of an Upstream. It
//
//  1. overwrites X-Auth-Request-Email on every request (the ingress does the
//     same, so a client cannot choose its identity),
//  2. answers 403 itself, before anything is forwarded, to a request that is
//     not the page's own (see refusal): the identity is a capability, and
//     without this any page in the same browser (or a DNS-rebound name) could
//     use it,
//  3. records every request in arrival order (Entries),
//  4. can answer 404 / 500 / a stall instead of the upstream (InjectFault),
//  5. never rewrites a response header (the CSP the scoreboard sets reaches the
//     browser untouched) and adds no X-Forwarded-* header.
type Proxy struct {
	up    Upstream
	email string
	// host and origin are the only Host header and Origin the proxy serves:
	// "127.0.0.1:<port>" and "http://127.0.0.1:<port>", the form `make
	// e2e-serve` publishes and the browser harness navigates to.
	host   string
	origin string
	srv    *http.Server
	ln     net.Listener
	rp     *httputil.ReverseProxy

	closing chan struct{}
	closeMu sync.Once

	mu      sync.Mutex
	cond    *sync.Cond
	entries []Entry
	faults  []*faultRule
}

// NewProxy starts serving ln, forwarding to up with the identity email.
func NewProxy(ln net.Listener, up Upstream, email string) (*Proxy, error) {
	if ln == nil || up == nil {
		return nil, errors.New("harness: NewProxy needs a listener and an upstream")
	}
	if email == "" || strings.ContainsAny(email, "\r\n") {
		return nil, fmt.Errorf("harness: invalid identity e-mail %q", email)
	}
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("harness: NewProxy needs a TCP listener, got %T", ln.Addr())
	}
	target := mustParseURL("http://" + up.upstreamAddr())
	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcp.Port))
	p := &Proxy{up: up, email: email, ln: ln, host: host, origin: "http://" + host, closing: make(chan struct{})}
	p.cond = sync.NewCond(&p.mu)
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Set(IdentityHeader, email)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"upstream unavailable"}`))
		},
	}
	p.srv = &http.Server{Handler: http.HandlerFunc(p.serve)}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

// Origin is the scheme://host:port the browser must use. It is always the
// 127.0.0.1 form, whatever address the listener is bound to (in the e2e-serve
// container it is bound to every interface, and only this Host is served).
func (p *Proxy) Origin() string { return p.origin }

// Email is the identity the proxy injects.
func (p *Proxy) Email() string { return p.email }

// Close stops the proxy and releases stalled requests.
func (p *Proxy) Close() {
	p.closeMu.Do(func() {
		close(p.closing)
		_ = p.srv.Close()
		p.mu.Lock()
		p.cond.Broadcast()
		p.mu.Unlock()
	})
}

// statusRecorder keeps the first status the handler writes. Unwrap lets
// http.ResponseController (and so ReverseProxy's flushing) reach the real
// writer.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// FlushPath is answered by the Proxy itself (204, not forwarded, not logged): a
// same-origin request the browser harness uses as a marker to learn that the
// network events before it have been handled (Browser.Flush). It is the only
// path the Proxy does not forward, and the page's own CSP (connect-src 'self')
// allows it.
const FlushPath = "/__e2e/flush"

// refusedPrefixes are the paths the Proxy never forwards. /falco/events is the
// webhook the event feeds (the seeds put events into the child directly, not
// through here) and /internal/ is the server-to-server surface; a browser page
// has no business on either, and forwarding them with an injected identity
// would hand any local page a way in. Matched on the raw and on the cleaned
// path, since the proxy has no mux that would clean it before the check.
// TestProxy_RefusesExactlyTheSpecsInternalRoutes keeps this list equal to the
// operations docs/openapi-scoreboard.yaml marks `x-ctf-audience: internal`.
var refusedPrefixes = []string{"/falco/events", "/internal"}

func refusedPath(p string) bool {
	for _, cand := range []string{p, path.Clean("/" + p)} {
		for _, pre := range refusedPrefixes {
			if cand == pre || strings.HasPrefix(cand, pre+"/") {
				return true
			}
		}
	}
	return false
}

// refusal returns why r must be answered 403 without being forwarded, or "".
//
//   - Host must be exactly 127.0.0.1:<port>: any other name (a DNS-rebound
//     one, a LAN address, localhost) is not the origin this proxy serves.
//   - A request that carries an Origin must carry the proxy's own (a form or
//     fetch from another page sends its own origin, "null" included).
//   - Sec-Fetch-Site other than same-origin / none (a typed or bookmarked
//     navigation) is another page's request: cross-site, and same-site (another
//     port on 127.0.0.1) too. A client that sends none of these headers (curl)
//     is not a browser acting for another page and is let through.
//   - /falco/events and /internal/ are never forwarded.
func (p *Proxy) refusal(r *http.Request) string {
	if r.Host != p.host {
		return "host"
	}
	if vals, ok := r.Header["Origin"]; ok && (len(vals) != 1 || vals[0] != p.origin) {
		return "origin"
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return "fetch-site"
	}
	if refusedPath(r.URL.Path) {
		return "path"
	}
	return ""
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	if why := p.refusal(r); why != "" {
		seq := p.begin(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"refused by the e2e proxy"}`))
		p.finish(seq, http.StatusForbidden, "refused-"+why)
		return
	}
	if r.URL.Path == FlushPath {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	seq := p.begin(r)
	rec := &statusRecorder{ResponseWriter: w}
	fault := p.matchFault(r.Method, r.URL.Path)
	if fault != "" {
		p.answerFault(rec, r, fault)
	} else {
		p.rp.ServeHTTP(rec, r)
	}
	p.finish(seq, rec.status, string(fault))
}

func (p *Proxy) answerFault(w http.ResponseWriter, r *http.Request, kind FaultKind) {
	switch kind {
	case Fault404, Fault500:
		code := http.StatusNotFound
		if kind == Fault500 {
			code = http.StatusInternalServerError
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"error":"injected fault"}`))
	case FaultStall:
		select {
		case <-r.Context().Done():
		case <-p.closing:
		}
	}
}

func (p *Proxy) begin(r *http.Request) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	seq := len(p.entries) + 1
	p.entries = append(p.entries, Entry{Seq: seq, Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery})
	p.cond.Broadcast()
	return seq
}

func (p *Proxy) finish(seq, status int, fault string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := &p.entries[seq-1]
	e.Status, e.Done, e.Fault = status, true, fault
	p.cond.Broadcast()
}

func (p *Proxy) matchFault(method, path string) FaultKind {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.faults {
		if f.match(method, path) {
			return f.kind
		}
	}
	return ""
}

// InjectFault makes every later request that match accepts get kind instead of
// the upstream's answer. The returned func removes the rule.
func (p *Proxy) InjectFault(match func(method, path string) bool, kind FaultKind) (remove func()) {
	rule := &faultRule{match: match, kind: kind}
	p.mu.Lock()
	p.faults = append(p.faults, rule)
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		for i, f := range p.faults {
			if f == rule {
				p.faults = append(p.faults[:i], p.faults[i+1:]...)
				return
			}
		}
	}
}

// Entries returns a copy of the log.
func (p *Proxy) Entries() []Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Entry(nil), p.entries...)
}

// Mark returns a position in the log: Since(mark) is what arrived after it.
func (p *Proxy) Mark() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// Since returns the entries that arrived after mark (a value from Mark).
func (p *Proxy) Since(mark int) []Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	if mark < 0 || mark > len(p.entries) {
		return nil
	}
	return append([]Entry(nil), p.entries[mark:]...)
}

// Writes returns, in arrival order, the "METHOD /path" of every write request
// (anything but a GET) that arrived after mark.
func (p *Proxy) Writes(mark int) []string {
	var out []string
	for _, e := range p.Since(mark) {
		if e.IsWrite() {
			out = append(out, e.Op())
		}
	}
	return out
}

// Wait blocks until pred(log) is true. It is woken by every change to the log,
// so a scenario waits on what the proxy recorded and never on a clock; ctx is
// the deadline (an upper bound on how long a failure takes to show, never a
// condition for success). pred runs with the proxy's lock held and must not
// call back into the Proxy.
func (p *Proxy) Wait(ctx context.Context, what string, pred func(log []Entry) bool) error {
	stop := context.AfterFunc(ctx, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.cond.Broadcast()
	})
	defer stop()
	p.mu.Lock()
	defer p.mu.Unlock()
	for !pred(p.entries) {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("waiting for %s: %w\nproxy log:\n%s", what, err, formatLog(p.entries))
		}
		select {
		case <-p.closing:
			return fmt.Errorf("waiting for %s: proxy closed\nproxy log:\n%s", what, formatLog(p.entries))
		default:
		}
		p.cond.Wait()
	}
	return nil
}

// Matcher selects log entries by method and exact path.
type Matcher struct {
	Method string
	Path   string
	// Prefix matches by path prefix instead of exact path.
	Prefix bool
}

// Match reports whether e is selected.
func (m Matcher) Match(e Entry) bool {
	if m.Method != "" && e.Method != m.Method {
		return false
	}
	if m.Prefix {
		return strings.HasPrefix(e.Path, m.Path)
	}
	return e.Path == m.Path
}

// CountDoneAfter counts the finished entries after mark that m selects.
func CountDoneAfter(log []Entry, mark int, m Matcher) int {
	n := 0
	for _, e := range log {
		if e.Seq > mark && e.Done && m.Match(e) {
			n++
		}
	}
	return n
}

// SettledAfter is the synchronisation point of ADR-0031 H1 (b)(1): every
// request m selects that started before the change (Seq <= mark) has finished,
// and at least min requests m selects that started after it have finished. A
// setInterval GET overlaps the previous one and responses can arrive reversed,
// so "the next response" is not enough: an answer computed before the change
// must be out of the way too.
func SettledAfter(log []Entry, mark, min int, m Matcher) bool {
	after := 0
	for _, e := range log {
		if !m.Match(e) {
			continue
		}
		if e.Seq <= mark && !e.Done {
			return false
		}
		if e.Seq > mark && e.Done {
			after++
		}
	}
	return after >= min
}

func formatLog(log []Entry) string {
	var b strings.Builder
	for _, e := range log {
		b.WriteString("  ")
		b.WriteString(e.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// FormatLog renders a log for a failure message.
func FormatLog(log []Entry) string { return formatLog(log) }
