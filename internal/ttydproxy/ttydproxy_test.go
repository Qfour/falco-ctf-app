package ttydproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// htmlUpstream is a stand-in ttyd that serves a canned HTML document — the
// case the CSP mitigation exists for (ttyd's index page loaded in an
// iframe).
func htmlUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<html><body>ttyd</body></html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDefaultIsFailSafeNone(t *testing.T) {
	up := htmlUpstream(t)
	h, err := New(up.URL, "", testLogger()) // empty -> default
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(h)
	t.Cleanup(proxySrv.Close)

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("CSP = %q, want frame-ancestors 'none'", got)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("XFO = %q, want DENY when frame-ancestors is 'none'", got)
	}
}

func TestExplicitNoneMatchesDefault(t *testing.T) {
	up := htmlUpstream(t)
	h, err := New(up.URL, "'none'", testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(h)
	t.Cleanup(proxySrv.Close)

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("CSP = %q, want frame-ancestors 'none'", got)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("XFO = %q, want DENY", got)
	}
}

func TestPortalOriginConfiguredOmitsXFO(t *testing.T) {
	up := htmlUpstream(t)
	const portal = "https://ctf-event.example.com"
	h, err := New(up.URL, portal, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(h)
	t.Cleanup(proxySrv.Close)

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if want := "frame-ancestors " + portal; resp.Header.Get("Content-Security-Policy") != want {
		t.Errorf("CSP = %q, want %q", resp.Header.Get("Content-Security-Policy"), want)
	}
	// XFO cannot express "allow this one cross-origin portal" (see package
	// doc) — it must be absent, not SAMEORIGIN/DENY, once a real origin is
	// configured, otherwise legacy browsers honouring XFO would block the
	// only legitimate embedder.
	if got := resp.Header.Get("X-Frame-Options"); got != "" {
		t.Errorf("XFO = %q, want absent when a portal origin is configured", got)
	}
}

func TestUpstreamUnreachableFailsClosedWithCSP(t *testing.T) {
	// Point at a port nothing is listening on.
	h, err := New("http://127.0.0.1:1", "'none'", testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(h)
	t.Cleanup(proxySrv.Close)

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("CSP on error path = %q, want frame-ancestors 'none'", got)
	}
}

func TestInvalidUpstreamURLErrors(t *testing.T) {
	if _, err := New("://not-a-url", "'none'", testLogger()); err == nil {
		t.Error("New with malformed upstream URL: want error, got nil")
	}
}

// TestFrameAncestorsControlCharRejected proves New fails closed (refuses to
// start) rather than passing a CR/LF/control-character-laden FRAME_ANCESTORS
// value through to a response header. net/http does NOT refuse CR/LF in a
// header value, it replaces each with a space, so a line break would reach the
// wire as a separator (a second source); the grammar (ADR-0044) is the check.
func TestFrameAncestorsControlCharRejected(t *testing.T) {
	up := htmlUpstream(t)
	cases := []string{
		"https://ctf-event.example.com\r\nX-Injected: evil",
		"https://ctf-event.example.com\nSet-Cookie: pwned=1",
		"https://ctf-event.example.com\x00",
		"https://ctf-event.example.com\x07", // bell — any control char, not just CR/LF
	}
	for _, v := range cases {
		if _, err := New(up.URL, v, testLogger()); err == nil {
			t.Errorf("New(%q): want error (fail-closed on control char), got nil", v)
		}
	}
}

// TestFrameAncestorsPlainValueAccepted is the control for the case above —
// the two forms of the grammar (ADR-0044) must still work.
func TestFrameAncestorsPlainValueAccepted(t *testing.T) {
	up := htmlUpstream(t)
	for _, v := range []string{"'none'", "https://ctf-event.example.com"} {
		if _, err := New(up.URL, v, testLogger()); err != nil {
			t.Errorf("New(%q): unexpected error: %v", v, err)
		}
	}
}

// TestFrameAncestorsOutsideTheGrammarRefusesToStart: a value that widens who may frame the
// root-shell terminal is an error at start, not a CSP (ADR-0044 D4). The full table is
// frame_ancestors_grammar_test.go; these are the ones the issue is about.
func TestFrameAncestorsOutsideTheGrammarRefusesToStart(t *testing.T) {
	up := htmlUpstream(t)
	for _, v := range []string{"*", "'self'", "https://a.example *", "https://a.example https://b.example",
		"https://a.example;script-src *", "http://a.example", "https://a.example:8443", "none"} {
		if _, err := New(up.URL, v, testLogger()); err == nil {
			t.Errorf("New(%q): want error (outside the FRAME_ANCESTORS grammar), got nil", v)
		}
	}
}

// TestWebSocketUpgradeTunnelled proves the proxy transparently tunnels a
// WebSocket Upgrade handshake through to the upstream (ttyd's terminal runs
// entirely over WS) and still stamps the CSP header on the 101 response —
// see ModifyResponse's doc comment on why that's harmless and simpler than
// special-casing the upgrade response.
func TestWebSocketUpgradeTunnelled(t *testing.T) {
	// Minimal upstream: accept the Upgrade request, hijack the connection,
	// hand-write a 101 response, then echo one line back over the raw TCP
	// connection so the test can observe end-to-end tunnelling without
	// pulling in a WS client library.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		line, _ := brw.ReadString('\n')
		_, _ = brw.WriteString("echo:" + line)
		_ = brw.Flush()
	}))
	t.Cleanup(upstream.Close)

	h, err := New(upstream.URL, "'none'", testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(h)
	t.Cleanup(proxySrv.Close)

	proxyURL, err := parseHostPort(proxySrv.URL)
	if err != nil {
		t.Fatalf("parseHostPort: %v", err)
	}

	conn, err := net.DialTimeout("tcp", proxyURL, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	req := "GET / HTTP/1.1\r\nHost: ttyd\r\nOrigin: https://ttyd\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" // ADR-0048: the seat's own origin
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if statusLine != "HTTP/1.1 101 Switching Protocols\r\n" {
		t.Fatalf("status line = %q, want 101 Switching Protocols", statusLine)
	}
	// Drain headers until the blank line separator.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write tunnelled payload: %v", err)
	}
	echoed, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if echoed != "echo:ping\n" {
		t.Fatalf("echoed = %q, want tunnelled round-trip \"echo:ping\\n\"", echoed)
	}
}

func parseHostPort(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

// --- ADR-0048: a WebSocket Upgrade is served only with Origin == "https://" + Host ---

// countingUpstream is a stand-in ttyd that counts the requests that reach it, answers an
// Upgrade with 101 (then closes the connection) and anything else with 200.
func countingUpstream(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Upgrade") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// doRaw sends one hand-written request (so Host and Origin are exactly as given: the
// Go client would normalise or refuse some of them) and returns the response status.
func doRaw(t *testing.T, proxyURL string, lines ...string) int {
	t.Helper()
	addr, err := parseHostPort(proxyURL)
	if err != nil {
		t.Fatalf("parseHostPort: %v", err)
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET / HTTP/1.1\r\n" + strings.Join(lines, "\r\n") + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestWebSocketUpgradeOrigin(t *testing.T) {
	const host = "seat1.ctf.example.com"
	upgrade := []string{"Upgrade: websocket", "Connection: Upgrade"}
	cases := []struct {
		name  string
		lines []string // everything after the request line
		want  int
	}{
		// accepted: the seat's own origin
		{"own origin", append([]string{"Host: " + host, "Origin: https://" + host}, upgrade...), 101},
		{"own origin, port in Host", append([]string{"Host: " + host + ":8443", "Origin: https://" + host + ":8443"}, upgrade...), 101},
		{"Connection is a list, own origin", []string{"Host: " + host, "Origin: https://" + host, "Upgrade: WebSocket", "Connection: keep-alive, upgrade"}, 101},
		// refused: fail-closed
		{"no Origin", append([]string{"Host: " + host}, upgrade...), 403},
		{"other origin", append([]string{"Host: " + host, "Origin: https://evil.example"}, upgrade...), 403},
		{"http scheme", append([]string{"Host: " + host, "Origin: http://" + host}, upgrade...), 403},
		{"port the Host does not have", append([]string{"Host: " + host, "Origin: https://" + host + ":8443"}, upgrade...), 403},
		{"port the Origin does not have", append([]string{"Host: " + host + ":8443", "Origin: https://" + host}, upgrade...), 403},
		{"upper-case Host", append([]string{"Host: Seat1.CTF.example.com", "Origin: https://seat1.ctf.example.com"}, upgrade...), 403},
		{"upper-case Origin", append([]string{"Host: " + host, "Origin: https://SEAT1.ctf.example.com"}, upgrade...), 403},
		{"trailing slash", append([]string{"Host: " + host, "Origin: https://" + host + "/"}, upgrade...), 403},
		{"trailing dot", append([]string{"Host: " + host, "Origin: https://" + host + "."}, upgrade...), 403},
		{"opaque origin", append([]string{"Host: " + host, "Origin: null"}, upgrade...), 403},
		{"empty Origin", append([]string{"Host: " + host, "Origin:"}, upgrade...), 403},
		{"two Origin lines, both the seat's", append([]string{"Host: " + host, "Origin: https://" + host, "Origin: https://" + host}, upgrade...), 403},
		{"empty Host and a bare https://", append([]string{"Host:", "Origin: https://"}, upgrade...), 403},
		{"another upgrade type is checked too", []string{"Host: " + host, "Upgrade: h2c", "Connection: Upgrade"}, 403},
		// the forms real clients and ingress-nginx send: each of these is refused on its own,
		// so each one is what pins one part of the Connection token comparison
		{"ingress-nginx form: lower-case tokens, no Origin", []string{"Host: " + host, "Upgrade: websocket", "Connection: upgrade"}, 403},
		{"Firefox form: Connection is a list, other origin", []string{"Host: " + host, "Origin: https://evil.example", "Upgrade: websocket", "Connection: keep-alive, Upgrade"}, 403},
		{"upper-case Connection token, other origin", []string{"Host: " + host, "Origin: https://evil.example", "Upgrade: websocket", "Connection: UPGRADE"}, 403},
		{"Connection split over two lines", []string{"Host: " + host, "Upgrade: websocket", "Connection: keep-alive", "Connection: Upgrade"}, 403},
		// not an upgrade: untouched, no Origin needed
		{"plain GET without Origin", []string{"Host: " + host, "Connection: close"}, 200},
		{"plain GET with another origin", []string{"Host: " + host, "Origin: https://evil.example", "Connection: close"}, 200},
		{"Connection: Upgrade without an Upgrade header", []string{"Host: " + host, "Connection: Upgrade"}, 200},
		{"Upgrade header without the Connection token", []string{"Host: " + host, "Upgrade: websocket", "Connection: close"}, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up, hits := countingUpstream(t)
			h, err := New(up.URL, "https://app.ctf.example.com", testLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			proxySrv := httptest.NewServer(h)
			t.Cleanup(proxySrv.Close)

			if got := doRaw(t, proxySrv.URL, c.lines...); got != c.want {
				t.Fatalf("status = %d, want %d", got, c.want)
			}
			if wantHit := c.want != http.StatusForbidden; (hits.Load() == 1) != wantHit {
				t.Errorf("upstream hits = %d, want reached = %v (a refused Upgrade must not reach ttyd)", hits.Load(), wantHit)
			}
		})
	}
}

// A refusal carries the CSP and does not write the Origin it refused into the log.
func TestWebSocketUpgradeRefusalLogsNoRawOrigin(t *testing.T) {
	up, _ := countingUpstream(t)
	var logBuf bytes.Buffer
	h, err := New(up.URL, "https://app.ctf.example.com", slog.New(slog.NewTextHandler(&logBuf, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Host = "seat1.ctf.example.com"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://secret-marker.evil.example/path")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors https://app.ctf.example.com" {
		t.Errorf("CSP on the refusal = %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("XFO on the refusal = %q, want absent when a portal origin is configured", got)
	}
	logged := logBuf.String()
	if strings.Contains(logged, "secret-marker") || strings.Contains(logged, "evil.example") {
		t.Errorf("the log carries the raw Origin: %s", logged)
	}
	for _, want := range []string{"origin_len=" + fmt.Sprint(len("https://secret-marker.evil.example/path")), "origin_scheme=https"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the log lacks %q: %s", want, logged)
		}
	}
}

// With the default 'none' the 403 and the 502 carry the same framing headers as a proxied
// response (one stampFrameHeaders for all three).
func TestRefusalAndBadGatewayCarryXFOWhenNone(t *testing.T) {
	h, err := New("http://127.0.0.1:1", "'none'", testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	refused := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Host = "seat1.ctf.example.com"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	h.ServeHTTP(refused, req)
	badGateway := httptest.NewRecorder()
	h.ServeHTTP(badGateway, httptest.NewRequest(http.MethodGet, "/", nil))
	for name, rec := range map[string]*httptest.ResponseRecorder{"403": refused, "502": badGateway} {
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: XFO = %q, want DENY", name, got)
		}
		if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
			t.Errorf("%s: CSP = %q", name, got)
		}
	}
	if refused.Code != http.StatusForbidden || badGateway.Code != http.StatusBadGateway {
		t.Errorf("codes = %d, %d, want 403, 502", refused.Code, badGateway.Code)
	}
}

// A control or bidi character in the path of a refused request does not reach the log raw.
func TestWebSocketUpgradeRefusalLogsPathEscaped(t *testing.T) {
	up, _ := countingUpstream(t)
	var logBuf bytes.Buffer
	h, err := New(up.URL, "'none'", slog.New(slog.NewTextHandler(&logBuf, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws%E2%80%AEevil%0Aforged=1", nil)
	req.Host = "seat1.ctf.example.com"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	logged := logBuf.String()
	if strings.ContainsRune(logged, '\u202e') || strings.Count(logged, "\n") != 1 {
		t.Errorf("the log carries a raw bidi or line-break character from the path: %q", logged)
	}
	if !strings.Contains(logged, "u202e") {
		t.Errorf("the log lacks the escaped path: %q", logged)
	}
}
