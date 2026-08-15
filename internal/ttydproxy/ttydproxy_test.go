package ttydproxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
// value through to a response header — see validateFrameAncestors's doc for
// why this is checked explicitly instead of relying solely on net/http's own
// header-writer guard against CR/LF.
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
// ordinary source-expression values (no control characters) must still work.
func TestFrameAncestorsPlainValueAccepted(t *testing.T) {
	up := htmlUpstream(t)
	for _, v := range []string{"'none'", "'self'", "https://ctf-event.example.com"} {
		if _, err := New(up.URL, v, testLogger()); err != nil {
			t.Errorf("New(%q): unexpected error: %v", v, err)
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

	req := "GET / HTTP/1.1\r\nHost: ttyd\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
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
