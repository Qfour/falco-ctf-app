package serverutil

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The shared http.Server rejects a request whose header block is over the cap
// with 431 before any handler runs, and still serves an ordinary request.
func TestNewServer_OversizedHeaderIs431(t *testing.T) {
	called := false
	srv := newServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	if srv.MaxHeaderBytes != 64<<10 {
		t.Fatalf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 64<<10)
	}
	// No Protocols: HTTP/1.1 only on a plain listener (unencrypted HTTP/2 stays off).
	// ttyd-proxy's WebSocket Origin check (ADR-0048, Signpost 3) reads the HTTP/1.1
	// Upgrade headers; an h2c listener would carry an extended CONNECT that this
	// check does not see, so enabling it needs that ADR revisited first.
	if srv.Protocols != nil {
		t.Fatalf("Protocols = %v, want nil (HTTP/1.1 only, no unencrypted HTTP/2; ADR-0048 Signpost 3)", srv.Protocols)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Fatalf("IdleTimeout = %v, want 120s", srv.IdleTimeout)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	base := "http://" + ln.Addr().String()

	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Header.Set("X-Pad", strings.Repeat("a", 100<<10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431", resp.StatusCode)
	}
	if called {
		t.Fatal("the handler ran for an oversized request")
	}

	resp, err = http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !called {
		t.Fatalf("ordinary request: status = %d called = %v, want 200 and the handler to run", resp.StatusCode, called)
	}
}
