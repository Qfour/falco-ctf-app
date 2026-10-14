package harness

import (
	"net"
	"net/http"
	"sync"
)

// Site is a tiny page server the harness starts for the self-test of the
// assertions (ADR-0031 V2): a handler on a loopback port that the Proxy may
// forward to, like the scoreboard child. It exists so that the self-test pages
// travel the same path as the portal (browser -> Proxy -> upstream).
type Site struct {
	ln   net.Listener
	srv  *http.Server
	once sync.Once
}

// NewSite serves h on a free loopback port.
func NewSite(h http.Handler) (*Site, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Site{ln: ln, srv: &http.Server{Handler: h}}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

func (s *Site) upstreamAddr() string { return s.ln.Addr().String() }

// Close stops the site.
func (s *Site) Close() { s.once.Do(func() { _ = s.srv.Close() }) }
