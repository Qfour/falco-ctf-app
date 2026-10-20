package httpx

import (
	"net/http/httptest"
	"testing"
)

func TestPeerHost(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"192.0.2.1:1234", "192.0.2.1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"192.0.2.1", "192.0.2.1"}, // no port: returned as it is
		{"", ""},
		{"@", "@"}, // a unix socket peer has no host:port shape
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.in
		if got := PeerHost(r); got != c.want {
			t.Errorf("PeerHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
