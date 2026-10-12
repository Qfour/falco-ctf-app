package api

import (
	"net/http/httptest"
	"testing"
)

// ADR-0034 D5 / V11 at the unit level: the canonical-form parser and the exact
// self comparison, including the empty-domain fail-closed behaviour.
func TestUsernameFromEmail(t *testing.T) {
	cases := []struct{ email, domain, want string }{
		{"alice@ctf.local", "ctf.local", "alice"},
		{"user-7@ctf.local", "ctf.local", "user-7"},
		{"alice@other.example", "ctf.local", ""},
		{"alice@sub.ctf.local", "ctf.local", ""},
		{"alice@ctf.local.", "ctf.local", ""},
		{"alice@", "ctf.local", ""},
		{"@ctf.local", "ctf.local", ""},
		{"alice", "ctf.local", ""},
		{"", "ctf.local", ""},
		{"Alice@ctf.local", "ctf.local", ""}, // callers lower-case first; an unlowered one is not a seat
		{"al ice@ctf.local", "ctf.local", ""},
		{"alice@ctf.local", "", ""}, // empty domain: nobody
		{"alice@", "", ""},
	}
	for _, c := range cases {
		if got := UsernameFromEmail(c.email, c.domain); got != c.want {
			t.Errorf("UsernameFromEmail(%q, %q) = %q, want %q", c.email, c.domain, got, c.want)
		}
	}
}

func TestEmailMatchesUser_ExactCanonical(t *testing.T) {
	cases := []struct {
		email, user, domain string
		want                bool
	}{
		{"user1@ctf.local", "user1", "ctf.local", true},
		{"user10@ctf.local", "user1", "ctf.local", false},
		{"user1@ctf.local", "user10", "ctf.local", false},
		{"user1@other.example", "user1", "ctf.local", false},
		{"user1@ctf.local.evil.example", "user1", "ctf.local", false},
		{"user1@ctf.localx.example", "user1", "ctf.local", false},
		{"alice@", "alice", "", false}, // V11: empty domain, header `alice@`
		{"alice@ctf.local", "alice", "", false},
		{"", "alice", "ctf.local", false},
		{"alice@ctf.local", "", "ctf.local", false},
	}
	for _, c := range cases {
		if got := emailMatchesUser(c.email, c.user, c.domain); got != c.want {
			t.Errorf("emailMatchesUser(%q, %q, %q) = %v, want %v", c.email, c.user, c.domain, got, c.want)
		}
	}
}

func TestNewUsernameDeriver(t *testing.T) {
	d := NewUsernameDeriver(" CTF.Local ")
	req := func(email string) string {
		r := httptest.NewRequest("GET", "/portal", nil)
		if email != "" {
			r.Header.Set("X-Auth-Request-Email", email)
		}
		return d(r)
	}
	if got := req("Alice@CTF.LOCAL"); got != "alice" {
		t.Errorf("canonical (any case) = %q, want alice", got)
	}
	if got := req("alice@evil.example"); got != "" {
		t.Errorf("foreign domain derived %q, want empty", got)
	}
	if got := req(""); got != "" {
		t.Errorf("no header derived %q", got)
	}
	empty := NewUsernameDeriver("")
	r := httptest.NewRequest("GET", "/portal", nil)
	r.Header.Set("X-Auth-Request-Email", "alice@ctf.local")
	if got := empty(r); got != "" {
		t.Errorf("empty domain derived %q, want empty", got)
	}
}
