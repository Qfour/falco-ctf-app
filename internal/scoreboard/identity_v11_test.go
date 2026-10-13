package scoreboard_test

// ADR-0034 V11: the scoreboard's "self" is EXACT equality with the canonical
// `<user>@<EXPECTED_EMAIL_DOMAIN>` that auth-policy stamps. The old rule was a
// prefix (`<user>@…`, any domain), which only auth-policy's roster made safe;
// with an external IdP that prefix would let `user7@<anywhere>` read user7.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
)

func TestV11_SelfIsTheCanonicalFormOnly(t *testing.T) {
	cases := []struct {
		name  string
		user  string
		email string
		want  int
	}{
		{"canonical", "user7", "user7@ctf.local", 200},
		{"canonical, upper-cased header", "user7", "USER7@CTF.LOCAL", 200},
		{"canonical with surrounding blanks", "user7", "  user7@ctf.local ", 200},
		// the point of D5: same local part, different domain
		{"other domain", "user7", "user7@other.example", 403},
		{"look-alike domain suffix", "user7", "user7@ctf.local.evil.example", 403},
		{"look-alike domain prefix", "user7", "user7@evil.ctf.local", 403},
		{"subdomain of the expected domain", "user7", "user7@sub.ctf.local", 403},
		{"trailing dot", "user7", "user7@ctf.local.", 403},
		{"no domain at all", "user7", "user7@", 403},
		{"no @ (a bare username)", "user7", "user7", 403},
		{"another seat", "user7", "user8@ctf.local", 403},
		// the old prefix boundary still holds
		{"seat is a prefix of the caller (user1 vs user10)", "user1", "user10@ctf.local", 403},
		{"caller is a prefix of the seat (user10 vs user1)", "user10", "user1@ctf.local", 403},
		{"caller is a prefix of the seat, other domain", "user10", "user1@other.example", 403},
		{"+tag is not folded here (auth-policy folds, never the scoreboard)", "user7", "user7+x@ctf.local", 403},
	}
	for _, c := range cases {
		for _, ep := range []string{"/me", "/journey"} {
			t.Run(c.name+ep, func(t *testing.T) {
				f := newJourneyFixture(t)
				w := f.reqAs("GET", "/api/users/"+c.user+ep, c.email, nil)
				if w.Code != c.want {
					t.Fatalf("GET /api/users/%s%s as %q: got %d (%s), want %d", c.user, ep, c.email, w.Code, w.Body, c.want)
				}
			})
		}
	}
}

// V11: an EMPTY EXPECTED_EMAIL_DOMAIN means no email is ever a participant's
// own — header `alice@` (the old "empty domain" shape) and `alice@ctf.local`
// both fail, on reads and on header-present writes. An admin still gets in.
func TestV11_EmptyDomainNobodyIsSelf(t *testing.T) {
	newEmpty := func(t *testing.T) *journeyFixture {
		return newJourneyFixture(t,
			scoreboard.WithExpectedEmailDomain(""),
			scoreboard.WithAdminEmails([]string{"root@ctf.local"}))
	}
	for _, email := range []string{"alice@", "alice@ctf.local", "alice@anything.example", "alice", "@"} {
		t.Run(email, func(t *testing.T) {
			f := newEmpty(t)
			for _, ep := range []string{"/me", "/journey"} {
				if w := f.reqAs("GET", "/api/users/alice"+ep, email, nil); w.Code != http.StatusForbidden {
					t.Errorf("GET %s as %q with an empty domain: got %d, want 403", ep, email, w.Code)
				}
			}
			// header-present write (selfOrAdminWrite's gate): same closed answer.
			// A route whose browser path is open (display-name's is closed, so
			// a 403 there would prove nothing about the domain).
			if w := f.reqAs("POST", "/api/users/alice/challenges/01-recon/hints/1", email, nil); w.Code != http.StatusForbidden {
				t.Errorf("POST hint open as %q with an empty domain: got %d, want 403", email, w.Code)
			}
		})
	}
	t.Run("admin is unaffected", func(t *testing.T) {
		f := newEmpty(t)
		if w := f.reqAs("GET", "/api/users/alice/me", "root@ctf.local", nil); w.Code != http.StatusOK {
			t.Fatalf("admin with an empty domain: got %d (%s), want 200", w.Code, w.Body)
		}
	})
	// control: the same fixture with the domain set lets alice@ctf.local in, so
	// the 403s above are caused by the empty domain and nothing else.
	t.Run("control: domain set", func(t *testing.T) {
		f := newJourneyFixture(t)
		if w := f.reqAs("GET", "/api/users/alice/me", "alice@ctf.local", nil); w.Code != http.StatusOK {
			t.Fatalf("control: got %d (%s)", w.Code, w.Body)
		}
		if w := f.reqAs("POST", "/api/users/alice/challenges/01-recon/hints/1", "alice@ctf.local", nil); w.Code != http.StatusOK {
			t.Fatalf("control (write): got %d (%s)", w.Code, w.Body)
		}
	})
}

// v11WriteRoutes are the header-gated WRITE routes that stay open to a
// header-bearing participant: they all go through selfOrAdminWrite, and each
// answers 200 for the canonical identity. display-name is deliberately NOT
// among them: the browser path to it is closed (ADR-0034 D12 / the display-name
// hotfix: with X-Auth-Request-* present it is always 403), so a 200 control or a
// 403 there would not say anything about the domain comparison.
var v11WriteRoutes = []struct {
	name, target string
	body         any
	prep         func(t *testing.T, f *journeyFixture)
}{
	{"step check", "/api/users/user7/challenges/01-recon/steps/0/check", map[string]any{"checked": true}, nil},
	{"hint open", "/api/users/user7/challenges/01-recon/hints/1", nil, nil},
	{"reset-dirty", "/api/users/user7/challenges/02-evade/reset-dirty", nil, func(t *testing.T, f *journeyFixture) {
		t.Helper()
		if err := f.st.MarkDirty("user7", "02-evade", "Recon Rule", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}},
}

// V11: header-present writes use the same exact comparison. For every
// selfOrAdminWrite route the canonical identity gets 200 (the control) while the
// same local part on another domain, and another seat on the right domain, get
// 403 from the identity comparison: the header is present and well-formed in
// every case, so "empty header" cannot be the reason (the canonical row is the
// control on the same route and fixture).
//
// There is deliberately no header-less case here: selfOrAdminWrite's header-less
// fallback has no legitimate caller on these routes (the collector does not
// forward them and a workspace cannot reach the scoreboard: NetworkPolicy).
func TestV11_WriteGateIsExactToo(t *testing.T) {
	cases := []struct {
		name  string
		email string
		want  int
	}{
		{"canonical identity (control)", "user7@ctf.local", http.StatusOK},
		{"canonical, upper-cased header", "USER7@CTF.LOCAL", http.StatusOK},
		{"same local part, foreign domain", "user7@other.example", http.StatusForbidden},
		{"same local part, look-alike domain suffix", "user7@ctf.local.evil.example", http.StatusForbidden},
		{"another seat on the right domain", "user8@ctf.local", http.StatusForbidden},
		{"seat is a prefix of the caller", "user70@ctf.local", http.StatusForbidden},
	}
	for _, rt := range v11WriteRoutes {
		for _, c := range cases {
			t.Run(rt.name+"/"+c.name, func(t *testing.T) {
				f := newJourneyFixture(t)
				if rt.prep != nil {
					rt.prep(t, f)
				}
				w := f.reqAs("POST", rt.target, c.email, rt.body)
				if w.Code != c.want {
					t.Fatalf("POST %s as %q: got %d (%s), want %d", rt.target, c.email, w.Code, w.Body, c.want)
				}
			})
		}
	}
}

// V11: the derived username (portal hint and board author) accepts only the
// canonical form too: `alice@evil.example` must not become the board author
// "alice", nor the portal's __PORTAL_USER__.
func TestV11_DerivedUsernameIsCanonicalOnly(t *testing.T) {
	f := newBoardFixture(t)
	post := func(email string) *httpResult {
		w := f.do("POST", "/api/board/threads", email, map[string]any{"audience": "all", "subject": "s", "body": "b"})
		return &httpResult{code: w.Code, body: w.Body.String()}
	}
	if r := post("alice@other.example"); r.code != http.StatusForbidden {
		t.Errorf("board create as alice@other.example: got %d (%s), want 403 (not a canonical identity)", r.code, r.body)
	}
	if r := post("alice@"); r.code != http.StatusForbidden {
		t.Errorf("board create as alice@: got %d, want 403", r.code)
	}
	if r := post("alice@ctf.local"); r.code != http.StatusOK {
		t.Errorf("board create as alice@ctf.local: got %d (%s), want 200", r.code, r.body)
	}

	// With an empty domain NOBODY can post on the board (author unusable).
	fe := newBoardFixture(t, scoreboard.WithExpectedEmailDomain(""))
	if w := fe.do("POST", "/api/board/threads", "alice@ctf.local", map[string]any{"audience": "all", "subject": "s", "body": "b"}); w.Code != http.StatusForbidden {
		t.Errorf("board create with an empty domain: got %d (%s), want 403", w.Code, w.Body)
	}

	// The portal hint.
	for _, c := range []struct{ email, wantUser string }{
		{"alice@ctf.local", `window.__PORTAL_USER__ = "alice"`},
		{"alice@other.example", `window.__PORTAL_USER__ = ""`},
		{"alice@", `window.__PORTAL_USER__ = ""`},
	} {
		pf := newFixture(t, nil)
		w := pf.doAs("GET", "/portal", c.email, nil)
		if !strings.Contains(w.Body.String(), c.wantUser) {
			t.Errorf("/portal as %q: want %q in the page", c.email, c.wantUser)
		}
	}
}

type httpResult struct {
	code int
	body string
}
