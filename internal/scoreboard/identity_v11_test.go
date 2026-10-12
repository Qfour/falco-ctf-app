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
			if w := f.reqAs("POST", "/api/users/alice/display-name", email, map[string]any{"name": "Alice"}); w.Code != http.StatusForbidden {
				t.Errorf("POST display-name as %q with an empty domain: got %d, want 403", email, w.Code)
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
	})
}

// V11: header-present writes use the same exact comparison.
func TestV11_WriteGateIsExactToo(t *testing.T) {
	f := newJourneyFixture(t)
	if w := f.reqAs("POST", "/api/users/user7/display-name", "user7@other.example", map[string]any{"name": "mallory"}); w.Code != http.StatusForbidden {
		t.Fatalf("foreign-domain write as user7: got %d (%s), want 403", w.Code, w.Body)
	}
	if w := f.reqAs("POST", "/api/users/user7/display-name", "user7@ctf.local", map[string]any{"name": "Seven"}); w.Code != http.StatusOK {
		t.Fatalf("canonical write as user7: got %d (%s), want 200", w.Code, w.Body)
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
