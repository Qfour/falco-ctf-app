package scoreboard_test

import (
	"net/http"
	"strings"
	"testing"
)

// app#428: the body's `user` of POST /api/challenges/{cid}/submit and
// POST /internal/exfil/{cid} is claimed (the collector forwards it verbatim; that
// is the known claimed-identity premise), but it is STORED and later shown as a
// mission's first_solver on the operator's screens. It must therefore be a
// username slug (the shape validUser pins: ^[a-z0-9][a-z0-9-]{0,62}$), or the
// request is a 400 and nothing is stored, with a fixed message that does not
// echo the input.

// nonSlugUsers are values that are not a slug. Each one would have been stored
// before app#428.
var nonSlugUsers = []struct{ name, user string }{
	{"upper case", "Alice"},
	{"inner space", "user 1"},
	{"right-to-left override U+202E", "user‮1"},
	{"zero width space U+200B", "user​1"},
	{"markup", "<b>x</b>"},
	{"64 characters (one over the limit)", "a" + strings.Repeat("b", 63)},
	{"leading hyphen", "-alice"},
	{"underscore", "user_1"},
	{"inner newline", "user\n1"},
	{"email-shaped", "alice@ctf.local"},
}

// slugUsers are values the slug rule accepts; the 63-character one is the longest.
var slugUsers = []string{"user1", "team-a", "0day", "a" + strings.Repeat("b", 62)}

func TestSubmit_UserMustBeASlug_NotStored(t *testing.T) {
	for _, c := range nonSlugUsers {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, nil)
			w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": c.user, "flag": "FALCO{ok}"})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
			}
			if got := strings.TrimSpace(w.Body.String()); got != `{"error":"invalid user"}` {
				t.Fatalf("body=%s, want the fixed {\"error\":\"invalid user\"}", got)
			}
			if f.st.IsSolved(c.user, "02-evade") || f.st.SolvedCount() != 0 {
				t.Fatalf("a solve was stored for %q despite the 400 (SolvedCount=%d)", c.user, f.st.SolvedCount())
			}
		})
	}
}

func TestSubmit_SlugUserIsAcceptedAsBefore(t *testing.T) {
	for _, u := range slugUsers {
		t.Run(u, func(t *testing.T) {
			f := newFixture(t, nil)
			w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": u, "flag": "FALCO{ok}"})
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body)
			}
			if !f.st.IsSolved(u, "02-evade") {
				t.Fatalf("%q was not recorded as a solve", u)
			}
		})
	}
}

// A wrong flag from a non-slug user is still a 400 about the user (the user is
// checked before the flag is graded), so the response does not depend on the flag.
func TestSubmit_UserSlugIsCheckedBeforeTheFlag(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "Alice", "flag": "WRONG"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
	}
}

func TestExfil_UserMustBeASlug_NotStored(t *testing.T) {
	for _, c := range nonSlugUsers {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, nil)
			w := f.do("POST", "/internal/exfil/03-exfil", map[string]any{"user": c.user, "flag": "FALCO{boss}"})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
			}
			if got := strings.TrimSpace(w.Body.String()); got != `{"error":"invalid user"}` {
				t.Fatalf("body=%s, want the fixed {\"error\":\"invalid user\"}", got)
			}
			if f.st.HasExfilAny(c.user, "03-exfil") {
				t.Fatalf("an exfil receipt was stored for %q despite the 400", c.user)
			}
		})
	}
}

func TestExfil_SlugUserIsAcceptedAsBefore(t *testing.T) {
	for _, u := range slugUsers {
		t.Run(u, func(t *testing.T) {
			f := newFixture(t, nil)
			w := f.do("POST", "/internal/exfil/03-exfil", map[string]any{"user": u, "flag": "FALCO{boss}"})
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", w.Code, w.Body)
			}
			if !f.st.HasExfilAny(u, "03-exfil") {
				t.Fatalf("no receipt was stored for %q", u)
			}
		})
	}
}
