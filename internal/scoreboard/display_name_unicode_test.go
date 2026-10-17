package scoreboard_test

import (
	"net/http"
	"testing"
)

// app#331 at the HTTP layer: BOTH routes that set a display name — the
// participant profile route (ADR-0034 D8; display_name field) and the admin
// one — go through the same validDisplayName, so a Unicode Cf / C1 character is
// a 400 on either, and a rejected request does not change the stored name.

var displayNameRoutes = []struct {
	name   string
	target string
	do     func(f *fixture, target string, body any) int
}{
	{"participant POST /api/users/{user}/profile", "/api/users/alice/profile",
		func(f *fixture, target string, body any) int {
			// body is {"name": n}; the profile route's field is display_name.
			return f.doUser("POST", target, "alice", map[string]any{"display_name": body.(map[string]any)["name"]}).Code
		}},
	{"admin POST /api/admin/users/{user}/display-name", "/api/admin/users/alice/display-name",
		func(f *fixture, target string, body any) int { return f.doAdmin("POST", target, body).Code }},
}

func TestDisplayName_RejectsFormatAndC1OnBothRoutes(t *testing.T) {
	bad := map[string]string{
		"U+200B zero width space": "Ali\u200bce",
		"U+202E bidi override":    "\u202eecilA",
		"U+0085 NEL":              "Ali\u0085ce",
		"U+009F C1":               "Ali\u009fce",
		"U+FEFF":                  "Ali\ufeffce",
		"ZWJ after a letter":      "Alice\u200d",
	}
	for _, rt := range displayNameRoutes {
		for label, name := range bad {
			t.Run(rt.name+"/"+label, func(t *testing.T) {
				f := newFixture(t, nil)
				if code := rt.do(f, rt.target, map[string]any{"name": name}); code != http.StatusBadRequest {
					t.Fatalf("name=%q: got %d, want 400", name, code)
				}
				// Rejected => nothing stored: still the username default.
				got := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
				if got["display_name"] != "alice" {
					t.Fatalf("a rejected name must not be stored, display_name=%v", got["display_name"])
				}
			})
		}
	}
}

func TestDisplayName_AcceptsJapaneseEmojiAndCombiningOnBothRoutes(t *testing.T) {
	good := []string{"山田 太郎", "🦊 Fox", "👩\u200d💻", "Cafe\u0301", "Alice ★"}
	for _, rt := range displayNameRoutes {
		for _, name := range good {
			t.Run(rt.name+"/"+name, func(t *testing.T) {
				f := newFixture(t, nil)
				if code := rt.do(f, rt.target, map[string]any{"name": name}); code != http.StatusOK {
					t.Fatalf("name=%q: got %d, want 200", name, code)
				}
				got := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
				if got["display_name"] != name {
					t.Fatalf("stored display_name = %q, want %q", got["display_name"], name)
				}
			})
		}
	}
}
