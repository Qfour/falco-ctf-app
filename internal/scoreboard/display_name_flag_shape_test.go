package scoreboard_test

import (
	"net/http"
	"strings"
	"testing"
)

// app#402 at the HTTP layer: BOTH routes that set a display name (the participant
// profile route and the admin one) refuse a flag-shaped name with a fixed 400
// sentence that does not echo the input, and store nothing.
func TestDisplayName_FlagShapeRejectedOnBothRoutes(t *testing.T) {
	const want = `{"error":"display name must not contain a flag-shaped value"}`
	for _, rt := range displayNameRoutes {
		for _, name := range []string{"FALCO{x}", "FALCO{}", "Alice FALCO{x}"} {
			t.Run(rt.name+"/"+name, func(t *testing.T) {
				f := newFixture(t, nil)
				var body string
				switch {
				case strings.Contains(rt.name, "admin"):
					w := f.doAdmin("POST", rt.target, map[string]any{"name": name})
					if w.Code != http.StatusBadRequest {
						t.Fatalf("got %d body=%s, want 400", w.Code, w.Body)
					}
					body = strings.TrimSpace(w.Body.String())
				default:
					w := f.doUser("POST", rt.target, "alice", map[string]any{"display_name": name})
					if w.Code != http.StatusBadRequest {
						t.Fatalf("got %d body=%s, want 400", w.Code, w.Body)
					}
					body = strings.TrimSpace(w.Body.String())
				}
				if body != want {
					t.Fatalf("body = %s, want the fixed %s", body, want)
				}
				got := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
				if got["display_name"] != "alice" {
					t.Fatalf("a rejected name must not be stored, display_name=%v", got["display_name"])
				}
			})
		}
	}
}

// Names that merely look like the word are still accepted on both routes.
func TestDisplayName_NotFlagShapedIsStillAcceptedOnBothRoutes(t *testing.T) {
	for _, rt := range displayNameRoutes {
		for _, name := range []string{"FALCO", "{}", "falco{x}", "FALCO{x"} {
			t.Run(rt.name+"/"+name, func(t *testing.T) {
				f := newFixture(t, nil)
				if code := rt.do(f, rt.target, map[string]any{"name": name}); code != http.StatusOK {
					t.Fatalf("name=%q: got %d, want 200", name, code)
				}
			})
		}
	}
}
