package scoreboard_test

import (
	"net/http"
	"strings"
	"testing"
)

// app#402 at the HTTP layer: BOTH routes that set a display name (the participant
// profile route and the admin one, displayNameRoutes) refuse a flag-shaped name with
// a fixed 400 sentence that does not echo the input, and a refusal leaves the
// EXISTING stored name as it was.
func TestDisplayName_FlagShapeRejectedOnBothRoutes(t *testing.T) {
	const want = `{"error":"display name must not contain a flag-shaped value"}`
	for _, rt := range displayNameRoutes {
		for _, name := range []string{"FALCO{x}", "FALCO{}", "Alice FALCO{x}"} {
			t.Run(rt.name+"/"+name, func(t *testing.T) {
				f := newFixture(t, nil)
				if w := rt.send(f, rt.target, "Alice"); w.Code != http.StatusOK {
					t.Fatalf("setting the first name: got %d body=%s, want 200", w.Code, w.Body)
				}
				w := rt.send(f, rt.target, name)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("got %d body=%s, want 400", w.Code, w.Body)
				}
				if body := strings.TrimSpace(w.Body.String()); body != want {
					t.Fatalf("body = %s, want the fixed %s", body, want)
				}
				got := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
				if got["display_name"] != "Alice" {
					t.Fatalf("a rejected name must leave the stored one alone: display_name=%v, want Alice", got["display_name"])
				}
			})
		}
	}
}

// Names that merely look like the word are still accepted on both routes, and the
// stored name is what was sent.
func TestDisplayName_NotFlagShapedIsStillAcceptedOnBothRoutes(t *testing.T) {
	for _, rt := range displayNameRoutes {
		for _, name := range []string{"FALCO", "{}", "falco{x}", "FALCO{x"} {
			t.Run(rt.name+"/"+name, func(t *testing.T) {
				f := newFixture(t, nil)
				if w := rt.send(f, rt.target, name); w.Code != http.StatusOK {
					t.Fatalf("name=%q: got %d body=%s, want 200", name, w.Code, w.Body)
				}
				got := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
				if got["display_name"] != name {
					t.Fatalf("stored display_name = %q, want %q", got["display_name"], name)
				}
			})
		}
	}
}
