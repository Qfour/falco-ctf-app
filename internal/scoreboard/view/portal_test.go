package view

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRenderPortal_RoleAndUserInjection proves the two display-only globals
// are populated as expected for each isAdmin/deriveUser combination P23-1
// relies on. This is a lower-level unit test of renderPortal itself; the
// end-to-end wiring (real isAdmin/DeriveUsername, real HTTP gates on
// /api/state) is covered by internal/scoreboard's server_test.go.
func TestRenderPortal_RoleAndUserInjection(t *testing.T) {
	cases := []struct {
		name       string
		isAdmin    func(*http.Request) bool
		deriveUser func(*http.Request) string
		wantRole   string
		wantUser   string
	}{
		{
			name:       "admin with derived user",
			isAdmin:    func(*http.Request) bool { return true },
			deriveUser: func(*http.Request) string { return "alice" },
			wantRole:   `"admin"`,
			wantUser:   `"alice"`,
		},
		{
			name:       "participant with derived user",
			isAdmin:    func(*http.Request) bool { return false },
			deriveUser: func(*http.Request) string { return "bob" },
			wantRole:   `"participant"`,
			wantUser:   `"bob"`,
		},
		{
			name:       "nil isAdmin defaults to participant",
			isAdmin:    nil,
			deriveUser: func(*http.Request) string { return "carol" },
			wantRole:   `"participant"`,
			wantUser:   `"carol"`,
		},
		{
			name:       "nil deriveUser yields empty user",
			isAdmin:    func(*http.Request) bool { return true },
			deriveUser: nil,
			wantRole:   `"admin"`,
			wantUser:   `""`,
		},
		{
			name:       "both nil (test caller supplying no allowlist)",
			isAdmin:    nil,
			deriveUser: nil,
			wantRole:   `"participant"`,
			wantUser:   `""`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/portal", nil)
			w := httptest.NewRecorder()
			if err := renderPortal(w, r, tc.isAdmin, tc.deriveUser, ""); err != nil {
				t.Fatalf("renderPortal: %v", err)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status: %d", w.Code)
			}
			body := w.Body.String()
			if !strings.Contains(body, "window.__PORTAL_ROLE__ = "+tc.wantRole) {
				t.Errorf("role injection: want %s in body, body=%s", tc.wantRole, body)
			}
			if !strings.Contains(body, "window.__PORTAL_USER__ = "+tc.wantUser) {
				t.Errorf("user injection: want %s in body, body=%s", tc.wantUser, body)
			}
		})
	}
}

// TestRenderPortal_UserValueIsJSONEscaped proves a maliciously-shaped derived
// username (e.g. containing quotes / script-closing sequences — should never
// happen in practice since DeriveUsername validates against validUser, but
// this function must not assume its caller always will) cannot break out of
// the JS string context and inject a script. html/template's escaping of a
// template.JS value is what's under test here, not the *content* of a real
// DeriveUsername username (which is validated elsewhere).
func TestRenderPortal_UserValueIsJSONEscaped(t *testing.T) {
	malicious := `</script><script>alert(1)</script>`
	r := httptest.NewRequest("GET", "/portal", nil)
	w := httptest.NewRecorder()
	deriveUser := func(*http.Request) string { return malicious }
	if err := renderPortal(w, r, nil, deriveUser, ""); err != nil {
		t.Fatalf("renderPortal: %v", err)
	}
	body := w.Body.String()
	// json.Marshal escapes "<" and "/" (Go's encoding/json HTML-escapes by
	// default) so the literal "</script>" sequence must not appear verbatim.
	if strings.Contains(body, "</script><script>alert(1)</script>") {
		t.Fatalf("malicious username broke out of the JS string context: body=%s", body)
	}
}

// TestRenderPortal_MissingIdentityDegradesGracefully proves an entirely
// unauthenticated request (no X-Auth-Request-Email — e.g. a misrouted
// cluster-internal caller) still renders 200 with the safe defaults
// (participant, no username hint), matching how GET /journey and GET /me
// already degrade today for an unknown identity.
func TestRenderPortal_MissingIdentityDegradesGracefully(t *testing.T) {
	r := httptest.NewRequest("GET", "/portal", nil)
	w := httptest.NewRecorder()
	// A real isAdmin/deriveUser pair, exercised with NO identity header set on r.
	isAdmin := func(req *http.Request) bool { return req.Header.Get("X-Auth-Request-Email") == "admin@ctf.local" }
	deriveUser := func(req *http.Request) string {
		email := req.Header.Get("X-Auth-Request-Email")
		if email == "" {
			return ""
		}
		return strings.SplitN(email, "@", 2)[0]
	}
	if err := renderPortal(w, r, isAdmin, deriveUser, "ctf-event.dev"); err != nil {
		t.Fatalf("renderPortal: %v", err)
	}
	body := w.Body.String()
	if !strings.Contains(body, `window.__PORTAL_ROLE__ = "participant"`) {
		t.Errorf("expected participant default, body=%s", body)
	}
	if !strings.Contains(body, `window.__PORTAL_USER__ = ""`) {
		t.Errorf("expected empty user default, body=%s", body)
	}
	// No derived username → ttyd URL is also "" even though a suffix IS
	// configured (ttydURLFor needs BOTH inputs) — fail-safe placeholder, not
	// a guessed host.
	if !strings.Contains(body, `window.__PORTAL_TTYD_URL__ = ""`) {
		t.Errorf("expected empty ttyd URL default when identity is missing, body=%s", body)
	}
}

// TestRenderPortal_HomePanelsInjected proves GET /portal's response body
// contains the real, gen-time-rendered Home panels (the SAME homePanelsHTML
// package var every request serves — see portal.go's HomePanelsHTML field
// doc), for BOTH admin and participant callers identically (P23-5: no
// per-viewer variation, no hints, no admin-only content in this pane).
func TestRenderPortal_HomePanelsInjected(t *testing.T) {
	if len(HomeFragments) == 0 {
		t.Fatal("HomeFragments is empty — run `make gen-home-fragments` before running this test")
	}
	for _, isAdmin := range []bool{true, false} {
		r := httptest.NewRequest("GET", "/portal", nil)
		w := httptest.NewRecorder()
		fn := func(*http.Request) bool { return isAdmin }
		if err := renderPortal(w, r, fn, nil, ""); err != nil {
			t.Fatalf("renderPortal: %v", err)
		}
		body := w.Body.String()
		if !strings.Contains(body, `id="pane-home-panels"`) {
			t.Fatalf("expected the Home panels container in the response, isAdmin=%v", isAdmin)
		}
		// Every top-level Home panel label must appear somewhere in the body
		// EXCEPT "story" (P23 portal-redesign): that fragment moved to the
		// Story tab's own overview block (see home.go's buildStoryPanelHTML),
		// which renders its HTML directly with no <summary>Label</summary>
		// wrapper — so its Label is not expected to appear anywhere in a
		// fresh /portal response. See TestRenderPortal_StoryPanelInjected
		// below for the corresponding assertion on StoryPanelHTML's content.
		for _, f := range HomeFragments {
			if f.ID == "story" {
				continue
			}
			if f.ChalNN == "" {
				if !strings.Contains(body, f.Label) {
					t.Errorf("expected static panel label %q in body, isAdmin=%v", f.Label, isAdmin)
				}
			}
		}
	}
}

// TestRenderPortal_StoryPanelInjected proves GET /portal's response body
// contains the real, gen-time-rendered Story overview (the SAME
// storyPanelHTML package var every request serves — see portal.go's
// StoryPanelHTML field doc and home.go's buildStoryPanelHTML), for BOTH
// admin and participant callers identically, and that it is NOT duplicated
// into the Home panels list (see TestRenderPortal_HomePanelsInjected's
// story-exclusion note above).
func TestRenderPortal_StoryPanelInjected(t *testing.T) {
	if len(HomeFragments) == 0 {
		t.Fatal("HomeFragments is empty — run `make gen-home-fragments` before running this test")
	}
	var storyHTML string
	for _, f := range HomeFragments {
		if f.ID == "story" {
			storyHTML = f.HTML
		}
	}
	if storyHTML == "" {
		t.Skip("no story HomeFragment present in this build (fail-soft; nothing to assert)")
	}
	for _, isAdmin := range []bool{true, false} {
		r := httptest.NewRequest("GET", "/portal", nil)
		w := httptest.NewRecorder()
		fn := func(*http.Request) bool { return isAdmin }
		if err := renderPortal(w, r, fn, nil, ""); err != nil {
			t.Fatalf("renderPortal: %v", err)
		}
		body := w.Body.String()
		if !strings.Contains(body, `class="story-overview`) {
			t.Fatalf("expected the Story overview container in the response, isAdmin=%v", isAdmin)
		}
		if !strings.Contains(body, storyHTML) {
			t.Errorf("expected the story fragment's HTML in the Story overview, isAdmin=%v", isAdmin)
		}
	}
}

// TestTtydURLFor proves the iframe src builder (P23-4) only ever produces
// the CALLER's OWN host (`https://<user>.<suffix>`, matching
// charts/ctf-user's `<username>.<dnsSuffix>` Ingress host pattern exactly)
// and fails safe (returns "", so the Terminal pane shows its "not
// configured" placeholder instead of an iframe) whenever either input is
// missing — there is no code path here that can be steered by a caller into
// naming a DIFFERENT user's host, because the function never takes a
// caller-supplied hostname as input at all.
func TestTtydURLFor(t *testing.T) {
	cases := []struct {
		name   string
		user   string
		suffix string
		want   string
	}{
		{name: "both set", user: "user1", suffix: "ctf-event.dev", want: "https://user1.ctf-event.dev"},
		{name: "colima nip.io suffix", user: "user2", suffix: "10.0.0.5.nip.io", want: "https://user2.10.0.0.5.nip.io"},
		{name: "no user", user: "", suffix: "ctf-event.dev", want: ""},
		{name: "no suffix (PORTAL_TTYD_SUFFIX unset)", user: "user1", suffix: "", want: ""},
		{name: "neither set", user: "", suffix: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ttydURLFor(tc.user, tc.suffix); got != tc.want {
				t.Errorf("ttydURLFor(%q, %q) = %q, want %q", tc.user, tc.suffix, got, tc.want)
			}
		})
	}
}

// TestRenderPortal_TtydURLInjection proves the /portal HTML embeds the
// EXACT ttyd URL ttydURLFor computes for the caller's OWN derived username —
// never a different user's host — and that an empty suffix (the default,
// pre-P19 deploys) yields the fail-safe "" rather than a guessed value.
func TestRenderPortal_TtydURLInjection(t *testing.T) {
	cases := []struct {
		name       string
		deriveUser func(*http.Request) string
		suffix     string
		wantURL    string
	}{
		{
			name:       "user1 with suffix configured",
			deriveUser: func(*http.Request) string { return "user1" },
			suffix:     "ctf-event.dev",
			wantURL:    `"https://user1.ctf-event.dev"`,
		},
		{
			name:       "user2 gets ONLY their own host, never user1's",
			deriveUser: func(*http.Request) string { return "user2" },
			suffix:     "ctf-event.dev",
			wantURL:    `"https://user2.ctf-event.dev"`,
		},
		{
			name:       "suffix unset (pre-P19 / not configured) degrades to empty",
			deriveUser: func(*http.Request) string { return "user1" },
			suffix:     "",
			wantURL:    `""`,
		},
		{
			name:       "no derived user degrades to empty even with suffix set",
			deriveUser: nil,
			suffix:     "ctf-event.dev",
			wantURL:    `""`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/portal", nil)
			w := httptest.NewRecorder()
			if err := renderPortal(w, r, nil, tc.deriveUser, tc.suffix); err != nil {
				t.Fatalf("renderPortal: %v", err)
			}
			body := w.Body.String()
			if !strings.Contains(body, "window.__PORTAL_TTYD_URL__ = "+tc.wantURL) {
				t.Errorf("ttyd URL injection: want %s in body, body=%s", tc.wantURL, body)
			}
			// Cross-check: whenever a non-empty URL is expected, it must name
			// the SAME username DeriveUser returned — a regression that
			// swapped inputs (e.g. always using some fixed/admin identity)
			// would still produce a syntactically valid but WRONG host, which
			// the exact-string check above already catches, but assert the
			// substring explicitly too for a readable failure message.
			if tc.wantURL != `""` && tc.deriveUser != nil {
				user := tc.deriveUser(r)
				if !strings.Contains(body, "https://"+user+"."+tc.suffix) {
					t.Errorf("expected ttyd URL to embed the caller's own derived user %q, body=%s", user, body)
				}
			}
		})
	}
}
