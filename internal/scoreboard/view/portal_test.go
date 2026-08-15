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
			if err := renderPortal(w, r, tc.isAdmin, tc.deriveUser); err != nil {
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
// happen in practice since DeriveUsername validates against ValidUser, but
// this function must not assume its caller always will) cannot break out of
// the JS string context and inject a script. html/template's escaping of a
// template.JS value is what's under test here, not the *content* of a real
// DeriveUsername username (which is validated elsewhere).
func TestRenderPortal_UserValueIsJSONEscaped(t *testing.T) {
	malicious := `</script><script>alert(1)</script>`
	r := httptest.NewRequest("GET", "/portal", nil)
	w := httptest.NewRecorder()
	deriveUser := func(*http.Request) string { return malicious }
	if err := renderPortal(w, r, nil, deriveUser); err != nil {
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
	if err := renderPortal(w, r, isAdmin, deriveUser); err != nil {
		t.Fatalf("renderPortal: %v", err)
	}
	body := w.Body.String()
	if !strings.Contains(body, `window.__PORTAL_ROLE__ = "participant"`) {
		t.Errorf("expected participant default, body=%s", body)
	}
	if !strings.Contains(body, `window.__PORTAL_USER__ = ""`) {
		t.Errorf("expected empty user default, body=%s", body)
	}
}
