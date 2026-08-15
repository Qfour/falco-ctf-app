package scoreboard_test

// P23-2: origin guard integration tests. These exercise the middleware
// end-to-end through scoreboard.NewHandler (not the originguard package
// directly) so the assertions match what a real deployment sees: the exact
// set of routes wrapped in internal/scoreboard/api.Register, wired via
// scoreboard.WithAllowedOrigins.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// newOriginFixture builds a handler carrying an evade + exfil-required
// challenge (so /submit and /internal/exfil/{cid} are both exercisable) and
// an admin identity, with the given allowed origins wired in.
func newOriginFixture(t *testing.T, allowedOrigins []string) *scoreboard.Handler {
	t.Helper()
	cat := catalog.Catalog{
		"02-evade": {
			ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"},
			ExpectedFlag: "FALCO{ok}", WindowSeconds: 10,
		},
		"03-exfil": {
			ID: "03-exfil", Type: "evade", ForbiddenRules: []string{"r"},
			ExpectedFlag: "FALCO{boss}", WindowSeconds: 10, RequireExfil: true,
		},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "og.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithAdminEmails([]string{"admin@ctf.local"}),
		scoreboard.WithAllowedOrigins(allowedOrigins),
	)
}

// ogReq issues a request against srv with optional Origin/Referer/auth
// headers. body may be nil (several protected routes, like /api/admin/reset,
// take no body at all — the mitigation's core case).
func ogReq(t *testing.T, srv *scoreboard.Handler, method, target string, origin, referer, authEmail string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, body)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if referer != "" {
		r.Header.Set("Referer", referer)
	}
	if authEmail != "" {
		r.Header.Set("X-Auth-Request-Email", authEmail)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

const allowedOrigin = "https://scoreboard.ctf.example.com"

// TestOriginGuard_ResetFormCSRF is the mitigation's headline case: a
// body-less POST /api/admin/reset (the route a CSRF <form> auto-submit can
// hit without any CORS preflight) must be rejected when the request carries
// a foreign Origin, even though the caller also presents a valid admin
// identity header — an attacker riding a victim admin's session cookie would
// still supply that header via the browser, so the Origin check must be the
// thing that stops it.
func TestOriginGuard_ResetFormCSRF(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})

	w := ogReq(t, srv, "POST", "/api/admin/reset", "https://evil.example.com", "", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin reset: status=%d body=%s, want 403", w.Code, w.Body)
	}

	w = ogReq(t, srv, "POST", "/api/admin/reset", allowedOrigin, "", "admin@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("same-origin reset: status=%d body=%s, want 200", w.Code, w.Body)
	}
}

// TestOriginGuard_MissingOriginAndReferer covers the fail-closed default: a
// protected POST with neither Origin nor Referer is denied, even carrying a
// valid admin identity.
func TestOriginGuard_MissingOriginAndReferer(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})
	w := ogReq(t, srv, "POST", "/api/admin/reset", "", "", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", w.Code, w.Body)
	}
}

// TestOriginGuard_EmptyAllowlistDeniesAll asserts the fail-closed default
// (ALLOWED_ORIGINS unset): every guarded route denies even a same-origin-
// looking request, because nothing is in the allowlist to match against.
func TestOriginGuard_EmptyAllowlistDeniesAll(t *testing.T) {
	srv := newOriginFixture(t, nil)
	w := ogReq(t, srv, "POST", "/api/admin/reset", allowedOrigin, "", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403 (empty allowlist must deny)", w.Code, w.Body)
	}
}

// TestOriginGuard_RefererFallback: browsers that omit Origin on some
// navigations still send Referer; the guard must derive the origin from it
// and apply the same allowlist check.
func TestOriginGuard_RefererFallback(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})

	// Allowed referer origin (path/query beyond the origin must be ignored).
	w := ogReq(t, srv, "POST", "/api/admin/reset", "", allowedOrigin+"/admin/panel?x=1", "admin@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("allowed referer: status=%d body=%s, want 200", w.Code, w.Body)
	}

	// Disallowed referer origin → 403.
	w = ogReq(t, srv, "POST", "/api/admin/reset", "", "https://evil.example.com/x", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("disallowed referer: status=%d body=%s, want 403", w.Code, w.Body)
	}
}

// TestOriginGuard_OriginWinsOverReferer: when both headers are present,
// Origin is authoritative — a mismatched Referer must not save (or sink) the
// request if Origin itself passes (or fails) the allowlist.
func TestOriginGuard_OriginWinsOverReferer(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})

	// Origin allowed, Referer would fail on its own — request still passes.
	w := ogReq(t, srv, "POST", "/api/admin/reset", allowedOrigin, "https://evil.example.com/x", "admin@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("origin allowed despite bad referer: status=%d body=%s, want 200", w.Code, w.Body)
	}
}

// TestOriginGuard_MultipleAllowedOrigins: the CSV allowlist supports more
// than one entry (future portal origin alongside the existing scoreboard
// host), and each is matched independently/exactly.
func TestOriginGuard_MultipleAllowedOrigins(t *testing.T) {
	const portalOrigin = "https://portal.ctf.example.com"
	srv := newOriginFixture(t, []string{allowedOrigin, portalOrigin})

	for _, origin := range []string{allowedOrigin, portalOrigin} {
		w := ogReq(t, srv, "POST", "/api/admin/reset", origin, "", "admin@ctf.local", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("origin %s: status=%d body=%s, want 200", origin, w.Code, w.Body)
		}
	}
	// A third, unlisted origin is still denied.
	w := ogReq(t, srv, "POST", "/api/admin/reset", "https://unlisted.example.com", "", "admin@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unlisted origin: status=%d body=%s, want 403", w.Code, w.Body)
	}
}

// TestOriginGuard_AllProtectedRoutesEnforced walks every browser-facing
// state-changing route the api handler registers and asserts a cross-origin
// POST is rejected on each — this is the regression fence against a future
// route being added to Register without being wrapped in the guard.
func TestOriginGuard_AllProtectedRoutesEnforced(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})
	const evilOrigin = "https://evil.example.com"

	cases := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{"admin_reset", "POST", "/api/admin/reset", ""},
		{"admin_display_name", "POST", "/api/admin/users/alice/display-name", `{"name":"Alice"}`},
		{"admin_hints", "POST", "/api/admin/hints", `{"mission":"02-evade","hint":1,"released":true}`},
		{"submit", "POST", "/api/challenges/02-evade/submit", `{"user":"alice","flag":"FALCO{ok}"}`},
		{"submit_detect", "POST", "/api/challenges/02-evade/submit-detect", `{"user":"alice","condition":"x"}`},
		{"step_check", "POST", "/api/users/alice/challenges/02-evade/steps/0/check", `{"checked":true}`},
		{"open_hint", "POST", "/api/users/alice/challenges/02-evade/hints/1", ""},
		{"display_name", "POST", "/api/users/alice/display-name", `{"name":"Alice"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			w := ogReq(t, srv, tc.method, tc.target, evilOrigin, "", "admin@ctf.local", body)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s: status=%d body=%s, want 403 (cross-origin must be denied)", tc.name, w.Code, w.Body)
			}
		})
	}
}

// TestOriginGuard_ExfilBypassesGuard is the collector-only server-to-server
// sink regression fence: POST /internal/exfil/{cid} must NOT be gated by the
// origin guard — it has no browser Origin/Referer, and gating it would
// silently break the boss-capstone scoring path (exfil receipts would 403
// forever regardless of ALLOWED_ORIGINS).
func TestOriginGuard_ExfilBypassesGuard(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin}) // non-empty allowlist, still no Origin sent below

	body := strings.NewReader(`{"user":"alice","flag":"FALCO{boss}"}`)
	w := ogReq(t, srv, "POST", "/internal/exfil/03-exfil", "", "", "", body)
	if w.Code != http.StatusOK {
		t.Fatalf("exfil without Origin/Referer: status=%d body=%s, want 200 (server-to-server sink must not be origin-gated)", w.Code, w.Body)
	}

	// Also true with an EMPTY allowlist — exfil must keep working even before
	// an operator has configured ALLOWED_ORIGINS at all.
	srv2 := newOriginFixture(t, nil)
	w2 := ogReq(t, srv2, "POST", "/internal/exfil/03-exfil", "", "", "", strings.NewReader(`{"user":"bob","flag":"FALCO{boss}"}`))
	if w2.Code != http.StatusOK {
		t.Fatalf("exfil with empty allowlist: status=%d body=%s, want 200", w2.Code, w2.Body)
	}
}
