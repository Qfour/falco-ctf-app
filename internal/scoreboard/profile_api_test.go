package scoreboard_test

// ADR-0034 S1 (D8-D10) verification at the HTTP boundary: V1 (route, header,
// self), V2 (avatar id validation, no partial write), V4 (persistence,
// state, reset), V8 (no email in any GET), plus the identity rate-limit
// bucket (D8) and the "no email / name / image field" shape of the API (V7's
// HTTP half; the DB half is internal/store's column-set pin).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/avatar"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

const (
	profileOrigin = "https://scoreboard.ctf.local"
	profileAdmin  = "admin@ctf.local"
	profileAdmin2 = "ops.lead@ctf.local"
)

type profileFixture struct {
	t       *testing.T
	srv     *scoreboard.Handler
	st      *store.Store
	dbPath  string
	boardDB string
	extra   []scoreboard.Option // re-applied by reopen, so a restart keeps the same config
}

// newProfileFixture opens a store at a path the test can re-open (V4), with two
// admins so V8 can look for more than one ADMIN_EMAILS value.
func newProfileFixture(t *testing.T, extra ...scoreboard.Option) *profileFixture {
	t.Helper()
	dir := t.TempDir()
	f := &profileFixture{t: t, dbPath: filepath.Join(dir, "profile.db"), boardDB: filepath.Join(dir, "profile-board.db"), extra: extra}
	f.open(extra...)
	return f
}

func (f *profileFixture) open(extra ...scoreboard.Option) {
	f.t.Helper()
	cat := catalog.Catalog{
		"01-recon": {ID: "01-recon", Type: "trigger", ExpectedRules: []string{"Recon Rule"}},
		"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"},
	}
	st, err := store.Open(f.dbPath)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = st.Close() })
	bs, err := board.Open(f.boardDB)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = bs.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	opts := append([]scoreboard.Option{
		scoreboard.WithAdminEmails([]string{profileAdmin, profileAdmin2}),
		scoreboard.WithAllowedOrigins([]string{profileOrigin}),
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain),
		scoreboard.WithBoard(bs),
		scoreboard.WithOrder([]string{"01-recon", "02-evade"}),
	}, extra...)
	f.st = st
	f.srv = scoreboard.NewHandler(cat, st, logger, opts...)
}

// reopen closes the store and opens a brand-new store + handler on the same
// files, so anything the next request sees came back from SQLite.
func (f *profileFixture) reopen() {
	f.t.Helper()
	if err := f.st.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.open(f.extra...)
}

// raw sends body verbatim with the allowed Origin and, when email != "", the
// identity header.
func (f *profileFixture) raw(method, target, email, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	r.Header.Set("Origin", profileOrigin)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func (f *profileFixture) do(method, target, email string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	if body == nil {
		return f.raw(method, target, email, "")
	}
	b, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.raw(method, target, email, string(b))
}

func (f *profileFixture) decode(w *httptest.ResponseRecorder) map[string]any {
	f.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		f.t.Fatalf("decode JSON: %v (status=%d body=%s)", err, w.Code, w.Body)
	}
	return m
}

func (f *profileFixture) setProfile(user, email string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do("POST", "/api/users/"+user+"/profile", email, body)
}

// me reads /me as the user themselves.
func (f *profileFixture) me(user string) map[string]any {
	f.t.Helper()
	w := f.do("GET", "/api/users/"+user+"/me", user+"@ctf.local", nil)
	if w.Code != http.StatusOK {
		f.t.Fatalf("me(%s): status=%d body=%s", user, w.Code, w.Body)
	}
	return f.decode(w)
}

func (f *profileFixture) wantProfile(user, wantName, wantAvatar string) {
	f.t.Helper()
	m := f.me(user)
	if m["display_name"] != wantName || m["avatar"] != wantAvatar {
		f.t.Fatalf("%s profile = %q / %q, want %q / %q", user, m["display_name"], m["avatar"], wantName, wantAvatar)
	}
}

// --- V1: route, header, self --------------------------------------------------

// The headline: a request with an ALLOWED Origin and NO identity header is 403
// and writes nothing. (With a header-less-allowing implementation this would be a
// claimed-identity 200 — the origin guard only stops the no-Origin curl shape,
// not a forged Origin.)
func TestProfile_V1_HeaderlessWithAllowedOriginIs403(t *testing.T) {
	f := newProfileFixture(t)
	w := f.setProfile("user3", "", map[string]any{"display_name": "Mallory", "avatar": "bug-lime"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("header-less profile write: status=%d body=%s, want 403", w.Code, w.Body)
	}
	f.wantProfile("user3", "user3", avatar.Default("user3"))
}

// V1: "Routes() から self-or-admin の全 route を導出してヘッダ無しの 403を確かめる".
// The existing derivation (TestAuthz_AllDeclaredGatesEnforced) only fires with a
// MISMATCHED identity, which a header-less-allowing handler also rejects, so it
// cannot tell the two gates apart. This one sends NO header, with an allowed
// Origin (so the origin guard cannot be the thing that answered 403).
func headerlessViolation(srv http.Handler, rt apispec.Route) string {
	target := authzConcretePath(rt)
	var body io.Reader
	if rt.Method != http.MethodGet {
		body = strings.NewReader(authzGenericBody)
	}
	r := httptest.NewRequest(rt.Method, target, body)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Origin", allowedOrigin)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		return fmt.Sprintf("%s: header-less status=%d body=%s, want 403 (Authz: %s requires the identity header)", rt.MuxPattern(), w.Code, w.Body, rt.Authz)
	}
	return ""
}

func TestProfile_V1_EverySelfOrAdminRouteRejectsHeaderless(t *testing.T) {
	srv := newAuthzFixture(t)
	var checked []string
	for _, rt := range srv.Routes() {
		if rt.Authz != apispec.AuthzSelfOrAdmin {
			continue
		}
		checked = append(checked, rt.MuxPattern())
		rt := rt
		t.Run(rt.MuxPattern(), func(t *testing.T) {
			if v := headerlessViolation(srv, rt); v != "" {
				t.Fatal(v)
			}
		})
	}
	sort.Strings(checked)
	// non-vacuous: the 2 reads + steps/check + hints + reset-dirty + profile
	// + submit-detect (app#346: it used to be self-or-admin-write).
	if len(checked) != 7 {
		t.Fatalf("derived %d self-or-admin routes %v, want 7 (the derivation is broken, or a route changed gate)", len(checked), checked)
	}
	found := false
	for _, c := range checked {
		found = found || c == "POST /api/users/{user}/profile"
	}
	if !found {
		t.Fatalf("POST /api/users/{user}/profile is not declared self-or-admin: %v", checked)
	}
}

// The detector is not vacuous: a self-or-admin route backed by a handler that
// falls back to claimed-identity (the removed selfOrAdminWrite's shape) is flagged.
func TestProfile_V1_HeaderlessDetectorCatchesClaimedIdentityFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/users/{user}/profile", func(w http.ResponseWriter, r *http.Request) {
		// the removed self-or-admin-write gate's header-less branch: no header -> allow.
		if r.Header.Get("X-Auth-Request-Email") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	rt := apispec.Route{Method: "POST", Pattern: "/api/users/{user}/profile", Authz: apispec.AuthzSelfOrAdmin}
	if v := headerlessViolation(mux, rt); v == "" {
		t.Fatal("a header-less 200 on a self-or-admin route was not flagged")
	}
}

func TestProfile_V1_OtherParticipantIs403AndWritesNothing(t *testing.T) {
	f := newProfileFixture(t)
	for _, tc := range []struct{ name, email string }{
		{"a different seat", "user4@ctf.local"},
		{"prefix-longer seat (user30@ is not user3@)", "user30@ctf.local"},
		{"suffix of the seat", "xuser3@ctf.local"},
		{"outside domain, other seat", "user5@evil.example"},
		// ADR-0034 D5: self is EXACT equality with <user>@<EXPECTED_EMAIL_DOMAIN>,
		// so the same local part on another domain is not user3 either.
		{"same seat, foreign domain (I8: exact, not prefix)", "user3@evil.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.setProfile("user3", tc.email, map[string]any{"display_name": "Hijack", "avatar": "flame-slate"})
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s writing user3's profile: status=%d body=%s, want 403", tc.email, w.Code, w.Body)
			}
			f.wantProfile("user3", "user3", avatar.Default("user3"))
		})
	}
}

func TestProfile_AdminMaySetAnyonesProfile(t *testing.T) {
	f := newProfileFixture(t)
	w := f.setProfile("user3", profileAdmin, map[string]any{"display_name": "Renamed by ops", "avatar": "lock-amber"})
	if w.Code != http.StatusOK {
		t.Fatalf("admin profile write: status=%d body=%s", w.Code, w.Body)
	}
	f.wantProfile("user3", "Renamed by ops", "lock-amber")
}

func TestProfile_OriginGuardRejectsMissingAndForeignOrigin(t *testing.T) {
	f := newProfileFixture(t)
	for _, origin := range []string{"", "https://evil.example"} {
		r := httptest.NewRequest("POST", "/api/users/user3/profile", strings.NewReader(`{"display_name":"x"}`))
		r.Header.Set("X-Auth-Request-Email", "user3@ctf.local")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		f.srv.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("origin %q: status=%d body=%s, want 403", origin, w.Code, w.Body)
		}
	}
	f.wantProfile("user3", "user3", avatar.Default("user3"))
}

// --- happy path and response shape -----------------------------------------------

func TestProfile_SelfSetsBoth_ResponseAndReadsAgree(t *testing.T) {
	f := newProfileFixture(t)
	w := f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "  Alice  ", "avatar": "bug-lime"})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	got := f.decode(w)
	// The response is exactly {ok, user, display_name, avatar} (no email, no extras).
	want := map[string]any{"ok": true, "user": "user3", "display_name": "Alice", "avatar": "bug-lime"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("response = %v, want %v", got, want)
	}
	f.wantProfile("user3", "Alice", "bug-lime")

	// journey carries both too.
	jw := f.do("GET", "/api/users/user3/journey", "user3@ctf.local", nil)
	j := f.decode(jw)
	if j["display_name"] != "Alice" || j["avatar"] != "bug-lime" {
		t.Fatalf("journey profile = %v / %v", j["display_name"], j["avatar"])
	}
}

func TestProfile_PartialBodyKeepsTheOtherField_LastWriteWins(t *testing.T) {
	f := newProfileFixture(t)
	f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "First", "avatar": "bug-lime"})
	// avatar only
	if w := f.setProfile("user3", "user3@ctf.local", map[string]any{"avatar": "key-cyan"}); w.Code != http.StatusOK {
		t.Fatalf("avatar-only: %d %s", w.Code, w.Body)
	}
	f.wantProfile("user3", "First", "key-cyan")
	// name only, overwriting (NOT first-set-only)
	if w := f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "Second"}); w.Code != http.StatusOK {
		t.Fatalf("name-only: %d %s", w.Code, w.Body)
	}
	f.wantProfile("user3", "Second", "key-cyan")
}

// --- V2: validation, no partial write ----------------------------------------------

func TestProfile_V2_InvalidFieldIs400AndNothingChanges(t *testing.T) {
	long := strings.Repeat("あ", 33)
	for _, tc := range []struct {
		name string
		body string
	}{
		{"unknown avatar id with a VALID name (the partial-write case)", `{"display_name":"Fresh","avatar":"not-an-avatar"}`},
		{"valid glyph, unknown colour", `{"display_name":"Fresh","avatar":"falcon-red"}`},
		{"upper-case id", `{"display_name":"Fresh","avatar":"Falcon-Cyan"}`},
		{"empty avatar", `{"display_name":"Fresh","avatar":""}`},
		{"the operator's fixed StaffID (a table id a participant may not hold, ADR-0034 D8)", `{"display_name":"Fresh","avatar":"` + avatar.StaffID + `"}`},
		{"the operator's fixed StaffID alone", `{"avatar":"` + avatar.StaffID + `"}`},
		{"avatar with a file extension", `{"display_name":"Fresh","avatar":"falcon-cyan.svg"}`},
		{"avatar that is a path", `{"avatar":"../falcon-cyan"}`},
		{"avatar that is a URL / data URI", `{"avatar":"data:image/svg+xml;base64,PHN2Zy8+"}`},
		{"valid avatar with an INVALID name (empty)", `{"display_name":"   ","avatar":"key-cyan"}`},
		{"valid avatar with an INVALID name (33 runes)", `{"display_name":"` + long + `","avatar":"key-cyan"}`},
		{"valid avatar with an INVALID name (html)", `{"display_name":"<b>x</b>","avatar":"key-cyan"}`},
		{"both invalid", `{"display_name":"","avatar":"nope"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "Original", "avatar": "bug-lime"})
			w := f.raw("POST", "/api/users/user3/profile", "user3@ctf.local", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
			}
			assertErrorOnlyBody(t, w)
			f.wantProfile("user3", "Original", "bug-lime")
			f.reopen() // ...and nothing reached the DB either.
			f.wantProfile("user3", "Original", "bug-lime")
		})
	}
}

func TestProfile_V2_BodyMustBeExactlyTheAllowedObject(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"unknown key next to a valid one", `{"display_name":"Fresh","email":"a@b.example"}`},
		{"unknown key alone", `{"image":"AAAA"}`},
		{"email key", `{"email":"user3@ctf.local"}`},
		{"real-name key", `{"name":"Fresh"}`},
		{"empty object", `{}`},
		{"JSON null body", `null`},
		{"array body", `[]`},
		{"string body", `"x"`},
		{"avatar null (never means clear)", `{"avatar":null}`},
		{"display_name null", `{"display_name":null,"avatar":"key-cyan"}`},
		{"avatar number", `{"avatar":7}`},
		{"display_name object", `{"display_name":{"a":1}}`},
		{"trailing second object", `{"avatar":"key-cyan"}{"avatar":"bug-lime"}`},
		{"trailing garbage", `{"avatar":"key-cyan"} x`},
		{"truncated JSON", `{"avatar":"key-cyan"`},
		{"not JSON", `avatar=key-cyan`},
		{"over the size cap", `{"display_name":"` + strings.Repeat("a", 4096) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			w := f.raw("POST", "/api/users/user3/profile", "user3@ctf.local", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
			}
			assertErrorOnlyBody(t, w)
			// no decoder text / field names echoed back (Issue #113)
			for _, leak := range []string{"json:", "cannot unmarshal", "unexpected", "EOF", "oapi", "Go value"} {
				if strings.Contains(w.Body.String(), leak) {
					t.Fatalf("error body leaks decoder text %q: %s", leak, w.Body)
				}
			}
			f.wantProfile("user3", "user3", avatar.Default("user3"))
		})
	}
}

func TestProfile_InvalidUserSlugIs400(t *testing.T) {
	f := newProfileFixture(t)
	w := f.do("POST", "/api/users/User_3/profile", profileAdmin, map[string]any{"avatar": "key-cyan"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
	}
}

func assertErrorOnlyBody(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, w.Body)
	}
	if len(m) != 1 || m["error"] == nil {
		t.Fatalf("non-2xx body must be exactly {\"error\": ...}, got %v", m)
	}
}

// --- V4: persistence, /api/state, reset ----------------------------------------------

func TestProfile_V4_SurvivesReopeningTheStore(t *testing.T) {
	f := newProfileFixture(t)
	if w := f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "Persisted", "avatar": "radar-violet"}); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	f.reopen()
	f.wantProfile("user3", "Persisted", "radar-violet")
}

func (f *profileFixture) leaderboardRow(user string) map[string]any {
	f.t.Helper()
	w := f.do("GET", "/api/state", profileAdmin, nil)
	if w.Code != http.StatusOK {
		f.t.Fatalf("/api/state: %d %s", w.Code, w.Body)
	}
	lb, _ := f.decode(w)["leaderboard"].([]any)
	for _, e := range lb {
		if row, _ := e.(map[string]any); row["user"] == user {
			return row
		}
	}
	f.t.Fatalf("%s is not on the leaderboard: %v", user, lb)
	return nil
}

func TestProfile_V4_StateShowsNewValuesAndProfileResetRestoresDefaults(t *testing.T) {
	f := newProfileFixture(t)
	if _, err := f.st.MarkSolved("user3", "01-recon", "2026-10-13T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	row := f.leaderboardRow("user3")
	if row["display_name"] != "user3" || row["avatar"] != avatar.Default("user3") {
		t.Fatalf("before: leaderboard row = %v", row)
	}

	f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "Alice", "avatar": "bug-lime"})
	row = f.leaderboardRow("user3")
	if row["display_name"] != "Alice" || row["avatar"] != "bug-lime" {
		t.Fatalf("after set: leaderboard row = %v", row)
	}

	// profile-reset: back to the seat and the seat's derived avatar.
	w := f.do("POST", "/api/admin/users/user3/profile-reset", profileAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("profile-reset: %d %s", w.Code, w.Body)
	}
	got := f.decode(w)
	if got["display_name"] != "user3" || got["avatar"] != avatar.Default("user3") || got["ok"] != true {
		t.Fatalf("profile-reset response = %v", got)
	}
	row = f.leaderboardRow("user3")
	if row["display_name"] != "user3" || row["avatar"] != avatar.Default("user3") {
		t.Fatalf("after reset: leaderboard row = %v", row)
	}
	f.reopen()
	f.wantProfile("user3", "user3", avatar.Default("user3"))
}

func TestProfile_V4_StateCarriesAvatarOnEverySolverShape(t *testing.T) {
	f := newProfileFixture(t)
	if _, err := f.st.MarkSolved("user3", "01-recon", "2026-10-13T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	f.setProfile("user3", "user3@ctf.local", map[string]any{"avatar": "lock-amber"})
	m := f.decode(f.do("GET", "/api/state", profileAdmin, nil))

	var seen int
	for _, c := range m["challenges"].([]any) {
		for _, sd := range c.(map[string]any)["solver_details"].([]any) {
			seen++
			if sd.(map[string]any)["avatar"] != "lock-amber" {
				t.Fatalf("solver_details entry = %v, want avatar lock-amber", sd)
			}
		}
	}
	for _, key := range []string{"recent_solves", "solved"} {
		for _, rec := range m[key].([]any) {
			seen++
			if rec.(map[string]any)["avatar"] != "lock-amber" {
				t.Fatalf("%s entry = %v, want avatar lock-amber", key, rec)
			}
		}
	}
	if seen != 3 { // solver_details + recent_solves + solved(back-compat)
		t.Fatalf("checked %d solver-shaped entries, want 3 (the fixture lost a shape)", seen)
	}
}

func TestProfile_AdminResetRouteKeepsTheProfile(t *testing.T) {
	f := newProfileFixture(t)
	f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "Alice", "avatar": "bug-lime"})
	if w := f.do("POST", "/api/admin/reset", profileAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("admin reset: %d %s", w.Code, w.Body)
	}
	f.wantProfile("user3", "Alice", "bug-lime")
	f.reopen()
	f.wantProfile("user3", "Alice", "bug-lime")
}

func TestProfile_ProfileResetIsAdminOnlyGuardedAndIdempotent(t *testing.T) {
	f := newProfileFixture(t)
	f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "Alice", "avatar": "bug-lime"})
	url := "/api/admin/users/user3/profile-reset"

	for _, tc := range []struct {
		name, email string
	}{
		{"self (non-admin)", "user3@ctf.local"},
		{"other participant", "user4@ctf.local"},
		{"no header", ""},
	} {
		if w := f.do("POST", url, tc.email, nil); w.Code != http.StatusForbidden {
			t.Fatalf("%s: status=%d body=%s, want 403", tc.name, w.Code, w.Body)
		}
	}
	// admin, but a foreign Origin: the guard denies first.
	r := httptest.NewRequest("POST", url, nil)
	r.Header.Set("X-Auth-Request-Email", profileAdmin)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign Origin: status=%d, want 403", w.Code)
	}
	f.wantProfile("user3", "Alice", "bug-lime") // none of the above reset anything

	if w := f.do("POST", "/api/admin/users/User_3/profile-reset", profileAdmin, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid user: status=%d, want 400", w.Code)
	}
	for i := 0; i < 2; i++ {
		if w := f.do("POST", url, profileAdmin, nil); w.Code != http.StatusOK {
			t.Fatalf("admin reset #%d: %d %s", i, w.Code, w.Body)
		}
	}
	f.wantProfile("user3", "user3", avatar.Default("user3"))
	// resetting an untouched seat is a no-op 200.
	if w := f.do("POST", "/api/admin/users/user9/profile-reset", profileAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("untouched seat: %d %s", w.Code, w.Body)
	}
}

// --- defaults (D9) as the API shows them ---------------------------------------------

func TestProfile_DefaultsInResponses(t *testing.T) {
	f := newProfileFixture(t)
	seen := map[string]string{}
	for n := 1; n <= avatar.SeatCapacity; n++ {
		user := fmt.Sprintf("user%d", n)
		a, _ := f.me(user)["avatar"].(string)
		if a != avatar.IDs()[n-1] {
			t.Fatalf("%s default = %q, want the %d-th id %q", user, a, n, avatar.IDs()[n-1])
		}
		if prev, dup := seen[a]; dup {
			t.Fatalf("%s and %s share the default %q", user, prev, a)
		}
		seen[a] = user
	}
	reserved := map[string]bool{}
	for _, id := range avatar.ParticipantIDs()[avatar.SeatCapacity:] {
		reserved[id] = true
	}
	for _, user := range []string{"test1", "user01", "user41"} {
		a, _ := f.me(user)["avatar"].(string)
		if !reserved[a] {
			t.Fatalf("%s default = %q, want one of the reserved 41st..47th ids", user, a)
		}
		if a == avatar.StaffID {
			t.Fatalf("%s default is the operator's StaffID", user)
		}
		if seen[a] != "" {
			t.Fatalf("%s default %q collides with %s", user, a, seen[a])
		}
	}
	if m := f.me("user3"); m["display_name"] != "user3" {
		t.Fatalf("default display name = %v, want the seat", m["display_name"])
	}
}

func TestProfile_StoredIDOutsideTheTableReadsAsTheDefaultEverywhere(t *testing.T) {
	f := newProfileFixture(t)
	// A row a later build no longer recognises (or a hand-edited DB): written
	// through the store directly, since the API refuses to create one.
	bogus := "retired-glyph"
	if err := f.st.SetProfile("user3", nil, &bogus, "2026-10-13T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.MarkSolved("user3", "01-recon", "2026-10-13T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	want := avatar.Default("user3")
	if got := f.me("user3")["avatar"]; got != want {
		t.Fatalf("/me avatar = %v, want the default %q", got, want)
	}
	j := f.decode(f.do("GET", "/api/users/user3/journey", "user3@ctf.local", nil))
	if j["avatar"] != want {
		t.Fatalf("journey avatar = %v, want %q", j["avatar"], want)
	}
	if row := f.leaderboardRow("user3"); row["avatar"] != want {
		t.Fatalf("leaderboard avatar = %v, want %q", row["avatar"], want)
	}
	// and the profile route's own response does not echo the bogus id either.
	w := f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "Name only"})
	if got := f.decode(w)["avatar"]; got != want {
		t.Fatalf("profile response avatar = %v, want %q", got, want)
	}
}

// --- board: authorAvatar --------------------------------------------------------------

func TestProfile_BoardMessagesCarryAuthorAvatar(t *testing.T) {
	f := newProfileFixture(t)
	f.setProfile("user3", "user3@ctf.local", map[string]any{"avatar": "terminal-magenta"})

	w := f.do("POST", "/api/board/threads", "user3@ctf.local", map[string]any{"audience": "admin", "subject": "help", "body": "stuck"})
	if w.Code != http.StatusOK {
		t.Fatalf("create thread: %d %s", w.Code, w.Body)
	}
	tid := f.decode(w)["id"].(string)
	if w := f.do("POST", "/api/admin/board/threads/"+tid+"/reply", profileAdmin, map[string]any{"body": "look at the hint"}); w.Code != http.StatusOK {
		t.Fatalf("admin reply: %d %s", w.Code, w.Body)
	}
	th := f.decode(f.do("GET", "/api/board/threads/"+tid, "user3@ctf.local", nil))
	msgs := th["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want 2", len(msgs))
	}
	if got := msgs[0].(map[string]any)["authorAvatar"]; got != "terminal-magenta" {
		t.Fatalf("participant message authorAvatar = %v, want terminal-magenta", got)
	}
	if got := msgs[1].(map[string]any)["authorAvatar"]; got != avatar.StaffID {
		t.Fatalf("staff message authorAvatar = %v, want the fixed %q", got, avatar.StaffID)
	}
	// the staff id does not depend on which admin replied or on any profile row.
	f.setProfile("staff", profileAdmin, map[string]any{"avatar": "key-cyan"})
	th = f.decode(f.do("GET", "/api/board/threads/"+tid, "user3@ctf.local", nil))
	if got := th["messages"].([]any)[1].(map[string]any)["authorAvatar"]; got != avatar.StaffID {
		t.Fatalf("staff message authorAvatar changed to %v after a profile for the 'staff' slug", got)
	}
}

// --- V8: no email in any GET -------------------------------------------------------------

// V8: seed every place an admin's identity could be recorded (a board reply, an
// admin rename, an admin profile write, profile-reset, admin reset), then read
// EVERY GET route in Routes() as an admin and look for ADMIN_EMAILS values (and
// the participant's own email) in the body and the headers. The route list is
// derived, so a GET added later is covered without touching this test.
func TestProfile_V8_NoEmailInAnyGetResponse(t *testing.T) {
	f := newProfileFixture(t)
	const participant = "user3@ctf.local"

	// admin writes that might record an identity
	if w := f.do("POST", "/api/board/threads", participant, map[string]any{"audience": "all", "subject": "q", "body": "b"}); w.Code != http.StatusOK {
		t.Fatalf("create thread: %d %s", w.Code, w.Body)
	} else {
		tid := f.decode(w)["id"].(string)
		for _, admin := range []string{profileAdmin, profileAdmin2} {
			if w := f.do("POST", "/api/admin/board/threads/"+tid+"/reply", admin, map[string]any{"body": "reply"}); w.Code != http.StatusOK {
				t.Fatalf("admin reply as %s: %d %s", admin, w.Code, w.Body)
			}
		}
	}
	if w := f.do("POST", "/api/admin/users/user3/display-name", profileAdmin, map[string]any{"name": "Ops Renamed"}); w.Code != http.StatusOK {
		t.Fatalf("admin rename: %d %s", w.Code, w.Body)
	}
	if w := f.setProfile("user4", profileAdmin2, map[string]any{"display_name": "Set by admin", "avatar": "radar-lime"}); w.Code != http.StatusOK {
		t.Fatalf("admin profile write: %d %s", w.Code, w.Body)
	}
	f.setProfile("user3", participant, map[string]any{"avatar": "bug-lime"})
	if w := f.do("POST", "/api/admin/users/user5/profile-reset", profileAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("profile-reset: %d %s", w.Code, w.Body)
	}
	if _, err := f.st.MarkSolved("user3", "01-recon", "2026-10-13T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	needles := []string{profileAdmin, profileAdmin2, "ops.lead", participant, "ctf.local"}
	var gets int
	for _, rt := range f.srv.Routes() {
		if rt.Method != http.MethodGet {
			continue
		}
		gets++
		rt := rt
		t.Run(rt.MuxPattern(), func(t *testing.T) {
			target := authzConcretePath(rt)
			if rt.Pattern == "/api/users/{user}/me" || rt.Pattern == "/api/users/{user}/journey" {
				target = strings.ReplaceAll(rt.Pattern, "{user}", "user3")
			}
			for _, asEmail := range []string{profileAdmin, participant, ""} {
				r := httptest.NewRequest("GET", target, nil)
				r.Header.Set("Origin", profileOrigin)
				if asEmail != "" {
					r.Header.Set("X-Auth-Request-Email", asEmail)
				}
				w := httptest.NewRecorder()
				f.srv.ServeHTTP(w, r)
				var all strings.Builder
				all.Write(w.Body.Bytes())
				for k, vs := range w.Header() {
					all.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
				}
				hay := strings.ToLower(all.String())
				for _, n := range needles {
					if strings.Contains(hay, strings.ToLower(n)) {
						t.Fatalf("GET %s (as %q) status=%d contains %q:\n%s", target, asEmail, w.Code, n, truncate(all.String(), 400))
					}
				}
			}
		})
	}
	if gets < 8 {
		t.Fatalf("derived only %d GET routes, want >= 8 (the derivation is broken, not clean)", gets)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- V7 (HTTP half): the API has no email / name / image field ------------------------------

func TestProfile_V7_ResponsesCarryNoEmailOrImageField(t *testing.T) {
	f := newProfileFixture(t)
	w := f.setProfile("user3", "user3@ctf.local", map[string]any{"display_name": "A", "avatar": "key-cyan"})
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if fmt.Sprint(keys) != "[avatar display_name ok user]" {
		t.Fatalf("profile response keys = %v, want exactly [avatar display_name ok user]", keys)
	}
	body := bytes.ToLower(w.Body.Bytes())
	for _, banned := range []string{"@", "email", "image", "photo", "picture", "base64"} {
		if bytes.Contains(body, []byte(banned)) {
			t.Fatalf("profile response contains %q: %s", banned, w.Body)
		}
	}
}

// --- V5: scoring and visibility are untouched by a profile ---------------------------------

// stateBoard returns the /api/state leaderboard as admin: every row, in order.
func (f *profileFixture) stateBoard() []map[string]any {
	f.t.Helper()
	w := f.do("GET", "/api/state", profileAdmin, nil)
	if w.Code != http.StatusOK {
		f.t.Fatalf("/api/state: %d %s", w.Code, w.Body)
	}
	raw, _ := f.decode(w)["leaderboard"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		row, _ := e.(map[string]any)
		out = append(out, row)
	}
	return out
}

// scoreColumns is the part of a leaderboard that scoring decides, rendered as
// one comparable string: order, user, rank, score, solved and tiebreak. The
// display_name and avatar columns are deliberately left out (they are what a
// profile changes).
func scoreColumns(rows []map[string]any) string {
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%v|rank=%v|score=%v|solved=%v|earliest=%v|events=%v\n",
			r["user"], r["rank"], r["score"], r["solved"], r["earliest"], r["events"])
	}
	return b.String()
}

// ADR-0034 V5 (golden): with the same solved + hint_views, changing a display
// name or an avatar never changes who ranks where or by how much. The names
// below are chosen so an alphabetical tie-break (or any name-keyed sort) would
// reorder the board: the leader gets the alphabetically last name.
func TestProfile_V5_RankAndScoreDoNotDependOnNameOrAvatar(t *testing.T) {
	f := newProfileFixture(t)
	solve := func(user, cid, at string) {
		t.Helper()
		if _, err := f.st.MarkSolved(user, cid, at); err != nil {
			t.Fatal(err)
		}
	}
	solve("user1", "01-recon", "2026-10-13T00:01:00Z")
	solve("user1", "02-evade", "2026-10-13T00:05:00Z")
	solve("user2", "01-recon", "2026-10-13T00:02:00Z")
	solve("user3", "01-recon", "2026-10-13T00:03:00Z")
	if _, err := f.st.RecordHintView("user2", "01-recon", 1, "2026-10-13T00:02:30Z"); err != nil {
		t.Fatal(err)
	}

	before := f.stateBoard()
	if len(before) < 3 {
		t.Fatalf("precondition: leaderboard has %d rows, want the 3 solvers: %v", len(before), before)
	}
	golden := scoreColumns(before)
	if !strings.Contains(golden, "rank=1") || !strings.Contains(golden, "rank=2") {
		t.Fatalf("precondition: no ranked rows in the golden:\n%s", golden)
	}

	for user, p := range map[string]map[string]any{
		"user1": {"display_name": "Zed (last alphabetically)", "avatar": "bug-slate"},
		"user2": {"display_name": "Aaron (first alphabetically)", "avatar": "falcon-cyan"},
		"user3": {"avatar": "flame-lime"},
	} {
		if w := f.setProfile(user, user+"@ctf.local", p); w.Code != http.StatusOK {
			t.Fatalf("setProfile(%s): %d %s", user, w.Code, w.Body)
		}
	}
	after := f.stateBoard()
	if got := scoreColumns(after); got != golden {
		t.Fatalf("a profile change moved the scoring columns:\n before:\n%s after:\n%s", golden, got)
	}
	// the test must be able to fail: the profile columns DID change.
	changed := false
	for i := range after {
		if after[i]["display_name"] != before[i]["display_name"] || after[i]["avatar"] != before[i]["avatar"] {
			changed = true
		}
	}
	if !changed {
		t.Fatal("precondition: the profile change did not reach the leaderboard (the golden would pass vacuously)")
	}

	// ...and again after a reset and after a restart.
	if w := f.do("POST", "/api/admin/users/user1/profile-reset", profileAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("profile-reset: %d %s", w.Code, w.Body)
	}
	f.reopen()
	if got := scoreColumns(f.stateBoard()); got != golden {
		t.Fatalf("scoring columns moved after profile-reset + reopen:\n before:\n%s after:\n%s", golden, got)
	}
}

// ADR-0034 V5 (hidden seats): HIDDEN_USERS removes a seat from the board, and a
// profile written for that seat (by itself or by an admin) does not bring it
// back, neither as a row nor through its new display name anywhere in /api/state.
func TestProfile_V5_HiddenSeatStaysOffTheBoardAfterAProfileIsSet(t *testing.T) {
	f := newProfileFixture(t, scoreboard.WithHiddenUsers([]string{"user9"}))
	for _, u := range []string{"user3", "user9"} {
		if _, err := f.st.MarkSolved(u, "01-recon", "2026-10-13T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	onBoard := func(user string) bool {
		for _, r := range f.stateBoard() {
			if r["user"] == user {
				return true
			}
		}
		return false
	}
	if !onBoard("user3") || onBoard("user9") {
		t.Fatalf("precondition: user3 on board = %v (want true), hidden user9 on board = %v (want false)", onBoard("user3"), onBoard("user9"))
	}

	const secretName = "HiddenSeatName"
	if w := f.setProfile("user9", "user9@ctf.local", map[string]any{"display_name": secretName, "avatar": "radar-lime"}); w.Code != http.StatusOK {
		t.Fatalf("hidden seat's own profile write: %d %s", w.Code, w.Body)
	}
	if w := f.setProfile("user9", profileAdmin, map[string]any{"avatar": "key-amber"}); w.Code != http.StatusOK {
		t.Fatalf("admin writing the hidden seat's profile: %d %s", w.Code, w.Body)
	}
	if onBoard("user9") {
		t.Fatal("a profile brought the HIDDEN_USERS seat onto the leaderboard")
	}
	// HIDDEN_USERS is a leaderboard filter (api.go: the per-challenge solver
	// lists and the recent-solve feed are untouched by design), so the seat's
	// name is not asserted absent from those: it shows there under the seat id
	// already. What V5 pins is the board, and that the stats do not count it.
	var st struct {
		Stats struct {
			Users int `json:"users"`
		} `json:"stats"`
	}
	if w := f.do("GET", "/api/state", profileAdmin, nil); json.Unmarshal(w.Body.Bytes(), &st) != nil || st.Stats.Users != 1 {
		t.Fatalf("stats.users = %d after the hidden seat set a profile, want 1 (only user3 is counted): %s", st.Stats.Users, w.Body)
	}
	f.reopen()
	if onBoard("user9") {
		t.Fatal("the hidden seat is back on the leaderboard after a restart")
	}
	if !onBoard("user3") {
		t.Fatal("the visible seat disappeared")
	}
}
