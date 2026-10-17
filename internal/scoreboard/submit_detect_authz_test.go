package scoreboard_test

// app#346: POST /api/challenges/{cid}/submit-detect used to run the dual-path
// write gate (self-or-admin-write), whose header-less branch was a
// claimed-identity allow for the collector's forwards. After ADR-0034 S1 the
// collector no longer forwards this route and no workspace can reach it, so
// that branch had no legitimate caller. submit-detect is now plain
// self-or-admin (identity header REQUIRED, exact canonical match per ADR-0034
// S2) and the self-or-admin-write VOCABULARY — constant, spec value, gate
// function — is deleted. This file pins the route's behaviour. That the
// vocabulary cannot come back as dead words is not pinned here by name: it is
// the general form in internal/apispec/authz_vocabulary_test.go (every Authz
// constant is used by a Route and appears in a spec; every spec value is a
// constant) plus specparity.ClaimedIdentityForwardViolations on each
// service's Routes() (app#376).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// submitDetectAs issues POST /api/challenges/03-detect/submit-detect on the
// authz fixture (noop detect runner, so a request that passes the gate is a
// plain 200 "missed" verdict) with an ALLOWED Origin, body user `bodyUser`,
// and X-Auth-Request-Email: email when email != "" (no header at all
// otherwise).
func submitDetectAs(t *testing.T, srv http.Handler, bodyUser, email string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/challenges/03-detect/submit-detect",
		strings.NewReader(`{"user":"`+bodyUser+`","condition":"evt.type=execve"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", allowedOrigin)
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

// The table shares ONE fixture, so it depends on (a) the per-IP submit bucket
// (burst 10 per RemoteAddr; submit-detect is limited by it) — the rows must
// stay under that budget, and a new row past it turns into a 429 — and (b)
// authz_test.go's noopDetectRunner returning a "missed" verdict, which is
// what makes a request that passes the gate a plain 200.
func TestSubmitDetect_RequiresProvenIdentity(t *testing.T) {
	srv := newAuthzFixture(t)
	for _, tc := range []struct {
		name     string
		bodyUser string
		email    string
		want     int
	}{
		// The point of app#346: an allowed Origin (forgeable by anything
		// in-cluster) with NO identity header is 403, not a claimed-identity 200.
		{"no identity header (the removed claimed-identity branch)", "alice", "", http.StatusForbidden},
		{"matching identity", "alice", "alice@ctf.local", http.StatusOK},
		{"admin grading any seat", "alice", authzAdminEmail, http.StatusOK},
		{"other seat", "alice", "bob@ctf.local", http.StatusForbidden},
		{"prefix-longer seat (alice2@ is not alice@)", "alice", "alice2@ctf.local", http.StatusForbidden},
		{"same seat, foreign domain (I8: exact, not prefix)", "alice", "alice@evil.example", http.StatusForbidden},
		{"proven identity grading as another body user", "bob", "alice@ctf.local", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := submitDetectAs(t, srv, tc.bodyUser, tc.email)
			if w.Code != tc.want {
				t.Fatalf("body user %q, X-Auth-Request-Email %q: status=%d body=%s, want %d", tc.bodyUser, tc.email, w.Code, w.Body, tc.want)
			}
			if tc.want == http.StatusForbidden && !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatalf("403 body is not the {\"error\": ...} shape: %s", w.Body)
			}
		})
	}
}
