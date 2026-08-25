package scoreboard_test

// Issue #113 (security P2): api.go must never put err.Error() from a
// store/SQLite call or a JSON decode failure into a response body — the
// store can surface driver text/schema/file paths, and the decoder can name
// internal struct fields. This file pins that contract end-to-end through
// the mux (matching this package's existing httptest style, see
// server_test.go's fixture/doAs/doAdmin helpers) rather than unit-testing
// internal/scoreboard/api directly (that package has no handler-level test
// file of its own; the black-box tests here already exercise the same
// registered routes).
//
// Two fault-injection shapes are used:
//   - malformed JSON body → exercises the decode-error path
//   - the fixture's underlying SQLite handle closed before the call →
//     exercises the store-error path with a REAL driver error (not a mock),
//     so a regression that reintroduces err.Error() in the body would show
//     up as a literal "sql: database is closed" leak here.
import (
	"net/http/httptest"
	"strings"
	"testing"
)

// leakySubstrings are internal implementation details that must never reach
// a response body. Case-insensitive containment check.
var leakySubstrings = []string{
	"sql:",
	"sqlite",
	"database is closed",
	"no such table",
	"json:",
	"cannot unmarshal",
	"invalid character",
}

func assertNoLeak(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	body := strings.ToLower(w.Body.String())
	for _, s := range leakySubstrings {
		if strings.Contains(body, strings.ToLower(s)) {
			t.Fatalf("response body leaks an internal implementation detail (%q): %s", s, w.Body.String())
		}
	}
}

// assertErrorBody decodes the response and asserts its "error" field is
// EXACTLY want — not just "does not leak", but "is the one stable string a
// future RFC 9457 migration can carry forward unchanged".
func assertErrorBody(t *testing.T, w *httptest.ResponseRecorder, wantCode int, want string) {
	t.Helper()
	if w.Code != wantCode {
		t.Fatalf("status = %d, want %d (body=%s)", w.Code, wantCode, w.Body.String())
	}
	got := decode(t, w)
	if got["error"] != want {
		t.Fatalf(`error = %q, want %q`, got["error"], want)
	}
	assertNoLeak(t, w)
}

// doRawAs sends a literal, possibly-malformed body (bypassing json.Marshal)
// so a decode error is actually triggered — f.do/doAs/doAdmin/doUser
// (server_test.go) always marshal a valid Go value first.
func (f *fixture) doRawAs(method, target, email, rawBody string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(rawBody))
	r.Header.Set("Content-Type", "application/json")
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	r.Header.Set("Origin", fixtureOrigin)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

// --- decode-error path (malformed JSON body) --------------------------------

func TestErrorLeak_InvalidBody_AdminReleaseHint(t *testing.T) {
	f := newFixture(t, nil)
	w := f.doRawAs("POST", "/api/admin/hints", fixtureAdminEmail, "{")
	assertErrorBody(t, w, 400, "invalid request body")
}

func TestErrorLeak_InvalidBody_AdminSetDisplayName(t *testing.T) {
	f := newFixture(t, nil)
	w := f.doRawAs("POST", "/api/admin/users/alice/display-name", fixtureAdminEmail, "{")
	assertErrorBody(t, w, 400, "invalid request body")
}

func TestErrorLeak_InvalidBody_Submit(t *testing.T) {
	f := newFixture(t, nil)
	w := f.doRawAs("POST", "/api/challenges/02-evade/submit", "", "{")
	assertErrorBody(t, w, 400, "invalid request body")
}

func TestErrorLeak_InvalidBody_SubmitDetect(t *testing.T) {
	f := newFixture(t, nil)
	// No detect runner wired in this fixture, so submitDetect short-circuits
	// with 503 before it ever reaches the decoder. That is fine here — the
	// point of this table is the decode-error path, and TestErrorLeak_*Submit
	// above already pins the same "err.Error() must not reach the body"
	// contract for the identical json.NewDecoder call shape submitDetect
	// uses. If a future change wires a runner into this fixture, tighten
	// this test to also exercise the malformed-body 400 here.
	w := f.doRawAs("POST", "/api/challenges/nope/submit-detect", "", "{")
	if w.Code != 503 {
		t.Fatalf("status = %d, want 503 (no detect runner wired)", w.Code)
	}
	assertNoLeak(t, w)
}

func TestErrorLeak_InvalidBody_ExfilInternal(t *testing.T) {
	f := newFixture(t, nil)
	w := f.doRawAs("POST", "/internal/exfil/03-exfil", "", "{")
	assertErrorBody(t, w, 400, "invalid request body")
}

func TestErrorLeak_InvalidBody_SetDisplayName(t *testing.T) {
	f := newFixture(t, nil)
	w := f.doRawAs("POST", "/api/users/alice/display-name", "", "{")
	assertErrorBody(t, w, 400, "invalid request body")
}

// --- store-error path (real SQLite failure via closed handle) --------------
//
// Closing f.st before the call is fault injection with a REAL driver, not a
// mock: h.store.<Op> genuinely returns an error (sql.ErrConnDone-shaped),
// so these tests catch a regression that reintroduces err.Error() in the
// body exactly the way the original leak (Issue #113) manifested.

func TestErrorLeak_StoreError_AdminReset(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.doAdmin("POST", "/api/admin/reset", nil)
	assertErrorBody(t, w, 500, "could not reset scoreboard")
}

func TestErrorLeak_StoreError_AdminReleaseHint(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.doAdmin("POST", "/api/admin/hints", map[string]any{
		"mission": "01-initial-recon", "hint": 1, "released": true,
	})
	assertErrorBody(t, w, 500, "could not release hint")
}

func TestErrorLeak_StoreError_AdminSetDisplayName(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.doAdmin("POST", "/api/admin/users/alice/display-name", map[string]any{"name": "Alice"})
	assertErrorBody(t, w, 500, "could not set display name")
}

func TestErrorLeak_StoreError_SetDisplayName(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.do("POST", "/api/users/alice/display-name", map[string]any{"name": "Alice"})
	assertErrorBody(t, w, 500, "could not set display name")
}
