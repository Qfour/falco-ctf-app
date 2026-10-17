package scoreboard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// app#328: POST /api/challenges/{cid}/submit-detect is browser-only, origin
// guarded, and ATTACHES A SOLVE. This file pins what is specific to that
// route: a request that is turned away (no identity header, another site's
// Origin, another seat) never makes the handler read the body, never reaches
// the grader and records no solve. The bucket itself (detectMW: burst, rate,
// identity keying, header-less 403 without a token, kept apart from submit's
// per-IP bucket and the action bucket) is a row of identity_bucket_test.go's
// table; og -> detectMW is TestOriginGuardRunsBeforeRateLimiter, derived from
// Routes(). The authz half (header REQUIRED, exact canonical form, admin
// exception) is app#346 in submit_detect_authz_test.go.

const (
	sdOrigin = "https://scoreboard.ctf.local"
	sdURL    = "/api/challenges/05-detect/submit-detect"
)

// countingRunner counts Grade calls so a test can prove a denied request never
// reached the grader.
type countingRunner struct{ calls atomic.Int64 }

func (r *countingRunner) Grade(_ context.Context, _, _ string) (int, int, bool, error) {
	r.calls.Add(1)
	return 1, 0, false, nil // fires on evasion, silent on benign => solve
}

type sdFixture struct {
	t      *testing.T
	srv    *scoreboard.Handler
	st     *store.Store
	runner *countingRunner
}

func newSDFixture(t *testing.T) *sdFixture {
	t.Helper()
	cat := catalog.Catalog{
		"02-evade":  {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"},
		"05-detect": {ID: "05-detect", Type: "detect"},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "sd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	runner := &countingRunner{}
	now := time.Unix(1_700_000_000, 0)
	srv := scoreboard.NewHandler(cat, st, slog.New(slog.NewTextHandler(io.Discard, nil)),
		scoreboard.WithNow(func() time.Time { return now }),
		scoreboard.WithAdminEmails([]string{"root@ctf.local"}),
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain),
		scoreboard.WithAllowedOrigins([]string{sdOrigin}),
		scoreboard.WithDetect(api.DetectConfig{Runner: runner}),
	)
	return &sdFixture{t: t, srv: srv, st: st, runner: runner}
}

// do POSTs body with an allowed Origin (so the origin guard can never be the
// reason for a 403) and X-Auth-Request-Email = email (omitted when blank).
func (f *sdFixture) do(target, email string, body map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", target, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", sdOrigin)
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func (f *sdFixture) detect(email, user string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(sdURL, email, map[string]any{"user": user, "condition": "evt.type=open"})
}

// readTracker records whether anything read the request body.
type readTracker struct {
	r     io.Reader
	reads atomic.Int64
}

func (rt *readTracker) Read(p []byte) (int, error) {
	rt.reads.Add(1)
	return rt.r.Read(p)
}

// A header-less request must be turned away by the rate-limit middleware
// BEFORE the handler runs: the handler is the code that json-decodes the body
// (and then validates the user / calls the grader), so an anonymous flood must
// not make the server parse request bodies. Pinned by counting reads of the
// body and grader calls, not just by the status code.
func TestSubmitDetect_HeaderlessNeverEntersHandlerOrReadsBody(t *testing.T) {
	f := newSDFixture(t)
	for _, email := range []string{"", "   "} {
		body := &readTracker{r: bytes.NewReader([]byte(`{"user":"alice","condition":"evt.type=open"}`))}
		r := httptest.NewRequest("POST", sdURL, body)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", sdOrigin)
		if email != "" {
			r.Header.Set("X-Auth-Request-Email", email)
		}
		w := httptest.NewRecorder()
		f.srv.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("header %q: got %d, want 403 body=%s", email, w.Code, w.Body)
		}
		if n := body.reads.Load(); n != 0 {
			t.Fatalf("header %q: the request body was read %d times before the identity check, want 0", email, n)
		}
	}
	if n := f.runner.calls.Load(); n != 0 {
		t.Fatalf("header-less requests reached the grader %d times, want 0", n)
	}
	if f.st.IsSolved("alice", "05-detect") {
		t.Fatal("a header-less request recorded a solve for alice")
	}
	// Control: with an identity the same shape of request DOES read the body
	// and grade, so the zeros above are not an artifact of the fixture.
	body := &readTracker{r: bytes.NewReader([]byte(`{"user":"alice","condition":"evt.type=open"}`))}
	r := httptest.NewRequest("POST", sdURL, body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", sdOrigin)
	r.Header.Set("X-Auth-Request-Email", "alice@ctf.local")
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("control: got %d, want 200 body=%s", w.Code, w.Body)
	}
	if body.reads.Load() == 0 {
		t.Fatal("control: the handler never read the body; the tracker proves nothing")
	}
	if n := f.runner.calls.Load(); n != 1 {
		t.Fatalf("control: grader calls = %d, want 1", n)
	}
}

// crossOrigin POSTs as `email` with an Origin that is NOT in ALLOWED_ORIGINS.
// The identity header is valid, so the only thing that can (and must) stop
// the request is the origin guard.
func (f *sdFixture) crossOrigin(target, email string, body map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", target, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("X-Auth-Request-Email", email)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

// The route-specific half of og -> detectMW -> handler (security review of
// app#379, L1; the order itself, for every guarded rate-limited route, is
// TestOriginGuardRunsBeforeRateLimiter). Cookies are SameSite=None, so
// another site's page can make a victim's browser POST with the victim's
// identity header: that flood is 403 and never grades or solves anything.
func TestSubmitDetect_CrossOriginNeverReachesGrader(t *testing.T) {
	f := newSDFixture(t)
	for i := 0; i < 30; i++ { // far past the detect burst
		w := f.crossOrigin(sdURL, "alice@ctf.local", map[string]any{"user": "alice", "condition": "evt.type=open"})
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-origin #%d: got %d, want 403 body=%s", i, w.Code, w.Body)
		}
	}
	if n := f.runner.calls.Load(); n != 0 {
		t.Fatalf("cross-origin requests reached the grader %d times, want 0", n)
	}
	if f.st.IsSolved("alice", "05-detect") {
		t.Fatal("a cross-origin request recorded a solve for alice")
	}
	// Control: from the allowed origin the same request grades and solves.
	if w := f.detect("alice@ctf.local", "alice"); w.Code != http.StatusOK {
		t.Fatalf("control: got %d, want 200 body=%s", w.Code, w.Body)
	}
	if n := f.runner.calls.Load(); n != 1 || !f.st.IsSolved("alice", "05-detect") {
		t.Fatalf("control: grader calls = %d, solved = %v, want 1 and true", n, f.st.IsSolved("alice", "05-detect"))
	}
}

// A request for another seat is turned away by selfOrAdmin, and it must be
// turned away BEFORE the grader runs (security review of app#379, L3). The
// runner here solves on every call, so "grade first, 403 afterwards" would
// leave a victim's solve in the store and calls > 0; status alone would not
// catch that.
func TestSubmitDetect_DeniedIdentityNeverReachesGrader(t *testing.T) {
	f := newSDFixture(t)
	for _, tc := range []struct{ name, email string }{
		{"other seat (bob@ grades as alice)", "bob@ctf.local"},
		{"prefix-longer seat (alice2@ grades as alice)", "alice2@ctf.local"},
	} {
		if w := f.detect(tc.email, "alice"); w.Code != http.StatusForbidden {
			t.Fatalf("%s: got %d, want 403 body=%s", tc.name, w.Code, w.Body)
		}
	}
	if n := f.runner.calls.Load(); n != 0 {
		t.Fatalf("denied requests reached the grader %d times, want 0", n)
	}
	if f.st.IsSolved("alice", "05-detect") {
		t.Fatal("a denied request recorded a solve for alice")
	}
	// Control: the proven identity DOES reach the grader and the runner does
	// solve, so the zeros above cannot be an artifact of this fixture.
	if w := f.detect("alice@ctf.local", "alice"); w.Code != http.StatusOK {
		t.Fatalf("control: got %d, want 200 body=%s", w.Code, w.Body)
	}
	if n := f.runner.calls.Load(); n != 1 {
		t.Fatalf("control: grader calls = %d, want 1", n)
	}
	if !f.st.IsSolved("alice", "05-detect") {
		t.Fatal("control: the solving runner did not record a solve; the IsSolved check proves nothing")
	}
}
