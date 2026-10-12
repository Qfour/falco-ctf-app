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
// guarded, and ATTACHES A SOLVE. It runs on its OWN identity-keyed bucket
// (detectMW -> MiddlewareStrict), not on /submit's per-IP bucket nor the
// hint/step/reset-dirty one: a header-less
// request is 403 before a token is consumed and before the handler reads the
// body, and under a venue NAT (everyone behind one IP) one participant's
// Grade clicks cannot 429 anyone else's submit. The authz half (header
// REQUIRED, exact canonical form, admin exception) is app#346 and is pinned in
// submit_detect_authz_test.go; this file pins the rate-limit half only.
//
// The clock is frozen so no bucket refills mid-test (burst 10 -> the 11th
// request in a bucket is 429, deterministically). httptest requests all share
// one RemoteAddr, i.e. the venue-NAT case: "same IP" below is literal.

const (
	sdOrigin = "https://scoreboard.ctf.local"
	sdURL    = "/api/challenges/05-detect/submit-detect"
	sdSubmit = "/api/challenges/02-evade/submit"
	sdReset  = "/api/users/alice/challenges/02-evade/reset-dirty"
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

// drain sends detect requests as `email` (grading as `user`) until the first
// 429 and returns how many were NOT limited (fails if it never 429s).
func (f *sdFixture) drain(email, user string) int {
	f.t.Helper()
	ok := 0
	for i := 0; i < 30; i++ {
		switch w := f.detect(email, user); w.Code {
		case http.StatusTooManyRequests:
			return ok
		case http.StatusOK:
			ok++
		default:
			f.t.Fatalf("submit-detect as %s: unexpected %d body=%s", email, w.Code, w.Body)
		}
	}
	f.t.Fatalf("submit-detect as %s: never rate-limited in 30 requests", email)
	return ok
}

// A header-less request (allowed Origin, no X-Auth-Request-Email) is 403 every
// time — never 429 — never reaches the grader, records no solve, and drains no
// one's bucket (it must not degrade to an IP-keyed or "unlimited" bucket).
func TestSubmitDetect_HeaderlessIs403AndConsumesNoBucket(t *testing.T) {
	f := newSDFixture(t)
	for i := 0; i < 30; i++ { // far past burst 10: 403 every time, never 429
		if w := f.detect("", "alice"); w.Code != http.StatusForbidden {
			t.Fatalf("header-less submit-detect #%d: got %d, want 403 body=%s", i, w.Code, w.Body)
		}
	}
	if n := f.runner.calls.Load(); n != 0 {
		t.Fatalf("header-less requests reached the grader %d times, want 0", n)
	}
	// A blank (whitespace-only) header is the same as no header.
	if w := f.detect("   ", "alice"); w.Code != http.StatusForbidden {
		t.Fatalf("blank-header submit-detect: got %d, want 403 body=%s", w.Code, w.Body)
	}
	// A real identity behind the same IP still has its full burst.
	if n := f.drain("alice@ctf.local", "alice"); n != 10 {
		t.Fatalf("alice's burst after the anonymous flood = %d, want 10", n)
	}
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
// body, not just by the status code.
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
	// Control: with an identity the same shape of request DOES read the body,
	// so the zero above is not an artifact of the tracker.
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
}

// Same IP, different identities: alice draining her bucket does not touch bob's.
func TestSubmitDetect_IdentityBucketsAreIndependentOnSameIP(t *testing.T) {
	f := newSDFixture(t)
	if n := f.drain("alice@ctf.local", "alice"); n != 10 {
		t.Fatalf("alice should get exactly the burst (10) before 429, got %d", n)
	}
	if w := f.detect("alice@ctf.local", "alice"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("alice stays limited, got %d body=%s", w.Code, w.Body)
	}
	if n := f.drain("bob@ctf.local", "bob"); n != 10 {
		t.Fatalf("bob (same IP) must be unaffected by alice's bucket, got burst %d want 10", n)
	}
}

// submit-detect left submit's per-IP bucket (they used to share it): draining
// one never limits the other, in either direction.
func TestSubmitDetect_DoesNotShareSubmitIPBucket(t *testing.T) {
	f := newSDFixture(t)
	f.drain("alice@ctf.local", "alice")
	for i := 0; i < 10; i++ { // a full submit burst must still be available
		w := f.do(sdSubmit, "", map[string]any{"user": "alice", "flag": "x"})
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("submit %d got 429 after submit-detect spam: the buckets are shared; body=%s", i, w.Body)
		}
	}
	// Converse (and the proof the first half can fail): submit's per-IP bucket
	// still 429s submit, but not submit-detect.
	limited := false
	for i := 0; i < 30 && !limited; i++ {
		limited = f.do(sdSubmit, "", map[string]any{"user": "alice", "flag": "x"}).Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("submit's per-IP bucket must still rate-limit (burst 10)")
	}
	if w := f.detect("bob@ctf.local", "bob"); w.Code != http.StatusOK {
		t.Fatalf("submit-detect must not be limited by submit's exhausted IP bucket, got %d body=%s", w.Code, w.Body)
	}
}

// submit-detect has its OWN identity bucket: draining it never limits
// reset-dirty (steps/check, hints) for the same participant, and the reverse.
// A burst of grader submissions must not 429 a hint open.
func TestSubmitDetect_DoesNotShareActionBucketWithResetDirty(t *testing.T) {
	f := newSDFixture(t)
	if n := f.drain("alice@ctf.local", "alice"); n != 10 {
		t.Fatalf("alice's detect burst = %d, want 10", n)
	}
	for i := 0; i < 10; i++ { // a full action burst must still be available
		if w := f.do(sdReset, "alice@ctf.local", nil); w.Code != http.StatusOK {
			t.Fatalf("reset-dirty #%d after detect exhaustion: %d body=%s (buckets shared?)", i, w.Code, w.Body)
		}
	}
	if w := f.do(sdReset, "alice@ctf.local", nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("reset-dirty past its own burst: got %d, want 429 body=%s", w.Code, w.Body)
	}
	// ...and exhausting the action bucket did not refill or spend detect's.
	if w := f.detect("alice@ctf.local", "alice"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("detect stays limited on its own bucket, got %d body=%s", w.Code, w.Body)
	}
}
