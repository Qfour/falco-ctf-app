package scoreboard_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
)

// app#315 (ADR-0027 Consequences, ADR-0032 D3): steps/check, hints/{idx} and
// reset-dirty share an IDENTITY-keyed bucket that is separate from submit's
// per-IP bucket. httptest requests all come from one RemoteAddr, i.e. the
// venue-NAT case: "same IP" below is literal.
//
// The clock is frozen so no bucket refills mid-test (burst 10 -> the 11th
// request in a bucket is 429, deterministically).

const (
	hintAlice = "/api/users/alice/challenges/01-recon/hints/1"
	hintBob   = "/api/users/bob/challenges/01-recon/hints/1"
	submitURL = "/api/challenges/01-recon/submit"
)

func newFrozenJourneyFixture(t *testing.T) *journeyFixture {
	t.Helper()
	now := time.Unix(1_700_000_000, 0)
	return newJourneyFixture(t, scoreboard.WithNow(func() time.Time { return now }))
}

// exhaust sends up to 30 requests as `email` and returns how many were
// answered with 200 before the first 429 (fails if it never 429s).
func (f *journeyFixture) exhaust(target, email string) int {
	f.t.Helper()
	ok := 0
	for i := 0; i < 30; i++ {
		switch w := f.reqAs("POST", target, email, nil); w.Code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			return ok
		default:
			f.t.Fatalf("%s as %s: unexpected %d body=%s", target, email, w.Code, w.Body)
		}
	}
	f.t.Fatalf("%s as %s: never rate-limited in 30 requests", target, email)
	return ok
}

// (a) Same IP, different identities: alice draining her hint bucket does not
// touch bob's.
func TestActionLimiter_SameIPDifferentIdentitiesDoNotShareBucket(t *testing.T) {
	f := newFrozenJourneyFixture(t)
	if n := f.exhaust(hintAlice, "alice@ctf.local"); n != 10 {
		t.Fatalf("alice should get exactly the burst (10) before 429, got %d", n)
	}
	if w := f.reqAs("POST", hintAlice, "alice@ctf.local", nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("alice stays limited, got %d body=%s", w.Code, w.Body)
	}
	for i := 0; i < 10; i++ {
		if w := f.reqAs("POST", hintBob, "bob@ctf.local", nil); w.Code != http.StatusOK {
			t.Fatalf("bob (same IP) request %d must be unaffected by alice's bucket, got %d body=%s", i, w.Code, w.Body)
		}
	}
}

// (b1) Draining the action bucket must not 429 the same identity's submit
// (the issue's acceptance test: a participant opening hints 20 times can never
// make a submit from that IP 429).
func TestActionLimiter_HintsDoNotConsumeSubmitBucket(t *testing.T) {
	f := newFrozenJourneyFixture(t)
	f.exhaust(hintAlice, "alice@ctf.local")
	for i := 0; i < 10; i++ { // a full submit burst must still be available
		w := f.reqAs("POST", submitURL, "alice@ctf.local", map[string]any{"user": "alice", "flag": "x"})
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("submit %d got 429 after hint spam: the buckets are shared; body=%s", i, w.Body)
		}
	}
}

// (b2) The converse, and the proof (b1) can fail: draining submit's per-IP
// bucket still 429s submit, but not hints for an identity behind that IP.
func TestActionLimiter_SubmitBucketStaysPerIPAndDoesNotLimitHints(t *testing.T) {
	f := newFrozenJourneyFixture(t)
	limited := false
	for i := 0; i < 30 && !limited; i++ {
		w := f.reqAs("POST", submitURL, "", map[string]any{"user": "alice", "flag": "x"})
		limited = w.Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("submit's per-IP bucket must still rate-limit (burst 10)")
	}
	if w := f.reqAs("POST", hintBob, "bob@ctf.local", nil); w.Code != http.StatusOK {
		t.Fatalf("hint open must not be limited by submit's exhausted IP bucket, got %d body=%s", w.Code, w.Body)
	}
}

// steps/check, hints and reset-dirty draw from ONE identity bucket.
func TestActionLimiter_ThreeRoutesShareOneIdentityBucket(t *testing.T) {
	f := newFrozenJourneyFixture(t)
	step := "/api/users/alice/challenges/01-recon/steps/0/check"
	reset := "/api/users/alice/challenges/02-evade/reset-dirty"
	for i := 0; i < 4; i++ {
		f.reqAs("POST", step, "alice@ctf.local", map[string]any{"checked": true})
	}
	for i := 0; i < 3; i++ {
		f.reqAs("POST", hintAlice, "alice@ctf.local", nil)
	}
	for i := 0; i < 3; i++ {
		f.reqAs("POST", reset, "alice@ctf.local", nil)
	}
	for name, target := range map[string]string{"steps/check": step, "hints": hintAlice, "reset-dirty": reset} {
		if w := f.reqAs("POST", target, "alice@ctf.local", map[string]any{"checked": true}); w.Code != http.StatusTooManyRequests {
			t.Fatalf("%s after 10 mixed action requests: got %d, want 429 body=%s", name, w.Code, w.Body)
		}
	}
}

// (c) A header-less request (allowed Origin, no X-Auth-Request-Email) is
// rejected 403, never 429, does its work for nobody, and drains no one's
// bucket — in particular it must not degrade to an IP-keyed bucket.
func TestActionLimiter_HeaderlessIsDeniedAndConsumesNoBucket(t *testing.T) {
	f := newFrozenJourneyFixture(t)
	targets := []string{
		hintAlice,
		"/api/users/alice/challenges/01-recon/steps/0/check",
		"/api/users/alice/challenges/02-evade/reset-dirty",
	}
	for _, target := range targets {
		for i := 0; i < 30; i++ { // far past burst 10: 403 every time, never 429
			if w := f.reqAs("POST", target, "", map[string]any{"checked": true}); w.Code != http.StatusForbidden {
				t.Fatalf("header-less %s #%d: got %d, want 403 body=%s", target, i, w.Code, w.Body)
			}
		}
	}
	// Nothing was opened or ticked...
	d := f.journey("alice")["detail"].(map[string]any)
	if opened := d["hints"].(map[string]any)["opened"].([]any); len(opened) != 0 {
		t.Fatalf("header-less requests opened hints: %v", opened)
	}
	// ...and a real identity behind the same IP still has its full burst.
	if n := f.exhaust(hintAlice, "alice@ctf.local"); n != 10 {
		t.Fatalf("alice's burst after the anonymous flood = %d, want 10", n)
	}
}
