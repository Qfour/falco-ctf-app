package scoreboard_test

// app#479: POST /api/challenges/{cid}/submit-detect answers a body `user` that is
// not a seat with 400 "invalid user" BEFORE a grader Job is started. Two gates
// stand in front of the Job runner: the handler's identity.ValidSeat (the first,
// which answers here) and the Grader's own (scoring.SubmitDetect, the second,
// covered in scoring's TestGrader_NonSlugUserIsRefused). Neither may start the
// runner, which is a Kubernetes Job in production.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type countingDetectRunner struct{ calls atomic.Int32 }

func (c *countingDetectRunner) Grade(_ context.Context, _, _ string) (int, int, bool, error) {
	c.calls.Add(1)
	return 0, 0, false, nil
}

func TestSubmitDetect_NonSeatBodyUserIs400BeforeTheRunner(t *testing.T) {
	runner := &countingDetectRunner{}
	srv := newAuthzFixtureRunner(t, runner)
	for _, user := range []string{"Alice", "bad user", "a_b", "-lead", "evil\u202euser", strings.Repeat("a", 64), "alice@ctf.local"} {
		t.Run(user, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"user": user, "condition": "evt.type=execve"})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "/api/challenges/03-detect/submit-detect", strings.NewReader(string(body)))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", allowedOrigin)
			r.Header.Set("X-Auth-Request-Email", authzAdminEmail) // an admin may grade any SEAT; not a non-seat
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != `{"error":"invalid user"}` {
				t.Fatalf("status=%d body=%s, want 400 {\"error\":\"invalid user\"}", w.Code, w.Body)
			}
		})
	}
	if n := runner.calls.Load(); n != 0 {
		t.Fatalf("the grader runner was called %d times for a non-seat user, want 0", n)
	}
	// The other half: a seat reaches the runner (the fixture is not refusing everything).
	if w := submitDetectAs(t, srv, "alice", "alice@ctf.local"); w.Code != http.StatusOK || runner.calls.Load() != 1 {
		t.Fatalf("seat: status=%d runner calls=%d, want 200 and 1", w.Code, runner.calls.Load())
	}
}
