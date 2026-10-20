package api

// app#479 review-5x: the handler's mapping of the Grader's second seat gate is
// unreachable over real HTTP (submitDetect's own identity.ValidSeat answers first),
// so deleting the branch left every test green. gradeDetect is the seam: a fake
// answers ErrInvalidUser (or another error) for a body user the first gate accepted.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

type neverRunner struct{ calls int }

func (n *neverRunner) Grade(context.Context, string, string) (int, int, bool, error) {
	n.calls++
	return 0, 0, false, nil
}

func submitDetectWithGrader(t *testing.T, gradeErr error) (code int, body map[string]any, logs string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	cat := catalog.Catalog{"03-detect": {ID: "03-detect", Type: "detect"}}
	var logBuf bytes.Buffer
	now := func() time.Time { return time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC) }
	h := New(cat, scoring.New(cat, s, now), s, slog.New(slog.NewJSONHandler(&logBuf, nil)), now,
		nil, nil, nil, JourneyConfig{}, DetectConfig{Runner: &neverRunner{}}, BoardConfig{},
		IdentityConfig{ExpectedEmailDomain: "ctf.local"})
	h.gradeDetect = func(context.Context, scoring.DetectRunner, string, string, string) (scoring.DetectOutcome, error) {
		return scoring.DetectOutcome{}, gradeErr
	}
	r := httptest.NewRequest(http.MethodPost, "/api/challenges/03-detect/submit-detect",
		strings.NewReader(`{"user":"alice","condition":"evt.type=execve"}`))
	r.Pattern = "POST /api/challenges/{cid}/submit-detect"
	r.SetPathValue("cid", "03-detect")
	r.Header.Set("X-Auth-Request-Email", "alice@ctf.local")
	r.RemoteAddr = "192.0.2.5:999"
	w := httptest.NewRecorder()
	h.submitDetect(w, r)
	body = map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body, err)
	}
	return w.Code, body, logBuf.String()
}

// The Grader's gate answering after the handler's own: 400 invalid user (never a
// 500), plus the one fixed-field Warn.
func TestSubmitDetect_GraderErrInvalidUser_Is400(t *testing.T) {
	code, body, logs := submitDetectWithGrader(t, scoring.ErrInvalidUser)
	if code != http.StatusBadRequest || body["error"] != "invalid user" || len(body) != 1 {
		t.Fatalf("status %d body %v, want 400 {error: invalid user}", code, body)
	}
	var warn int
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "grader refused a non-seat user" {
			warn++
			if m["entry"] != "SubmitDetect" || m["route"] != "POST /api/challenges/{cid}/submit-detect" || m["remote_addr"] != "192.0.2.5" {
				t.Fatalf("Warn = %v", m)
			}
		}
	}
	if warn != 1 {
		t.Fatalf("%d refused-user Warn lines, want 1:\n%s", warn, logs)
	}
}

// Any other error is still the fail-closed 500 with the fixed message and no
// internal text, and does not log the refused-user Warn.
func TestSubmitDetect_GraderOtherError_Is500(t *testing.T) {
	code, body, logs := submitDetectWithGrader(t, errors.New("falco replay exited non-zero"))
	if code != http.StatusInternalServerError || body["error"] != "could not grade condition" || len(body) != 1 {
		t.Fatalf("status %d body %v, want 500 {error: could not grade condition}", code, body)
	}
	if strings.Contains(logs, "grader refused a non-seat user") {
		t.Fatalf("a non-ErrInvalidUser error logged the refused-user Warn:\n%s", logs)
	}
}
