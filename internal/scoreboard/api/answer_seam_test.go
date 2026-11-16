package api

// ADR-0056 D4: the answer adapter's mapping of the Grader's typed errors to a
// status. gradeAnswer is the seam (like gradeEvade / recordExfil, app#486): a fake
// answers each error on cue, so the 500 and the second-seat-gate rows, which a real
// store cannot be made to give, are held here. The route-level behaviour with a real
// store and Judge (the four statuses, the attempt count, self-only, the leak checks)
// is internal/scoreboard/answer_route_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

const (
	seamAnswerCID    = "90-ir-demo"
	seamAnswerTyped  = "TYPED-seam-xxxx"
	seamAnswerErrMsg = "answer: could not grade"
)

// runAnswerSeam drives submitAnswer directly (the front, the guard and the bucket
// are Routes()' and are not under test here) with a Grader that answers res, gradeErr.
func runAnswerSeam(t *testing.T, res scoring.AnswerResult, gradeErr error) (code int, body map[string]any, logs string) {
	t.Helper()
	code, body, logs, called := runAnswerSeamAs(t, "alice@ctf.local", nil, res, gradeErr)
	if want := "alice|" + seamAnswerCID + "|who|" + seamAnswerTyped; called != want {
		t.Fatalf("the Grader was called with %q, want %q (the path ids and the body's answer, once)", called, want)
	}
	return code, body, logs
}

// runAnswerSeamAs is runAnswerSeam for a caller with this X-Auth-Request-Email
// (the path is alice's) and these ADMIN_EMAILS. called is what the Grader was
// called with ("" when it was not called).
func runAnswerSeamAs(t *testing.T, email string, admins []string, res scoring.AnswerResult, gradeErr error) (code int, body map[string]any, logs, called string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	cat := catalog.Catalog{seamAnswerCID: {ID: seamAnswerCID, Type: catalog.TypeInvestigate, Investigate: &catalog.Investigate{
		Questions: []catalog.Question{{ID: "who", Format: answerformat.Name, Attempts: 3}},
	}}}
	var logBuf bytes.Buffer
	now := func() time.Time { return time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC) }
	h := New(cat, scoring.New(cat, s, now), s, slog.New(slog.NewJSONHandler(&logBuf, nil)), now,
		admins, nil, nil, JourneyConfig{}, DetectConfig{}, BoardConfig{},
		IdentityConfig{ExpectedEmailDomain: "ctf.local"})
	var gotInput string
	h.gradeAnswer = func(_ context.Context, user, cid, qid, raw string) (scoring.AnswerResult, error) {
		gotInput = fmt.Sprint(user, "|", cid, "|", qid, "|", raw)
		return res, gradeErr
	}

	target := "/api/users/alice/challenges/" + seamAnswerCID + "/questions/who/answer"
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"answer":"`+seamAnswerTyped+`"}`))
	r.Header.Set("Content-Type", "application/json")
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	r.Pattern = "POST /api/users/{user}/challenges/{cid}/questions/{qid}/answer"
	r.SetPathValue("user", "alice")
	r.SetPathValue("cid", seamAnswerCID)
	r.SetPathValue("qid", "who")
	r.RemoteAddr = "192.0.2.7:999"
	w := httptest.NewRecorder()
	h.submitAnswer(w, r)
	body = map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body, err)
	}
	return w.Code, body, logBuf.String(), gotInput
}

// The handler runs the self gate again in full (defence in depth: Routes()' front is
// not the only thing between a request and the Grader). Called directly, without the
// front, a request that is not exactly alice is a 403 and the Grader is NOT called
// (so no attempt can be spent), whoever it is: another seat, an ADMIN_EMAILS
// identity (no override), another domain, no identity at all.
func TestSubmitAnswer_HandlerRechecksSelfWithoutTheFront(t *testing.T) {
	for _, tc := range []struct{ name, email string }{
		{"another seat", "bob@ctf.local"},
		{"an ADMIN_EMAILS identity on the seat domain", "admin@ctf.local"},
		{"an ADMIN_EMAILS identity on another domain", "ops@staff.example"},
		{"the same seat on another domain", "alice@evil.example"},
		{"no identity header", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admins := []string{"admin@ctf.local", "ops@staff.example"}
			code, body, logs, called := runAnswerSeamAs(t, tc.email, admins, scoring.AnswerResult{Status: scoring.AnswerCorrect, Correct: true}, nil)
			if code != http.StatusForbidden || len(body) != 1 || body["error"] != "forbidden" {
				t.Fatalf("status %d body %v, want 403 {error: forbidden}", code, body)
			}
			if called != "" {
				t.Fatalf("the Grader was called (%q) for a request the self gate refuses", called)
			}
			if strings.Contains(logs, seamAnswerTyped) {
				t.Fatalf("the typed answer reached the log:\n%s", logs)
			}
		})
	}
}

func logLines(logs, msg string) int {
	n := 0
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, `"msg":"`+msg+`"`) {
			n++
		}
	}
	return n
}

// The mapping, one row per typed error. wrapped is how the Grader really returns
// ErrAnswerFormat (fmt.Errorf("scoring: answer: %w", ...)).
func TestSubmitAnswer_GraderErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		code    int
		msg     string
		errLogs int // lines of the adapter's own Error line "answer: could not grade"
	}{
		{"unknown challenge", scoring.ErrUnknownChallenge, 404, "unknown challenge", 0},
		{"unknown question", scoring.ErrUnknownQuestion, 404, "unknown question", 0},
		{"not an investigate challenge", scoring.ErrNotInvestigate, 400, "not an investigate challenge", 0},
		{"a format error, wrapped as the Grader returns it", fmt.Errorf("scoring: answer: %w", scoring.ErrAnswerFormat), 400, "answer does not fit the question's format", 0},
		{"the Grader's missing row (it logged it already)", scoring.ErrAnswerCellMissing, 500, "could not grade the answer", 0},
		{"no answers table", scoring.ErrAnswersUnavailable, 500, "could not grade the answer", 1},
		{"a store failure", fmt.Errorf("scoring: answer attempt: %w", errors.New("sqlite: disk I/O error")), 500, "could not grade the answer", 1},
		{"a cancelled request", context.Canceled, 500, "could not grade the answer", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body, logs := runAnswerSeam(t, scoring.AnswerResult{}, tc.err)
			if code != tc.code || len(body) != 1 || body["error"] != tc.msg {
				t.Fatalf("status %d body %v, want %d {error: %q}", code, body, tc.code, tc.msg)
			}
			if got := logLines(logs, seamAnswerErrMsg); got != tc.errLogs {
				t.Fatalf("%d %q line(s), want %d:\n%s", got, seamAnswerErrMsg, tc.errLogs, logs)
			}
			if strings.Contains(jsonOf(body), "disk I/O") || strings.Contains(jsonOf(body), "sqlite") {
				t.Fatalf("an internal error text reached the body: %v", body)
			}
			// the typed text is in no log line, whatever the error
			if strings.Contains(logs, seamAnswerTyped) {
				t.Fatalf("the typed answer reached the log:\n%s", logs)
			}
		})
	}
}

// The Grader's second seat gate answering after the adapter's own (app#479): 400
// invalid user with the one fixed-field Warn, never a 500, and no user in the log.
func TestSubmitAnswer_ErrInvalidUser_Is400WithOneWarn(t *testing.T) {
	code, body, logs := runAnswerSeam(t, scoring.AnswerResult{}, scoring.ErrInvalidUser)
	if code != http.StatusBadRequest || body["error"] != "invalid user" || len(body) != 1 {
		t.Fatalf("status %d body %v, want 400 {error: invalid user}", code, body)
	}
	warns := refusedWarns(t, logs)
	if len(warns) != 1 {
		t.Fatalf("%d refused-user Warn lines, want 1:\n%s", len(warns), logs)
	}
	if w := warns[0]; w["entry"] != scoring.EntrySubmitAnswer || w["remote_addr"] != "192.0.2.7" {
		t.Fatalf("Warn = %v, want entry %s remote_addr 192.0.2.7", w, scoring.EntrySubmitAnswer)
	}
	for _, l := range lineWith(logs, refusedWarnMsg) {
		if strings.Contains(l, "alice") {
			t.Fatalf("the refused-user Warn carries the user: %s", l)
		}
	}
}

// The 200 body is the four fields of D6, from the Grader's result, and never Newly;
// the operator's log line carries newly (A3b-2 counts the solve metric on it).
func TestSubmitAnswer_ResponseIsTheFourFieldsAndNeverNewly(t *testing.T) {
	code, body, logs := runAnswerSeam(t, scoring.AnswerResult{
		Status: scoring.AnswerCorrect, Correct: true, Solved: true, Newly: true, Remaining: 2,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("status %d body %v, want 200", code, body)
	}
	want := map[string]any{"status": "correct", "correct": true, "solved": true, "remaining": float64(2)}
	if len(body) != len(want) {
		t.Fatalf("body %v has %d keys, want exactly the four of AnswerResult", body, len(body))
	}
	for k, v := range want {
		if body[k] != v {
			t.Fatalf("body[%q] = %v, want %v (body %v)", k, body[k], v, body)
		}
	}
	if _, leaked := body["newly"]; leaked {
		t.Fatal("Newly is Go-only and must not be serialised")
	}
	if !strings.Contains(logs, `"msg":"answer"`) || !strings.Contains(logs, `"newly":true`) {
		t.Fatalf("the operator's line must carry newly=true for the solve metric:\n%s", logs)
	}
}
