package api

// app#486 (the same seam as submit_detect_grader_err_test.go): submit's and
// exfilInternal's own identity.ValidSeat answers first, so their mapping of the
// Grader's second seat gate (scoring.ErrInvalidUser -> 400 {"error": "invalid user"}
// + one fixed-field Warn) is unreachable over real HTTP, and deleting the branch
// left every test green. gradeEvade / recordExfil are the seams: a fake answers
// ErrInvalidUser for a body user the handler's own gate accepted. The three
// handlers share refuseGraderUser; this holds each call site.

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

const refusedWarnMsg = "grader refused a non-seat user"

type seamCase struct {
	name, entry, route, path string
	// call drives the handler with the fake Grader answering gradeErr.
	call func(h *Handler, w http.ResponseWriter, r *http.Request, gradeErr error)
	// otherStatus / otherError: what any other Grader error answers.
	otherStatus int
	otherError  string
	// counted: the handler counts a bad_request in SubmissionsTotal for the refusal.
	counted bool
}

func seamCases() []seamCase {
	return []seamCase{
		{
			name: "submit (SubmitEvade)", entry: scoring.EntrySubmitEvade,
			route: "POST /api/challenges/{cid}/submit", path: "/api/challenges/02-evade/submit",
			call: func(h *Handler, w http.ResponseWriter, r *http.Request, gradeErr error) {
				h.gradeEvade = func(string, string, string) (scoring.EvadeOutcome, error) {
					return scoring.EvadeOutcome{}, gradeErr
				}
				h.submit(w, r)
			},
			otherStatus: http.StatusInternalServerError, counted: true,
		},
		{
			name: "exfil (RecordExfil)", entry: scoring.EntryRecordExfil,
			route: "POST /internal/exfil/{cid}", path: "/internal/exfil/02-evade",
			call: func(h *Handler, w http.ResponseWriter, r *http.Request, gradeErr error) {
				h.recordExfil = func(string, string, string) (scoring.ExfilStatus, error) {
					return 0, gradeErr
				}
				h.exfilInternal(w, r)
			},
			otherStatus: http.StatusInternalServerError, otherError: "could not record exfil",
		},
	}
}

func runSeam(t *testing.T, c seamCase, gradeErr error) (code int, body map[string]any, logs string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	cat := catalog.Catalog{"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{dev-x}", RequireExfil: true}}
	var logBuf bytes.Buffer
	now := func() time.Time { return time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC) }
	h := New(cat, scoring.New(cat, s, now), s, slog.New(slog.NewJSONHandler(&logBuf, nil)), now,
		nil, nil, nil, JourneyConfig{}, DetectConfig{}, BoardConfig{},
		IdentityConfig{ExpectedEmailDomain: "ctf.local"})
	r := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(`{"user":"alice","flag":"FALCO{dev-x}"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Pattern = c.route
	r.SetPathValue("cid", "02-evade")
	r.RemoteAddr = "192.0.2.7:999"
	w := httptest.NewRecorder()
	c.call(h, w, r, gradeErr)
	body = map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body, err)
	}
	return w.Code, body, logBuf.String()
}

func refusedWarns(t *testing.T, logs string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == refusedWarnMsg {
			out = append(out, m)
		}
	}
	return out
}

// The Grader's gate answering after the handler's own: 400 invalid user (never a
// 500), the one fixed-field Warn with this entry, and no user in the log.
func TestGraderSecondGate_ErrInvalidUser_Is400WithOneWarn(t *testing.T) {
	for _, c := range seamCases() {
		t.Run(c.name, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.SubmissionsTotal.WithLabelValues("02-evade", "bad_request"))
			code, body, logs := runSeam(t, c, scoring.ErrInvalidUser)
			if code != http.StatusBadRequest || body["error"] != "invalid user" || len(body) != 1 {
				t.Fatalf("status %d body %v, want 400 {error: invalid user}", code, body)
			}
			warns := refusedWarns(t, logs)
			if len(warns) != 1 {
				t.Fatalf("%d refused-user Warn lines, want 1:\n%s", len(warns), logs)
			}
			if w := warns[0]; w["entry"] != c.entry || w["route"] != c.route || w["remote_addr"] != "192.0.2.7" {
				t.Fatalf("Warn = %v, want entry %s route %s remote_addr 192.0.2.7", w, c.entry, c.route)
			}
			for _, l := range lineWith(logs, refusedWarnMsg) {
				if strings.Contains(l, "alice") {
					t.Fatalf("the refused-user Warn carries the user: %s", l)
				}
			}
			if c.counted {
				if got := testutil.ToFloat64(metrics.SubmissionsTotal.WithLabelValues("02-evade", "bad_request")) - before; got != 1 {
					t.Fatalf("submissions bad_request rose by %v, want 1", got)
				}
			}
		})
	}
}

func lineWith(logs, msg string) []string {
	var out []string
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, msg) {
			out = append(out, l)
		}
	}
	return out
}

// Any other Grader error is still the fail-closed 500 and does not log the
// refused-user Warn.
func TestGraderSecondGate_OtherError_Is500WithoutTheWarn(t *testing.T) {
	for _, c := range seamCases() {
		t.Run(c.name, func(t *testing.T) {
			code, body, logs := runSeam(t, c, errors.New("sqlite: disk I/O error"))
			if code != c.otherStatus {
				t.Fatalf("status %d body %v, want %d", code, body, c.otherStatus)
			}
			if c.otherError != "" && body["error"] != c.otherError {
				t.Fatalf("body %v, want error %q", body, c.otherError)
			}
			if strings.Contains(jsonOf(body), "disk I/O") {
				t.Fatalf("an internal error text reached the body: %v", body)
			}
			if n := len(refusedWarns(t, logs)); n != 0 {
				t.Fatalf("a non-ErrInvalidUser error logged the refused-user Warn %d time(s)", n)
			}
		})
	}
}

func jsonOf(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }
