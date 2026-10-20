package ingest

// app#479 review-5x: the adapter's mapping of the Grader's second seat gate is
// unreachable over real HTTP (receive's ns gate answers first), so it used to be
// untested: deleting the branch left every test green. ruleFireGrader is the seam:
// a fake Grader answers ErrInvalidUser (or another error) for a namespace the
// first gate accepted, and the full receive runs.

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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

type fakeRuleFireGrader struct {
	affects        bool
	onRuleFireErr  error
	taintTainted   string
	taintErr       error
	onRuleFireCall int
	taintCall      int
}

func (f *fakeRuleFireGrader) AffectsScoring(string) bool { return f.affects }
func (f *fakeRuleFireGrader) OnRuleFire(_, _ string) (scoring.RuleFireOutcome, error) {
	f.onRuleFireCall++
	return scoring.RuleFireOutcome{}, f.onRuleFireErr
}
func (f *fakeRuleFireGrader) TaintOnOverflow(_, _ string) (string, error) {
	f.taintCall++
	return f.taintTainted, f.taintErr
}

// receiveFixture is a real Handler (real store, real receive and mux) whose Grader
// is the fake. burst is the per-participant bucket size for both buckets.
func receiveFixture(t *testing.T, g *fakeRuleFireGrader, burst float64) (http.Handler, *bytes.Buffer) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	fixed := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed } // frozen: buckets never refill
	var logBuf bytes.Buffer
	h := New(nil, s, slog.New(slog.NewJSONHandler(&logBuf, nil)), clock, "", SecretModeOff)
	h.grader = g
	h.WithLimits(0, burst, 0, burst)
	mux, _ := apispec.NewMux(h.Routes())
	return mux, &logBuf
}

func sendEvent(t *testing.T, mux http.Handler, ns string) (int, map[string]any) {
	t.Helper()
	buf, _ := json.Marshal(map[string]any{"rule": "Some rule", "priority": "Warning", "output_fields": map[string]any{
		"k8s.ns.name": ns, "k8s.pod.name": "workspace", "container.image.repository": "falco-ctf/challenge"}})
	r := httptest.NewRequest(http.MethodPost, "/falco/events", bytes.NewReader(buf))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "192.0.2.9:1111"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body, err)
	}
	return w.Code, body
}

// warnLines are the log lines with msg "grader refused a non-seat user".
func warnLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		if m["msg"] == "grader refused a non-seat user" {
			out = append(out, m)
		}
	}
	return out
}

func requireIgnoredAnswer(t *testing.T, code int, body map[string]any) {
	t.Helper()
	if code != http.StatusOK || body["ignored"] != true || body["reason"] != "not a ctf workspace event" || len(body) != 2 {
		t.Fatalf("status %d body %v, want the ns gate's 200 {ignored, reason}", code, body)
	}
}

// OnRuleFire answering ErrInvalidUser right after the first gate: 200 ignored, no
// taint_error, one fixed-field Warn.
func TestReceive_OnRuleFireErrInvalidUser_IsIgnoredNotAnError(t *testing.T) {
	g := &fakeRuleFireGrader{affects: false, onRuleFireErr: scoring.ErrInvalidUser}
	mux, logBuf := receiveFixture(t, g, 100)
	ign, taint, storeErr := receivedCount(t, "ignored"), receivedCount(t, "taint_error"), receivedCount(t, "store_error")
	code, body := sendEvent(t, mux, "ctf-alice")
	requireIgnoredAnswer(t, code, body)
	if g.onRuleFireCall != 1 {
		t.Fatalf("OnRuleFire called %d times, want 1 (the first gate accepted ctf-alice)", g.onRuleFireCall)
	}
	if d := receivedCount(t, "ignored") - ign; d != 1 {
		t.Fatalf("FalcoEventsReceived{ignored} moved by %v, want 1", d)
	}
	if d := receivedCount(t, "taint_error") - taint; d != 0 {
		t.Fatalf("taint_error moved by %v, want 0", d)
	}
	if d := receivedCount(t, "store_error") - storeErr; d != 0 {
		t.Fatalf("store_error moved by %v, want 0", d)
	}
	w := warnLines(t, logBuf)
	if len(w) != 1 || w[0]["entry"] != "OnRuleFire" || w[0]["route"] != "POST /falco/events" || w[0]["remote_addr"] != "192.0.2.9" {
		t.Fatalf("Warn lines = %v, want one with entry=OnRuleFire route=POST /falco/events remote_addr=192.0.2.9", w)
	}
}

// TaintOnOverflow answering ErrInvalidUser for a seat over its scoring bucket:
// the same 200 ignored, not counted as an overflow, no 500 taint_error.
func TestReceive_TaintOnOverflowErrInvalidUser_IsIgnoredNotAnError(t *testing.T) {
	g := &fakeRuleFireGrader{affects: true, taintErr: scoring.ErrInvalidUser}
	mux, logBuf := receiveFixture(t, g, 1) // first event takes the one token, second overflows
	if code, _ := sendEvent(t, mux, "ctf-alice"); code != http.StatusOK || g.onRuleFireCall != 1 {
		t.Fatalf("first event: status %d, OnRuleFire calls %d, want 200 and 1", code, g.onRuleFireCall)
	}
	ign, taint := receivedCount(t, "ignored"), receivedCount(t, "taint_error")
	code, body := sendEvent(t, mux, "ctf-alice")
	requireIgnoredAnswer(t, code, body)
	if g.taintCall != 1 {
		t.Fatalf("TaintOnOverflow called %d times, want 1", g.taintCall)
	}
	if d := receivedCount(t, "ignored") - ign; d != 1 {
		t.Fatalf("FalcoEventsReceived{ignored} moved by %v, want 1", d)
	}
	if d := receivedCount(t, "taint_error") - taint; d != 0 {
		t.Fatalf("taint_error moved by %v, want 0", d)
	}
	if got := nsOverflow(t, "ctf-alice"); got != 0 {
		t.Fatalf("a refused event was counted as a scoring overflow (%v)", got)
	}
	w := warnLines(t, logBuf)
	if len(w) != 1 || w[0]["entry"] != "TaintOnOverflow" {
		t.Fatalf("Warn lines = %v, want one with entry=TaintOnOverflow", w)
	}
}

// Any OTHER error from OnRuleFire is not read as a clean event: 500 with the fixed
// message and store_error, and no ignored-style Warn.
func TestReceive_OnRuleFireOtherError_Fails500StoreError(t *testing.T) {
	g := &fakeRuleFireGrader{onRuleFireErr: errors.New("driver: disk I/O error at /var/lib/x.db")}
	mux, logBuf := receiveFixture(t, g, 100)
	storeErr, ign := receivedCount(t, "store_error"), receivedCount(t, "ignored")
	code, body := sendEvent(t, mux, "ctf-alice")
	if code != http.StatusInternalServerError || body["error"] != errMsgRecordRuleFire || len(body) != 1 {
		t.Fatalf("status %d body %v, want 500 {error: %q} with no internal text", code, body, errMsgRecordRuleFire)
	}
	if d := receivedCount(t, "store_error") - storeErr; d != 1 {
		t.Fatalf("store_error moved by %v, want 1", d)
	}
	if d := receivedCount(t, "ignored") - ign; d != 0 {
		t.Fatalf("ignored moved by %v, want 0", d)
	}
	if w := warnLines(t, logBuf); len(w) != 0 {
		t.Fatalf("a non-ErrInvalidUser error logged the refused-user Warn: %v", w)
	}
}

// nsOverflow is scoreboard_ingest_falco_events_scoring_overflow_total{ns=ns}, 0 when
// the series does not exist (the same read nscount_test.go does for package ingest_test).
func nsOverflow(t *testing.T, ns string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "scoreboard_ingest_falco_events_scoring_overflow_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "ns" && lp.GetValue() == ns {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
