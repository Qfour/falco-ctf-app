package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// app#479: the Grader's second seat gate. receive's own ns gate runs first and
// answers, so ErrInvalidUser from OnRuleFire / TaintOnOverflow cannot be reached
// over HTTP today (the Grader's own table test covers the refusal). What this
// pins is the adapter's mapping, called directly: it answers exactly as the ns
// gate does (200 ignored, no taint, no 500 / taint_error), logs ONE fixed-field
// Warn that holds no part of the refused value, and is rate-limited.

const badUser = "Bad_User-canary-91c"

func receivedCount(t *testing.T, outcome string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "scoreboard_ingest_falco_events_received_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "outcome" && lp.GetValue() == outcome {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestGraderRefused_AnswersLikeTheNamespaceGateAndLogsOneFixedWarn(t *testing.T) {
	const forbidden = "Read sensitive file untrusted"
	cat := catalog.Catalog{"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{forbidden}, ExpectedFlag: "FALCO{dev-x}"}}
	s, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	fixed := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed } // frozen: the audit bucket never refills
	var logBuf bytes.Buffer
	h := New(scoring.New(cat, s, clock), s, slog.New(slog.NewJSONHandler(&logBuf, nil)), clock, "", SecretModeOff)

	// OnRuleFire refuses a non-seat user before any write, and the adapter maps it.
	if _, err := h.grader.OnRuleFire(badUser, forbidden); !errors.Is(err, scoring.ErrInvalidUser) {
		t.Fatalf("OnRuleFire err = %v, want ErrInvalidUser", err)
	}
	if tainted, err := h.grader.TaintOnOverflow(badUser, forbidden); !errors.Is(err, scoring.ErrInvalidUser) || tainted != "" {
		t.Fatalf("TaintOnOverflow = (%q, %v), want (\"\", ErrInvalidUser)", tainted, err)
	}

	ignoredBefore, taintBefore := receivedCount(t, "ignored"), receivedCount(t, "taint_error")
	post := func(entry string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/falco/events", nil)
		r.Pattern = "POST /falco/events"
		r.RemoteAddr = "192.0.2.7:4242"
		h.graderRefused(w, r, entry)
		return w
	}
	w := post(scoring.EntryOnRuleFire)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || body["ignored"] != true || body["reason"] != "not a ctf workspace event" || len(body) != 2 {
		t.Fatalf("status %d body %v, want the ns gate's 200 {ignored, reason}", w.Code, body)
	}
	if got := receivedCount(t, "ignored") - ignoredBefore; got != 1 {
		t.Fatalf("FalcoEventsReceived{ignored} moved by %v, want 1", got)
	}
	if got := receivedCount(t, "taint_error") - taintBefore; got != 0 {
		t.Fatalf("FalcoEventsReceived{taint_error} moved by %v, want 0 (a refused user is not a persistence failure)", got)
	}
	if got := s.DirtyRules(badUser, "02-evade"); len(got) != 0 {
		t.Fatalf("a refused user was tainted: %v", got)
	}

	post(scoring.EntryTaintOnOverflow) // same 10 s window: no second line
	lines := strings.Split(strings.TrimSpace(logBuf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("log has %d lines, want exactly 1 (rate-limited): %s", len(lines), logBuf.String())
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(line))
	for k := range line {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if want := []string{"entry", "level", "msg", "remote_addr", "route", "time"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("log attributes = %v, want the closed set %v", keys, want)
	}
	if line["level"] != "WARN" || line["msg"] != "grader refused a non-seat user" || line["entry"] != "OnRuleFire" ||
		line["route"] != "POST /falco/events" || line["remote_addr"] != "192.0.2.7" {
		t.Fatalf("log line = %v", line)
	}
	for _, frag := range []string{badUser, "canary", "91c", "Bad_User"} {
		if strings.Contains(logBuf.String(), frag) {
			t.Fatalf("the log holds the fragment %q of the refused value", frag)
		}
	}
}
