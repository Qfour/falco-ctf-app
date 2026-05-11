package scoreboard_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

type fixture struct {
	t   *testing.T
	cat catalog.Catalog
	st  *store.Store
	srv *scoreboard.Handler
}

func newFixture(t *testing.T, now func() time.Time) *fixture {
	t.Helper()
	cat := catalog.Catalog{
		"01-read-shadow": catalog.Challenge{
			ID:            "01-read-shadow",
			Type:          "trigger",
			ExpectedRules: []string{"Read sensitive file untrusted"},
			WindowSeconds: 10,
		},
		"02-evade": catalog.Challenge{
			ID:             "02-evade",
			Type:           "evade",
			ForbiddenRules: []string{"Read sensitive file untrusted"},
			ExpectedFlag:   "FALCO{ok}",
			WindowSeconds:  10,
		},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if now == nil {
		now = time.Now
	}
	srv := scoreboard.NewHandler(cat, st, logger, scoreboard.WithNow(now))
	return &fixture{t: t, cat: cat, st: st, srv: srv}
}

func (f *fixture) do(method, target string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, target, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	return m
}

func TestHealthz(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("GET", "/healthz", nil)
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	m := decode(t, w)
	if m["ok"] != true {
		t.Errorf("ok: %v", m["ok"])
	}
}

func TestFalcoEvents_IgnoresNonCTFNamespace(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/falco/events", map[string]any{
		"rule": "Read sensitive file untrusted",
		"output_fields": map[string]any{
			"k8s.ns.name":  "kube-system",
			"k8s.pod.name": "workspace",
		},
	})
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if decode(t, w)["ignored"] != true {
		t.Fatalf("kube-system events must be ignored: %s", w.Body)
	}
}

func TestFalcoEvents_IgnoresNonWorkspacePod(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/falco/events", map[string]any{
		"rule": "Read sensitive file untrusted",
		"output_fields": map[string]any{
			"k8s.ns.name":  "ctf-alice",
			"k8s.pod.name": "sidecar",
		},
	})
	if decode(t, w)["ignored"] != true {
		t.Fatalf("non-workspace pod must be ignored: %s", w.Body)
	}
}

func TestFalcoEvents_TriggerSolves(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/falco/events", map[string]any{
		"rule": "Read sensitive file untrusted",
		"time": "2026-05-11T10:00:00Z",
		"output_fields": map[string]any{
			"k8s.ns.name":  "ctf-alice",
			"k8s.pod.name": "workspace",
		},
	})
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	state := decode(t, f.do("GET", "/api/state", nil))
	stats := state["stats"].(map[string]any)
	if stats["solves"].(float64) != 1 {
		t.Fatalf("expected 1 solve, got %v", stats["solves"])
	}
	lb := state["leaderboard"].([]any)
	if lb[0].(map[string]any)["user"].(string) != "alice" {
		t.Fatalf("leaderboard top: %v", lb[0])
	}
}

func TestFalcoEvents_NonMatchingRuleDoesNotSolve(t *testing.T) {
	f := newFixture(t, nil)
	f.do("POST", "/falco/events", map[string]any{
		"rule": "Unrelated rule",
		"output_fields": map[string]any{
			"k8s.ns.name":  "ctf-alice",
			"k8s.pod.name": "workspace",
		},
	})
	if got := decode(t, f.do("GET", "/api/state", nil))["stats"].(map[string]any)["solves"]; got.(float64) != 0 {
		t.Fatalf("expected 0 solves, got %v", got)
	}
}

func TestSubmit_UnknownChallenge_404(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/api/challenges/does-not-exist/submit", map[string]any{"user": "u", "flag": "x"})
	if w.Code != 404 {
		t.Fatalf("status: %d", w.Code)
	}
}

func TestSubmit_TriggerChallenge_400(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/api/challenges/01-read-shadow/submit", map[string]any{"user": "u", "flag": "x"})
	if w.Code != 400 {
		t.Fatalf("status: %d", w.Code)
	}
}

func TestSubmit_WrongFlag(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "WRONG"})
	m := decode(t, w)
	if m["correct"] != false {
		t.Fatalf("expected correct=false, got %v", m)
	}
}

func TestSubmit_CorrectFlag_NoForbiddenFires_Solves(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })
	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m := decode(t, w)
	if m["correct"] != true || m["evaded"] != true || m["solved"] != true {
		t.Fatalf("expected solved evade: %v", m)
	}
}

func TestSubmit_CorrectFlag_WithRecentForbiddenFire_NotSolved(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })

	// Fire forbidden rule just before submission (within window=10s).
	f.do("POST", "/falco/events", map[string]any{
		"rule": "Read sensitive file untrusted",
		"time": now.Add(-2 * time.Second).Format(time.RFC3339),
		"output_fields": map[string]any{
			"k8s.ns.name":  "ctf-alice",
			"k8s.pod.name": "workspace",
		},
	})

	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m := decode(t, w)
	if m["correct"] != true {
		t.Fatalf("flag should be considered correct: %v", m)
	}
	if m["evaded"] != false {
		t.Fatalf("expected evaded=false (forbidden rule fired): %v", m)
	}
}

func TestSubmit_CorrectFlag_AfterWindow_Solves(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })

	// Fire forbidden rule 30s ago — outside the 10s window.
	f.do("POST", "/falco/events", map[string]any{
		"rule": "Read sensitive file untrusted",
		"time": now.Add(-30 * time.Second).Format(time.RFC3339),
		"output_fields": map[string]any{
			"k8s.ns.name":  "ctf-alice",
			"k8s.pod.name": "workspace",
		},
	})

	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m := decode(t, w)
	if m["solved"] != true {
		t.Fatalf("expected solved (old fire outside window): %v", m)
	}
}

func TestLeaderboard_TieBreakByEarliest(t *testing.T) {
	// Inject a controllable clock so the two solves get deterministic
	// receipt timestamps (10:00 then 10:30). The recvAt is now the tiebreak
	// signal — Falco's `time` field no longer drives leaderboard ordering.
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })

	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", map[string]any{
		"rule":          "Read sensitive file untrusted",
		"output_fields": map[string]any{"k8s.ns.name": "ctf-alice", "k8s.pod.name": "workspace"},
	})

	clock = time.Date(2026, 5, 11, 10, 30, 0, 0, time.UTC)
	f.do("POST", "/falco/events", map[string]any{
		"rule":          "Read sensitive file untrusted",
		"output_fields": map[string]any{"k8s.ns.name": "ctf-bob", "k8s.pod.name": "workspace"},
	})

	lb := decode(t, f.do("GET", "/api/state", nil))["leaderboard"].([]any)
	if lb[0].(map[string]any)["user"] != "alice" {
		t.Fatalf("earlier solver must win tie; got %v", lb)
	}
}

// Pins the bug fix: solve `at` must reflect when scoreboard received the
// event, not Falco's event time. Falco/falcosidekick can buffer or batch,
// delivering events with stale timestamps — that should not retro-date
// the dashboard's "RECENT ACTIVITY" display.
func TestFalcoEvents_SolveTimestampUsesReceiptTime(t *testing.T) {
	fixedNow := time.Date(2026, 5, 11, 11, 38, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return fixedNow })

	f.do("POST", "/falco/events", map[string]any{
		"rule":          "Read sensitive file untrusted",
		"time":          "2026-05-11T10:00:00Z", // 1.5h before "now" — simulates Falco lag
		"output_fields": map[string]any{"k8s.ns.name": "ctf-alice", "k8s.pod.name": "workspace"},
	})

	solved := decode(t, f.do("GET", "/api/state", nil))["solved"].([]any)
	if len(solved) != 1 {
		t.Fatalf("expected 1 solve, got %d", len(solved))
	}
	at := solved[0].(map[string]any)["at"].(string)
	if !strings.HasPrefix(at, "2026-05-11T11:38") {
		t.Errorf("solve `at` should be receipt time (11:38…), got %q "+
			"(this likely means Falco's event time is leaking through)", at)
	}
}

func TestIndexHTML_ServedAtRoot(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("GET", "/", nil)
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct == "" {
		t.Fatalf("missing Content-Type")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("<title>falco-ctf")) {
		t.Fatalf("html body did not contain expected title")
	}
}

func TestUnknownPath_404(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("GET", "/nope", nil)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestMetricsEndpoint_ExposesScoreboardCounters(t *testing.T) {
	f := newFixture(t, nil)
	// Drive one ingest path so a counter has a non-zero value to expose.
	f.do("POST", "/falco/events", map[string]any{
		"rule":          "Read sensitive file untrusted",
		"output_fields": map[string]any{"k8s.ns.name": "ctf-alice", "k8s.pod.name": "workspace"},
	})

	w := f.do("GET", "/metrics", nil)
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"scoreboard_ingest_falco_events_received_total",
		"scoreboard_solves_total",
		"go_goroutines", // go runtime metrics come for free with promhttp
	} {
		if !bytes.Contains([]byte(body), []byte(want)) {
			t.Errorf("/metrics missing expected series %q", want)
		}
	}
}
