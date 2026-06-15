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

// falcoEventBody builds a minimal valid /falco/events payload. Tests pass
// option funcs to override defaults; image repo + workspace pod are baked in
// so the H2 filter doesn't drop legitimate test events.
func falcoEventBody(rule, user string, opts ...func(map[string]any)) map[string]any {
	body := map[string]any{
		"rule": rule,
		"output_fields": map[string]any{
			"k8s.ns.name":               "ctf-" + user,
			"k8s.pod.name":              "workspace",
			"container.image.repository": "docker.io/falco-ctf/challenge",
		},
	}
	for _, o := range opts {
		o(body)
	}
	return body
}

// withRawNS overrides k8s.ns.name on an event for "ignored" path tests.
func withRawNS(ns string) func(map[string]any) {
	return func(b map[string]any) {
		b["output_fields"].(map[string]any)["k8s.ns.name"] = ns
	}
}

// withRawPod overrides k8s.pod.name on an event for "ignored" path tests.
func withRawPod(pod string) func(map[string]any) {
	return func(b map[string]any) {
		b["output_fields"].(map[string]any)["k8s.pod.name"] = pod
	}
}

// withImageRepo overrides container.image.repository.
func withImageRepo(repo string) func(map[string]any) {
	return func(b map[string]any) {
		b["output_fields"].(map[string]any)["container.image.repository"] = repo
	}
}

// withPriority sets the top-level priority field.
func withPriority(p string) func(map[string]any) {
	return func(b map[string]any) {
		b["priority"] = p
	}
}

// withTime sets the top-level time field (kept for tests covering Falco lag).
func withTime(s string) func(map[string]any) {
	return func(b map[string]any) {
		b["time"] = s
	}
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

func TestAdminReset(t *testing.T) {
	cat := catalog.Catalog{
		"02-evade": catalog.Challenge{ID: "02-evade", Type: "evade", ExpectedFlag: "FALCO{ok}", WindowSeconds: 10},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.MarkSolved("user1", "02-evade", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := scoreboard.NewHandler(cat, st, logger, scoreboard.WithAdminEmails([]string{"admin@ctf.local"}))

	post := func(email string) int {
		r := httptest.NewRequest("POST", "/api/admin/reset", nil)
		if email != "" {
			r.Header.Set("X-Auth-Request-Email", email)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w.Code
	}

	// No auth header (cluster-internal Service path: workspace/falco) → 403,
	// solve preserved.
	if code := post(""); code != http.StatusForbidden {
		t.Fatalf("no-header reset must 403, got %d", code)
	}
	if st.SolvedCount() != 1 {
		t.Fatal("denied reset must not clear solves")
	}
	// Non-admin authenticated email → 403.
	if code := post("user1@ctf.local"); code != http.StatusForbidden {
		t.Fatalf("non-admin reset must 403, got %d", code)
	}
	// Admin → 200, solves cleared.
	if code := post("admin@ctf.local"); code != http.StatusOK {
		t.Fatalf("admin reset must 200, got %d", code)
	}
	if st.SolvedCount() != 0 {
		t.Fatal("admin reset must clear solves")
	}
}

func TestAdminSetDisplayName(t *testing.T) {
	cat := catalog.Catalog{"01-x": catalog.Challenge{ID: "01-x", Type: "trigger", ExpectedRules: []string{"r"}, WindowSeconds: 10}}
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := scoreboard.NewHandler(cat, st, logger, scoreboard.WithAdminEmails([]string{"admin@ctf.local"}))

	post := func(email, user, name string) int {
		body, _ := json.Marshal(map[string]string{"name": name})
		r := httptest.NewRequest("POST", "/api/admin/users/"+user+"/display-name", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if email != "" {
			r.Header.Set("X-Auth-Request-Email", email)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w.Code
	}

	// non-admin (no header) → 403, name unchanged (default = username)
	if code := post("", "user5", "Mallory"); code != http.StatusForbidden {
		t.Fatalf("non-admin set must 403, got %d", code)
	}
	if got := st.DisplayName("user5"); got != "user5" {
		t.Fatalf("default must stay username, got %q", got)
	}
	// admin sets → 200
	if code := post("admin@ctf.local", "user5", "Alice"); code != http.StatusOK {
		t.Fatalf("admin set must 200, got %d", code)
	}
	if got := st.DisplayName("user5"); got != "Alice" {
		t.Fatalf("name not set, got %q", got)
	}
	// admin CHANGES (override, unlike participant first-set-only) → 200
	if code := post("admin@ctf.local", "user5", "Alice (renamed)"); code != http.StatusOK {
		t.Fatalf("admin override must 200, got %d", code)
	}
	if got := st.DisplayName("user5"); got != "Alice (renamed)" {
		t.Fatalf("override failed, got %q", got)
	}
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
	w := f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice", withRawNS("kube-system")))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if decode(t, w)["ignored"] != true {
		t.Fatalf("kube-system events must be ignored: %s", w.Body)
	}
}

func TestFalcoEvents_IgnoresNonWorkspacePod(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice", withRawPod("sidecar")))
	if decode(t, w)["ignored"] != true {
		t.Fatalf("non-workspace pod must be ignored: %s", w.Body)
	}
}

// App-H2: events from a pod whose image is not falco-ctf/challenge must be
// rejected even if namespace/pod match the workspace pattern.
func TestFalcoEvents_IgnoresNonChallengeContainer(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/falco/events", falcoEventBody(
		"Read sensitive file untrusted", "alice",
		withImageRepo("docker.io/library/alpine"),
	))
	if decode(t, w)["ignored"] != true {
		t.Fatalf("non-challenge container events must be ignored: %s", w.Body)
	}
}

// App-H2: events explicitly tagged below the Notice priority threshold are
// dropped to match the Falco rule contract.
func TestFalcoEvents_IgnoresBelowMinimumPriority(t *testing.T) {
	f := newFixture(t, nil)
	for _, p := range []string{"Debug", "Informational"} {
		w := f.do("POST", "/falco/events", falcoEventBody(
			"Read sensitive file untrusted", "alice",
			withPriority(p),
		))
		if decode(t, w)["ignored"] != true {
			t.Fatalf("%s-priority events must be ignored: %s", p, w.Body)
		}
	}
}

func TestFalcoEvents_TriggerSolves(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/falco/events", falcoEventBody(
		"Read sensitive file untrusted", "alice",
		withTime("2026-05-11T10:00:00Z"),
	))
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
	f.do("POST", "/falco/events", falcoEventBody("Unrelated rule", "alice"))
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

	// Fire forbidden rule at the same server `now` as the submit — inside the
	// 10s window. Note: rule-fire timestamps now derive from server time, not
	// the (attacker-controlled) ev.Time. See App-H3.
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

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
	// Mutable clock: forbidden fire is recorded at t=10:00:00, the submit
	// happens at t=10:00:30 — 30s later, well past the 10s evade window.
	// Since App-H3 the recorded fire time is server-side now(), so advancing
	// the test clock between the fire and the submit is required.
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })

	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

	clock = clock.Add(30 * time.Second)
	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m := decode(t, w)
	if m["solved"] != true {
		t.Fatalf("expected solved (fire outside 10s window): %v", m)
	}
}

// App-H3: a forged event with ev.Time set far in the past must NOT escape
// the evade window. Rule-fire timestamps are taken from server time, so the
// attacker cannot pre-age their own forbidden fire.
func TestFalcoEvents_EvadeWindow_IgnoresAttackerTime(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })

	// Attacker tries to bury the forbidden fire 1 hour ago.
	f.do("POST", "/falco/events", falcoEventBody(
		"Read sensitive file untrusted", "alice",
		withTime(now.Add(-1*time.Hour).Format(time.RFC3339)),
	))

	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m := decode(t, w)
	if m["evaded"] != false {
		t.Fatalf("evade window must be evaluated against server time, not ev.Time: %v", m)
	}
}

func TestLeaderboard_TieBreakByEarliest(t *testing.T) {
	// Inject a controllable clock so the two solves get deterministic
	// receipt timestamps (10:00 then 10:30). The recvAt is now the tiebreak
	// signal — Falco's `time` field no longer drives leaderboard ordering.
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })

	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

	clock = time.Date(2026, 5, 11, 10, 30, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "bob"))

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

	f.do("POST", "/falco/events", falcoEventBody(
		"Read sensitive file untrusted", "alice",
		withTime("2026-05-11T10:00:00Z"), // 1.5h before "now" — simulates Falco lag
	))

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

// ---------------- /me page + /api/users/{user}/me ----------------

func TestUserMe_MissingUser_Rejected(t *testing.T) {
	f := newFixture(t, nil)
	// Empty user segment must not yield a usable /me response. Stdlib mux
	// may 301-redirect "//me" to "/me" before our handler sees it, which
	// also satisfies the "no usable response for an empty user" intent.
	w := f.do("GET", "/api/users//me", nil)
	switch w.Code {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMovedPermanently:
		// expected
	default:
		t.Fatalf("expected 301/400/404 for empty user, got %d", w.Code)
	}
}

func TestUserMe_NoActivity_ReturnsEmptyShape(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("GET", "/api/users/alice/me", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	m := decode(t, w)
	if m["user"] != "alice" {
		t.Errorf("user echo: %v", m["user"])
	}
	if m["solved_count"].(float64) != 0 {
		t.Errorf("solved_count: %v", m["solved_count"])
	}
	if m["total_challenges"].(float64) != 2 {
		t.Errorf("total_challenges: %v", m["total_challenges"])
	}
	// next_unsolved should be the first catalog id ("01-read-shadow" or
	// "02-evade" — Catalog.IDs sorts lexicographically).
	if m["next_unsolved"] == nil {
		t.Errorf("expected a next_unsolved id, got nil")
	}
	fires, _ := m["recent_rule_fires"].([]any)
	if len(fires) != 0 {
		t.Errorf("expected no rule fires, got %d", len(fires))
	}
}

func TestUserMe_AfterSolve_SurfacesProgress(t *testing.T) {
	f := newFixture(t, nil)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

	w := f.do("GET", "/api/users/alice/me", nil)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	m := decode(t, w)
	if m["solved_count"].(float64) != 1 {
		t.Fatalf("expected 1 solve, got %v", m["solved_count"])
	}
	solved := m["solved"].([]any)
	first := solved[0].(map[string]any)
	if first["challenge"] != "01-read-shadow" {
		t.Errorf("solved.challenge: %v", first["challenge"])
	}
	if m["next_unsolved"] != "02-evade" {
		t.Errorf("next_unsolved should advance to 02-evade, got %v", m["next_unsolved"])
	}
}

func TestUserMe_RecentRuleFires(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })

	// Fire a rule but not a trigger rule — just records to the user's window.
	f.do("POST", "/falco/events", falcoEventBody("Generic file access", "alice"))

	m := decode(t, f.do("GET", "/api/users/alice/me", nil))
	fires := m["recent_rule_fires"].([]any)
	if len(fires) != 1 {
		t.Fatalf("expected 1 rule fire, got %d (%v)", len(fires), fires)
	}
	if fires[0].(map[string]any)["rule"] != "Generic file access" {
		t.Errorf("rule name: %v", fires[0])
	}
}

// ---------------- /api/users/{user}/display-name ----------------

func TestDisplayName_SetThenReadInState(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/api/users/alice/display-name", map[string]any{"name": "Alice ★"})
	if w.Code != 200 {
		t.Fatalf("status: %d body=%s", w.Code, w.Body)
	}
	m := decode(t, w)
	if m["display_name"] != "Alice ★" || m["user"] != "alice" {
		t.Fatalf("response: %v", m)
	}

	// /api/users/{user}/me reflects it
	got := decode(t, f.do("GET", "/api/users/alice/me", nil))
	if got["display_name"] != "Alice ★" {
		t.Errorf("/me display_name: %v", got["display_name"])
	}

	// /api/state leaderboard entries get it too (need at least one solve to
	// surface alice in the leaderboard — fire a trigger).
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))
	state := decode(t, f.do("GET", "/api/state", nil))
	lb := state["leaderboard"].([]any)
	first := lb[0].(map[string]any)
	if first["display_name"] != "Alice ★" {
		t.Errorf("leaderboard display_name: %v (full row=%v)", first["display_name"], first)
	}
}

func TestDisplayName_DefaultsToIdentity(t *testing.T) {
	f := newFixture(t, nil)
	// Never set; me should fall back to identity.
	got := decode(t, f.do("GET", "/api/users/bob/me", nil))
	if got["display_name"] != "bob" {
		t.Fatalf("expected fallback to identity, got %v", got["display_name"])
	}
}

func TestDisplayName_Validation(t *testing.T) {
	f := newFixture(t, nil)
	bad := []map[string]any{
		{"name": ""},                                          // empty
		{"name": "<script>"},                                   // HTML metachar
		{"name": "ab&cd"},                                      // HTML metachar
		{"name": "ab\x00cd"},                                   // control char
		{"name": "1234567890123456789012345678901234567890"},   // > 32 runes
	}
	for _, b := range bad {
		w := f.do("POST", "/api/users/alice/display-name", b)
		if w.Code != 400 {
			t.Errorf("name=%v should be 400, got %d", b["name"], w.Code)
		}
	}
}

// Participants can set AND change their own display name (last-write-wins).
// Pins the self-service rename contract.
func TestDisplayName_ParticipantCanChange(t *testing.T) {
	f := newFixture(t, nil)
	w1 := f.do("POST", "/api/users/alice/display-name", map[string]any{"name": "First"})
	if w1.Code != 200 {
		t.Fatalf("first set should succeed, got %d", w1.Code)
	}
	w2 := f.do("POST", "/api/users/alice/display-name", map[string]any{"name": "Second"})
	if w2.Code != 200 {
		t.Fatalf("second set (change) should succeed, got %d", w2.Code)
	}
	// /me reflects the latest name
	got := decode(t, f.do("GET", "/api/users/alice/me", nil))
	if got["display_name"] != "Second" {
		t.Fatalf("latest name should win, got %v", got["display_name"])
	}
}

func TestMeHTML_ServedAtMe(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("GET", "/me?user=alice", nil)
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("<title>falco-ctf · me")) {
		t.Fatalf("/me html missing expected title")
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
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

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
