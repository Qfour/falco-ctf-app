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
		"03-exfil": catalog.Challenge{
			ID:             "03-exfil",
			Type:           "evade",
			ForbiddenRules: []string{"Read sensitive file untrusted"},
			ExpectedFlag:   "FALCO{boss}",
			WindowSeconds:  10,
			RequireExfil:   true,
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
	// P18: /api/state and GET / are admin-gated; wire a known admin so the
	// existing full-view tests can authenticate as the operator via doAdmin.
	// P23-2: wire fixtureOrigin into the allowlist too, and doAs/do send it as
	// Origin on every request (mirroring what a real browser sends on a
	// state-changing fetch/form submit) — this fixture exercises the OTHER
	// gates (P18 self/admin, rate limits, scoring), not the origin guard
	// itself (see origin_guard_test.go for that), so it must not be
	// collaterally denied by the fail-closed default.
	srv := scoreboard.NewHandler(cat, st, logger, scoreboard.WithNow(now),
		scoreboard.WithAdminEmails([]string{fixtureAdminEmail}),
		scoreboard.WithAllowedOrigins([]string{fixtureOrigin}))
	return &fixture{t: t, cat: cat, st: st, srv: srv}
}

// fixtureAdminEmail is the operator identity the default fixture recognises as
// admin (ADMIN_EMAILS). doAdmin authenticates as this address.
const fixtureAdminEmail = "admin@ctf.local"

// fixtureOrigin is the sole entry in the default fixture's ALLOWED_ORIGINS
// (P23-2). do/doAs/doAdmin/doUser all send it as the request's Origin header
// so pre-existing tests (which predate the origin guard and exercise
// unrelated gates) keep passing without per-test changes.
const fixtureOrigin = "https://scoreboard.ctf.local"

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
	return f.doAs(method, target, "", body)
}

// doAs issues a request carrying X-Auth-Request-Email = email (omitted when
// blank). Used to exercise the P18 self-scope / admin read gates.
func (f *fixture) doAs(method, target, email string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, target, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	// P23-2: send the allowed fixture Origin so the origin guard (independently
	// covered by origin_guard_test.go) does not collaterally 403 these
	// auth/scoring-focused tests.
	r.Header.Set("Origin", fixtureOrigin)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

// doAdmin issues a request authenticated as the fixture operator (admin).
func (f *fixture) doAdmin(method, target string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.doAs(method, target, fixtureAdminEmail, body)
}

// doUser issues a request authenticated as participant "<user>@ctf.local"
// (self). Mirrors what oauth2-proxy injects on the participant journey host.
func (f *fixture) doUser(method, target, user string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.doAs(method, target, user+"@ctf.local", body)
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
	srv := scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithAdminEmails([]string{"admin@ctf.local"}),
		scoreboard.WithAllowedOrigins([]string{fixtureOrigin}))

	post := func(email string) int {
		r := httptest.NewRequest("POST", "/api/admin/reset", nil)
		if email != "" {
			r.Header.Set("X-Auth-Request-Email", email)
		}
		// P23-2: this test targets the admin-identity gate, not the origin
		// guard (see origin_guard_test.go), so send the allowed Origin.
		r.Header.Set("Origin", fixtureOrigin)
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
	srv := scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithAdminEmails([]string{"admin@ctf.local"}),
		scoreboard.WithAllowedOrigins([]string{fixtureOrigin}))

	post := func(email, user, name string) int {
		body, _ := json.Marshal(map[string]string{"name": name})
		r := httptest.NewRequest("POST", "/api/admin/users/"+user+"/display-name", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if email != "" {
			r.Header.Set("X-Auth-Request-Email", email)
		}
		// P23-2: this test targets the admin-identity gate, not the origin
		// guard (see origin_guard_test.go), so send the allowed Origin.
		r.Header.Set("Origin", fixtureOrigin)
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

// /api/state exposes per-challenge solver_details ranked by solve time with
// display names — the data behind the per-challenge leaderboard view.
func TestState_SolverDetailsRankedWithNames(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.st.MarkSolved("alice", "01-read-shadow", "2026-01-01T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.MarkSolved("bob", "01-read-shadow", "2026-01-01T00:00:02Z"); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetDisplayName("alice", "Alice ★", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	d := decode(t, f.doAdmin("GET", "/api/state", nil))
	for _, ci := range d["challenges"].([]any) {
		c := ci.(map[string]any)
		if c["id"] != "01-read-shadow" {
			continue
		}
		det := c["solver_details"].([]any)
		if len(det) != 2 {
			t.Fatalf("want 2 solver_details, got %d", len(det))
		}
		first := det[0].(map[string]any)
		if first["user"] != "alice" || first["display_name"] != "Alice ★" {
			t.Fatalf("first (earliest) solver wrong: %v", first)
		}
		second := det[1].(map[string]any)
		if second["user"] != "bob" || second["display_name"] != "bob" {
			t.Fatalf("second solver should fall back to username: %v", second)
		}
		return
	}
	t.Fatal("01-read-shadow not found in /api/state challenges")
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
	state := decode(t, f.doAdmin("GET", "/api/state", nil))
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
	if got := decode(t, f.doAdmin("GET", "/api/state", nil))["stats"].(map[string]any)["solves"]; got.(float64) != 0 {
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

func TestSubmit_RequireExfil_WithoutExfil_NotSolved(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })
	// Correct flag, clean window, but the user never exfiltrated to the collector.
	w := f.do("POST", "/api/challenges/03-exfil/submit", map[string]any{"user": "alice", "flag": "FALCO{boss}"})
	m := decode(t, w)
	if m["correct"] != true || m["evaded"] != true {
		t.Fatalf("flag correct + window clean expected: %v", m)
	}
	if m["exfiltrated"] != false || m["solved"] == true {
		t.Fatalf("expected exfiltrated=false and not solved: %v", m)
	}
}

func TestSubmit_RequireExfil_AfterExfil_Solves(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })
	// Deliver to the internal collector sink first, then submit.
	we := f.do("POST", "/internal/exfil/03-exfil", map[string]any{"user": "alice", "flag": "FALCO{boss}"})
	if me := decode(t, we); me["received"] != true {
		t.Fatalf("expected exfil received: %v", me)
	}
	w := f.do("POST", "/api/challenges/03-exfil/submit", map[string]any{"user": "alice", "flag": "FALCO{boss}"})
	m := decode(t, w)
	if m["correct"] != true || m["evaded"] != true || m["solved"] != true {
		t.Fatalf("expected solved after exfil: %v", m)
	}
}

func TestExfil_WrongFlagRecorded_SubmitStillBlocked(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })
	// Exfiltrate a value that does not match the real flag.
	f.do("POST", "/internal/exfil/03-exfil", map[string]any{"user": "alice", "flag": "FALCO{wrong}"})
	w := f.do("POST", "/api/challenges/03-exfil/submit", map[string]any{"user": "alice", "flag": "FALCO{boss}"})
	m := decode(t, w)
	if m["exfiltrated"] != false || m["solved"] == true {
		t.Fatalf("mismatched exfil must not satisfy the gate: %v", m)
	}
}

func TestExfil_NotRequired_Rejected(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/internal/exfil/02-evade", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("exfil on a non-exfil challenge should be 400, got %d", w.Code)
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

	lb := decode(t, f.doAdmin("GET", "/api/state", nil))["leaderboard"].([]any)
	if lb[0].(map[string]any)["user"] != "alice" {
		t.Fatalf("earlier solver must win tie; got %v", lb)
	}
}

// TestLeaderboard_ScoreField_Additive proves /api/state leaderboard entries now
// carry the #40 score alongside the existing solved/earliest fields, and that
// the score reflects the per-hint reveal penalty (Grader.UserScore →
// ComputeScore single source). Default policy: 100/solve, 10/hint.
func TestLeaderboard_ScoreField_Additive(t *testing.T) {
	fixedNow := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return fixedNow })

	// alice solves one trigger challenge (100) and reveals 2 hints (-20) → 80.
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))
	at := fixedNow.UTC().Format(time.RFC3339Nano)
	if _, err := f.st.RecordHintView("alice", "01-read-shadow", 1, at); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.RecordHintView("alice", "01-read-shadow", 2, at); err != nil {
		t.Fatal(err)
	}

	lb := decode(t, f.doAdmin("GET", "/api/state", nil))["leaderboard"].([]any)
	if len(lb) != 1 {
		t.Fatalf("want 1 leaderboard entry, got %d: %v", len(lb), lb)
	}
	row := lb[0].(map[string]any)
	// Additive: solved is still present and unchanged.
	if row["solved"].(float64) != 1 {
		t.Errorf("solved = %v, want 1 (existing field must remain)", row["solved"])
	}
	// Score reflects the hint penalty: 1*100 - 2*10 = 80.
	if row["score"].(float64) != 80 {
		t.Errorf("score = %v, want 80 (100 per solve - 2 hints * 10)", row["score"])
	}
}

// TestLeaderboard_RankByScoreThenEarliest proves the CEO decision (#40): the
// leaderboard order is Score desc with Earliest solve as the tiebreak. Two
// players solve the same single challenge; the one who revealed hints scores
// lower and therefore ranks below the hint-free solver even though bob solved
// LATER — so score, not solve count or solve time alone, drives the ranking.
func TestLeaderboard_RankByScoreThenEarliest(t *testing.T) {
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })

	// alice solves FIRST (10:00) but leans on 3 hints → 100 - 30 = 70.
	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))
	at := clock.UTC().Format(time.RFC3339Nano)
	for _, idx := range []int{1, 2, 3} {
		if _, err := f.st.RecordHintView("alice", "01-read-shadow", idx, at); err != nil {
			t.Fatal(err)
		}
	}

	// bob solves LATER (10:30) with no hints → 100. Higher score must outrank
	// alice despite the later solve time.
	clock = time.Date(2026, 5, 11, 10, 30, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "bob"))

	lb := decode(t, f.doAdmin("GET", "/api/state", nil))["leaderboard"].([]any)
	if len(lb) != 2 {
		t.Fatalf("want 2 entries, got %d: %v", len(lb), lb)
	}
	top := lb[0].(map[string]any)
	if top["user"] != "bob" {
		t.Fatalf("higher score must rank first; got order %v (bob=100 should beat alice=70)", lb)
	}
	if top["score"].(float64) != 100 || top["rank"].(float64) != 1 {
		t.Errorf("top row score/rank = %v/%v, want 100/1", top["score"], top["rank"])
	}
	second := lb[1].(map[string]any)
	if second["user"] != "alice" || second["score"].(float64) != 70 || second["rank"].(float64) != 2 {
		t.Errorf("second row = %v, want alice score=70 rank=2", second)
	}
}

// TestLeaderboard_ScoreTie_BreaksByEarliest proves that when two players have
// the EQUAL score the earlier first-solve still wins (the prior first-blood
// tiebreak is preserved as the secondary key under the new Score-desc primary).
func TestLeaderboard_ScoreTie_BreaksByEarliest(t *testing.T) {
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })

	// Both solve exactly one challenge with no hints → equal score (100). alice
	// solves first (10:00), bob second (10:30): alice must rank first.
	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))
	clock = time.Date(2026, 5, 11, 10, 30, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "bob"))

	lb := decode(t, f.doAdmin("GET", "/api/state", nil))["leaderboard"].([]any)
	a := lb[0].(map[string]any)
	if a["user"] != "alice" || a["score"].(float64) != 100 {
		t.Fatalf("equal-score tie must break by earliest solve; got %v", lb)
	}
	if lb[1].(map[string]any)["user"] != "bob" {
		t.Fatalf("bob should be second on the tiebreak; got %v", lb)
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

	solved := decode(t, f.doAdmin("GET", "/api/state", nil))["solved"].([]any)
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
	w := f.doUser("GET", "/api/users/alice/me", "alice", nil)
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
	if m["total_challenges"].(float64) != 3 {
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

	w := f.doUser("GET", "/api/users/alice/me", "alice", nil)
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

	m := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
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
	got := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
	if got["display_name"] != "Alice ★" {
		t.Errorf("/me display_name: %v", got["display_name"])
	}

	// /api/state leaderboard entries get it too (need at least one solve to
	// surface alice in the leaderboard — fire a trigger).
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))
	state := decode(t, f.doAdmin("GET", "/api/state", nil))
	lb := state["leaderboard"].([]any)
	first := lb[0].(map[string]any)
	if first["display_name"] != "Alice ★" {
		t.Errorf("leaderboard display_name: %v (full row=%v)", first["display_name"], first)
	}
}

func TestDisplayName_DefaultsToIdentity(t *testing.T) {
	f := newFixture(t, nil)
	// Never set; me should fall back to identity.
	got := decode(t, f.doUser("GET", "/api/users/bob/me", "bob", nil))
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
	got := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
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
	// P18-1: GET / is admin-gated at the app layer; authenticate as operator.
	w := f.doAdmin("GET", "/", nil)
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct == "" {
		t.Fatalf("missing Content-Type")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("<title>Falco CTF")) {
		t.Fatalf("html body did not contain expected title")
	}
}

// ---------------- P23-1: unified portal shell ----------------
//
// GET /portal is served to ANY authenticated caller (unlike GET /, which
// stays admin-only) — it carries no admin/participant DATA, only two
// display-only hints (role label, derived username). Authorization for the
// actual data stays entirely in the API layer (isAdmin / selfOrAdmin), which
// these tests independently prove still 403s a non-admin's /api/state call
// regardless of what the portal HTML says about their role.

func TestPortalHTML_ServedToParticipant(t *testing.T) {
	f := newFixture(t, nil)
	w := f.doUser("GET", "/portal", "alice", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct == "" {
		t.Fatalf("missing Content-Type")
	}
	body := w.Body.String()
	if !strings.Contains(body, `window.__PORTAL_ROLE__ = "participant"`) {
		t.Errorf("expected participant role injection, body=%s", body)
	}
	if !strings.Contains(body, `window.__PORTAL_USER__ = "alice"`) {
		t.Errorf("expected derived username injection for alice, body=%s", body)
	}
	// The admin-only Scoreboard tab must not be shown to a participant
	// (defense-in-depth; the API-side gate is proven separately below).
	if !strings.Contains(body, `id="tab-scoreboard" hidden`) {
		t.Errorf("expected the scoreboard tab to render hidden by default (participant), body=%s", body)
	}
}

func TestPortalHTML_ServedToAdmin(t *testing.T) {
	f := newFixture(t, nil)
	w := f.doAdmin("GET", "/portal", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, `window.__PORTAL_ROLE__ = "admin"`) {
		t.Errorf("expected admin role injection, body=%s", body)
	}
	// DeriveUsername runs the same code path for admin as for a participant:
	// fixtureAdminEmail ("admin@ctf.local") has an "@"-prefix that IS a valid
	// username slug, so the shell still gets a derived-user hint for the
	// admin viewer (display-only — see the no-admin-data assertions below for
	// the actual security invariant).
	if !strings.Contains(body, `window.__PORTAL_USER__ = "admin"`) {
		t.Errorf("expected derived username injection for admin, body=%s", body)
	}
}

func TestPortalHTML_ServedToUnauthenticated(t *testing.T) {
	// No X-Auth-Request-Email at all (e.g. a misrouted cluster-internal
	// request). The portal still renders (it carries no data to protect) —
	// it degrades to the participant role with no username hint, exactly as
	// GET /journey and GET /me already do today for an unknown identity.
	f := newFixture(t, nil)
	w := f.do("GET", "/portal", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, `window.__PORTAL_ROLE__ = "participant"`) {
		t.Errorf("expected participant (non-admin) role injection for an unauthenticated request, body=%s", body)
	}
	if !strings.Contains(body, `window.__PORTAL_USER__ = ""`) {
		t.Errorf("expected empty username injection for an unauthenticated request, body=%s", body)
	}
}

// TestPortalHTML_NoAdminDataEmbedded is the P23-1 security invariant proof:
// the portal HTML — even when rendered for an admin viewer — must never
// contain the actual leaderboard/solve/event DATA that /api/state serves.
// Only the API route may hand that data out (and only to admins). This
// guards against a future edit accidentally SSR-ing admin data into the
// shared shell (which participants also receive).
func TestPortalHTML_NoAdminDataEmbedded(t *testing.T) {
	f := newFixture(t, nil)
	// Generate some admin-visible state so there is something to leak if the
	// invariant were violated.
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

	adminBody := f.doAdmin("GET", "/portal", nil).Body.String()
	participantBody := f.doUser("GET", "/portal", "alice", nil).Body.String()

	// buildState()'s JSON keys are a reliable fingerprint of the admin-only
	// payload (see api.go's buildState / state handler) — none of them
	// should appear as literal data in the static shell HTML.
	for _, marker := range []string{`"leaderboard"`, `"recent_solves"`, `"solver_details"`} {
		if strings.Contains(adminBody, marker) {
			t.Errorf("admin-rendered /portal HTML must not embed state data, found %q", marker)
		}
		if strings.Contains(participantBody, marker) {
			t.Errorf("participant-rendered /portal HTML must not embed state data, found %q", marker)
		}
	}
}

// TestPortalAPIGate_StillEnforcedRegardlessOfPortalRole proves the actual
// authorization boundary (api.Handler.state / isAdmin) is untouched by
// P23-1: a participant fetching /api/state directly (as the Scoreboard
// pane's own JS would) still 403s, even though they were served a /portal
// page moments ago. The portal's role hint is display-only and cannot
// widen this.
func TestPortalAPIGate_StillEnforcedRegardlessOfPortalRole(t *testing.T) {
	f := newFixture(t, nil)
	_ = f.doUser("GET", "/portal", "alice", nil) // participant opens the shell
	if w := f.doUser("GET", "/api/state", "alice", nil); w.Code != http.StatusForbidden {
		t.Fatalf("participant /api/state must stay 403 after opening /portal, got %d body=%s", w.Code, w.Body)
	}
	if w := f.doAdmin("GET", "/api/state", nil); w.Code != http.StatusOK {
		t.Fatalf("admin /api/state must still 200, got %d body=%s", w.Code, w.Body)
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

// ---------------- P18: participant-facing read self-scope gate ----------------
//
// The read endpoints exposed on the participant journey host derive the caller
// identity from X-Auth-Request-Email and enforce self-or-admin (I8 mirrored to
// the read path). {user} in the path is self-claimed and never trusted on its
// own. Fail-closed: a missing/blank header is denied.

// readEndpoints are the three participant-facing per-user reads guarded by the
// self-scope gate. Table-driven so every case (self/other/admin/missing/
// prefix-mismatch) is proven identically across all of them.
func readEndpoints(user string) []string {
	return []string{
		"/api/users/" + user + "/me",
		"/api/users/" + user + "/journey",
	}
}

func TestReadGate_SelfAllowed(t *testing.T) {
	f := newFixture(t, nil)
	for _, ep := range readEndpoints("alice") {
		if w := f.doUser("GET", ep, "alice", nil); w.Code != http.StatusOK {
			t.Errorf("self read %s must 200, got %d body=%s", ep, w.Code, w.Body)
		}
	}
}

func TestReadGate_OtherUserForbidden(t *testing.T) {
	f := newFixture(t, nil)
	// bob authenticated, requests alice's data → 403.
	for _, ep := range readEndpoints("alice") {
		if w := f.doUser("GET", ep, "bob", nil); w.Code != http.StatusForbidden {
			t.Errorf("cross-user read %s must 403, got %d body=%s", ep, w.Code, w.Body)
		}
	}
}

func TestReadGate_AdminAnyUser(t *testing.T) {
	f := newFixture(t, nil)
	// Operator (ADMIN_EMAILS) may read any participant.
	for _, ep := range readEndpoints("alice") {
		if w := f.doAdmin("GET", ep, nil); w.Code != http.StatusOK {
			t.Errorf("admin read %s must 200, got %d body=%s", ep, w.Code, w.Body)
		}
	}
}

func TestReadGate_MissingHeaderFailClosed(t *testing.T) {
	f := newFixture(t, nil)
	// No X-Auth-Request-Email at all → 403 (never fall back to {user}).
	for _, ep := range readEndpoints("alice") {
		if w := f.do("GET", ep, nil); w.Code != http.StatusForbidden {
			t.Errorf("no-identity read %s must 403 (fail-closed), got %d body=%s", ep, w.Code, w.Body)
		}
	}
}

func TestReadGate_EmptyHeaderFailClosed(t *testing.T) {
	f := newFixture(t, nil)
	// Explicit blank / whitespace-only header → 403 (trimmed to empty).
	for _, ep := range readEndpoints("alice") {
		if w := f.doAs("GET", ep, "   ", nil); w.Code != http.StatusForbidden {
			t.Errorf("blank-identity read %s must 403 (fail-closed), got %d body=%s", ep, w.Code, w.Body)
		}
	}
}

// TestReadGate_PrefixExactNoMismatch is the core I8-mirror property: user1's
// identity must NOT satisfy a request for user10 / user1x. The match is
// prefix-exact ("user1@…"), not a substring/front-match, so the character after
// the username is pinned to '@'.
func TestReadGate_PrefixExactNoMismatch(t *testing.T) {
	f := newFixture(t, nil)
	// Caller user1@ requests user10's data → 403 (user10@ ≠ user1@ prefix).
	for _, ep := range readEndpoints("user10") {
		if w := f.doUser("GET", ep, "user1", nil); w.Code != http.StatusForbidden {
			t.Errorf("user1 must not match user10 on %s; want 403, got %d body=%s", ep, w.Code, w.Body)
		}
	}
	// And the exact self user still passes (user10@ == user10@ prefix).
	for _, ep := range readEndpoints("user10") {
		if w := f.doUser("GET", ep, "user10", nil); w.Code != http.StatusOK {
			t.Errorf("user10 self on %s must 200, got %d body=%s", ep, w.Code, w.Body)
		}
	}
	// Reverse direction: user10 must not match user1.
	for _, ep := range readEndpoints("user1") {
		if w := f.doUser("GET", ep, "user10", nil); w.Code != http.StatusForbidden {
			t.Errorf("user10 must not match user1 on %s; want 403, got %d body=%s", ep, w.Code, w.Body)
		}
	}
}

// TestReadGate_StateAdminOnly proves the /api/state defense-in-depth gate
// (P18-1): a self-authenticated participant (non-admin) cannot read the whole
// field; missing identity is likewise denied; an admin passes.
func TestReadGate_StateAdminOnly(t *testing.T) {
	f := newFixture(t, nil)
	if w := f.doUser("GET", "/api/state", "alice", nil); w.Code != http.StatusForbidden {
		t.Errorf("participant /api/state must 403, got %d body=%s", w.Code, w.Body)
	}
	if w := f.do("GET", "/api/state", nil); w.Code != http.StatusForbidden {
		t.Errorf("anonymous /api/state must 403 (fail-closed), got %d", w.Code)
	}
	if w := f.doAdmin("GET", "/api/state", nil); w.Code != http.StatusOK {
		t.Errorf("admin /api/state must 200, got %d body=%s", w.Code, w.Body)
	}
}

// TestReadGate_IndexAdminOnly proves the operator dashboard index (GET /)
// defense-in-depth gate (P18-1): non-admin / anonymous get 403; admin gets the
// HTML.
func TestReadGate_IndexAdminOnly(t *testing.T) {
	f := newFixture(t, nil)
	if w := f.doUser("GET", "/", "alice", nil); w.Code != http.StatusForbidden {
		t.Errorf("participant GET / must 403, got %d", w.Code)
	}
	if w := f.do("GET", "/", nil); w.Code != http.StatusForbidden {
		t.Errorf("anonymous GET / must 403 (fail-closed), got %d", w.Code)
	}
	w := f.doAdmin("GET", "/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin GET / must 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("<title>Falco CTF")) {
		t.Fatalf("admin index missing expected title")
	}
}
