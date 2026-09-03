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
		},
		"02-evade": catalog.Challenge{
			ID:             "02-evade",
			Type:           "evade",
			ForbiddenRules: []string{"Read sensitive file untrusted"},
			ExpectedFlag:   "FALCO{ok}",
		},
		"03-exfil": catalog.Challenge{
			ID:             "03-exfil",
			Type:           "evade",
			ForbiddenRules: []string{"Read sensitive file untrusted"},
			ExpectedFlag:   "FALCO{boss}",
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

// newFixtureWithHidden is newFixture plus a HIDDEN_USERS allowlist (see
// scoreboard.WithHiddenUsers) — same catalog/store/admin/origin wiring, so
// the HIDDEN_USERS tests below exercise the SAME leaderboard machinery
// (computeLeaderboard) every other Leaderboard/Me test in this file does,
// with only the hidden-set difference isolated.
func newFixtureWithHidden(t *testing.T, now func() time.Time, hidden []string) *fixture {
	t.Helper()
	cat := catalog.Catalog{
		"01-read-shadow": catalog.Challenge{
			ID:            "01-read-shadow",
			Type:          "trigger",
			ExpectedRules: []string{"Read sensitive file untrusted"},
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
	srv := scoreboard.NewHandler(cat, st, logger, scoreboard.WithNow(now),
		scoreboard.WithAdminEmails([]string{fixtureAdminEmail}),
		scoreboard.WithAllowedOrigins([]string{fixtureOrigin}),
		scoreboard.WithHiddenUsers(hidden))
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
		"02-evade": catalog.Challenge{ID: "02-evade", Type: "evade", ExpectedFlag: "FALCO{ok}"},
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
	cat := catalog.Catalog{"01-x": catalog.Challenge{ID: "01-x", Type: "trigger", ExpectedRules: []string{"r"}}}
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

// dirtyEvade02 taints 02-evade for `user` through the REAL ingest path, using
// exactly two fires of the rule 02-evade forbids (ADR-0003 attempt scope):
//
//  1. The first fire is 01-read-shadow's REQUIRED expectedRule — it solves
//     01-read-shadow and advances `user`'s current mission to 02-evade. This
//     fire must NOT taint 02-evade (it was not yet current when it fired) —
//     that exemption is the whole point of attempt scope (ADR-0003 §A1); PR
//     #124 shipped without it and permanently blocked this exact mission for
//     every regular participant.
//  2. The second, identical fire happens AFTER 02-evade has become current,
//     so THIS one taints it.
//
// Every test below that needs 02-evade dirty via the real write path (rather
// than one single "just fire it" call, which is no longer sufficient under
// attempt scope) uses this helper so the two-fire requirement is documented
// once instead of re-derived at each call site.
func (f *fixture) dirtyEvade02(user string) {
	f.t.Helper()
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", user))
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", user))
}

// TestSubmit_CorrectFlag_WithRecentForbiddenFire_NotSolved proves the dirty
// gate blocks a correct-flag submit once 02-evade has actually been tainted
// WHILE it was the participant's current mission (see dirtyEvade02's doc for
// why a single fire — the one that solves 01-read-shadow — is not enough
// under ADR-0003 attempt scope).
func TestSubmit_CorrectFlag_WithRecentForbiddenFire_NotSolved(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })

	f.dirtyEvade02("alice")

	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m := decode(t, w)
	if m["correct"] != true {
		t.Fatalf("flag should be considered correct: %v", m)
	}
	if m["evaded"] != false {
		t.Fatalf("expected evaded=false (forbidden rule fired while 02-evade was current): %v", m)
	}
}

// TestSubmit_RequiredTriggerFire_DoesNotDirtyFollowingEvade is ADR-0003's
// core HTTP-level regression pin (the BLOCKING-1 finding that sent PR #124
// back): the SINGLE fire that legitimately solves 01-read-shadow must NOT
// taint its evade twin 02-evade, even though 02-evade forbids the exact same
// rule name. Before attempt scope, this fire alone permanently blocked
// 02-evade for every regular participant who played the game straight.
func TestSubmit_RequiredTriggerFire_DoesNotDirtyFollowingEvade(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })

	// The ONE fire needed to clear 01-read-shadow.
	w := f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))
	if w.Code != http.StatusOK {
		t.Fatalf("falco event: status %d", w.Code)
	}

	sw := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m := decode(t, sw)
	if m["evaded"] != true || m["solved"] != true {
		t.Fatalf("ADR-0003 regression: 01-read-shadow's required fire must not taint its evade twin, got %v", m)
	}
}

// TestSubmit_CorrectFlag_AfterWaiting_StaysDirty_NotSolved is the App-H2
// exploit-#1 regression (this test USED TO be named
// TestSubmit_CorrectFlag_AfterWindow_Solves and asserted the opposite — that
// waiting past the 10s window cleared the forbidden fire and let the
// participant solve. That was exploit #1: fire the forbidden rule once, wait
// out the window, submit — solved every time, no clean re-run required. The
// dirty flag is now permanent: even advancing the clock a full day past the
// old window must not clear it. Only the explicit reset endpoint
// (POST /api/users/{user}/challenges/{cid}/reset-dirty) may.
//
// ADR-0003 update to this test's SETUP (name and assertions unchanged — see
// Verification (b), which requires this exact test name to keep passing): a
// single fire of the shared rule is no longer sufficient to dirty 02-evade
// under attempt scope (see dirtyEvade02's doc) — it now takes the documented
// two-fire sequence (solve 01-read-shadow, THEN fire again while 02-evade is
// current) to reach the dirty state this test's clock-independence assertion
// is actually about.
func TestSubmit_CorrectFlag_AfterWaiting_StaysDirty_NotSolved(t *testing.T) {
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })

	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f.dirtyEvade02("alice")

	clock = clock.Add(30 * time.Second) // well past the old 10s window
	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m := decode(t, w)
	if m["solved"] == true {
		t.Fatalf("App-H2 regression: waiting past the old window must not clear the dirty taint: %v", m)
	}
	if m["evaded"] != false {
		t.Fatalf("expected evaded=false (still dirty): %v", m)
	}

	clock = clock.Add(24 * time.Hour) // even a full day later must not clear it
	w = f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m = decode(t, w)
	if m["solved"] == true {
		t.Fatalf("App-H2 regression: time must never clear the dirty taint: %v", m)
	}
}

// TestResetDirty_A2_2_ClearsExfilReceipt_StaleReceiptCannotSolve is the
// HTTP-level end-to-end proof of ADR-0003 A2-2 (CEO enforce decision,
// 2026-08-18): dirtying 03-exfil (which is RequireExfil), delivering the
// collector receipt, then calling reset-dirty must NOT leave the pair
// solvable off the STALE receipt — a manual submit right after the reset
// must still report not-solved/not-exfiltrated, and only a FRESH exfil
// delivery clears the gate. Before A2-2, ResetDirty cleared only the taint
// and left the exfil row in place, so this exact sequence ("fire → reset →
// solve off the stale receipt") reopened the App-H2 exploit through a
// different door — and the Sweeper (scoring.Grader.Sweep, run every 5s in
// production) would have auto-solved it with zero further participant
// action, which this test's final manual-submit check also rules out.
func TestResetDirty_A2_2_ClearsExfilReceipt_StaleReceiptCannotSolve(t *testing.T) {
	f := newFixture(t, nil)

	// Advance alice to 03-exfil being current: 01-read-shadow's required
	// fire, then a clean submit of 02-evade.
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))
	if w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"}); decode(t, w)["solved"] != true {
		t.Fatalf("02-evade must solve cleanly to advance current, body=%s", w.Body)
	}

	// 03-exfil is now current: fire the shared rule again to taint it, then
	// deliver the (soon-to-be-stale) exfil receipt.
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))
	if w := f.do("POST", "/internal/exfil/03-exfil", map[string]any{"user": "alice", "flag": "FALCO{boss}"}); decode(t, w)["received"] != true {
		t.Fatalf("exfil receipt not recorded, body=%s", w.Body)
	}

	if w := f.doUser("POST", "/api/users/alice/challenges/03-exfil/reset-dirty", "alice", nil); w.Code != http.StatusOK {
		t.Fatalf("reset-dirty: want 200, got %d body=%s", w.Code, w.Body.String())
	}

	// A2-2: the stale receipt must NOT satisfy the gate.
	w := f.do("POST", "/api/challenges/03-exfil/submit", map[string]any{"user": "alice", "flag": "FALCO{boss}"})
	m := decode(t, w)
	if m["exfiltrated"] == true || m["solved"] == true {
		t.Fatalf("A2-2 regression: reset must not leave a stale exfil receipt able to solve, got %v", m)
	}

	// A fresh delivery after the reset finally satisfies the gate.
	if w := f.do("POST", "/internal/exfil/03-exfil", map[string]any{"user": "alice", "flag": "FALCO{boss}"}); decode(t, w)["received"] != true {
		t.Fatalf("fresh exfil receipt not recorded, body=%s", w.Body)
	}
	w = f.do("POST", "/api/challenges/03-exfil/submit", map[string]any{"user": "alice", "flag": "FALCO{boss}"})
	m = decode(t, w)
	if m["solved"] != true {
		t.Fatalf("fresh exfil after reset must solve, got %v", m)
	}
}

// TestResetDirty_ClearsTaint_ThenCleanSubmitSolves proves the ONLY documented
// way back to clean: the participant's explicit reset endpoint. After it, a
// submit with no NEW forbidden fire since the reset solves normally.
func TestResetDirty_ClearsTaint_ThenCleanSubmitSolves(t *testing.T) {
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })
	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)

	f.dirtyEvade02("alice")
	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	if decode(t, w)["solved"] == true {
		t.Fatal("must still be dirty before reset")
	}

	rw := f.doUser("POST", "/api/users/alice/challenges/02-evade/reset-dirty", "alice", nil)
	if rw.Code != http.StatusOK {
		t.Fatalf("reset-dirty: want 200, got %d body=%s", rw.Code, rw.Body.String())
	}

	w = f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	m := decode(t, w)
	if m["solved"] != true {
		t.Fatalf("clean submit after an explicit reset must solve, got %v", m)
	}
}

// TestResetDirty_SelfScope proves the reset endpoint is gated exactly like the
// other /api/users/{user}/* writes (selfOrAdminWrite, I8): a third party
// cannot clear another participant's taint, and admin may reset anyone's.
func TestResetDirty_SelfScope(t *testing.T) {
	f := newFixture(t, nil)
	f.dirtyEvade02("alice")

	if w := f.doUser("POST", "/api/users/alice/challenges/02-evade/reset-dirty", "bob", nil); w.Code != http.StatusForbidden {
		t.Fatalf("cross-user reset-dirty must be forbidden, got %d body=%s", w.Code, w.Body.String())
	}
	// Still dirty — the denied cross-user attempt must not have cleared it.
	w := f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	if decode(t, w)["solved"] == true {
		t.Fatal("a denied cross-user reset must not clear the taint")
	}

	if w := f.doAdmin("POST", "/api/users/alice/challenges/02-evade/reset-dirty", nil); w.Code != http.StatusOK {
		t.Fatalf("admin reset-dirty must be allowed, got %d body=%s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})
	if decode(t, w)["solved"] != true {
		t.Fatal("admin reset must clear the taint and let a clean submit solve")
	}
}

// App-H3 (and, since App-H2, doubly so): a forged event with ev.Time set far
// in the past must NOT escape the dirty gate. The dirty-taint timestamp is
// stamped from server time (never ev.Time) and, since App-H2, the gate does
// not even consult a time window at all — so pre-aging the event buys the
// attacker nothing either way.
func TestFalcoEvents_EvadeWindow_IgnoresAttackerTime(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return now })

	// First: the REQUIRED fire that solves 01-read-shadow and advances
	// current to 02-evade (ADR-0003 attempt scope — this fire must not taint
	// 02-evade itself; see dirtyEvade02's doc).
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

	// Second: NOW 02-evade is current, so this fire taints it. The attacker
	// tries to bury it 1 hour in the past via the forged `time` field.
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
// the score reflects the per-hint-index penalty schedule (Grader.UserScore →
// ComputeScore single source). Default policy: 100/solve, HINT1=10/HINT2=30/
// HINT3=50 (CEO-confirmed schedule).
func TestLeaderboard_ScoreField_Additive(t *testing.T) {
	fixedNow := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newFixture(t, func() time.Time { return fixedNow })

	// alice solves one trigger challenge (100) and reveals HINT1+HINT2
	// (-(10+30)=-40) → 60.
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
	// Score reflects the schedule penalty: 1*100 - (HINT1=10 + HINT2=30) = 60.
	if row["score"].(float64) != 60 {
		t.Errorf("score = %v, want 60 (100 per solve - HINT1(10) - HINT2(30))", row["score"])
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

	// alice solves FIRST (10:00) but leans on all 3 hints →
	// 100 - (HINT1=10 + HINT2=30 + HINT3=50) = 10.
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
		t.Fatalf("higher score must rank first; got order %v (bob=100 should beat alice=10)", lb)
	}
	if top["score"].(float64) != 100 || top["rank"].(float64) != 1 {
		t.Errorf("top row score/rank = %v/%v, want 100/1", top["score"], top["rank"])
	}
	second := lb[1].(map[string]any)
	if second["user"] != "alice" || second["score"].(float64) != 10 || second["rank"].(float64) != 2 {
		t.Errorf("second row = %v, want alice score=10 rank=2", second)
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

// TestLeaderboard_ScoreTie_BreaksByCompletionOrder_NotFirstSolve pins the
// 2026-09-03 CEO decision: for players tied on score, the tiebreak is who
// reached that score SOONEST (their most recent solve), not who started
// first. alice solves her first challenge before bob but finishes her
// second (and final, for this fixture) challenge AFTER bob finishes his —
// so bob, who completed later-in-wall-clock-order but reached the tied
// score first, must rank ahead of alice despite starting later. This is the
// exact shape of the live incident that prompted the change: a fast starter
// who finishes slow must not outrank a slower starter who finishes first.
func TestLeaderboard_ScoreTie_BreaksByCompletionOrder_NotFirstSolve(t *testing.T) {
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })

	// alice starts first (10:00), solving the trigger challenge...
	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

	// ...bob starts second (10:10), solving the same trigger challenge...
	clock = time.Date(2026, 5, 11, 10, 10, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "bob"))

	// ...bob finishes his second (evade) challenge at 10:20, reaching
	// score=200 first...
	clock = time.Date(2026, 5, 11, 10, 20, 0, 0, time.UTC)
	f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "bob", "flag": "FALCO{ok}"})

	// ...alice finishes her second (evade) challenge LAST at 10:30, also
	// reaching score=200, despite having started 10 minutes before bob.
	clock = time.Date(2026, 5, 11, 10, 30, 0, 0, time.UTC)
	f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "alice", "flag": "FALCO{ok}"})

	lb := decode(t, f.doAdmin("GET", "/api/state", nil))["leaderboard"].([]any)
	top := lb[0].(map[string]any)
	if top["user"] != "bob" || top["score"].(float64) != 200 {
		t.Fatalf("bob reached the tied score first and must rank first despite "+
			"starting later; got order %v", lb)
	}
	second := lb[1].(map[string]any)
	if second["user"] != "alice" {
		t.Fatalf("alice must rank second (finished the tied score later, even "+
			"though she started first); got %v", lb)
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

// TestUserMe_NoActivity_RankIsZero proves a 0-solve participant's own /me
// response reports rank 0 (the UI renders this as "-", same convention
// /api/state already uses for an unranked participant — see
// computeLeaderboard's "Rank only participants who have solved something"
// comment in api.go).
func TestUserMe_NoActivity_RankIsZero(t *testing.T) {
	f := newFixture(t, nil)
	m := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
	if m["rank"].(float64) != 0 {
		t.Errorf("expected rank 0 for a 0-solve participant, got %v", m["rank"])
	}
	if m["score"].(float64) != 0 {
		t.Errorf("expected score 0 for a 0-solve participant, got %v", m["score"])
	}
}

// TestUserMe_AfterSolve_SurfacesOwnRank proves /me now surfaces the caller's
// OWN rank (P23-ME-1, CEO decision 案① 完全プライベート), sourced from the same
// computeLeaderboard the admin dashboard uses — extracted for DRY (#40/#39
// continuity), no ranking semantics changed.
func TestUserMe_AfterSolve_SurfacesOwnRank(t *testing.T) {
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })

	// alice solves first (10:00) → rank 1 while sole participant.
	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

	m := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
	if m["rank"].(float64) != 1 {
		t.Fatalf("expected alice rank 1 as sole solver, got %v", m["rank"])
	}
	if m["score"].(float64) != 100 {
		t.Fatalf("expected alice score 100 (no hints used), got %v", m["score"])
	}

	// bob solves later (10:30) with no hints → ties alice's score (100) but
	// loses the earliest-solve tiebreak, so alice keeps rank 1 and bob is 2.
	clock = time.Date(2026, 5, 11, 10, 30, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "bob"))

	mAlice := decode(t, f.doUser("GET", "/api/users/alice/me", "alice", nil))
	if mAlice["rank"].(float64) != 1 {
		t.Errorf("alice should keep rank 1 (earliest tiebreak), got %v", mAlice["rank"])
	}
	mBob := decode(t, f.doUser("GET", "/api/users/bob/me", "bob", nil))
	if mBob["rank"].(float64) != 2 {
		t.Errorf("bob should be rank 2, got %v", mBob["rank"])
	}
}

// TestUserMe_NoOtherParticipantDataLeaks is the P23-ME-1 security invariant
// proof (CEO decision 案① 完全プライベート): a participant's own /me response
// must NEVER contain any OTHER participant's identifiers, display name, or
// leaderboard-shaped data — computeLeaderboard is shared with buildState
// (admin /api/state) and computes the FULL field, so a future edit that
// forgot to narrow the result to the caller's own row would leak the whole
// leaderboard here. This guards specifically against that regression: it
// seeds TWO other participants (bob, carol) with distinct solves/display
// names/scores, then asserts alice's own /me response contains no trace of
// either "bob"/"carol" (as a bare user id) or a "leaderboard"-shaped key.
func TestUserMe_NoOtherParticipantDataLeaks(t *testing.T) {
	var clock time.Time
	f := newFixture(t, func() time.Time { return clock })

	clock = time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))
	clock = time.Date(2026, 5, 11, 9, 30, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "bob"))
	clock = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "carol"))
	if w := f.doAdmin("POST", "/api/admin/users/bob/display-name", map[string]string{"name": "bob-the-hacker"}); w.Code != http.StatusOK {
		t.Fatalf("admin display-name set for bob failed: %d body=%s", w.Code, w.Body)
	}

	w := f.doUser("GET", "/api/users/alice/me", "alice", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body)
	}
	body := w.Body.String()

	m := decode(t, w)
	if m["rank"].(float64) != 1 {
		t.Fatalf("alice should be rank 1 (earliest solve), got %v", m["rank"])
	}

	// No leaderboard-shaped key at all — /me must not carry the admin
	// dashboard's field-wide payload shape under any key name.
	for _, marker := range []string{`"leaderboard"`, `"solver_details"`, `"recent_solves"`, `"events_per_user"`} {
		if strings.Contains(body, marker) {
			t.Errorf("participant /me response must not embed admin-shaped state, found %q in body=%s", marker, body)
		}
	}
	// No other participant's identifier/display name anywhere in the body.
	for _, other := range []string{"bob", "carol", "bob-the-hacker"} {
		if strings.Contains(body, other) {
			t.Errorf("participant /me response must not mention other participant %q, body=%s", other, body)
		}
	}
}

// ---------------- HIDDEN_USERS (venue-demo account exclusion) ----------------

// TestLeaderboard_HiddenUsers_ExcludedAndRankCloses proves HIDDEN_USERS (a
// venue-demo account, e.g. "test1", that an operator drives live during the
// event) is excluded from computeLeaderboard's ranked field: it gets no row
// in the admin dashboard's leaderboard array (GET /api/state), and — because
// exclusion happens at userSet-construction time rather than by
// post-hoc-hiding a computed row — the remaining participant's rank is NOT
// left with a gap where the hidden user would have sorted (rank stays
// consecutive over the VISIBLE field only).
func TestLeaderboard_HiddenUsers_ExcludedAndRankCloses(t *testing.T) {
	var clock time.Time
	f := newFixtureWithHidden(t, func() time.Time { return clock }, []string{"test1"})

	// test1 (hidden) solves FIRST. If it were not excluded, the earliest-solve
	// tiebreak would put it at rank 1 and push alice to rank 2.
	clock = time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "test1"))
	clock = time.Date(2026, 5, 11, 9, 30, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "alice"))

	lb := decode(t, f.doAdmin("GET", "/api/state", nil))["leaderboard"].([]any)
	if len(lb) != 1 {
		t.Fatalf("leaderboard must exclude the hidden user, want 1 entry, got %d: %v", len(lb), lb)
	}
	row := lb[0].(map[string]any)
	if row["user"] != "alice" {
		t.Fatalf("only alice should be visible on the leaderboard, got %v", row)
	}
	if row["rank"].(float64) != 1 {
		t.Errorf("alice's rank must close the gap left by the excluded hidden user, want 1, got %v", row["rank"])
	}
}

// TestLeaderboard_HiddenUsers_UnknownEventOnlyUser proves the exclusion also
// covers a hidden user who has ONLY tripped Falco rules without solving
// anything (computeLeaderboard's userSet is seeded from BOTH
// snap.EventsPerUser and snap.Solved — see its doc — so both sources of
// membership must independently honour HIDDEN_USERS, not just the Solved
// one exercised by the test above).
func TestLeaderboard_HiddenUsers_UnknownEventOnlyUser(t *testing.T) {
	f := newFixtureWithHidden(t, nil, []string{"test1"})

	// A rule name that matches no challenge's ExpectedRules/ForbiddenRules
	// (so OnRuleFire solves nothing) still bumps store.RecordRuleFire's
	// eventsPerUser counter unconditionally — that is the OTHER membership
	// source (snap.EventsPerUser) computeLeaderboard reads, independent of
	// the snap.Solved source the test above exercises.
	f.do("POST", "/falco/events", falcoEventBody("Unrelated benign rule", "test1"))

	lb := decode(t, f.doAdmin("GET", "/api/state", nil))["leaderboard"].([]any)
	// Without HIDDEN_USERS, this event alone would have given test1 exactly
	// one lbEntry (via the EventsPerUser membership source) — assert the
	// slice is empty, not just "no entry named test1", so an implementation
	// that silently dropped the EventsPerUser exclusion (leaving only the
	// Solved-side one) cannot pass by accident.
	if len(lb) != 0 {
		t.Fatalf("hidden user must not appear in the leaderboard via EventsPerUser membership either, want 0 entries, got %d: %v", len(lb), lb)
	}
}

// TestUserMe_HiddenUser_SeesOwnScore_RankZero proves the HIDDEN_USERS
// exclusion is display-only for the LEADERBOARD, not a block on the hidden
// user's own self-view: a hidden user reading their own
// GET /api/users/{user}/me must not crash and must still see their real
// solved_count/score (scoring is completely untouched by the leaderboard
// filter) — only rank falls back to computeLeaderboard's "no lbEntry found"
// zero-value, the same "-"-rendering fallback a genuine zero-solve
// participant already gets (TestUserMe_NoActivity_RankIsZero).
func TestUserMe_HiddenUser_SeesOwnScore_RankZero(t *testing.T) {
	var clock time.Time
	f := newFixtureWithHidden(t, func() time.Time { return clock }, []string{"test1"})

	clock = time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	f.do("POST", "/falco/events", falcoEventBody("Read sensitive file untrusted", "test1"))

	w := f.doUser("GET", "/api/users/test1/me", "test1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("hidden user's own /me must not error, got %d body=%s", w.Code, w.Body)
	}
	m := decode(t, w)
	if m["solved_count"].(float64) != 1 {
		t.Errorf("hidden user's own /me must still report its real solved_count, got %v", m["solved_count"])
	}
	if m["score"].(float64) != 100 {
		t.Errorf("hidden user's own /me must still report its real score (100, no hints used), got %v", m["score"])
	}
	if m["rank"].(float64) != 0 {
		t.Errorf("hidden user has no leaderboard row, so rank must fall back to 0 (renders as \"-\"), got %v", m["rank"])
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

// NOTE: TestMeHTML_ServedAtMe (asserted GET /me served the legacy me.html
// shell) was REMOVED in P19-2b — that route no longer exists (see
// internal/scoreboard/view/view.go's package doc). The equivalent
// HTML-serving coverage for the unified portal shell lives in
// internal/scoreboard/view/portal_test.go (TestRenderPortal_*), and
// TestDisplayName_ParticipantCanChange above already covers the underlying
// /api/users/{user}/me data path the portal's Me pane fetches from.

// TestLegacyMeJourneyRoutes_Removed pins the P19-2b cutover: GET /me and
// GET /journey must be gone from the mux entirely (not merely empty), so a
// future accidental re-registration is caught immediately rather than
// silently reopening the removed route. The portal (/portal#me,
// /portal#journey) is the sole replacement — see view.go's package doc.
func TestLegacyMeJourneyRoutes_Removed(t *testing.T) {
	f := newFixture(t, nil)
	for _, path := range []string{"/me", "/me?user=alice", "/journey", "/journey?user=alice"} {
		w := f.do("GET", path, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want 404 (route removed)", path, w.Code)
		}
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
