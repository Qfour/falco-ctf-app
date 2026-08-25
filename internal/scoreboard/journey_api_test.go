package scoreboard_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// journeyFixture builds a handler with a 3-mission catalog (01 trigger,
// 02 evade, 03 trigger), journey content for 01 + 02 only (03 exercises the
// graceful-degrade path), and an explicit progression order.
type journeyFixture struct {
	t   *testing.T
	srv *scoreboard.Handler
	st  *store.Store
}

func newJourneyFixture(t *testing.T, extra ...scoreboard.Option) *journeyFixture {
	t.Helper()
	cat := catalog.Catalog{
		"01-recon": {ID: "01-recon", Type: "trigger", ExpectedRules: []string{"Recon Rule"}},
		"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"Recon Rule"}, ExpectedFlag: "FALCO{ok}"},
		"03-late":  {ID: "03-late", Type: "trigger", ExpectedRules: []string{"Late Rule"}},
	}
	journeys := catalog.Journeys{
		"01-recon": {
			ChallengeID: "01-recon", Title: "偵察", Tagline: "obj-1", Briefing: "brief-1",
			Steps:   []catalog.JourneyStep{{Label: "s0", Detail: "d0"}, {Label: "s1", Detail: "d1"}},
			Hints:   []string{"h1", "h2", "h3"},
			Bridge:  "bridge-1",
			DocsURL: "/missions/01-recon/",
		},
		"02-evade": {
			ChallengeID: "02-evade", Title: "回避", Tagline: "obj-2", Briefing: "brief-2",
			Steps: []catalog.JourneyStep{{Label: "s0", Detail: "d0"}},
			Hints: []string{"eh1", "eh2"},
		},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "j.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// P23-2: wire journeyFixtureOrigin into the allowlist; req/reqAs send it as
	// Origin on every request. This fixture exercises the OTHER gates (P18,
	// journey progression, scoring) so it must not be collaterally denied by
	// the origin guard's fail-closed default (see origin_guard_test.go for the
	// guard's own dedicated coverage).
	opts := append([]scoreboard.Option{
		scoreboard.WithJourneys(journeys),
		scoreboard.WithOrder([]string{"01-recon", "02-evade", "03-late"}),
		scoreboard.WithAllowedOrigins([]string{journeyFixtureOrigin}),
	}, extra...)
	srv := scoreboard.NewHandler(cat, st, logger, opts...)
	return &journeyFixture{t: t, srv: srv, st: st}
}

// journeyFixtureOrigin is the sole entry in journeyFixture's ALLOWED_ORIGINS
// (P23-2). req/reqAs send it as Origin on every request.
const journeyFixtureOrigin = "https://scoreboard.ctf.local"

func (f *journeyFixture) req(method, target string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.reqAs(method, target, "", body)
}

// reqAs issues a request carrying X-Auth-Request-Email = email (omitted when
// blank), so journey-read tests can authenticate as self / admin against the
// P18 self-scope gate. Write paths (step/hint) are ungated and use req().
func (f *journeyFixture) reqAs(method, target, email string, body any) *httptest.ResponseRecorder {
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
	// P23-2: see journeyFixtureOrigin doc.
	r.Header.Set("Origin", journeyFixtureOrigin)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func (f *journeyFixture) journey(user string) map[string]any {
	f.t.Helper()
	// Self-scoped read (P18): authenticate as the participant themselves.
	w := f.reqAs("GET", "/api/users/"+user+"/journey", user+"@ctf.local", nil)
	if w.Code != http.StatusOK {
		f.t.Fatalf("journey status: %d body=%s", w.Code, w.Body)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		f.t.Fatalf("decode: %v", err)
	}
	return m
}

// journeyAt is journey() with a `?mission=<id>` override — the P23 free
// mission browsing query param. Still authenticates self-scoped as `user`.
func (f *journeyFixture) journeyAt(user, mission string) map[string]any {
	f.t.Helper()
	w := f.reqAs("GET", "/api/users/"+user+"/journey?mission="+mission, user+"@ctf.local", nil)
	if w.Code != http.StatusOK {
		f.t.Fatalf("journey status: %d body=%s", w.Code, w.Body)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		f.t.Fatalf("decode: %v", err)
	}
	return m
}

func statusOf(m map[string]any, id string) string {
	for _, mi := range m["missions"].([]any) {
		mm := mi.(map[string]any)
		if mm["id"] == id {
			return mm["status"].(string)
		}
	}
	return ""
}

func TestJourney_InitialStatesGuided(t *testing.T) {
	f := newJourneyFixture(t)
	m := f.journey("alice")
	if m["current"] != "01-recon" {
		t.Fatalf("current should be 01-recon, got %v", m["current"])
	}
	if s := statusOf(m, "01-recon"); s != "current" {
		t.Fatalf("01 status=%q want current", s)
	}
	if s := statusOf(m, "02-evade"); s != "locked" {
		t.Fatalf("02 status=%q want locked", s)
	}
	if s := statusOf(m, "03-late"); s != "locked" {
		t.Fatalf("03 status=%q want locked", s)
	}
	det := m["detail"].(map[string]any)
	if det["id"] != "01-recon" || det["briefing"] != "brief-1" || det["hasJourney"] != true {
		t.Fatalf("detail wrong: %v", det)
	}
	steps := det["steps"].([]any)
	if len(steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(steps))
	}
	hints := det["hints"].(map[string]any)
	if hints["total"].(float64) != 3 || hints["lockedCount"].(float64) != 3 {
		t.Fatalf("hints meta wrong: %v", hints)
	}
	if len(hints["opened"].([]any)) != 0 {
		t.Fatal("no hints should be opened initially")
	}
}

func TestJourney_AdvancesOnSolve(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	f := newJourneyFixture(t)
	// Solve 01 directly via the store (equivalent to a trigger auto-solve).
	if _, err := f.st.MarkSolved("alice", "01-recon", now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	m := f.journey("alice")
	if m["current"] != "02-evade" {
		t.Fatalf("current should advance to 02-evade, got %v", m["current"])
	}
	if s := statusOf(m, "01-recon"); s != "solved" {
		t.Fatalf("01 status=%q want solved", s)
	}
	if s := statusOf(m, "02-evade"); s != "current" {
		t.Fatalf("02 status=%q want current", s)
	}
	det := m["detail"].(map[string]any)
	if det["id"] != "02-evade" || det["type"] != "evade" {
		t.Fatalf("detail should be the evade mission: %v", det)
	}
}

func bridgeOf(m map[string]any, id string) string {
	for _, mi := range m["missions"].([]any) {
		mm := mi.(map[string]any)
		if mm["id"] == id {
			s, _ := mm["bridge"].(string)
			return s
		}
	}
	return ""
}

// TestJourney_BridgeAndLeadIn proves the #47 narrative-bridge wiring:
//   - each mission carries its own `bridge` teaser in the mission map (drives
//     the CLEARED overlay when the mission flips to solved);
//   - the first mission's detail has an empty `leadIn` (no previous mission);
//   - after solving 01, the now-current mission (02) detail exposes the PREVIOUS
//     mission's bridge as `leadIn`, so the pull persists past the overlay.
// All fields are display-only and never gate a solve.
func TestJourney_BridgeAndLeadIn(t *testing.T) {
	f := newJourneyFixture(t)

	// Mission map carries 01's bridge; 02 has none (fixture leaves it empty).
	m := f.journey("alice")
	if got := bridgeOf(m, "01-recon"); got != "bridge-1" {
		t.Fatalf("01 bridge=%q want %q", got, "bridge-1")
	}
	if got := bridgeOf(m, "02-evade"); got != "" {
		t.Fatalf("02 bridge=%q want empty (fail-soft)", got)
	}
	// First mission's detail has no lead-in (nothing precedes it).
	if li, _ := m["detail"].(map[string]any)["leadIn"].(string); li != "" {
		t.Fatalf("first mission leadIn=%q want empty", li)
	}

	// Solve 01 → 02 becomes current and inherits 01's bridge as its leadIn.
	if _, err := f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	det := f.journey("alice")["detail"].(map[string]any)
	if det["id"] != "02-evade" {
		t.Fatalf("current should be 02-evade, got %v", det["id"])
	}
	if li, _ := det["leadIn"].(string); li != "bridge-1" {
		t.Fatalf("02 leadIn=%q want %q (previous mission bridge)", li, "bridge-1")
	}
}

func TestJourney_GracefulDegradeNoJourneyYaml(t *testing.T) {
	f := newJourneyFixture(t)
	// Solve 01 and 02 so 03-late (no journey.yaml) becomes current.
	_, _ = f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:00Z")
	_, _ = f.st.MarkSolved("alice", "02-evade", "2026-01-01T00:00:01Z")
	m := f.journey("alice")
	if m["current"] != "03-late" {
		t.Fatalf("current should be 03-late, got %v", m["current"])
	}
	det := m["detail"].(map[string]any)
	if det["hasJourney"] != false {
		t.Fatalf("03-late has no journey.yaml; hasJourney should be false: %v", det)
	}
}

func TestJourney_AllSolvedNoCurrent(t *testing.T) {
	f := newJourneyFixture(t)
	_, _ = f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:00Z")
	_, _ = f.st.MarkSolved("alice", "02-evade", "2026-01-01T00:00:01Z")
	_, _ = f.st.MarkSolved("alice", "03-late", "2026-01-01T00:00:02Z")
	m := f.journey("alice")
	if m["current"] != nil {
		t.Fatalf("current should be null when all solved, got %v", m["current"])
	}
	if m["detail"] != nil {
		t.Fatalf("detail should be null when all solved, got %v", m["detail"])
	}
}

func TestJourney_StepCheckReflectedInProjection(t *testing.T) {
	f := newJourneyFixture(t)
	w := f.req("POST", "/api/users/alice/challenges/01-recon/steps/0/check", map[string]any{"checked": true})
	if w.Code != http.StatusOK {
		t.Fatalf("step check status: %d body=%s", w.Code, w.Body)
	}
	det := f.journey("alice")["detail"].(map[string]any)
	steps := det["steps"].([]any)
	if steps[0].(map[string]any)["checked"] != true {
		t.Fatalf("step 0 should be checked: %v", steps[0])
	}
	if steps[1].(map[string]any)["checked"] != false {
		t.Fatalf("step 1 should be unchecked: %v", steps[1])
	}
}

// TestJourney_ExfilReceivedProjection proves the P16 read-only auto-solve
// fields: requireExfil is true for an exfil-required evade mission and
// exfilReceived flips to true once the store has any collector receipt for
// (user, challenge). These drive the Journey UI live status; they are purely
// projected and never affect the solve verdict (the sweeper / manual submit
// still gate on the exact flag + clean window).
func TestJourney_ExfilReceivedProjection(t *testing.T) {
	cat := catalog.Catalog{
		"01-boss": {ID: "01-boss", Type: "evade", ForbiddenRules: []string{"Reverse shell"}, ExpectedFlag: "FALCO{boss}", RequireExfil: true},
	}
	journeys := catalog.Journeys{
		"01-boss": {ChallengeID: "01-boss", Title: "boss", Briefing: "b"},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "j.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithJourneys(journeys),
		scoreboard.WithOrder([]string{"01-boss"}),
	)
	f := &journeyFixture{t: t, srv: srv, st: st}

	det := f.journey("alice")["detail"].(map[string]any)
	if det["requireExfil"] != true {
		t.Fatalf("requireExfil must be true for exfil-required evade, got %v", det["requireExfil"])
	}
	if det["exfilReceived"] != false {
		t.Fatalf("exfilReceived must be false before any receipt, got %v", det["exfilReceived"])
	}
	// ADR-0003 A3: windowSeconds is gone; dirty/dirtyRules replace it.
	if det["dirty"] != false {
		t.Fatalf("dirty must be false before any forbidden fire, got %v", det["dirty"])
	}
	if got := det["dirtyRules"].([]any); len(got) != 0 {
		t.Fatalf("dirtyRules must be empty before any forbidden fire, got %v", got)
	}

	// Record a collector receipt (any value) → exfilReceived flips true.
	if err := st.RecordExfil("alice", "01-boss", "FALCO{whatever}", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	det = f.journey("alice")["detail"].(map[string]any)
	if det["exfilReceived"] != true {
		t.Fatalf("exfilReceived must be true after a receipt, got %v", det["exfilReceived"])
	}

	// 01-boss is the sole (hence always-current) mission, so a direct
	// MarkDirty (mirroring what a real forbidden Falco fire would do via
	// Grader.OnRuleFire) flips dirty/dirtyRules true — proving the
	// replacement fields actually reflect store.DirtyRules, not a static
	// placeholder.
	if err := st.MarkDirty("alice", "01-boss", "Reverse shell", "2026-01-01T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	det = f.journey("alice")["detail"].(map[string]any)
	if det["dirty"] != true {
		t.Fatalf("dirty must be true once a forbidden rule has fired, got %v", det["dirty"])
	}
	dirtyRules := det["dirtyRules"].([]any)
	if len(dirtyRules) != 1 || dirtyRules[0] != "Reverse shell" {
		t.Fatalf("dirtyRules must surface the offending rule name (never a flag value, I10), got %v", dirtyRules)
	}
}

// TestJourney_ExpectedRuleFiredProjection proves the ADR-0008 read-only
// projection fields: requireExpectedRuleFire is true for a
// positive-proof-required evade mission, and expectedRuleFired flips to true
// once the store records ANY expectedRules fire for (user, challenge). Like
// TestJourney_ExfilReceivedProjection, these are purely projected and never
// affect the solve verdict directly (SubmitEvade re-derives the same gate via
// evaluateClean).
func TestJourney_ExpectedRuleFiredProjection(t *testing.T) {
	cat := catalog.Catalog{
		"01-proof": {
			ID: "01-proof", Type: "evade", ExpectedRules: []string{"Shell Redirected Private Key Read"},
			RequireExpectedRuleFire: true, ExpectedFlag: "FALCO{proof}",
		},
	}
	journeys := catalog.Journeys{
		"01-proof": {ChallengeID: "01-proof", Title: "proof", Briefing: "b"},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "j.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithJourneys(journeys),
		scoreboard.WithOrder([]string{"01-proof"}),
	)
	f := &journeyFixture{t: t, srv: srv, st: st}

	det := f.journey("alice")["detail"].(map[string]any)
	if det["requireExpectedRuleFire"] != true {
		t.Fatalf("requireExpectedRuleFire must be true for a proof-required evade, got %v", det["requireExpectedRuleFire"])
	}
	if det["expectedRuleFired"] != false {
		t.Fatalf("expectedRuleFired must be false before any fire, got %v", det["expectedRuleFired"])
	}

	// Record a positive-proof fire directly (mirroring what a real Falco fire
	// would do via Grader.OnRuleFire) → expectedRuleFired flips true.
	if err := st.RecordExpectedRuleFire("alice", "01-proof", "Shell Redirected Private Key Read", "2026-08-25T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	det = f.journey("alice")["detail"].(map[string]any)
	if det["expectedRuleFired"] != true {
		t.Fatalf("expectedRuleFired must be true after a fire, got %v", det["expectedRuleFired"])
	}
}

// TestJourney_TriggerDetectionProjection proves the #39 trigger-solve live
// feedback fields: a trigger mission surfaces its success signal
// (expectedRules) and the subset of those rules the user has fired in the
// recent window (detectedRules). These are read-only projections that drive the
// Journey UI's "run the action → Falco detected it → cleared" status; they never
// affect the solve verdict (ingest → Grader.EvaluateTrigger owns that).
func TestJourney_TriggerDetectionProjection(t *testing.T) {
	f := newJourneyFixture(t) // 01-recon is a trigger with ExpectedRules ["Recon Rule"]

	det := f.journey("alice")["detail"].(map[string]any)
	if det["type"] != "trigger" {
		t.Fatalf("01-recon must be a trigger mission, got %v", det["type"])
	}
	expected := det["expectedRules"].([]any)
	if len(expected) != 1 || expected[0] != "Recon Rule" {
		t.Fatalf("expectedRules must surface the success signal, got %v", det["expectedRules"])
	}
	// No fire yet → detectedRules empty (present as [] so the UI can iterate).
	if got := det["detectedRules"].([]any); len(got) != 0 {
		t.Fatalf("detectedRules must be empty before any fire, got %v", got)
	}

	// The user's action makes Falco emit the expected rule within the recent
	// lookback window → detectedRules picks it up.
	if _, err := f.st.RecordRuleFire("alice", "Recon Rule", float64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	det = f.journey("alice")["detail"].(map[string]any)
	detected := det["detectedRules"].([]any)
	if len(detected) != 1 || detected[0] != "Recon Rule" {
		t.Fatalf("detectedRules must include the fired expected rule, got %v", det["detectedRules"])
	}

	// A non-expected rule fire must NOT appear in detectedRules (only the
	// mission's own success signal is surfaced).
	if _, err := f.st.RecordRuleFire("alice", "Some Other Rule", float64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	det = f.journey("alice")["detail"].(map[string]any)
	if got := det["detectedRules"].([]any); len(got) != 1 {
		t.Fatalf("detectedRules must ignore non-expected rules, got %v", got)
	}
}

// TestJourney_TriggerDetectionOutsideWindow proves the detectedRules projection
// respects the UI lookback (triggerDetectWindowSeconds): an expected-rule fire
// that is older than the window is inside the store's 300s retention but must
// NOT surface as "detected" — the on-screen cue only reflects recent activity.
func TestJourney_TriggerDetectionOutsideWindow(t *testing.T) {
	f := newJourneyFixture(t) // 01-recon trigger, ExpectedRules ["Recon Rule"]

	// Fire the expected rule 120s ago: within the 300s ruleFires retention but
	// well outside the 60s detect window the projection uses.
	stale := float64(time.Now().Unix()) - 120
	if _, err := f.st.RecordRuleFire("alice", "Recon Rule", stale); err != nil {
		t.Fatal(err)
	}
	det := f.journey("alice")["detail"].(map[string]any)
	if got := det["detectedRules"].([]any); len(got) != 0 {
		t.Fatalf("fire older than the detect window must not surface, got %v", got)
	}
}

// TestJourney_EvadeHasNoTriggerFields proves the detection fields stay
// trigger-scoped: an evade mission surfaces expectedRules as [] and
// detectedRules as [] (the evade UX uses the flag-submit / exfil flow, not the
// trigger detection status), so the UI's `det.type === 'trigger'` gate is the
// only thing that renders the triggerSection.
func TestJourney_EvadeHasNoTriggerFields(t *testing.T) {
	f := newJourneyFixture(t)
	// Solve 01-recon so the current mission advances to the evade 02-evade.
	if _, err := f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	det := f.journey("alice")["detail"].(map[string]any)
	if det["type"] != "evade" {
		t.Fatalf("current should be the evade mission, got %v", det["type"])
	}
	if got := det["expectedRules"].([]any); len(got) != 0 {
		t.Fatalf("evade mission must not surface expectedRules, got %v", got)
	}
	if got := det["detectedRules"].([]any); len(got) != 0 {
		t.Fatalf("evade mission must not surface detectedRules, got %v", got)
	}
}

func TestJourney_StepCheck_InvalidIndex(t *testing.T) {
	f := newJourneyFixture(t)
	w := f.req("POST", "/api/users/alice/challenges/01-recon/steps/9/check", map[string]any{"checked": true})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("out-of-range step must 400, got %d", w.Code)
	}
}

func TestJourney_HintInOrderReveal(t *testing.T) {
	f := newJourneyFixture(t)
	// Opening hint 2 before hint 1 must be rejected (409).
	if w := f.req("POST", "/api/users/alice/challenges/01-recon/hints/2", nil); w.Code != http.StatusConflict {
		t.Fatalf("out-of-order hint must 409, got %d body=%s", w.Code, w.Body)
	}
	// Open hint 1, then 2.
	w1 := f.req("POST", "/api/users/alice/challenges/01-recon/hints/1", nil)
	if w1.Code != http.StatusOK {
		t.Fatalf("hint 1 status: %d body=%s", w1.Code, w1.Body)
	}
	var d1 map[string]any
	_ = json.Unmarshal(w1.Body.Bytes(), &d1)
	if d1["hint"] != "h1" {
		t.Fatalf("hint 1 text: %v", d1["hint"])
	}
	if w2 := f.req("POST", "/api/users/alice/challenges/01-recon/hints/2", nil); w2.Code != http.StatusOK {
		t.Fatalf("hint 2 after 1 must 200, got %d", w2.Code)
	}
	// Projection shows 2 opened, 1 locked, nextIndex=3.
	det := f.journey("alice")["detail"].(map[string]any)
	hints := det["hints"].(map[string]any)
	if len(hints["opened"].([]any)) != 2 {
		t.Fatalf("want 2 opened hints, got %v", hints["opened"])
	}
	if hints["lockedCount"].(float64) != 1 || hints["nextIndex"].(float64) != 3 {
		t.Fatalf("hint meta wrong: %v", hints)
	}
}

// TestJourney_ScorePenaltyOnHintReveal proves the #40 end-to-end behaviour:
// the journey projection surfaces a score, the per-hint-index penalty is
// exposed on the hints block, and self-revealing hints deducts the SCHEDULED
// amount (clamped at 0). Uses the fixture's default policy (100/solve,
// [10,30,50] HINT1/HINT2/HINT3 schedule) unless overridden.
func TestJourney_ScorePenaltyOnHintReveal(t *testing.T) {
	f := newJourneyFixture(t)

	// Baseline: no solves, no reveals → score 0. The top-level hint_penalty is
	// the representative HINT1 cost (10); the mission-specific hints.penalty
	// prices the NEXT unopened hint, also HINT1 (10) since none is opened yet.
	m := f.journey("alice")
	if m["score"].(float64) != 0 {
		t.Fatalf("initial score should be 0, got %v", m["score"])
	}
	if m["hint_penalty"].(float64) != 10 {
		t.Fatalf("hint_penalty should be 10 (HINT1, default schedule), got %v", m["hint_penalty"])
	}
	det := m["detail"].(map[string]any)
	hints := det["hints"].(map[string]any)
	if hints["penalty"].(float64) != 10 {
		t.Fatalf("hints.penalty (next=HINT1) should be 10, got %v", hints["penalty"])
	}

	// Solve 01-recon → +100. Then it advances; solve gives score 100.
	if _, err := f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if s := f.journey("alice")["score"].(float64); s != 100 {
		t.Fatalf("score after 1 solve should be 100, got %v", s)
	}

	// Reveal HINT1+HINT2 on the now-current 02-evade mission → -(10+30)=-40 →
	// score 60 (steeper schedule: HINT2 costs more than HINT1).
	if w := f.req("POST", "/api/users/alice/challenges/02-evade/hints/1", nil); w.Code != http.StatusOK {
		t.Fatalf("hint 1 reveal: %d body=%s", w.Code, w.Body)
	}
	if w := f.req("POST", "/api/users/alice/challenges/02-evade/hints/2", nil); w.Code != http.StatusOK {
		t.Fatalf("hint 2 reveal: %d body=%s", w.Code, w.Body)
	}
	if s := f.journey("alice")["score"].(float64); s != 60 {
		t.Fatalf("score after 1 solve - HINT1 - HINT2 should be 60, got %v", s)
	}

	// /me projection must agree on score; hint_penalty stays the HINT1
	// representative figure (unaffected by which hints were revealed).
	me := f.reqAs("GET", "/api/users/alice/me", "alice@ctf.local", nil)
	if me.Code != http.StatusOK {
		t.Fatalf("me status: %d", me.Code)
	}
	var mm map[string]any
	_ = json.Unmarshal(me.Body.Bytes(), &mm)
	if mm["score"].(float64) != 60 || mm["hint_penalty"].(float64) != 10 {
		t.Fatalf("me score/penalty disagree: score=%v penalty=%v", mm["score"], mm["hint_penalty"])
	}
}

// TestJourney_ScoreClampsAtZeroWithHighPenalty proves the fail-closed clamp:
// with a penalty high enough to exceed the earned award, the score floors at 0
// (never negative). Overrides the policy via WithPoints with a length-1
// schedule (every hint index reuses that single entry, matching the pre-#40
// schedule flat-penalty behaviour under the "reuse last entry" rule).
func TestJourney_ScoreClampsAtZeroWithHighPenalty(t *testing.T) {
	f := newJourneyFixture(t, scoreboard.WithPoints(scoring.PointsPolicy{PerSolve: 10, HintPenalties: []int{50}}))
	if _, err := f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	// Earned 10 for the solve; one 50-point hint reveal would give -40 → clamp 0.
	if w := f.req("POST", "/api/users/alice/challenges/02-evade/hints/1", nil); w.Code != http.StatusOK {
		t.Fatalf("hint reveal: %d", w.Code)
	}
	if s := f.journey("alice")["score"].(float64); s != 0 {
		t.Fatalf("score must clamp at 0, got %v", s)
	}
}

func TestJourney_HintOutOfRange(t *testing.T) {
	f := newJourneyFixture(t)
	if w := f.req("POST", "/api/users/alice/challenges/01-recon/hints/99", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("out-of-range hint must 400, got %d", w.Code)
	}
}

func TestJourney_NoHintsForMissionWithoutJourney(t *testing.T) {
	f := newJourneyFixture(t)
	// 03-late has no journey content -> no hints -> 404.
	if w := f.req("POST", "/api/users/alice/challenges/03-late/hints/1", nil); w.Code != http.StatusNotFound {
		t.Fatalf("hint on journeyless mission must 404, got %d", w.Code)
	}
}

// --- P23 Story-as-docs: free mission browsing + Falco rule excerpt ---------

// TestJourney_FreeBrowsing_SolvedMission proves `?mission=<id>` can select an
// ALREADY-SOLVED mission's detail (CEO decision: brief/steps/rule are static
// content, safe to re-read after solving; only hints stay gated to the
// unlocked prefix — covered separately below).
func TestJourney_FreeBrowsing_SolvedMission(t *testing.T) {
	f := newJourneyFixture(t)
	if _, err := f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	// current is now 02-evade; browse back to the solved 01-recon.
	m := f.journeyAt("alice", "01-recon")
	if m["current"] != "02-evade" {
		t.Fatalf("current must stay 02-evade regardless of ?mission=, got %v", m["current"])
	}
	det := m["detail"].(map[string]any)
	if det["id"] != "01-recon" || det["briefing"] != "brief-1" {
		t.Fatalf("detail must be the browsed (solved) mission: %v", det)
	}
}

// TestJourney_FreeBrowsing_LockedMission proves `?mission=<id>` can select a
// LOCKED mission's detail (brief/steps/rule readable ahead of reaching it —
// CEO decision) while its hints stay fully locked (see the paired
// TestJourney_FreeBrowsing_LockedMissionHintsAlwaysHidden below for the
// fairness-critical assertion).
func TestJourney_FreeBrowsing_LockedMission(t *testing.T) {
	f := newJourneyFixture(t)
	// 03-late is locked (current is 01-recon).
	m := f.journeyAt("alice", "03-late")
	if m["current"] != "01-recon" {
		t.Fatalf("current must stay 01-recon regardless of ?mission=, got %v", m["current"])
	}
	det := m["detail"].(map[string]any)
	if det["id"] != "03-late" || det["type"] != "trigger" {
		t.Fatalf("detail must be the browsed (locked) mission: %v", det)
	}
}

// TestJourney_FreeBrowsing_InvalidMissionFallsBackToCurrent proves an unknown
// `?mission=` value is a silent fallback to `current`, not an error — this is
// a display convenience, not an API contract.
func TestJourney_FreeBrowsing_InvalidMissionFallsBackToCurrent(t *testing.T) {
	f := newJourneyFixture(t)
	m := f.journeyAt("alice", "99-does-not-exist")
	det := m["detail"].(map[string]any)
	if det["id"] != "01-recon" {
		t.Fatalf("invalid ?mission= must fall back to current (01-recon), got %v", det["id"])
	}
}

// TestJourney_FreeBrowsing_LockedMissionHintsAlwaysHidden is the fairness
// pin (CEO: "locked mission hints 秘匿は公平性の不可侵"). It proves TWO
// things:
//  1. The normal path: 02-evade is locked (alice has not solved 01-recon), and
//     ?mission=02-evade must report ALL hints as locked (lockedCount ==
//     total, opened empty, nextIndex 0) even though 02-evade DOES have
//     journey.yaml hints authored (eh1/eh2) — a lesser implementation might
//     only omit the panel when hints are wholly absent, which would not catch
//     this case.
//  2. The defensive path: even if the store somehow already has opened-hint
//     rows for a mission that is CURRENTLY locked (e.g. a participant opened
//     hints while it was briefly current in an earlier scenario, then a
//     scenario/order change relocked it), missionDetail must still refuse to
//     surface them for a status=="locked" view — the gate reads status, not
//     "does the store have anything", so it cannot be bypassed by a stale
//     store row.
func TestJourney_FreeBrowsing_LockedMissionHintsAlwaysHidden(t *testing.T) {
	f := newJourneyFixture(t)

	// (1) Normal path: 02-evade is locked; browse to it directly.
	m := f.journeyAt("alice", "02-evade")
	if s := statusOf(m, "02-evade"); s != "locked" {
		t.Fatalf("precondition: 02-evade should be locked, got %q", s)
	}
	det := m["detail"].(map[string]any)
	if det["id"] != "02-evade" {
		t.Fatalf("detail must be the browsed mission: %v", det)
	}
	hints := det["hints"].(map[string]any)
	if hints["total"].(float64) != 2 {
		t.Fatalf("02-evade should have 2 authored hints, got %v", hints["total"])
	}
	if hints["lockedCount"].(float64) != 2 {
		t.Fatalf("locked mission must report ALL hints locked, got %v", hints)
	}
	if len(hints["opened"].([]any)) != 0 {
		t.Fatalf("locked mission must never expose opened hint text, got %v", hints["opened"])
	}
	if hints["nextIndex"].(float64) != 0 {
		t.Fatalf("locked mission must never offer a next-reveal index, got %v", hints["nextIndex"])
	}

	// (2) Defensive path: directly poke the store as if a hint had been opened
	// for 02-evade in the past (simulating a stale row from before a relock),
	// then re-browse to it while it is STILL locked. The gate must still hide it.
	if _, err := f.st.RecordHintView("alice", "02-evade", 1, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	m2 := f.journeyAt("alice", "02-evade")
	det2 := m2["detail"].(map[string]any)
	hints2 := det2["hints"].(map[string]any)
	if len(hints2["opened"].([]any)) != 0 {
		t.Fatalf("stale store row must NOT leak through the locked gate, got %v", hints2["opened"])
	}
	if hints2["lockedCount"].(float64) != 2 {
		t.Fatalf("stale store row must not reduce lockedCount for a locked mission, got %v", hints2)
	}
}

// TestJourney_FreeBrowsing_LockedMissionStepsAlwaysUnchecked is the /review-5x
// C2 fixup pin: a locked mission's steps must render as a plain read-only
// preview (checked: false for every step), never leaking store-recorded tick
// state — mirrors the hints gate's "locked is static display only" posture
// (see TestJourney_FreeBrowsing_LockedMissionHintsAlwaysHidden immediately
// above) even though a step tick, unlike a hint reveal, has no scoring
// consequence of its own.
func TestJourney_FreeBrowsing_LockedMissionStepsAlwaysUnchecked(t *testing.T) {
	f := newJourneyFixture(t)

	// Directly poke the store as if alice had ticked 02-evade's one step
	// (e.g. while it was briefly current under a since-changed order), then
	// browse to it while it is CURRENTLY locked (current is 01-recon). The
	// gate must hide the tick regardless of what the store has on file.
	if err := f.st.SetStepCheck("alice", "02-evade", 0, true, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	m := f.journeyAt("alice", "02-evade")
	if s := statusOf(m, "02-evade"); s != "locked" {
		t.Fatalf("precondition: 02-evade should be locked, got %q", s)
	}
	det := m["detail"].(map[string]any)
	steps := det["steps"].([]any)
	if len(steps) != 1 {
		t.Fatalf("02-evade should have 1 authored step, got %d", len(steps))
	}
	if steps[0].(map[string]any)["checked"] != false {
		t.Fatalf("locked mission must never expose checked step state, got %v", steps[0])
	}

	// Sanity: the SAME store-recorded tick DOES surface once 02-evade becomes
	// current (solve 01-recon), proving the gate is status-keyed, not a
	// blanket "steps never reflect the store" regression.
	if _, err := f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	m2 := f.journey("alice")
	if s := statusOf(m2, "02-evade"); s != "current" {
		t.Fatalf("precondition: 02-evade should now be current, got %q", s)
	}
	det2 := m2["detail"].(map[string]any)
	steps2 := det2["steps"].([]any)
	if steps2[0].(map[string]any)["checked"] != true {
		t.Fatalf("current mission's step tick should surface once unlocked, got %v", steps2[0])
	}
}

// TestJourney_FalcoRuleExcerpt_PresentAndAbsent proves the falcoRule /
// hasFalcoRule projection: a challenge with a loaded excerpt gets its
// lists/macros/rules verbatim (structured, not a text blob) and
// hasFalcoRule==true; a challenge with none gets the zero-value excerpt
// (three non-nil empty slices, never null) and hasFalcoRule==false so the UI
// can omit the panel rather than render three empty sections.
func TestJourney_FalcoRuleExcerpt_PresentAndAbsent(t *testing.T) {
	rules := catalog.FalcoRuleExcerpts{
		"01-recon": {
			Lists:  []catalog.FalcoListItem{{Name: "grep_commands", Items: []string{"grep", "egrep"}}},
			Macros: []catalog.FalcoMacroItem{{Name: "protected_shell_spawner", Condition: "proc.pname exists"}},
			Rules: []catalog.FalcoRuleItem{{
				Name: "Search Private Keys or Passwords", Desc: "d", Condition: "c", Output: "o",
				Priority: "NOTICE", Tags: []string{"maturity_stable"},
			}},
		},
	}
	f := newJourneyFixture(t, scoreboard.WithFalcoRules(rules))

	m := f.journey("alice") // current = 01-recon, which HAS an excerpt
	det := m["detail"].(map[string]any)
	if det["hasFalcoRule"] != true {
		t.Fatalf("01-recon should have hasFalcoRule=true, got %v", det["hasFalcoRule"])
	}
	fr := det["falcoRule"].(map[string]any)
	lists := fr["lists"].([]any)
	if len(lists) != 1 || lists[0].(map[string]any)["name"] != "grep_commands" {
		t.Fatalf("lists wrong: %v", fr["lists"])
	}
	macros := fr["macros"].([]any)
	if len(macros) != 1 || macros[0].(map[string]any)["name"] != "protected_shell_spawner" {
		t.Fatalf("macros wrong: %v", fr["macros"])
	}
	rulesList := fr["rules"].([]any)
	if len(rulesList) != 1 || rulesList[0].(map[string]any)["name"] != "Search Private Keys or Passwords" {
		t.Fatalf("rules wrong: %v", fr["rules"])
	}

	// 03-late has no excerpt entry at all -> zero-value, non-nil empty slices,
	// hasFalcoRule=false.
	m2 := f.journeyAt("alice", "03-late")
	det2 := m2["detail"].(map[string]any)
	if det2["hasFalcoRule"] != false {
		t.Fatalf("03-late should have hasFalcoRule=false, got %v", det2["hasFalcoRule"])
	}
	fr2 := det2["falcoRule"].(map[string]any)
	if len(fr2["lists"].([]any)) != 0 || len(fr2["macros"].([]any)) != 0 || len(fr2["rules"].([]any)) != 0 {
		t.Fatalf("absent excerpt must yield empty (not null) slices: %v", fr2)
	}
}

// TestJourney_FalcoRuleExcerpt_VisibleEvenWhenLocked proves the Falco rule
// panel is exempt from the hints lock (CEO decision §B②: rule content is
// static and identical for every viewer, unlike hints) — browsing to a
// locked mission still returns its falcoRule excerpt.
func TestJourney_FalcoRuleExcerpt_VisibleEvenWhenLocked(t *testing.T) {
	rules := catalog.FalcoRuleExcerpts{
		"03-late": {
			Rules: []catalog.FalcoRuleItem{{Name: "Late Rule", Desc: "d", Condition: "c", Output: "o", Priority: "NOTICE", Tags: []string{"t"}}},
		},
	}
	f := newJourneyFixture(t, scoreboard.WithFalcoRules(rules))
	m := f.journeyAt("alice", "03-late") // locked
	if s := statusOf(m, "03-late"); s != "locked" {
		t.Fatalf("precondition: 03-late should be locked, got %q", s)
	}
	det := m["detail"].(map[string]any)
	if det["hasFalcoRule"] != true {
		t.Fatalf("locked mission's falcoRule must still be visible, got hasFalcoRule=%v", det["hasFalcoRule"])
	}
	fr := det["falcoRule"].(map[string]any)
	if len(fr["rules"].([]any)) != 1 {
		t.Fatalf("locked mission's rule excerpt must be intact, got %v", fr["rules"])
	}
}

func docsURLOf(m map[string]any, id string) string {
	for _, mi := range m["missions"].([]any) {
		mm := mi.(map[string]any)
		if mm["id"] == id {
			s, _ := mm["docsUrl"].(string)
			return s
		}
	}
	return ""
}

// With no DOCS_BASE_URL configured (local dev), docsUrl stays relative so the
// existing behaviour is unchanged.
func TestJourney_DocsURL_RelativeWhenUnset(t *testing.T) {
	f := newJourneyFixture(t)
	m := f.journey("alice")
	if got := docsURLOf(m, "01-recon"); got != "/missions/01-recon/" {
		t.Fatalf("map docsUrl=%q want relative /missions/01-recon/", got)
	}
	det := m["detail"].(map[string]any)
	if got, _ := det["docsUrl"].(string); got != "/missions/01-recon/" {
		t.Fatalf("detail docsUrl=%q want relative /missions/01-recon/", got)
	}
}

// With DOCS_BASE_URL set, docsUrl is rewritten to an absolute URL on the docs
// host in both the mission map and the current-mission detail. A trailing slash
// on the base is normalised away so the join never doubles it.
func TestJourney_DocsURL_AbsoluteWhenSet(t *testing.T) {
	f := newJourneyFixture(t, scoreboard.WithDocsBaseURL("https://docs.example.test/"))
	m := f.journey("alice")
	const want = "https://docs.example.test/missions/01-recon/"
	if got := docsURLOf(m, "01-recon"); got != want {
		t.Fatalf("map docsUrl=%q want %q", got, want)
	}
	det := m["detail"].(map[string]any)
	if got, _ := det["docsUrl"].(string); got != want {
		t.Fatalf("detail docsUrl=%q want %q", got, want)
	}
	// A mission whose journey.yaml omits docsUrl stays empty (no phantom link).
	// Advance so 02-evade (no docsUrl) becomes current.
	_, _ = f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:00Z")
	m2 := f.journey("alice")
	if got := docsURLOf(m2, "02-evade"); got != "" {
		t.Fatalf("02-evade has no docsUrl; want empty, got %q", got)
	}
}

// --- P18 5x: /api/users/{user}/* write gate ---------------------------------
//
// The write gate (selfOrAdminWrite) is conditional on the presence of the
// X-Auth-Request-Email header. Over an auth-proxied host (journey/admin) the
// header is set, so writes are self-or-admin gated. Over the cluster-internal
// Service (collector / workspace) no header is set, so the legacy
// claimed-identity model is preserved (collector display-name path unchanged).

// TestJourneyWriteGate_StepCheck_HeaderPresent proves the journey-host case:
// self may tick, a third party is 403, and admin may tick anyone.
func TestJourneyWriteGate_StepCheck_HeaderPresent(t *testing.T) {
	f := newJourneyFixture(t, scoreboard.WithAdminEmails([]string{"root@ctf.local"}))
	const target = "/api/users/alice/challenges/01-recon/steps/0/check"
	body := map[string]any{"checked": true}

	// self → allowed
	if w := f.reqAs("POST", target, "alice@ctf.local", body); w.Code != http.StatusOK {
		t.Fatalf("self step-check must 200, got %d body=%s", w.Code, w.Body)
	}
	// other participant → 403 (cross-user write blocked)
	if w := f.reqAs("POST", target, "mallory@ctf.local", body); w.Code != http.StatusForbidden {
		t.Fatalf("cross-user step-check must 403, got %d body=%s", w.Code, w.Body)
	}
	// prefix-adjacent (alice2) must NOT satisfy alice (I8 anti-mismatch)
	if w := f.reqAs("POST", target, "alice2@ctf.local", body); w.Code != http.StatusForbidden {
		t.Fatalf("alice2 writing alice must 403, got %d body=%s", w.Code, w.Body)
	}
	// admin → allowed for any user
	if w := f.reqAs("POST", target, "root@ctf.local", body); w.Code != http.StatusOK {
		t.Fatalf("admin step-check must 200, got %d body=%s", w.Code, w.Body)
	}
}

// TestJourneyWriteGate_StepCheck_NoHeader proves the collector / workspace
// case: with no auth header the claimed-identity model still applies (allow).
func TestJourneyWriteGate_StepCheck_NoHeader(t *testing.T) {
	f := newJourneyFixture(t)
	// req() sends no X-Auth-Request-Email — cluster-internal path.
	if w := f.req("POST", "/api/users/alice/challenges/01-recon/steps/0/check", map[string]any{"checked": true}); w.Code != http.StatusOK {
		t.Fatalf("header-less step-check must 200 (collector path), got %d body=%s", w.Code, w.Body)
	}
}

// TestJourneyWriteGate_OpenHint_CrossUserOracleBlocked proves the openHint
// 409/200 cross-user oracle is closed: a third party cannot probe another
// participant's hint order (403 before any 409/200 leak).
func TestJourneyWriteGate_OpenHint_CrossUserOracleBlocked(t *testing.T) {
	f := newJourneyFixture(t)
	if w := f.reqAs("POST", "/api/users/alice/challenges/01-recon/hints/1", "mallory@ctf.local", nil); w.Code != http.StatusForbidden {
		t.Fatalf("cross-user hint open must 403 (no oracle), got %d body=%s", w.Code, w.Body)
	}
	// self may open normally
	if w := f.reqAs("POST", "/api/users/alice/challenges/01-recon/hints/1", "alice@ctf.local", nil); w.Code != http.StatusOK {
		t.Fatalf("self hint open must 200, got %d body=%s", w.Code, w.Body)
	}
	// header-less (collector/workspace) still allowed
	if w := f.req("POST", "/api/users/alice/challenges/01-recon/hints/1", nil); w.Code != http.StatusOK {
		t.Fatalf("header-less hint open must 200, got %d body=%s", w.Code, w.Body)
	}
}

// TestJourneyWriteGate_DisplayName proves display-name is self-or-admin gated
// on the auth-proxied host but stays claimed-identity over the collector path.
func TestJourneyWriteGate_DisplayName(t *testing.T) {
	f := newJourneyFixture(t, scoreboard.WithAdminEmails([]string{"root@ctf.local"}))
	body := map[string]any{"name": "Nickname"}

	// self → allowed
	if w := f.reqAs("POST", "/api/users/alice/display-name", "alice@ctf.local", body); w.Code != http.StatusOK {
		t.Fatalf("self display-name must 200, got %d body=%s", w.Code, w.Body)
	}
	// other → 403 (cannot overwrite another player's name)
	if w := f.reqAs("POST", "/api/users/alice/display-name", "mallory@ctf.local", body); w.Code != http.StatusForbidden {
		t.Fatalf("cross-user display-name must 403, got %d body=%s", w.Code, w.Body)
	}
	// admin → allowed for any user
	if w := f.reqAs("POST", "/api/users/alice/display-name", "root@ctf.local", body); w.Code != http.StatusOK {
		t.Fatalf("admin display-name must 200, got %d body=%s", w.Code, w.Body)
	}
	// header-less (collector-fronted display-name, accepted LOW) → allowed
	if w := f.req("POST", "/api/users/alice/display-name", body); w.Code != http.StatusOK {
		t.Fatalf("header-less display-name must 200 (collector path), got %d body=%s", w.Code, w.Body)
	}
}

// TestJourneyWriteGate_ResetDirty_HeaderPresent mirrors StepCheck (App-H2):
// self may reset own dirty taint, a third party is 403 and does NOT clear it,
// and admin may reset anyone's. 02-evade is this fixture's evade-type
// challenge (ForbiddenRules: ["Recon Rule"]).
func TestJourneyWriteGate_ResetDirty_HeaderPresent(t *testing.T) {
	f := newJourneyFixture(t, scoreboard.WithAdminEmails([]string{"root@ctf.local"}))
	const target = "/api/users/alice/challenges/02-evade/reset-dirty"

	// Seed a taint directly (as MarkDirtyOnRuleFire would on a forbidden Falco
	// fire), so the writes below have a real taint to (fail to) clear.
	if err := f.st.MarkDirty("alice", "02-evade", "Recon Rule", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	// other participant → 403, and the denied write must not clear the taint.
	if w := f.reqAs("POST", target, "mallory@ctf.local", nil); w.Code != http.StatusForbidden {
		t.Fatalf("cross-user reset-dirty must 403, got %d body=%s", w.Code, w.Body)
	}
	if got := f.st.DirtyRules("alice", "02-evade"); len(got) == 0 {
		t.Fatalf("a denied cross-user reset must not have cleared the taint: %v", got)
	}

	// self → allowed, clears the taint.
	if w := f.reqAs("POST", target, "alice@ctf.local", nil); w.Code != http.StatusOK {
		t.Fatalf("self reset-dirty must 200, got %d body=%s", w.Code, w.Body)
	}
	if got := f.st.DirtyRules("alice", "02-evade"); len(got) != 0 {
		t.Fatalf("self reset-dirty must clear the taint, still dirty: %v", got)
	}

	// re-dirty, then prove admin may reset anyone's.
	if err := f.st.MarkDirty("alice", "02-evade", "Recon Rule", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if w := f.reqAs("POST", target, "root@ctf.local", nil); w.Code != http.StatusOK {
		t.Fatalf("admin reset-dirty must 200, got %d body=%s", w.Code, w.Body)
	}
	if got := f.st.DirtyRules("alice", "02-evade"); len(got) != 0 {
		t.Fatalf("admin reset-dirty must clear the taint, still dirty: %v", got)
	}
}

// TestJourneyWriteGate_ResetDirty_NoHeader proves the collector/workspace
// case: with no auth header the claimed-identity model still applies (allow).
func TestJourneyWriteGate_ResetDirty_NoHeader(t *testing.T) {
	f := newJourneyFixture(t)
	if err := f.st.MarkDirty("alice", "02-evade", "Recon Rule", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if w := f.req("POST", "/api/users/alice/challenges/02-evade/reset-dirty", nil); w.Code != http.StatusOK {
		t.Fatalf("header-less reset-dirty must 200 (collector path), got %d body=%s", w.Code, w.Body)
	}
	if got := f.st.DirtyRules("alice", "02-evade"); len(got) != 0 {
		t.Fatalf("header-less reset-dirty must still clear the taint, still dirty: %v", got)
	}
}

// TestResetDirty_NonEvadeChallenge_Rejected proves the type guard: a dirty
// flag can only ever exist for an evade challenge (MarkDirtyOnRuleFire only
// writes ch.Type=="evade" pairs), so resetting a trigger challenge is
// rejected rather than silently no-op'd.
func TestResetDirty_NonEvadeChallenge_Rejected(t *testing.T) {
	f := newJourneyFixture(t)
	if w := f.req("POST", "/api/users/alice/challenges/01-recon/reset-dirty", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("reset-dirty on a non-evade challenge must 400, got %d body=%s", w.Code, w.Body)
	}
}

// TestResetDirty_UnknownChallenge_404 proves the pre-write catalog guard.
func TestResetDirty_UnknownChallenge_404(t *testing.T) {
	f := newJourneyFixture(t)
	if w := f.req("POST", "/api/users/alice/challenges/nope/reset-dirty", nil); w.Code != http.StatusNotFound {
		t.Fatalf("reset-dirty on an unknown challenge must 404, got %d body=%s", w.Code, w.Body)
	}
}

// NOTE: TestJourneyHTML_ServedAtJourney (asserted GET /journey served the
// legacy journey.html shell) was REMOVED in P19-2b — that route no longer
// exists (see internal/scoreboard/view/view.go's package doc). The
// equivalent HTML-serving coverage for the unified portal shell lives in
// internal/scoreboard/view/portal_test.go (TestRenderPortal_*).
