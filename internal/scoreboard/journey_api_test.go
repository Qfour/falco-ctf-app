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
		"01-recon": {ID: "01-recon", Type: "trigger", ExpectedRules: []string{"Recon Rule"}, WindowSeconds: 10},
		"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"Recon Rule"}, ExpectedFlag: "FALCO{ok}", WindowSeconds: 10},
		"03-late":  {ID: "03-late", Type: "trigger", ExpectedRules: []string{"Late Rule"}, WindowSeconds: 10},
	}
	journeys := catalog.Journeys{
		"01-recon": {
			ChallengeID: "01-recon", Title: "偵察", Tagline: "obj-1", Briefing: "brief-1",
			Steps:   []catalog.JourneyStep{{Label: "s0", Detail: "d0"}, {Label: "s1", Detail: "d1"}},
			Hints:   []string{"h1", "h2", "h3"},
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
	opts := append([]scoreboard.Option{
		scoreboard.WithJourneys(journeys),
		scoreboard.WithOrder([]string{"01-recon", "02-evade", "03-late"}),
	}, extra...)
	srv := scoreboard.NewHandler(cat, st, logger, opts...)
	return &journeyFixture{t: t, srv: srv, st: st}
}

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
		"01-boss": {ID: "01-boss", Type: "evade", ForbiddenRules: []string{"Reverse shell"}, ExpectedFlag: "FALCO{boss}", WindowSeconds: 30, RequireExfil: true},
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
	if det["windowSeconds"].(float64) != 30 {
		t.Fatalf("windowSeconds must be surfaced, got %v", det["windowSeconds"])
	}

	// Record a collector receipt (any value) → exfilReceived flips true.
	if err := st.RecordExfil("alice", "01-boss", "FALCO{whatever}", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	det = f.journey("alice")["detail"].(map[string]any)
	if det["exfilReceived"] != true {
		t.Fatalf("exfilReceived must be true after a receipt, got %v", det["exfilReceived"])
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

func TestJourneyHTML_ServedAtJourney(t *testing.T) {
	f := newJourneyFixture(t)
	w := f.req("GET", "/journey?user=alice", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("/journey status: %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("<title>Falco CTF · journey")) {
		t.Fatal("/journey html missing expected title")
	}
}
