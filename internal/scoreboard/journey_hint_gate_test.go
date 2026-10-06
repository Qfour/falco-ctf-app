package scoreboard_test

// ADR-0027 (P28-0b): the journey READ projection of hints and step ticks is a
// function of the store alone — it does not depend on `status`
// (solved | current | locked). This file holds:
//
//   - V3: the behaviours the decision deliberately does NOT change (the write
//     side: in-order 409, authz, 404s, solved missions keeping their opened
//     hints). They must be green both before and after the P28-0b change.
//   - V2: the same projection against the REAL catalog + the real
//     nimbusbreach-full order, in the shape the 2h edition actually runs
//     (01,02,03,04 solved, 05 and 07 skipped, hands-on at 06 and 08).
//
// The V1 inversions of the two older FreeBrowsing tests live next to their
// siblings in journey_api_test.go.

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// newRealOrderFixture builds a handler over the REAL challenges/ tree and the
// REAL nimbusbreach-full scenario (the same catalog.LoadScored +
// catalog.LoadJourneys path cmd/scoreboard takes), not newJourneyFixture's
// 3-mission synthetic catalog. It reuses journeyFixture so req/reqAs/journey
// behave identically.
func newRealOrderFixture(t *testing.T) (*journeyFixture, []string) {
	t.Helper()
	scored, err := catalog.LoadScored("../../challenges", "../../scenarios/nimbusbreach-full/scenario.yaml", "")
	if err != nil {
		t.Fatalf("LoadScored: %v", err)
	}
	if len(scored.Order) == 0 {
		t.Fatal("real scenario order is empty — extraction is broken, not \"nothing to check\"")
	}
	journeys, err := catalog.LoadJourneys("../../challenges", scored.Catalog)
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "real.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := scoreboard.NewHandler(scored.Catalog, st, logger,
		scoreboard.WithJourneys(journeys),
		scoreboard.WithOrder(scored.Order),
		scoreboard.WithAllowedOrigins([]string{journeyFixtureOrigin}),
	)
	return &journeyFixture{t: t, srv: srv, st: st}, scored.Order
}

// hintsOf returns the `detail.hints` object of a journey response.
func hintsOf(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	det, ok := m["detail"].(map[string]any)
	if !ok {
		t.Fatalf("journey response has no detail object: %v", m["detail"])
	}
	return det["hints"].(map[string]any)
}

// TestJourney_LockedMission_OutOfOrderRevealIs409 pins the write side's
// in-order rule on a locked mission: hint 2 before hint 1 is 409 and records
// nothing; hint 1 is accepted (the write side has never consulted status —
// ADR-0027 D3 leaves it that way).
func TestJourney_LockedMission_OutOfOrderRevealIs409(t *testing.T) {
	f := newJourneyFixture(t)
	if s := statusOf(f.journey("alice"), "02-evade"); s != "locked" {
		t.Fatalf("precondition: 02-evade should be locked, got %q", s)
	}
	w := f.req("POST", "/api/users/alice/challenges/02-evade/hints/2", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("hint 2 before hint 1 on a locked mission must 409, got %d body=%s", w.Code, w.Body)
	}
	if got := f.st.HintViews("alice")["02-evade"]; len(got) != 0 {
		t.Fatalf("a 409 must record nothing, store has %v", got)
	}
	if w := f.req("POST", "/api/users/alice/challenges/02-evade/hints/1", nil); w.Code != http.StatusOK {
		t.Fatalf("hint 1 on a locked mission must stay 200 (write side unchanged), got %d body=%s", w.Code, w.Body)
	}
}

// TestJourneyWriteGate_OpenHint_LockedMission_CrossUserIs403AndRecordsNothing
// pins that the self-or-admin write gate runs before anything else on a
// locked mission: a third party gets 403 (no 409/200 oracle) and, crucially,
// nothing is written to hint_views.
func TestJourneyWriteGate_OpenHint_LockedMission_CrossUserIs403AndRecordsNothing(t *testing.T) {
	f := newJourneyFixture(t)
	if s := statusOf(f.journey("alice"), "02-evade"); s != "locked" {
		t.Fatalf("precondition: 02-evade should be locked, got %q", s)
	}
	for _, idx := range []string{"1", "2"} {
		w := f.reqAs("POST", "/api/users/alice/challenges/02-evade/hints/"+idx, "mallory@ctf.local", nil)
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-user hint %s on a locked mission must 403, got %d body=%s", idx, w.Code, w.Body)
		}
	}
	// Prefix-adjacent identity (I8): alice2 must not satisfy alice either.
	if w := f.reqAs("POST", "/api/users/alice/challenges/02-evade/hints/1", "alice2@ctf.local", nil); w.Code != http.StatusForbidden {
		t.Fatalf("alice2 opening alice's hint must 403, got %d body=%s", w.Code, w.Body)
	}
	if got := f.st.HintViews("alice")["02-evade"]; len(got) != 0 {
		t.Fatalf("a refused write must leave hint_views empty, store has %v", got)
	}
	if got := f.st.HintViews("mallory")["02-evade"]; len(got) != 0 {
		t.Fatalf("the refused caller must not get a row either, store has %v", got)
	}
}

// TestJourney_SolvedMission_KeepsOpenedHints pins that a solved mission keeps
// showing the hints that were opened while it was current (and keeps counting
// the unopened ones as unopened).
func TestJourney_SolvedMission_KeepsOpenedHints(t *testing.T) {
	f := newJourneyFixture(t)
	for _, idx := range []string{"1", "2"} {
		if w := f.req("POST", "/api/users/alice/challenges/01-recon/hints/"+idx, nil); w.Code != http.StatusOK {
			t.Fatalf("hint %s: %d body=%s", idx, w.Code, w.Body)
		}
	}
	if _, err := f.st.MarkSolved("alice", "01-recon", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	m := f.journeyAt("alice", "01-recon")
	if s := statusOf(m, "01-recon"); s != "solved" {
		t.Fatalf("precondition: 01-recon should be solved, got %q", s)
	}
	hints := hintsOf(t, m)
	opened := hints["opened"].([]any)
	if len(opened) != 2 || opened[0].(map[string]any)["text"] != "h1" || opened[1].(map[string]any)["text"] != "h2" {
		t.Fatalf("a solved mission must keep its opened hints, got %v", opened)
	}
	if hints["lockedCount"].(float64) != 1 || hints["nextIndex"].(float64) != 3 {
		t.Fatalf("hint meta wrong for a solved mission: %v", hints)
	}
}

// TestJourney_OpenHint_UnknownChallengeIs404 pins that a challenge id outside
// the catalog is 404 on the write side, and records nothing.
func TestJourney_OpenHint_UnknownChallengeIs404(t *testing.T) {
	f := newJourneyFixture(t)
	w := f.req("POST", "/api/users/alice/challenges/99-does-not-exist/hints/1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown challenge hint open must 404, got %d body=%s", w.Code, w.Body)
	}
	if got := f.st.HintViews("alice")["99-does-not-exist"]; len(got) != 0 {
		t.Fatalf("a 404 must record nothing, store has %v", got)
	}
}

// TestJourney_OutOfScenarioMission_FallsBackAndRevealIs404 uses the REAL
// catalog: 11-cloud-cred-hunt exists under challenges/ but is not part of
// nimbusbreach-full, so the scored catalog does not hold it. The read side
// falls back to `current` (never to the out-of-scenario mission), and the
// write side is 404 and records nothing.
func TestJourney_OutOfScenarioMission_FallsBackAndRevealIs404(t *testing.T) {
	f, order := newRealOrderFixture(t)
	const outside = "11-cloud-cred-hunt"
	for _, id := range order {
		if id == outside {
			t.Fatalf("precondition: %s must be outside nimbusbreach-full, but it is in the order %v", outside, order)
		}
	}
	m := f.journeyAt("alice", outside)
	det := m["detail"].(map[string]any)
	if det["id"] != order[0] || m["current"] != order[0] {
		t.Fatalf("an out-of-scenario ?mission= must fall back to current (%s), got detail.id=%v current=%v", order[0], det["id"], m["current"])
	}
	w := f.req("POST", "/api/users/alice/challenges/"+outside+"/hints/1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("hint open on an out-of-scenario mission must 404, got %d body=%s", w.Code, w.Body)
	}
	if got := f.st.HintViews("alice")[outside]; len(got) != 0 {
		t.Fatalf("a 404 must record nothing, store has %v", got)
	}
}

// TestJourney_RealOrder_SkippedMissionHints is ADR-0027 V2: the 2h edition's
// real shape. 01-04 are solved, so current = 05-silent-search; the hands-on
// missions 06 and 08 are `locked` by status (D2: the enum is unchanged) but
// their hints must be openable and visible, priced 10 / 30 / 50 (D1).
func TestJourney_RealOrder_SkippedMissionHints(t *testing.T) {
	f, order := newRealOrderFixture(t)
	for _, cid := range []string{"01-initial-recon", "02-credential-files", "03-stealth-read", "04-key-search"} {
		if _, err := f.st.MarkSolved("alice", cid, "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if m := f.journey("alice"); m["current"] != "05-silent-search" {
		t.Fatalf("precondition: current must be 05-silent-search (order %v), got %v", order, m["current"])
	}

	for _, cid := range []string{"06-web-rce-shell", "08-c2-beacon"} {
		cid := cid
		t.Run(cid, func(t *testing.T) {
			before := f.journeyAt("alice", cid)
			if s := statusOf(before, cid); s != "locked" {
				t.Fatalf("D2: status must stay locked, got %q", s)
			}
			h := hintsOf(t, before)
			total := h["total"].(float64)
			if total < 2 {
				t.Fatalf("%s should have at least 2 authored hints for this test, got %v", cid, total)
			}
			if h["lockedCount"].(float64) != total || len(h["opened"].([]any)) != 0 ||
				h["nextIndex"].(float64) != 1 || h["penalty"].(float64) != 10 {
				t.Fatalf("before opening: want lockedCount==total, opened==[], nextIndex==1, penalty==10; got %v", h)
			}

			w := f.req("POST", "/api/users/alice/challenges/"+cid+"/hints/1", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("hint 1 open: %d body=%s", w.Code, w.Body)
			}
			var opened1 map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &opened1)
			text1, _ := opened1["hint"].(string)
			if text1 == "" {
				t.Fatalf("hint 1 response carries no text: %v", opened1)
			}

			after := f.journeyAt("alice", cid)
			if s := statusOf(after, cid); s != "locked" {
				t.Fatalf("D2: status must stay locked after opening, got %q", s)
			}
			h = hintsOf(t, after)
			op := h["opened"].([]any)
			if len(op) != 1 || op[0].(map[string]any)["text"] != text1 {
				t.Fatalf("after opening: opened must carry hint 1's text, got %v", op)
			}
			if h["nextIndex"].(float64) != 2 || h["penalty"].(float64) != 30 || h["lockedCount"].(float64) != total-1 {
				t.Fatalf("after opening: want nextIndex==2, penalty==30, lockedCount==total-1; got %v", h)
			}
		})
	}
}

// TestJourney_LockedMissionHintReveal_ScoreUnchanged is ADR-0027 V4's
// "same solved + hint_views, same Score" pin, in the exact state qa measured
// on 2026-10-04: 01-04 solved (400), a reveal of hint 1 on the LOCKED 06
// (HINT1 = -10) is 390 — before and after this change, because scoring is not
// touched. Both the journey and /me reads agree. (What the projection shows
// for the opened hint is V2's business; this test is arithmetic only.)
func TestJourney_LockedMissionHintReveal_ScoreUnchanged(t *testing.T) {
	f, _ := newRealOrderFixture(t)
	for _, cid := range []string{"01-initial-recon", "02-credential-files", "03-stealth-read", "04-key-search"} {
		if _, err := f.st.MarkSolved("alice", cid, "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if s := statusOf(f.journey("alice"), "06-web-rce-shell"); s != "locked" {
		t.Fatalf("precondition: 06-web-rce-shell should be locked, got %q", s)
	}
	if got := f.journey("alice")["score"].(float64); got != 400 {
		t.Fatalf("precondition: score with 4 solves must be 400, got %v", got)
	}
	if w := f.req("POST", "/api/users/alice/challenges/06-web-rce-shell/hints/1", nil); w.Code != http.StatusOK {
		t.Fatalf("hint 1: %d body=%s", w.Code, w.Body)
	}
	m := f.journeyAt("alice", "06-web-rce-shell")
	if m["score"].(float64) != 390 {
		t.Fatalf("score after a reveal on a locked mission must be 400-10 = 390, got %v", m["score"])
	}
	me := f.reqAs("GET", "/api/users/alice/me", "alice@ctf.local", nil)
	var mm map[string]any
	if err := json.Unmarshal(me.Body.Bytes(), &mm); err != nil || mm["score"].(float64) != 390 {
		t.Fatalf("/me score must agree (390): err=%v body=%s", err, me.Body)
	}
}
