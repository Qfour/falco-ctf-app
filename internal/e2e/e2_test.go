//go:build e2e

package e2e

import (
	"encoding/json"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/e2e/harness"
)

// The three sentences ADR-0027 V7 (D6) names: the "clean" verdict an evade
// shows only while it is the current mission. Product copy is the subject
// here, so it is asserted as text, inside #pane-journey-detail only (ADR-0031
// D3).
var cleanVerdict = []string{"クリーンです", "このまま提出できます", "クリーンな attempt を確認"}

// E2 (ADR-0027 V7 = D6; ADR-0031 V1): the current evade (05) shows the clean
// verdict, an evade that is not current (10) shows the neutral card instead
// (it has never been evaluated), and a forbidden-rule fire for 05 sent to
// ingest turns the screen to the dirty card with its reset button within two
// journey polls. Nothing in the scenario writes.
func TestE2E_E2_CleanVerdictOnlyOnTheCurrentEvadeAndDirtyWithinTwoPolls(t *testing.T) {
	const (
		current = "05-silent-search"
		other   = "10-final-exfil"
	)
	e := NewEnv(t, harness.SeedClean05)
	b, p := e.B, e.Proxy
	journey := harness.Matcher{Method: "GET", Path: "/api/users/user1/journey"}
	for _, id := range []string{current, other} {
		if e.Plan.Catalog[id].Type != "evade" {
			t.Fatalf("E2 needs %s to be an evade mission (it is %q)", id, e.Plan.Catalog[id].Type)
		}
	}
	forbidden := e.Plan.Catalog[current].ForbiddenRules
	if len(forbidden) == 0 {
		t.Fatalf("%s has no forbidden rule to fire", current)
	}
	resetButton := `!!document.querySelector('#pane-journey-detail #pane-journey-reset-dirty')`
	shown := func() []string {
		return Eval[[]string](b, `(function () { var t = `+detailText+`; return `+jsArray(cleanVerdict)+
			`.filter(function (s) { return t.includes(s); }); })()`)
	}

	// --- the current evade: the clean verdict ---
	b.Open("/portal#story")
	b.Wait("the current evade 05 with the clean verdict", missionIs(current)+
		` && (`+detailText+`).includes(`+jsString(cleanVerdict[0])+`) && (`+detailText+`).includes(`+jsString(cleanVerdict[1])+`) && !`+resetButton)

	// --- an evade that is not current: neutral, none of the three ---
	b.Click(`#pj-map li[data-mission="` + other + `"]`)
	// The sync point is the detection card in either form, so a broken D6
	// fails here on what it shows rather than on a deadline.
	b.Wait("the detection card of 10", missionIs(other)+` && (`+detailText+`).includes('検知状態')`)
	if got := shown(); len(got) != 0 {
		t.Errorf("mission %s is not current, yet its detail shows %q (ADR-0027 D6: a gate nobody evaluated must not read as passed)", other, got)
	}
	if !Eval[bool](b, `(`+detailText+`).includes('検知状態: 未評価')`) {
		t.Errorf("mission %s is not current, but its detection card is not the neutral one (検知状態: 未評価)", other)
	}

	// --- back to 05; a forbidden-rule fire goes to ingest ---
	b.Click(`#pane-journey-back-current`)
	b.Wait("the current evade 05 again, clean", missionIs(current)+` && (`+detailText+`).includes(`+jsString(cleanVerdict[0])+`)`)
	if err := e.Seeder.TaintCurrent(e.Ctx, e.User, current); err != nil {
		t.Fatal(err)
	}
	// The server is dirty from here on: every journey GET that starts after
	// this mark answers dirty (ADR-0031 H1 (b)(4): polls are counted as the
	// journey GETs that started after the change).
	mark := p.Mark()
	b.Wait("the dirty card with the fired rule and the reset button", missionIs(current)+` && `+resetButton+
		` && (`+detailText+`).includes('検知されています')`+
		` && Array.from(document.querySelectorAll('#pane-journey-detail .dirty-rule')).some(function (li) { return li.textContent.includes(`+jsString(forbidden[0])+`); })`)
	started := 0
	for _, en := range p.Since(mark) {
		if journey.Match(en) {
			started++
		}
	}
	if started > 2 {
		t.Errorf("the dirty card appeared only after %d journey polls that began after the fire, want at most 2\n%s", started, harness.FormatLog(p.Since(mark)))
	}
	if got := shown(); len(got) != 0 {
		t.Errorf("the dirty detail still shows the clean verdict %q", got)
	}

	b.AssertClean(0, nil)
}

// jsArray renders ss as a JavaScript array literal (JSON is a subset).
func jsArray(ss []string) string {
	b, err := json.Marshal(ss)
	if err != nil {
		panic(err) // a []string always marshals
	}
	return string(b)
}
