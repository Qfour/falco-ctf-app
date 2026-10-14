//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/e2e/harness"
)

// E1 (ADR-0027 V6; ADR-0031 V1): a mission ahead of the current one stays
// locked, yet its hints can be opened, and the cost is shown before the click
// and named in the dialog.
//
// 01-04 are solved, so 05 is current. The scenario opens 06 from the map,
// checks that the hint-1 button shows the server's penalty, cancels the
// dialog (no write, nothing opened), then accepts it: exactly one POST
// .../06-web-rce-shell/hints/1, the hint's text (read from the catalog, never
// copied here) appears, and the button moves on to hint 2 with its penalty.
func TestE2E_E1_LockedMissionHintOpensWithItsCostShownFirst(t *testing.T) {
	const (
		current  = "05-silent-search"
		target   = "06-web-rce-shell"
		hintPath = "/api/users/user1/challenges/06-web-rce-shell/hints/1"
	)
	e := NewEnv(t, harness.SeedClean05)
	b, p := e.B, e.Proxy
	journey := harness.Matcher{Method: "GET", Path: "/api/users/user1/journey"}

	jy, ok := e.Plan.Journeys[target]
	if !ok || len(jy.Hints) < 2 {
		t.Fatalf("%s needs at least two hints in its journey.yaml for E1 (has %d)", target, len(jy.Hints))
	}
	hint1 := jy.Hints[0].Text

	// Before: what the server says, over HTTP.
	before := e.Detail(target)
	hb, _ := before["hints"].(map[string]any)
	opened, _ := hb["opened"].([]any)
	pen, _ := hb["penalty"].(float64)
	if before["status"] != "locked" || len(opened) != 0 || hb["nextIndex"] != float64(1) || pen <= 0 {
		t.Fatalf("seed: %s should be locked with no hint opened, next 1 and a positive penalty; status=%v hints=%v", target, before["status"], hb)
	}
	penalty := int(pen)

	b.Open("/portal#story")
	b.Wait("the current mission 05", missionIs(current))
	b.Click(`#pj-map li[data-mission="` + target + `"]`)
	button := `document.getElementById('pane-journey-open-hint')`
	b.Wait("the locked detail of 06 with the hint-1 button and its cost", missionIs(target)+` && !!`+button+
		` && `+button+`.dataset.cid === `+jsString(target)+
		` && `+button+`.dataset.next === '1'`+
		` && `+button+`.dataset.penalty === `+jsString(fmt.Sprint(penalty))+
		` && `+button+`.textContent.includes(`+jsString(fmt.Sprintf("-%d点", penalty))+`)`)

	// --- cancel: nothing is written, nothing is opened ---
	cancelMark := p.Mark()
	dlg := b.ExpectDialog(false)
	b.Click(`#pane-journey-open-hint`)
	d := b.AwaitDialog(dlg, "hint 1 (cancel)")
	if d.Type != "confirm" || !strings.Contains(d.Message, "ヒント 1") || !strings.Contains(d.Message, fmt.Sprintf("%d 点", penalty)) {
		t.Errorf("the hint dialog is %s %q; it must be a confirm naming hint 1 and its %d-point cost", d.Type, d.Message, penalty)
	}
	b.WaitProxy("two journey polls after the cancelled dialog", func(log []harness.Entry) bool {
		return harness.CountDoneAfter(log, cancelMark, journey) >= 2
	})
	if w := p.Writes(cancelMark); len(w) != 0 {
		t.Errorf("cancelling the hint dialog still wrote: %q", w)
	}
	hc, _ := e.Detail(target)["hints"].(map[string]any)
	if o, _ := hc["opened"].([]any); len(o) != 0 {
		t.Errorf("cancelling the hint dialog opened a hint: %v", hc)
	}

	// --- accept: one POST, the text, the next hint's cost ---
	confirmMark := p.Mark()
	dlg = b.ExpectDialog(true)
	b.Click(`#pane-journey-open-hint`)
	b.AwaitDialog(dlg, "hint 1 (accept)")
	b.WaitProxy("the hint POST to finish", func(log []harness.Entry) bool {
		return harness.CountDoneAfter(log, confirmMark, harness.Matcher{Method: "POST", Path: hintPath}) >= 1
	})
	after := e.Detail(target)
	ha, _ := after["hints"].(map[string]any)
	openedAfter, _ := ha["opened"].([]any)
	nextPen, _ := ha["penalty"].(float64)
	if after["status"] != "locked" || len(openedAfter) != 1 || ha["nextIndex"] != float64(2) {
		t.Fatalf("after the accepted reveal, %s should still be locked with hint 1 opened and next 2; status=%v hints=%v", target, after["status"], ha)
	}
	b.Wait("hint 1's text and the hint-2 button with its cost",
		`Array.from(document.querySelectorAll('#pane-journey-detail .hint-open .ht')).some(function (el) { return el.textContent === `+jsString(hint1)+`; })`+
			` && !!`+button+` && `+button+`.dataset.next === '2'`+
			` && `+button+`.dataset.penalty === `+jsString(fmt.Sprint(int(nextPen))))
	postMark := p.Mark()
	b.WaitProxy("a journey poll after the reveal", func(log []harness.Entry) bool {
		return harness.SettledAfter(log, postMark, 1, journey)
	})
	if w := p.Writes(confirmMark); len(w) != 1 || w[0] != "POST "+hintPath {
		t.Errorf("accepting the hint dialog wrote %q, want exactly one POST %s", w, hintPath)
	}
	if n := len(b.Dialogs()); n != 2 {
		t.Errorf("the scenario opened %d dialogs, want exactly the two it expected", n)
	}
	b.AssertClean(0, []string{"POST " + hintPath})
}
