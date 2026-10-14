//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/e2e/harness"
)

// E3 (ADR-0032 ⑩ and the reset of a dirty mission): looking at the portal never
// writes, and the one write the portal can make on a dirty mission is asked for
// first and made once.
//
// 05-silent-search is dirty (a forbidden rule fired for the user's current
// mission). The scenario then
//
//  1. browses: polling for longer than the slowest poll (board, 5 s), three map
//     nodes, "back to current", the current node, every tab, a reload — and the
//     proxy must have seen no write at all (a double POST from a listener that
//     piles up on each re-render, or a call from render(), would show);
//  2. presses "やり直す" and cancels the dialog: still no write, still dirty;
//  3. presses it again and accepts: exactly one POST .../reset-dirty, then clean.
//
// The seed goes in over HTTP (POST /falco/events, POST .../submit) straight to
// the child, so it is not in the proxy's log.
func TestE2E_E3_DirtyMissionBrowseWritesNothingAndResetAsksFirst(t *testing.T) {
	const (
		current   = "05-silent-search"
		resetPath = "/api/users/user1/challenges/05-silent-search/reset-dirty"
	)
	e := NewEnv(t, harness.SeedDirty05)
	b, p := e.B, e.Proxy
	journey := harness.Matcher{Method: "GET", Path: "/api/users/user1/journey"}
	board := harness.Matcher{Method: "GET", Path: "/api/board/threads"}
	resetButton := `!!document.querySelector('#pane-journey-detail #pane-journey-reset-dirty')`

	// Before: what the server says, over HTTP.
	before := e.Detail("")
	if before["id"] != current || before["dirty"] != true {
		t.Fatalf("the seed did not leave %s dirty: id=%v dirty=%v", current, before["id"], before["dirty"])
	}
	hintsBefore, _ := before["hints"].(map[string]any)
	openedBefore, _ := hintsBefore["opened"].([]any)

	// --- 1. browse ---
	b.Open("/portal#story")
	b.Wait("the dirty mission 05 with its reset button", missionIs(current)+` && `+resetButton)
	browseMark := p.Mark()

	// Three map nodes, each a free-browse of another mission (a different
	// detail, so wireDetail runs again), then back.
	for _, id := range []string{"06-web-rce-shell", "07-persist", "04-key-search"} {
		b.Click(`#pj-map li[data-mission="` + id + `"]`)
		b.Wait("the detail of "+id, missionIs(id))
	}
	b.Click(`#pane-journey-back-current`)
	b.Wait("the dirty mission 05 again, repainted", missionIs(current)+` && `+resetButton)
	// Clicking the current mission's own node returns to auto-follow.
	m := p.Mark()
	b.Click(`.kc-node[data-mission="` + current + `"]`)
	b.WaitProxy("a journey poll that began after the click", func(log []harness.Entry) bool {
		return harness.SettledAfter(log, m, 1, journey)
	})
	// Every tab, and back.
	for _, tab := range []string{"me", "board", "terminal", "tutorial", "home", "story"} {
		b.Click(`#portal-tabs .tab[data-tab="` + tab + `"]`)
		b.Wait("the "+tab+" tab", `document.getElementById('pane-`+tab+`').classList.contains('active')`)
	}
	b.Reload()
	b.Wait("the dirty mission 05 after a reload", missionIs(current)+` && `+resetButton)

	// A quiet window at least as long as the slowest poll: from here on, two
	// board polls (5 s apart) and three journey polls must complete. Stacked
	// listeners or a timer that writes would have fired by then.
	quiet := p.Mark()
	b.WaitProxy("two board polls and three journey polls with no interaction", func(log []harness.Entry) bool {
		return harness.CountDoneAfter(log, quiet, board) >= 2 && harness.CountDoneAfter(log, quiet, journey) >= 3
	})
	if w := p.Writes(browseMark); len(w) != 0 {
		t.Errorf("browsing the portal wrote: %q", w)
	}
	afterBrowse := e.Detail("")
	hintsAfter, _ := afterBrowse["hints"].(map[string]any)
	openedAfter, _ := hintsAfter["opened"].([]any)
	if afterBrowse["dirty"] != true || len(openedAfter) != len(openedBefore) {
		t.Errorf("browsing changed the server state: dirty %v -> %v, opened hints %d -> %d",
			before["dirty"], afterBrowse["dirty"], len(openedBefore), len(openedAfter))
	}

	// --- 2. press the reset button, cancel the dialog ---
	cancelMark := p.Mark()
	dlg := b.ExpectDialog(false)
	b.Click(`#pane-journey-reset-dirty`)
	d := b.AwaitDialog(dlg, "reset (cancel)")
	// The dialog names what disappears: the detection history.
	if d.Type != "confirm" || !strings.Contains(d.Message, "検知履歴") {
		t.Errorf("the reset dialog is %s %q; it must be a confirm that names the detection history it deletes", d.Type, d.Message)
	}
	b.WaitProxy("two journey polls after the cancelled dialog", func(log []harness.Entry) bool {
		return harness.CountDoneAfter(log, cancelMark, journey) >= 2
	})
	if w := p.Writes(cancelMark); len(w) != 0 {
		t.Errorf("cancelling the reset dialog still wrote: %q", w)
	}
	b.Wait("the reset button still there", resetButton)
	if e.Detail("")["dirty"] != true {
		t.Error("cancelling the reset dialog cleared the dirty flag")
	}

	// --- 3. press it again, accept ---
	confirmMark := p.Mark()
	dlg = b.ExpectDialog(true)
	b.Click(`#pane-journey-reset-dirty`)
	b.AwaitDialog(dlg, "reset (accept)")
	b.WaitProxy("the reset POST to finish", func(log []harness.Entry) bool {
		return harness.CountDoneAfter(log, confirmMark, harness.Matcher{Method: "POST", Path: resetPath}) >= 1
	})
	b.Wait("the clean state after the reset", `!document.querySelector('#pane-journey-reset-dirty') && document.getElementById('pane-journey-detail').textContent.includes('クリーン')`)
	postMark := p.Mark()
	b.WaitProxy("a journey poll after the reset", func(log []harness.Entry) bool {
		return harness.SettledAfter(log, postMark, 1, journey)
	})
	if w := p.Writes(confirmMark); len(w) != 1 || w[0] != "POST "+resetPath {
		t.Errorf("accepting the reset dialog wrote %q, want exactly one POST %s", w, resetPath)
	}
	if e.Detail("")["dirty"] != false {
		t.Error("accepting the reset did not clear the dirty flag on the server")
	}
	if n := len(b.Dialogs()); n != 2 {
		t.Errorf("the scenario opened %d dialogs, want exactly the two it expected", n)
	}

	// --- the shared checks, over the whole scenario ---
	b.AssertClean(0, []string{"POST " + resetPath})
}
