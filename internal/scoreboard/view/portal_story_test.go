package view

import (
	"strings"
	"testing"
)

// funcBody returns the source of `function <name>(` up to the next top-level
// `\n  function ` (the pane scripts indent their functions by two spaces).
// Source-level only: no test here executes the page's JS.
func funcBody(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "\n  function "+name+"(")
	if start < 0 {
		t.Fatalf("pane-story.tmpl: function %s not found", name)
	}
	rest := src[start+1:]
	if end := strings.Index(rest[1:], "\n  function "); end >= 0 {
		return rest[:end+1]
	}
	return rest
}

// ADR-0027 D6: a non-current evade is never evaluated, so the story pane must
// not tell the participant its attempt is clean or submittable. The clean
// copy has to sit behind evalPending() in both places that render it.
func TestPortalStory_NoCleanClaimForNonCurrentEvade(t *testing.T) {
	src := partialBody(portalPartials(t), "pane-story.tmpl")

	if !strings.Contains(funcBody(t, src, "evalPending"), "det.status !== 'current' && !det.dirty") {
		t.Error("evalPending must be (status !== 'current' && !dirty): dirty is shown whatever the status, clean only for current")
	}

	dirty := funcBody(t, src, "dirtySection")
	guard := strings.Index(dirty, "if (evalPending(det))")
	clean := strings.Index(dirty, "この attempt はクリーンです")
	if guard < 0 || clean < 0 || guard > clean {
		t.Error("dirtySection: the 'クリーンです / このまま提出できます' card must come after an evalPending(det) early return")
	}
	if !strings.Contains(dirty, "未評価") {
		t.Error("dirtySection: the non-current card must say 未評価")
	}

	auto := funcBody(t, src, "autoSolveStatus")
	if !strings.Contains(auto, "const pending = evalPending(det)") {
		t.Error("autoSolveStatus must derive `pending` from evalPending(det)")
	}
	if got := strings.Count(auto, "received && !pending"); got < 3 {
		t.Errorf("autoSolveStatus: cls/dot/text of the 'クリーンな attempt を確認' row must all be gated on `received && !pending` (found %d of 3)", got)
	}
}

// ADR-0027 D2/D5: `locked` is "not yet reached on the guided path", not
// "read-restricted". The label must not say PREVIEW, and the hint-open button
// must not branch on status (it has to stay reachable for a locked mission).
func TestPortalStory_LockedMissionHintsStayReachable(t *testing.T) {
	src := partialBody(portalPartials(t), "pane-story.tmpl")
	if strings.Contains(src, "PREVIEW") {
		t.Error("pane-story.tmpl: PREVIEW implies look-only; locked missions can open hints (ADR-0027 D5)")
	}
	start := strings.Index(src, "let lockedHTML = '';")
	end := strings.Index(src, "const hintsBlock")
	if start < 0 || end < start {
		t.Fatal("pane-story.tmpl: lockedHTML block not found")
	}
	if blk := src[start:end]; strings.Contains(blk, "status") {
		t.Error("the hint-open button must not depend on the mission status (ADR-0027 D1/D5)")
	}
}
