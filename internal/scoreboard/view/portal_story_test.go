package view

import (
	"strings"
	"testing"
)

// funcBody returns the source of `function <name>(` up to the next top-level
// `\n  function ` (the pane scripts indent their functions by two spaces).
// Source-level only: no test here executes the page's JS (scripts/
// check-portal-render.sh does, on macOS, as an optional target).
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

// braceBlock returns the `{ ... }` block that opens at the first `{` at or
// after from (string/template literals are not parsed: the blocks checked
// here contain none of `{`/`}` outside a `${...}` pair, which balances).
func braceBlock(t *testing.T, s string, from int) string {
	t.Helper()
	open := strings.Index(s[from:], "{")
	if open < 0 {
		t.Fatal("no { found")
	}
	open += from
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[open : i+1]
			}
		}
	}
	t.Fatal("unbalanced braces")
	return ""
}

// cleanClaims are the strings that tell a participant the attempt is clean /
// will be judged clean. ADR-0027 D6: they may not reach a non-current evade.
// Each is pinned to the number of places it is written, and every place must
// be inside a function that consults evalPending() (the structural gate), so
// a rewrite of the condition into an equivalent form stays green while a new
// ungated copy of the claim, or a claim moved out of the gate, goes red.
// The rendered behaviour is checked by scripts/check-portal-render.sh.
var cleanClaims = map[string]int{
	"この attempt はクリーンです": 1,
	"このまま提出できます":         1,
	"クリーンな attempt を確認":  1,
	"禁止ルールが一度も発火していなければ自動的にクリアされます": 1,
}

func TestPortalStory_NoCleanClaimForNonCurrentEvade(t *testing.T) {
	src := partialBody(portalPartials(t), "pane-story.tmpl")

	// The exact condition is checked by behaviour (scripts/check-portal-render.sh),
	// so an equivalent rewrite stays green here; this only pins its inputs.
	if ep := funcBody(t, src, "evalPending"); !strings.Contains(ep, "det.status") || !strings.Contains(ep, "'current'") || !strings.Contains(ep, "det.dirty") {
		t.Error("evalPending must depend on det.status (vs 'current') and det.dirty")
	}

	gated := funcBody(t, src, "dirtySection") + funcBody(t, src, "autoSolveStatus")
	for _, fn := range []string{"dirtySection", "autoSolveStatus"} {
		if !strings.Contains(funcBody(t, src, fn), "evalPending(det)") {
			t.Errorf("%s must consult evalPending(det)", fn)
		}
	}
	for claim, want := range cleanClaims {
		if got := strings.Count(src, claim); got != want {
			t.Errorf("%q appears %d times in pane-story.tmpl, want %d (a new copy must be gated by evalPending and added to cleanClaims)", claim, got, want)
		}
		if got := strings.Count(gated, claim); got != want {
			t.Errorf("%q: %d of %d copies are outside dirtySection/autoSolveStatus (the evalPending-gated functions)", claim, want-got, want)
		}
	}

	// dirtySection: the early-return card for the pending state carries none of
	// the claims and says 未評価 / クリア済み.
	dirty := funcBody(t, src, "dirtySection")
	at := strings.Index(dirty, "if (evalPending(det))")
	if at < 0 {
		t.Fatal("dirtySection: the early return `if (evalPending(det))` is missing")
	}
	early := braceBlock(t, dirty, at)
	for claim := range cleanClaims {
		if strings.Contains(early, claim) {
			t.Errorf("dirtySection: the evalPending card must not contain %q", claim)
		}
	}
	if !strings.Contains(early, "未評価") || !strings.Contains(early, "return") {
		t.Error("dirtySection: the evalPending branch must return a card that says 未評価")
	}

	// autoSolveStatus: every claim sits on the false side of `pending`.
	auto := funcBody(t, src, "autoSolveStatus")
	if !strings.Contains(auto, "const pending = evalPending(det)") {
		t.Error("autoSolveStatus must derive `pending` from evalPending(det)")
	}
	if got := strings.Count(auto, "!pending"); got < 3 {
		t.Errorf("autoSolveStatus: the 'クリーンな attempt を確認' row (cls/dot/text) must be gated on !pending (found %d of 3)", got)
	}
	if !strings.Contains(auto, "${pending\n          ? 'この課題はまだ進行位置ではありません。'") {
		t.Error("autoSolveStatus: the footer hint must switch on `pending` before the 自動的にクリアされます copy")
	}
}

// ADR-0027 D2/D5: `locked` is "not yet reached on the guided path", not
// "read-restricted". The label must not say PREVIEW, and neither the hint-open
// button nor the whole hints block may branch on status.
func TestPortalStory_LockedMissionHintsStayReachable(t *testing.T) {
	src := partialBody(portalPartials(t), "pane-story.tmpl")
	if strings.Contains(src, "PREVIEW") {
		t.Error("pane-story.tmpl: PREVIEW implies look-only; locked missions can open hints (ADR-0027 D5)")
	}
	start := strings.Index(src, "let lockedHTML = '';")
	def := strings.Index(src, "const hintsBlock =")
	if start < 0 || def < start {
		t.Fatal("pane-story.tmpl: lockedHTML / hintsBlock definitions not found")
	}
	end := strings.Index(src[def:], "\n\n")
	if end < 0 {
		t.Fatal("pane-story.tmpl: end of the hintsBlock definition not found")
	}
	if blk := src[start : def+end]; strings.Contains(blk, "status") {
		t.Error("the hint-open button / hints block must not depend on the mission status (ADR-0027 D1/D5)")
	}
	// The render site must be the bare `${hintsBlock}` on its own line.
	if got := strings.Count(src, "hintsBlock"); got != 2 {
		t.Errorf("hintsBlock is referenced %d times, want 2 (definition + one render site)", got)
	}
	bare := false
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "hintsBlock") && strings.TrimSpace(line) == "${hintsBlock}" {
			bare = true
		}
	}
	if !bare {
		t.Error("the hints block must be rendered unconditionally as a bare ${hintsBlock} (no status branch around it)")
	}
}
