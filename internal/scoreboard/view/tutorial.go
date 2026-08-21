package view

import (
	"html/template"
	"strings"
)

// tutorialPanelsHTML is computed ONCE at package init from TutorialFragments
// (the gen-time-sanitized output of cmd/gen-tutorial-fragments — see
// tutorialfragments_gen.go's doc). It shares the EXACT SAME trust boundary
// homePanelsHTML/storyPanelHTML already carry (see home.go's homePanelsHTML
// doc): built once from committed, gen-time-sanitized content, never from
// anything request-derived, identical for every caller (admin and
// participant alike, no per-user variation) — the third portalData field
// injected as template.HTML rather than through esc()/html/template's
// default auto-escaping.
var tutorialPanelsHTML = template.HTML(buildTutorialPanelsHTML(TutorialFragments))

// buildTutorialPanelsHTML renders each TutorialFragment as a <details>
// disclosure panel, reusing the SAME .home-panel/.home-panel-body markup
// buildHomePanelsHTML's writeDetailsPanel already produces (design-engineer
// decision, REFACTORING.md P24: "既存 #pane-home-panels/.home-panel の既存
// CSS クラスを再利用し新規 CSS ブロックは最小限" — no new CSS tokens for the
// Tutorial pane). Unlike buildHomePanelsHTML, there is no ChalNN-based
// exclusion here: every TutorialFragment is static, non-per-challenge
// content (REFACTORING.md P24 architect decision §1), so every fragment
// that exists renders, in manifest (curriculum) order.
//
// Fail-soft (tutorial-chapters.yaml): a chapter with a missing source file
// or heading section simply has no TutorialFragments entry (see
// cmd/gen-tutorial-fragments), so there is nothing to skip HERE — this
// function only ever sees chapters that already exist. It performs NO
// synthesis of filler content for absent chapters.
func buildTutorialPanelsHTML(fragments []TutorialFragment) string {
	var b strings.Builder
	for _, f := range fragments {
		writeDetailsPanel(&b, f.Label, f.HTML)
	}
	return b.String()
}
