package view

import (
	"strings"
	"testing"
)

// TestBuildHomePanelsHTML_StaticPanelsRenderAsDetails proves each static
// (non-rule-explain, non-"story") HomeFragment becomes its own
// <details class="home-panel"> with the fragment's Label in <summary> and
// its already-sanitized HTML inside .home-panel-body, verbatim (no
// re-escaping — it is already-trusted gen-time output, see home.go's doc).
// Uses "cheatsheet" rather than "story" for the second fragment because
// ID=="story" is special-cased OUT of this function as of P23
// portal-redesign — see TestBuildHomePanelsHTML_ExcludesStoryFragment below,
// which pins that behavior explicitly.
func TestBuildHomePanelsHTML_StaticPanelsRenderAsDetails(t *testing.T) {
	frags := []HomeFragment{
		{ID: "intro", Label: "Falco CTF とは", HTML: "<p>hello</p>"},
		{ID: "cheatsheet", Label: "コマンド集", HTML: "<p>world</p>"},
	}
	got := buildHomePanelsHTML(frags)
	if strings.Count(got, `class="home-panel"`) != 2 {
		t.Fatalf("expected 2 home-panel details, got: %s", got)
	}
	if !strings.Contains(got, "Falco CTF とは") || !strings.Contains(got, "コマンド集") {
		t.Errorf("expected both labels present, got: %s", got)
	}
	if !strings.Contains(got, "<p>hello</p>") || !strings.Contains(got, "<p>world</p>") {
		t.Errorf("expected fragment HTML injected verbatim, got: %s", got)
	}
}

// TestBuildHomePanelsHTML_ExcludesStoryFragment proves the P23
// portal-redesign special-case: a HomeFragment with ID=="story" is skipped
// entirely by buildHomePanelsHTML (it moved to the Story tab's own overview
// — see buildStoryPanelHTML below), while every other fragment still
// renders as usual. Not shown twice: the story content must not also
// appear as a Home <details> panel.
func TestBuildHomePanelsHTML_ExcludesStoryFragment(t *testing.T) {
	frags := []HomeFragment{
		{ID: "intro", Label: "Falco CTF とは", HTML: "<p>hello</p>"},
		{ID: "story", Label: "ストーリー", HTML: "<p>the story</p>"},
	}
	got := buildHomePanelsHTML(frags)
	if strings.Count(got, `class="home-panel"`) != 1 {
		t.Fatalf("expected exactly 1 home-panel (intro only, story excluded), got: %s", got)
	}
	if strings.Contains(got, "ストーリー") || strings.Contains(got, "<p>the story</p>") {
		t.Errorf("expected the story fragment NOT to appear in Home panels, got: %s", got)
	}
	if !strings.Contains(got, "Falco CTF とは") || !strings.Contains(got, "<p>hello</p>") {
		t.Errorf("expected the intro fragment to still render, got: %s", got)
	}
}

// TestBuildStoryPanelHTML_ReturnsStoryFragmentVerbatim proves the Story
// tab's overview builder pulls the "story" HomeFragment's HTML out
// verbatim (no <details>/<summary> wrapper, unlike buildHomePanelsHTML)
// and ignores every other fragment.
func TestBuildStoryPanelHTML_ReturnsStoryFragmentVerbatim(t *testing.T) {
	frags := []HomeFragment{
		{ID: "intro", Label: "Falco CTF とは", HTML: "<p>hello</p>"},
		{ID: "story", Label: "ストーリー", HTML: "<p>the story</p>"},
	}
	got := buildStoryPanelHTML(frags)
	if got != "<p>the story</p>" {
		t.Errorf("expected the story fragment's HTML verbatim, got: %q", got)
	}
}

// TestBuildStoryPanelHTML_FailSoftWhenMissing proves a deployment missing
// the "story" HomeFragment (e.g. docs-site/home-fragments.yaml's story.md
// source absent) degrades to "" rather than erroring — the Story tab's
// overview block then simply renders empty, matching homePanelsHTML's own
// fail-soft convention.
func TestBuildStoryPanelHTML_FailSoftWhenMissing(t *testing.T) {
	frags := []HomeFragment{
		{ID: "intro", Label: "Falco CTF とは", HTML: "<p>hello</p>"},
	}
	if got := buildStoryPanelHTML(frags); got != "" {
		t.Errorf("expected empty string when no story fragment present, got: %q", got)
	}
	if got := buildStoryPanelHTML(nil); got != "" {
		t.Errorf("expected empty string for nil fragments, got: %q", got)
	}
}

// TestBuildHomePanelsHTML_ExcludesRuleExplainFragments proves the per-challenge
// rule-explain HomeFragments (ChalNN != "") are NOT rendered on Home (CEO item
// ⑥, P23 UI polish): that "なぜ発火するか" content is surfaced per-mission in
// the Story tab's Falco Rule accordion (List/Macro/Rule) now, so Home must show
// only the top-level static panels (ChalNN=="") and none of the rule-explain
// markup or bodies. Mirrors the "story" exclusion.
func TestBuildHomePanelsHTML_ExcludesRuleExplainFragments(t *testing.T) {
	frags := []HomeFragment{
		{ID: "intro", Label: "Falco CTF とは", HTML: "<p>intro</p>"},
		{ID: "cheatsheet", Label: "チートシート", HTML: "<p>cheat</p>"},
		{ID: "rule_explain_01", Label: "🔍 なぜ発火するか", HTML: "<p>r1</p>", ChalNN: "01"},
		{ID: "rule_explain_03", Label: "🔍 なぜ発火するか", HTML: "<p>r3</p>", ChalNN: "03"},
	}
	got := buildHomePanelsHTML(frags)
	// Only the 2 static (ChalNN=="") panels render — rule-explain excluded.
	if strings.Count(got, `class="home-panel"`) != 2 {
		t.Fatalf("expected exactly 2 home-panel details (intro + cheatsheet, rule-explain excluded), got: %s", got)
	}
	if strings.Contains(got, "home-rule-explain") {
		t.Errorf("expected NO rule-explain markup on Home, got: %s", got)
	}
	if strings.Contains(got, "<p>r1</p>") || strings.Contains(got, "<p>r3</p>") || strings.Contains(got, "なぜ発火するか") {
		t.Errorf("expected rule-explain content excluded from Home, got: %s", got)
	}
	if !strings.Contains(got, "<p>intro</p>") || !strings.Contains(got, "<p>cheat</p>") {
		t.Errorf("expected static panels (intro, cheatsheet) present, got: %s", got)
	}
}

// TestBuildHomePanelsHTML_NoRuleExplainOmitsThatPanelEntirely proves that
// when NO challenge has a rule-explain.md (empty input, or an input with
// only static panels), no rule-explain <details> is emitted at all — not an
// empty box, not a placeholder. This is the fail-soft behavior
// home-fragments.yaml requires ("Per-challenge panel MUST be omitted...
// when the file is absent... this is normal steady-state, not an error").
func TestBuildHomePanelsHTML_NoRuleExplainOmitsThatPanelEntirely(t *testing.T) {
	frags := []HomeFragment{
		{ID: "intro", Label: "Falco CTF とは", HTML: "<p>intro</p>"},
	}
	got := buildHomePanelsHTML(frags)
	if strings.Contains(got, "home-rule-explain") {
		t.Errorf("expected no rule-explain panel/items when none of the input fragments have ChalNN set, got: %s", got)
	}
	if strings.Count(got, `class="home-panel"`) != 1 {
		t.Fatalf("expected exactly 1 home-panel (intro only), got: %s", got)
	}
}

// TestBuildHomePanelsHTML_EmptyInputProducesNoPanels proves the degenerate
// all-fragments-missing case (every source file absent, e.g. a docs-site
// path typo — should not happen, but must degrade rather than break) yields
// an empty (but valid, non-erroring) Home panels block.
func TestBuildHomePanelsHTML_EmptyInputProducesNoPanels(t *testing.T) {
	got := buildHomePanelsHTML(nil)
	if got != "" {
		t.Errorf("expected empty output for nil fragments, got: %q", got)
	}
}

// TestBuildHomePanelsHTML_LabelIsEscaped proves the <summary> label goes
// through template.HTMLEscapeString even though today's HomeFragments.Label
// values are all generator-controlled constants — defense-in-depth so a
// future manifest/label change containing HTML-special characters cannot
// break out of the <summary> text context.
func TestBuildHomePanelsHTML_LabelIsEscaped(t *testing.T) {
	frags := []HomeFragment{
		{ID: "x", Label: `<script>alert(1)</script>`, HTML: "<p>y</p>"},
	}
	got := buildHomePanelsHTML(frags)
	if strings.Contains(got, "<script>alert(1)</script>") {
		t.Fatalf("label must be escaped, got: %s", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("expected escaped label text, got: %s", got)
	}
}
