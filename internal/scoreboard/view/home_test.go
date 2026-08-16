package view

import (
	"strings"
	"testing"
)

// TestBuildHomePanelsHTML_StaticPanelsRenderAsDetails proves each static
// (non-rule-explain) HomeFragment becomes its own <details class="home-panel">
// with the fragment's Label in <summary> and its already-sanitized HTML
// inside .home-panel-body, verbatim (no re-escaping — it is already-trusted
// gen-time output, see home.go's doc).
func TestBuildHomePanelsHTML_StaticPanelsRenderAsDetails(t *testing.T) {
	frags := []HomeFragment{
		{ID: "intro", Label: "Falco CTF とは", HTML: "<p>hello</p>"},
		{ID: "story", Label: "ストーリー", HTML: "<p>world</p>"},
	}
	got := buildHomePanelsHTML(frags)
	if strings.Count(got, `class="home-panel"`) != 2 {
		t.Fatalf("expected 2 home-panel details, got: %s", got)
	}
	if !strings.Contains(got, "Falco CTF とは") || !strings.Contains(got, "ストーリー") {
		t.Errorf("expected both labels present, got: %s", got)
	}
	if !strings.Contains(got, "<p>hello</p>") || !strings.Contains(got, "<p>world</p>") {
		t.Errorf("expected fragment HTML injected verbatim, got: %s", got)
	}
}

// TestBuildHomePanelsHTML_RuleExplainGroupedIntoOnePanel proves multiple
// per-challenge rule-explain HomeFragments (ChalNN != "") collapse into a
// SINGLE top-level <details> panel with one .home-rule-explain-item per
// challenge, rather than one top-level panel per challenge (which would
// dwarf the 3 static panels — see home.go's doc).
func TestBuildHomePanelsHTML_RuleExplainGroupedIntoOnePanel(t *testing.T) {
	frags := []HomeFragment{
		{ID: "intro", Label: "Falco CTF とは", HTML: "<p>intro</p>"},
		{ID: "rule_explain_01", Label: "🔍 なぜ発火するか", HTML: "<p>r1</p>", ChalNN: "01"},
		{ID: "rule_explain_03", Label: "🔍 なぜ発火するか", HTML: "<p>r3</p>", ChalNN: "03"},
	}
	got := buildHomePanelsHTML(frags)
	if strings.Count(got, `class="home-panel"`) != 2 { // intro + one combined rule-explain panel
		t.Fatalf("expected 2 top-level home-panel details (intro + combined rule-explain), got: %s", got)
	}
	if strings.Count(got, `class="home-rule-explain-item"`) != 2 {
		t.Fatalf("expected 2 home-rule-explain-item entries, got: %s", got)
	}
	if !strings.Contains(got, "Mission 01") || !strings.Contains(got, "Mission 03") {
		t.Errorf("expected both challenge numbers labeled, got: %s", got)
	}
	if !strings.Contains(got, "<p>r1</p>") || !strings.Contains(got, "<p>r3</p>") {
		t.Errorf("expected both rule-explain HTML bodies present, got: %s", got)
	}
}

// TestBuildHomePanelsHTML_RuleExplainLabelInvariant pins the documented
// single-label INVARIANT on home.go's buildHomePanelsHTML (merge-review
// fixup R4): the combined rule-explain panel's <summary> uses whichever
// rule-explain fragment's Label was seen LAST, on the assumption that every
// rule-explain fragment shares the same Label (true today — the generator
// always sets internal/homefragments.RuleExplainLabel uniformly). This test
// deliberately feeds DIFFERING labels to make that behavior visible and
// pinned: if a future change to buildHomePanelsHTML's grouping logic
// altered which label wins (first vs last vs some merge), this test fails
// and forces an explicit decision instead of a silent behavior change.
func TestBuildHomePanelsHTML_RuleExplainLabelInvariant(t *testing.T) {
	frags := []HomeFragment{
		{ID: "rule_explain_01", Label: "LABEL-A", HTML: "<p>r1</p>", ChalNN: "01"},
		{ID: "rule_explain_03", Label: "LABEL-B", HTML: "<p>r3</p>", ChalNN: "03"},
	}
	got := buildHomePanelsHTML(frags)
	if !strings.Contains(got, "<summary>LABEL-B</summary>") {
		t.Fatalf("expected the combined panel's <summary> to be the LAST rule-explain fragment's label (LABEL-B), got: %s", got)
	}
	if strings.Contains(got, "<summary>LABEL-A</summary>") {
		t.Fatalf("did not expect a separate <summary>LABEL-A</summary> — only one combined panel should exist, got: %s", got)
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
