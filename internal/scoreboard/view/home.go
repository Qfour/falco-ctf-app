package view

import (
	"html/template"
	"strings"
)

// homePanelsHTML is computed ONCE at package init from HomeFragments (the
// gen-time-sanitized output of cmd/gen-home-fragments — see
// homefragments_gen.go's doc). It is the P23-5 exception to the esc()
// invariant documented in portal.go/templates/portal.html: this is the
// ONLY value the portal template ever injects as template.HTML (trusted,
// unescaped) rather than through esc() or html/template's default
// auto-escaping. That trust is earned entirely at GEN TIME by
// internal/homefragments' allowlist sanitizer, never at request time — this
// function does no sanitization itself, does not touch anything
// request-derived, and every other dynamic value in the portal (role,
// username, ttyd URL, and everything the client-side JS renders from API
// responses) keeps going through esc()/template.JS exactly as before.
//
// P23 portal-redesign: storyPanelHTML (below) is now a SECOND template.HTML
// injection site sharing this EXACT SAME gen-time-sanitization guarantee —
// both are built once, from the same committed HomeFragments, never from
// anything request-derived. See storyPanelHTML's own doc for why splitting
// the "story" fragment OUT of this value and into that one is safe under
// the same invariant, not a new one.
var homePanelsHTML = template.HTML(buildHomePanelsHTML(HomeFragments))

// storyPanelHTML (P23 portal-redesign) is the Story tab's overview content —
// the SAME "story" HomeFragment previously folded into the Home tab's
// generic panel list, now surfaced directly at the top of the Story pane
// instead (see templates/portal.html's #pane-story .story-overview block
// and portal.go's StoryPanelHTML field doc for the full security note).
// Computed ONCE at package init, exactly like homePanelsHTML, from the same
// gen-time-sanitized, committed HomeFragments — never anything
// request-derived, never per-viewer.
var storyPanelHTML = template.HTML(buildStoryPanelHTML(HomeFragments))

// buildHomePanelsHTML renders each HomeFragment as a <details> disclosure
// panel. Fail-soft (home-fragments.yaml): a challenge with no
// rule-explain.md simply has no HomeFragments entry (see
// cmd/gen-home-fragments), so there is nothing to skip HERE — this function
// only ever sees panels that already exist. It performs NO synthesis of
// filler content for absent panels, matching the manifest's explicit "do
// not synthesize generic filler text" instruction.
//
// P23 portal-redesign: the "story" fragment (ID=="story") is EXCLUDED here —
// it moved to the Story tab's own lead-in (see buildStoryPanelHTML /
// storyPanelHTML above) so it is not shown twice. This is the one ID this
// function special-cases; every other fragment (intro, cheatsheet,
// rule-explain, and anything future) still flows through unchanged.
//
// Grouping: rule-explain panels (ChalNN != "") are rendered inside a single
// "🔍 なぜ発火するか" panel, one <details> per challenge number, so the Home
// tab shows one top-level entry for the whole rule-explain set rather than
// up to 11 top-level entries that would dwarf the remaining static panels.
//
// INVARIANT (merge-review fixup R4): this grouping assumes every rule-explain
// HomeFragment shares the SAME Label — cmd/gen-home-fragments' generator
// always sets every one of them to the single
// internal/homefragments.RuleExplainLabel constant (see manifest.go), so
// there is currently only ever one distinct label among them. This function
// takes the LAST rule-explain fragment's Label for the combined panel's
// <summary> (see ruleExplainLabel below) rather than the first / a
// deduplicated set, on the assumption that reading any one of them is
// equivalent to reading all of them. If a future generator change ever made
// rule-explain Labels vary per challenge, this function would silently show
// only the last one and swallow the others — see
// TestBuildHomePanelsHTML_RuleExplainLabelInvariant in home_test.go, which
// pins this exact behavior so a change that breaks the single-label
// assumption fails loudly instead of silently mis-rendering.
func buildHomePanelsHTML(fragments []HomeFragment) string {
	var b strings.Builder
	var ruleExplain []HomeFragment
	// ruleExplainLabel is every rule-explain HomeFragment's shared Label
	// (set by cmd/gen-home-fragments from internal/homefragments.RuleExplainLabel
	// — this package intentionally does not import internal/homefragments,
	// per homefragments_gen.go's doc: only the generator does, so goldmark +
	// the sanitizer stay out of this binary's dependency graph). Read off
	// the LAST rule-explain fragment seen rather than hardcoding the string
	// a second time — see the single-label INVARIANT note above this
	// function for what "the last one" relies on.
	var ruleExplainLabel string
	for _, f := range fragments {
		if f.ID == "story" {
			// P23 portal-redesign: moved to the Story tab's own overview
			// (buildStoryPanelHTML) — do not also render it as a Home panel.
			continue
		}
		if f.ChalNN != "" {
			ruleExplain = append(ruleExplain, f)
			ruleExplainLabel = f.Label
			continue
		}
		writeDetailsPanel(&b, f.Label, f.HTML)
	}
	if len(ruleExplain) > 0 {
		var inner strings.Builder
		for _, f := range ruleExplain {
			// f.ChalNN is generator-produced from challengeDirRe (`\d\d`,
			// see cmd/gen-home-fragments), never request-derived — escaped
			// here anyway as defense-in-depth, matching the label escaping
			// below, rather than relying solely on the generator's regex.
			inner.WriteString(`<div class="home-rule-explain-item">`)
			inner.WriteString(`<h4 class="home-rule-explain-chal">Mission ` + template.HTMLEscapeString(f.ChalNN) + `</h4>`)
			inner.WriteString(f.HTML)
			inner.WriteString(`</div>`)
		}
		writeDetailsPanel(&b, ruleExplainLabel, inner.String())
	}
	return b.String()
}

// buildStoryPanelHTML returns the "story" HomeFragment's already
// gen-time-sanitized HTML verbatim (no <details>/<summary> wrapper — the
// Story tab renders it as an always-visible overview at the top of the
// pane, not a collapsed disclosure like the Home tab's panels), or ""
// if no fragment has ID=="story".
//
// Fail-soft (matches homePanelsHTML's degrade behavior): a deployment
// missing docs-site's story.md source (see docs-site/home-fragments.yaml)
// simply has no "story" HomeFragment entry, and this function returns "" —
// the Story tab's overview block then renders empty rather than erroring,
// so a future content change that drops the story fragment cannot break
// the Story tab's game UI (mission map / briefing / steps / hints, all
// independent of this value).
func buildStoryPanelHTML(fragments []HomeFragment) string {
	for _, f := range fragments {
		if f.ID == "story" {
			return f.HTML
		}
	}
	return ""
}

func writeDetailsPanel(b *strings.Builder, label, innerHTML string) {
	b.WriteString(`<details class="home-panel"><summary>`)
	b.WriteString(template.HTMLEscapeString(label))
	// rich-content (P23 portal-redesign): shared markdown typography class
	// also used by the Story tab's overview block — see
	// templates/portal.html's ".rich-content" rule doc.
	b.WriteString(`</summary><div class="home-panel-body rich-content">`)
	b.WriteString(innerHTML)
	b.WriteString(`</div></details>`)
}
