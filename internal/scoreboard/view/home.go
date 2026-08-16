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
// storyPanelHTML above) so it is not shown twice.
//
// P23 UI polish (CEO item ⑥): the per-challenge rule-explain panels
// (ChalNN != "", "🔍 なぜ発火するか") are ALSO excluded here — that content is
// surfaced per-mission in the Story tab's Falco Rule accordion
// (List/Macro/Rule) instead, so showing it again on Home is redundant. Home
// now renders only the top-level static panels (intro, cheatsheet, and any
// future ChalNN=="" fragment). Both exclusions are display-side; the source
// fragments still exist in docs-site (their removal from home-fragments.yaml
// is a content follow-up).
func buildHomePanelsHTML(fragments []HomeFragment) string {
	var b strings.Builder
	for _, f := range fragments {
		if f.ID == "story" {
			// P23 portal-redesign: moved to the Story tab's own overview
			// (buildStoryPanelHTML) — do not also render it as a Home panel.
			continue
		}
		if f.ChalNN != "" {
			// P23 UI polish (CEO item ⑥): the per-challenge rule-explain
			// ("なぜ発火するか") fragments are surfaced per-mission in the
			// Story tab's Falco Rule accordion (List/Macro/Rule) now — do NOT
			// also render them on Home. Display-side exclusion (mirrors the
			// "story" skip above); the source fragments remain in docs-site,
			// their removal from home-fragments.yaml is a content follow-up.
			continue
		}
		writeDetailsPanel(&b, f.Label, f.HTML)
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
