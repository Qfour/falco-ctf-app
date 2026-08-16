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
// responses) keeps going through esc()/template.JS exactly as before. If a
// future edit adds a SECOND template.HTML injection site anywhere in this
// package, that is a new exception requiring the same gen-time-sanitization
// guarantee — this doc comment does not grandfather it in.
var homePanelsHTML = template.HTML(buildHomePanelsHTML(HomeFragments))

// buildHomePanelsHTML renders each HomeFragment as a <details> disclosure
// panel. Fail-soft (home-fragments.yaml): a challenge with no
// rule-explain.md simply has no HomeFragments entry (see
// cmd/gen-home-fragments), so there is nothing to skip HERE — this function
// only ever sees panels that already exist. It performs NO synthesis of
// filler content for absent panels, matching the manifest's explicit "do
// not synthesize generic filler text" instruction.
//
// Grouping: rule-explain panels (ChalNN != "") are rendered inside a single
// "🔍 なぜ発火するか" panel, one <details> per challenge number, so the Home
// tab shows one top-level entry for the whole rule-explain set rather than
// up to 11 top-level entries that would dwarf the three static panels.
func buildHomePanelsHTML(fragments []HomeFragment) string {
	var b strings.Builder
	var ruleExplain []HomeFragment
	// ruleExplainLabel is every rule-explain HomeFragment's shared Label
	// (set by cmd/gen-home-fragments from internal/homefragments.RuleExplainLabel
	// — this package intentionally does not import internal/homefragments,
	// per homefragments_gen.go's doc: only the generator does, so goldmark +
	// the sanitizer stay out of this binary's dependency graph). Read off
	// the first rule-explain fragment rather than hardcoding the string a
	// second time.
	var ruleExplainLabel string
	for _, f := range fragments {
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

func writeDetailsPanel(b *strings.Builder, label, innerHTML string) {
	b.WriteString(`<details class="home-panel"><summary>`)
	b.WriteString(template.HTMLEscapeString(label))
	b.WriteString(`</summary><div class="home-panel-body">`)
	b.WriteString(innerHTML)
	b.WriteString(`</div></details>`)
}
