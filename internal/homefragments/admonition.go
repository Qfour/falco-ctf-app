// Package homefragments implements the gen-time markdown-to-sanitized-HTML
// pipeline for the unified portal's Home tab (P23-5). See
// docs-site/home-fragments.yaml for the content contract (content-lead
// owned) this package implements against: which source .md files/sections
// become fragments, the sanitize allowlist, and the fail-soft rules.
//
// This package is a GEN-TIME tool only (invoked by cmd/gen-home-fragments,
// wired to `make gen-home-fragments`). The scoreboard binary that serves
// GET /portal never imports it and never runs markdown parsing or HTML
// sanitization at request time — it only go:embeds the already-sanitized
// HTML the generator produced (internal/scoreboard/view/homefragments_gen.go,
// committed like internal/*/oapi/types.gen.go). This keeps goldmark and the
// sanitizer out of the served binary's runtime dependency graph entirely.
package homefragments

import "strings"

// flattenAdmonitions rewrites MkDocs Material `!!! type "title"` blocks
// (used in docs-site/docs/index.md, story.md, cheatsheet.md) into plain
// markdown BEFORE the generic markdown-to-HTML pass, per
// home-fragments.yaml's admonition_handling note: goldmark has no built-in
// admonition extension, and a naive line-based stripper must not let the
// four-space-indented body silently merge into the prior paragraph.
//
// Every `!!! type "title"` block observed in the current source content
// (docs-site/docs/{index,story,cheatsheet}.md, checked 2026-08-16) has a
// SINGLE-paragraph, four-space-indented body with no nested lists/blank
// lines. This function only needs to handle that shape faithfully; it does
// not attempt to reproduce MkDocs' full admonition grammar (nested content,
// multiple paragraphs, collapsible ??? admonitions) since none of that
// appears in the manifest's sources. A future source that uses a shape this
// function does not handle will render as a paragraph of raw `!!! ...` text
// rather than panic — fail-soft, not fail-loud, matching the manifest's
// posture elsewhere.
//
// Output shape: the title becomes its own bold paragraph (**title**), and
// the dedented body lines become a following paragraph, exactly like
// home-fragments.yaml's admonition_handling describes as the fallback
// flattening ("pre-flatten `!!! x "title"` blocks to a plain `**title**` +
// indented-paragraph shape"). This intentionally drops the admonition TYPE
// (tip/note/warning) — the sanitize allowlist has no attributes to carry a
// type marker, and home-fragments.yaml's allowlist maps admonitions to
// <blockquote> with the title as a leading <strong> (see sanitize.go),
// which does not distinguish tip/note/warning either.
func flattenAdmonitions(src string) string {
	lines := strings.Split(src, "\n")
	var out []string
	i := 0
	for i < len(lines) {
		line := lines[i]
		title, ok := parseAdmonitionHeader(line)
		if !ok {
			out = append(out, line)
			i++
			continue
		}
		i++
		var body []string
		for i < len(lines) {
			l := lines[i]
			if strings.TrimSpace(l) == "" {
				// A single blank line inside the indented block is part of
				// the admonition body's own paragraph break in MkDocs syntax,
				// but since every real body here is single-paragraph, treat
				// a blank line as the end of the block (fail-soft: stop
				// consuming rather than guess at multi-paragraph nesting).
				break
			}
			if !strings.HasPrefix(l, "    ") {
				break
			}
			body = append(body, strings.TrimPrefix(l, "    "))
			i++
		}
		// Emit as a blockquote-shaped markdown region: a bold title line,
		// then the body, both prefixed with "> " so the generic markdown
		// pass turns the whole thing into a single <blockquote> (matching
		// the manifest's "title as a leading <strong>" note) instead of a
		// top-level paragraph indistinguishable from body prose.
		out = append(out, "> **"+title+"**")
		out = append(out, ">")
		for _, b := range body {
			out = append(out, "> "+b)
		}
		out = append(out, "")
	}
	return strings.Join(out, "\n")
}

// parseAdmonitionHeader matches a `!!! type "title"` line (any of
// tip/note/warning — home-fragments.yaml's admonition_handling list; an
// unrecognized type is still flattened the same way rather than skipped,
// since the allowlist collapses all types to the same <blockquote> shape
// anyway) and returns its title. ok=false for any non-matching line,
// including a bare `!!! type` with no title (not present in current
// sources; fail-soft leaves such a line untouched rather than guessing).
func parseAdmonitionHeader(line string) (title string, ok bool) {
	const prefix = "!!! "
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	// rest is now `type "title"` — find the type token, then the quoted title.
	sp := strings.IndexByte(rest, ' ')
	if sp < 0 {
		return "", false
	}
	quoted := strings.TrimSpace(rest[sp+1:])
	if len(quoted) < 2 || quoted[0] != '"' || quoted[len(quoted)-1] != '"' {
		return "", false
	}
	return quoted[1 : len(quoted)-1], true
}
