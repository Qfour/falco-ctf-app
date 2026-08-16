package homefragments

import (
	"fmt"
	"strings"
)

// SelectHeadingSection extracts one `## heading` markdown section (the
// heading line up to, but not including, the next `## ` line at the SAME
// level, or end of file) from src. heading must include the leading `## `
// exactly as it appears in the source (e.g. "## Falco とは" — see
// home-fragments.yaml's `intro` panel: `select: { heading: "## Falco とは" }`).
//
// Returns ok=false (fail-soft, per the manifest's fail_soft note for the
// `intro` panel: "omit panel entirely if file or heading missing") if the
// heading line is not found — the caller must treat that as "omit this
// panel", never as an error.
//
// Only matches at the SAME heading level as the marker itself (a "## X"
// search does not stop early at a nested "### Y" subheading — it stops at
// the next "## " or end of file), so a heading section that itself contains
// subsections stays intact as one panel.
func SelectHeadingSection(src, heading string) (section string, ok bool) {
	level := strings.IndexFunc(heading, func(r rune) bool { return r != '#' })
	if level <= 0 {
		return "", false
	}
	marker := heading[:level] // e.g. "##"
	lines := strings.Split(src, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == strings.TrimSpace(heading) {
			start = i
			break
		}
	}
	if start < 0 {
		return "", false
	}
	end := len(lines)
	for j := start + 1; j < len(lines); j++ {
		if strings.HasPrefix(lines[j], marker+" ") {
			end = j
			break
		}
	}
	section = strings.TrimRight(strings.Join(lines[start:end], "\n"), "\n") + "\n"
	return section, true
}

// StripLeadingH1 removes a leading `# title` markdown heading (and any
// blank line immediately following it) from src, for use on `whole_file:
// true` panel sources (story.md, cheatsheet.md — see home-fragments.yaml)
// BEFORE they reach RenderMarkdown.
//
// Why this exists (merge-review fixup, R2 F1): home-fragments.yaml's
// elements comment says "never render source h1 — H1 is the docs-site page
// title, redundant with the panel label the portal chrome already shows".
// sanitize.go's allowlist already drops the <h1> WRAPPER, but by design
// (see sanitize.go's "disallowed, not forbidden -> drop wrapper, keep
// children" rule, needed so an anchor's label text survives a dropped <a>)
// it re-parents the h1's TEXT as loose content instead of discarding it —
// so the title text leaked into the fragment as a bare, unstyled line ahead
// of the first real <p>, duplicating the <summary> label the Home panel
// already shows. Removing the h1 line at the markdown-source stage (same
// tier as flattenAdmonitions — a source-shape normalization before
// markdown parsing, not a change to the sanitizer's structural rules)
// means goldmark never emits an <h1> node for this text at all, so there is
// no text for the generic drop-wrapper rule to rescue.
//
// Only whole_file panels need this: the `intro` panel never sees this
// problem because SelectHeadingSection extracts ONLY the "## Falco とは"
// section, which never includes index.md's leading "# はじめに" h1 in the
// first place; rule-explain.md sources have no h1 at all (they open with
// "### ..."). Fail-soft: if src does not start with a `# ` line (unexpected
// shape), src is returned unchanged rather than erroring — a whole_file
// source without a leading h1 is not a real error, it just needs no
// stripping.
func StripLeadingH1(src string) string {
	lines := strings.Split(src, "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "# ") {
		return src
	}
	rest := lines[1:]
	for len(rest) > 0 && strings.TrimSpace(rest[0]) == "" {
		rest = rest[1:]
	}
	return strings.Join(rest, "\n")
}

// ValidateHeadingMarker is a small guard used by the generator to fail
// loudly (at gen time, not silently at runtime) if home-fragments.yaml ever
// specifies a heading selector with no "#" prefix at all — that would be a
// manifest authoring bug (content-lead's contract file), not a normal
// fail-soft "missing panel" case, so cmd/gen-home-fragments treats this
// error as gen-time-fatal rather than "omit the panel".
func ValidateHeadingMarker(heading string) error {
	if !strings.HasPrefix(heading, "#") {
		return fmt.Errorf("heading selector %q does not start with '#'", heading)
	}
	return nil
}
