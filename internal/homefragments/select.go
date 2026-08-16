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
