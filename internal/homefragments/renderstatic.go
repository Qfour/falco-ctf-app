package homefragments

import (
	"os"
	"path/filepath"
)

// RenderStaticPanel renders a StaticPanel's markdown source (given a
// repo-root-relative path resolved against root) into gen-time-sanitized
// HTML, following the exact pipeline order render.go's RenderMarkdown doc
// describes: a heading-selected panel (sp.Heading != "") is narrowed with
// SelectHeadingSection first; a whole_file panel (sp.Heading == "") has its
// leading "# title" line stripped via StripLeadingH1 first; both then go
// through RenderMarkdown.
//
// Extracted (REFACTORING.md P24 architect decision §1) from what was
// cmd/gen-home-fragments/main.go's private renderStaticPanel function, so
// cmd/gen-tutorial-fragments can share the SAME 140-line-class pipeline
// instead of a second copy that could bugfix-drift from this one —
// cmd/gen-home-fragments now calls this function too (see that command's
// updated renderStaticPanel wrapper).
//
// Fail-soft, matching both home-fragments.yaml and tutorial-chapters.yaml's
// contract: ok=false, err=nil means "omit this panel" (the source file does
// not exist, or a declared heading section is not found in it) — callers
// MUST treat that as "skip", never as an error. A non-nil err is gen-time
// FATAL: either a manifest authoring bug (ValidateHeadingMarker rejects a
// heading selector with no "#" prefix) or an actual markdown/HTML render
// failure — both are bugs in the pipeline or the manifest, not "content
// missing".
func RenderStaticPanel(root string, sp StaticPanel) (html string, ok bool, err error) {
	srcPath := filepath.Join(root, sp.Source)
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil // fail-soft: missing source file
		}
		return "", false, err
	}
	md := string(raw)
	if sp.Heading != "" {
		if verr := ValidateHeadingMarker(sp.Heading); verr != nil {
			return "", false, verr // manifest authoring bug: gen-time fatal
		}
		section, found := SelectHeadingSection(md, sp.Heading)
		if !found {
			return "", false, nil // fail-soft: heading not found
		}
		md = section
	} else {
		// whole_file panel: strip the source's leading "# title" line BEFORE
		// rendering (see StripLeadingH1's doc for why — avoids the h1 text
		// leaking into the fragment ahead of the first real <p>).
		md = StripLeadingH1(md)
	}
	rendered, rerr := RenderMarkdown(md)
	if rerr != nil {
		return "", false, rerr
	}
	return rendered, true, nil
}
