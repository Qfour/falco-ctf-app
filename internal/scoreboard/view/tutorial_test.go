package view

import (
	"strings"
	"testing"
)

// TestBuildTutorialPanelsHTML_ChaptersRenderAsDetails proves each
// TutorialFragment becomes its own <details class="home-panel"> with the
// fragment's Label in <summary> and its already-sanitized HTML inside
// .home-panel-body, verbatim (no re-escaping — already-trusted gen-time
// output, see tutorial.go's doc). Reuses the SAME markup
// buildHomePanelsHTML's writeDetailsPanel produces (design-engineer
// decision: no new CSS class for Tutorial).
func TestBuildTutorialPanelsHTML_ChaptersRenderAsDetails(t *testing.T) {
	frags := []TutorialFragment{
		{ID: "intro", Label: "Falco CTF とは", HTML: "<p>hello</p>"},
		{ID: "architecture", Label: "Falco のしくみ", HTML: "<p>world</p>"},
	}
	got := buildTutorialPanelsHTML(frags)
	if strings.Count(got, `class="home-panel"`) != 2 {
		t.Fatalf("expected 2 home-panel details, got: %s", got)
	}
	if !strings.Contains(got, "Falco CTF とは") || !strings.Contains(got, "Falco のしくみ") {
		t.Errorf("expected both labels present, got: %s", got)
	}
	if !strings.Contains(got, "<p>hello</p>") || !strings.Contains(got, "<p>world</p>") {
		t.Errorf("expected fragment HTML injected verbatim, got: %s", got)
	}
}

// TestBuildTutorialPanelsHTML_PreservesManifestOrder proves chapters render
// in the SAME order they appear in the input slice (curriculum order, per
// docs-site/tutorial-chapters.yaml — the Tutorial tab has no per-challenge
// sort/group step, unlike Home's rule-explain panels).
func TestBuildTutorialPanelsHTML_PreservesManifestOrder(t *testing.T) {
	frags := []TutorialFragment{
		{ID: "a", Label: "First", HTML: "<p>1</p>"},
		{ID: "b", Label: "Second", HTML: "<p>2</p>"},
		{ID: "c", Label: "Third", HTML: "<p>3</p>"},
	}
	got := buildTutorialPanelsHTML(frags)
	iFirst := strings.Index(got, "First")
	iSecond := strings.Index(got, "Second")
	iThird := strings.Index(got, "Third")
	if iFirst < 0 || iSecond < 0 || iThird < 0 {
		t.Fatalf("expected all three labels present, got: %s", got)
	}
	if !(iFirst < iSecond && iSecond < iThird) {
		t.Errorf("expected First < Second < Third ordering, got indices %d,%d,%d in: %s", iFirst, iSecond, iThird, got)
	}
}

// TestBuildTutorialPanelsHTML_EmptyInputProducesNoPanels proves the
// degenerate all-chapters-missing case (every source file absent) yields an
// empty (but valid, non-erroring) Tutorial panels block — matches
// buildHomePanelsHTML's own fail-soft convention.
func TestBuildTutorialPanelsHTML_EmptyInputProducesNoPanels(t *testing.T) {
	got := buildTutorialPanelsHTML(nil)
	if got != "" {
		t.Errorf("expected empty output for nil fragments, got: %q", got)
	}
}

// TestBuildTutorialPanelsHTML_LabelIsEscaped proves the <summary> label
// goes through template.HTMLEscapeString even though today's
// TutorialFragments.Label values are all generator-controlled constants —
// defense-in-depth so a future manifest/label change containing
// HTML-special characters cannot break out of the <summary> text context
// (mirrors TestBuildHomePanelsHTML_LabelIsEscaped in home_test.go, since
// both share the same writeDetailsPanel helper).
func TestBuildTutorialPanelsHTML_LabelIsEscaped(t *testing.T) {
	frags := []TutorialFragment{
		{ID: "x", Label: `<script>alert(1)</script>`, HTML: "<p>y</p>"},
	}
	got := buildTutorialPanelsHTML(frags)
	if strings.Contains(got, "<script>alert(1)</script>") {
		t.Fatalf("label must be escaped, got: %s", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("expected escaped label text, got: %s", got)
	}
}
