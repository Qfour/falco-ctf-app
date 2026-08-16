package homefragments

import "testing"

func TestSelectHeadingSection(t *testing.T) {
	src := "# Title\n\n" +
		"## 表示名について\n\nA\n\n" +
		"## Falco とは\n\nB1\nB2\n\n" +
		"## 推奨スキルレベルと前提知識\n\nC\n"

	got, ok := SelectHeadingSection(src, "## Falco とは")
	if !ok {
		t.Fatalf("expected ok=true")
	}
	want := "## Falco とは\n\nB1\nB2\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestSelectHeadingSection_LastSection(t *testing.T) {
	src := "## A\n\nfoo\n\n## B\n\nbar\n"
	got, ok := SelectHeadingSection(src, "## B")
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if got != "## B\n\nbar\n" {
		t.Errorf("got %q", got)
	}
}

// TestSelectHeadingSection_MissingHeadingFailsSoft proves a missing heading
// returns ok=false rather than an error/panic — the caller (cmd/gen-home-fragments)
// must treat this as "omit the panel", per home-fragments.yaml's fail_soft
// note on the `intro` panel.
func TestSelectHeadingSection_MissingHeadingFailsSoft(t *testing.T) {
	src := "## Something Else\n\nbody\n"
	_, ok := SelectHeadingSection(src, "## Falco とは")
	if ok {
		t.Fatalf("expected ok=false for a missing heading")
	}
}

// TestSelectHeadingSection_DoesNotStopAtNestedSubheading proves a "## X"
// search does not stop early at a "### Y" subheading nested inside the same
// section — only the next SAME-level "## " (or EOF) ends the section.
func TestSelectHeadingSection_DoesNotStopAtNestedSubheading(t *testing.T) {
	src := "## Falco とは\n\nintro\n\n### nested\n\nmore\n\n## Next\n\nX\n"
	got, ok := SelectHeadingSection(src, "## Falco とは")
	if !ok {
		t.Fatalf("expected ok=true")
	}
	want := "## Falco とは\n\nintro\n\n### nested\n\nmore\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestValidateHeadingMarker(t *testing.T) {
	if err := ValidateHeadingMarker("## Falco とは"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := ValidateHeadingMarker("Falco とは"); err == nil {
		t.Errorf("expected an error for a selector with no '#' prefix")
	}
}
