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

// TestStripLeadingH1 proves the leading "# title" line (and any blank line
// right after it) is removed, while the rest of the document — including a
// LATER "# " line, which must never happen in practice but must not be
// mistaken for the leading title either — is untouched. This is the
// merge-review fixup (R2 F1): whole_file panels (story.md, cheatsheet.md)
// must not carry their source h1 as bare leaked text ahead of the first
// real element.
func TestStripLeadingH1(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "leading h1 with blank line removed",
			src:  "# ストーリー：CTF Company のキルチェーン\n\nbody line 1\nbody line 2\n",
			want: "body line 1\nbody line 2\n",
		},
		{
			name: "leading h1 with no blank line removed",
			src:  "# Title\nbody\n",
			want: "body\n",
		},
		{
			name: "no leading h1 -> unchanged (fail-soft)",
			src:  "## Section\n\nbody\n",
			want: "## Section\n\nbody\n",
		},
		{
			name: "empty input -> unchanged",
			src:  "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := StripLeadingH1(tc.src)
			if got != tc.want {
				t.Errorf("StripLeadingH1(%q) = %q, want %q", tc.src, got, tc.want)
			}
		})
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
