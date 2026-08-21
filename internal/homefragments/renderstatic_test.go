package homefragments

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderStaticPanel exercises RenderStaticPanel's fail-soft branches
// (missing source file, missing heading section) and its gen-time-fatal
// branch (ValidateHeadingMarker rejecting a malformed heading selector)
// directly, with synthetic markdown fixtures under t.TempDir() — instead of
// only indirectly through manifest_verified_test.go's real-source-only
// callers (TestManifestVerifiedClean_TutorialChapters et al.), which never
// exercise the fail-soft paths because every real TutorialChapters/
// StaticPanels source and heading is expected to exist in this repo.
//
// app#157 (P24 /review-5x R4 finding on PR #153): RenderStaticPanel was
// exported so both cmd/gen-home-fragments and cmd/gen-tutorial-fragments
// share it, widening the blast radius of any regression in these branches
// without a corresponding direct test. Two happy-path cases (whole_file,
// heading-selected) are included alongside the fail-soft/fatal cases so the
// table documents RenderStaticPanel's full branch set in one place.
func TestRenderStaticPanel(t *testing.T) {
	dir := t.TempDir()

	wholeFilePath := filepath.Join(dir, "whole.md")
	if err := os.WriteFile(wholeFilePath, []byte("# Title\n\nBody text.\n"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	headedFilePath := filepath.Join(dir, "headed.md")
	headedContent := "# Doc Title\n\n## Section One\n\nSection one body.\n\n## Section Two\n\nSection two body.\n"
	if err := os.WriteFile(headedFilePath, []byte(headedContent), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	tests := []struct {
		name       string
		sp         StaticPanel
		wantOK     bool
		wantErr    bool
		wantInHTML string // non-empty: substring that must appear in html when wantOK
	}{
		{
			name: "whole_file success",
			sp: StaticPanel{
				ID:     "whole",
				Source: "whole.md",
			},
			wantOK:     true,
			wantInHTML: "Body text.",
		},
		{
			name: "heading-selected success",
			sp: StaticPanel{
				ID:      "headed",
				Source:  "headed.md",
				Heading: "## Section One",
			},
			wantOK:     true,
			wantInHTML: "Section one body.",
		},
		{
			name: "missing source file is fail-soft (ok=false, err=nil)",
			sp: StaticPanel{
				ID:     "missing-file",
				Source: "does-not-exist.md",
			},
			wantOK:  false,
			wantErr: false,
		},
		{
			name: "missing heading section is fail-soft (ok=false, err=nil)",
			sp: StaticPanel{
				ID:      "missing-heading",
				Source:  "headed.md",
				Heading: "## Section Nowhere",
			},
			wantOK:  false,
			wantErr: false,
		},
		{
			name: "malformed heading selector is gen-time-fatal (ValidateHeadingMarker error)",
			sp: StaticPanel{
				ID:      "bad-heading",
				Source:  "headed.md",
				Heading: "Section One", // missing leading "#"
			},
			wantOK:  false,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			html, ok, err := RenderStaticPanel(dir, tc.sp)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("RenderStaticPanel(%s) = ok=%v, err=nil; want a non-nil error", tc.sp.ID, ok)
				}
			} else if err != nil {
				t.Fatalf("RenderStaticPanel(%s): unexpected error: %v", tc.sp.ID, err)
			}

			if ok != tc.wantOK {
				t.Fatalf("RenderStaticPanel(%s) ok = %v, want %v (html=%q, err=%v)", tc.sp.ID, ok, tc.wantOK, html, err)
			}

			if tc.wantOK && !strings.Contains(html, tc.wantInHTML) {
				t.Errorf("RenderStaticPanel(%s) html = %q, want substring %q", tc.sp.ID, html, tc.wantInHTML)
			}

			if !tc.wantOK && html != "" {
				t.Errorf("RenderStaticPanel(%s) returned ok=false but non-empty html %q", tc.sp.ID, html)
			}
		})
	}
}
