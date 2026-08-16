package homefragments

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// flagRe matches any FALCO{...} literal, mirroring
// scripts/check-flags.sh's `FALCO\{[^}]*\}` pattern (the public-repo
// flag-hygiene gate) so this test enforces the exact same "which flag
// shapes are allowed" rule the CI-level flag guard already enforces on
// tracked source files, applied here to RENDERED fragment output instead.
var flagRe = regexp.MustCompile(`FALCO\{[^}]*\}`)

// repoRoot resolves the repository root from this test's package directory
// (internal/homefragments -> ../.. -> repo root). `go test` always runs
// with the package directory as cwd, and Dockerfile.test COPYs the whole
// repo preserving this layout, so a relative path is reliable in both the
// local (`go test ./...`) and containerized (`make test`) invocation paths
// — matching how cmd/gen-home-fragments itself takes a repo-root argument
// rather than assuming a fixed absolute path.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skipf("could not locate repo root at %s (go.mod not found) — skipping real-source verification: %v", root, err)
	}
	return root
}

// forbiddenLeaks is every string that must NEVER appear in a Home fragment
// rendered from the real docs-site/challenges sources, per
// docs-site/home-fragments.yaml's non-negotiables ("Home is PARTICIPANT-
// FACING and NON-HINT... or any flag/answer text") and its rule-explain
// panel's `verified_clean` note ("no 試すこと/クリア条件/環境にあるもの
// leakage, no FALCO{...} flags"). This is the manifest's verified_clean
// claim turned into an executable CI check (merge-review fixup R2 F2) —
// previously this was only verified by hand (see the P23-5 task report) and
// would silently go stale as content-lead edits story.md/cheatsheet.md/
// rule-explain.md over time.
//
// "FALCO{" alone would false-positive on the cheatsheet's own
// FALCO{...}-placeholder examples (explicitly sanctioned by the manifest:
// "Contains only generic commands + a FALCO{...} placeholder... not a real
// flag"), so this checks for a REAL flag shape instead: FALCO{ followed by
// something other than the literal placeholder ellipsis or "dev-" prefix.
var forbiddenLiteralSubstrings = []string{
	"試すこと",
	"クリア条件",
	"環境にあるもの",
}

// assertNoForbiddenLeaks fails t if html contains any forbidden literal
// substring, or a FALCO{...} occurrence that is not the sanctioned
// "FALCO{...}" ellipsis placeholder / "FALCO{dev-" local-dev placeholder
// shape (mirrors scripts/check-flags.sh's allowed-forms list).
func assertNoForbiddenLeaks(t *testing.T, panelID, html string) {
	t.Helper()
	for _, bad := range forbiddenLiteralSubstrings {
		if strings.Contains(html, bad) {
			t.Errorf("panel %q: forbidden substring %q leaked into rendered HTML:\n%s", panelID, bad, html)
		}
	}
	for _, m := range flagRe.FindAllString(html, -1) {
		if m != "FALCO{...}" && !strings.HasPrefix(m, "FALCO{dev-") {
			t.Errorf("panel %q: non-placeholder flag-shaped literal %q leaked into rendered HTML:\n%s", panelID, m, html)
		}
	}
}

// TestManifestVerifiedClean_StaticPanels runs the REAL
// docs-site/docs/{index,story,cheatsheet}.md sources through the exact
// pipeline cmd/gen-home-fragments uses (StripLeadingH1 for whole_file /
// SelectHeadingSection for the intro panel, then RenderMarkdown) and
// asserts none of the manifest's forbidden content leaks through. This
// turns home-fragments.yaml's hand-verified "verified_clean" claims into a
// test that fails the next time content-lead edits these files in a way
// that reintroduces hint/answer/flag content, rather than relying on a
// point-in-time manual check.
func TestManifestVerifiedClean_StaticPanels(t *testing.T) {
	root := repoRoot(t)
	for _, sp := range StaticPanels {
		t.Run(sp.ID, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, sp.Source))
			if err != nil {
				t.Fatalf("reading %s: %v", sp.Source, err)
			}
			md := string(raw)
			if sp.Heading != "" {
				section, ok := SelectHeadingSection(md, sp.Heading)
				if !ok {
					t.Fatalf("heading %q not found in %s", sp.Heading, sp.Source)
				}
				md = section
			} else {
				md = StripLeadingH1(md)
			}
			html, err := RenderMarkdown(md)
			if err != nil {
				t.Fatalf("RenderMarkdown(%s): %v", sp.Source, err)
			}
			assertNoForbiddenLeaks(t, sp.ID, html)
		})
	}
}

// TestManifestVerifiedClean_RuleExplainPanels runs every REAL
// challenges/<NN>-<slug>/rule-explain.md that exists today through
// RenderMarkdown (rule-explain.md sources have no leading h1 — they open
// with `###` — so no StripLeadingH1 step applies, matching
// cmd/gen-home-fragments' renderRuleExplainPanels) and asserts the same
// forbidden-content set never leaks. Challenges with no rule-explain.md are
// silently skipped (fail-soft — same posture as the generator itself); this
// test only re-verifies what actually gets rendered, not the 8/11
// coverage gap.
func TestManifestVerifiedClean_RuleExplainPanels(t *testing.T) {
	root := repoRoot(t)
	chalDir := filepath.Join(root, "challenges")
	entries, err := os.ReadDir(chalDir)
	if err != nil {
		t.Fatalf("reading %s: %v", chalDir, err)
	}
	checked := 0
	for _, e := range entries {
		if !e.IsDir() || !ChallengeDirRe.MatchString(e.Name()) {
			continue
		}
		explainPath := filepath.Join(chalDir, e.Name(), RuleExplainFilename)
		raw, err := os.ReadFile(explainPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue // fail-soft: no rule-explain.md for this challenge
			}
			t.Fatalf("reading %s: %v", explainPath, err)
		}
		checked++
		t.Run(e.Name(), func(t *testing.T) {
			html, err := RenderMarkdown(string(raw))
			if err != nil {
				t.Fatalf("RenderMarkdown(%s): %v", explainPath, err)
			}
			assertNoForbiddenLeaks(t, e.Name(), html)
		})
	}
	if checked == 0 {
		t.Fatal("expected at least one challenges/*/rule-explain.md to exist and be checked — 0 found, manifest's coverage_2026-08-16 list may be stale or the repo layout changed")
	}
}
