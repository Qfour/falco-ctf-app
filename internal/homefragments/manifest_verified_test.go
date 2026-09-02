package homefragments

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
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
//
// P24 follow-up (app#156): StaticPanels is now []StaticPanel{} (see
// manifest.go) — the intro/cheatsheet entries this test used to iterate
// over moved to TutorialChapters (see TestManifestVerifiedClean_
// TutorialChapters below), so as written today this test's body executes
// zero iterations and asserts nothing. That is the correct, intended state
// post-P24 (StaticPanels stays as the seam for any *future* Home-tab static
// panel, at which point this loop starts exercising it again) — it is kept
// rather than deleted so a future StaticPanels entry is covered without
// anyone having to remember to re-add this test.
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

// TestManifestVerifiedClean_TutorialChapters is TestManifestVerifiedClean_
// StaticPanels' equivalent for the Tutorial tab's chapters (P24). It exists
// because the `intro`/`cheatsheet` entries this test used to cover moved
// OUT of StaticPanels (now empty, see manifest.go's doc) and INTO
// TutorialChapters (REFACTORING.md P24 §2) — without this test, the
// "verified_clean" coverage those two panels had would silently regress to
// zero rather than following the content to its new home. Uses the shared
// RenderStaticPanel (the same function cmd/gen-tutorial-fragments calls)
// instead of re-deriving the heading/whole_file branch inline, so this test
// exercises the EXACT gen pipeline, not a parallel reimplementation of it.
func TestManifestVerifiedClean_TutorialChapters(t *testing.T) {
	root := repoRoot(t)
	checked := 0
	for _, sp := range TutorialChapters {
		t.Run(sp.ID, func(t *testing.T) {
			html, ok, err := RenderStaticPanel(root, sp)
			if err != nil {
				t.Fatalf("RenderStaticPanel(%s): %v", sp.ID, err)
			}
			if !ok {
				t.Fatalf("chapter %s: source/heading not found (tutorial-chapters.yaml's sources are expected to exist in this repo)", sp.ID)
			}
			checked++
			assertNoForbiddenLeaks(t, sp.ID, html)
		})
	}
	if checked == 0 {
		t.Fatal("expected at least one TutorialChapters entry to render and be checked — 0 found, TutorialChapters may be empty or every source missing")
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

// TestTutorialChaptersVerifiedClean_NoHintOverlap is the machine check
// REFACTORING.md P24 §4 specifies in place of a shell/grep gate: hints[] is
// a YAML block scalar (multi-line), which scripts/check-flags.sh's simple
// one-line-regex `git grep` cannot safely parse — so this test reuses
// internal/catalog.LoadJourneys, the ONE authoritative parser of
// journey.yaml's hints[] field, instead of writing a second regex-based
// parser that could drift from it.
//
// It renders every REAL TutorialChapters entry through the exact same
// pipeline cmd/gen-tutorial-fragments uses (homefragments.RenderStaticPanel)
// and fails if the rendered HTML contains ANY challenge's hint text OR any
// journey step's `detail` text as an exact literal substring — the same
// "exact literal substring, not a paraphrase/semantic check" posture
// assertNoForbiddenLeaks already uses above. `steps[].detail` was added to
// the check scope by app#154 (P24 follow-up, security-engineer /review-5x
// R1 finding on PR #153): a tutorial chapter (e.g. trigger-vs-evade.md) can
// be a verbatim/near-verbatim paraphrase of a step's guidance text just as
// easily as of a hint, and the original test only ever looked at hints[],
// leaving that overlap shape as a blind spot for future chapter edits. A
// chapter whose source is fail-soft-omitted (missing file/heading) is
// simply not checked, matching every other test in this file's fail-soft
// posture — that absence is exercised by the *_gen.go generator step
// instead, not here.
//
// This is the PERMANENT CI enforcement of tutorial-chapters.yaml's
// "Machine check (content-engineer's authoring-time gate)" note: it runs on
// every `make test`, which is already a required CI check (`test`), so no
// new CI job or branch-protection required-check change is needed.
func TestTutorialChaptersVerifiedClean_NoHintOverlap(t *testing.T) {
	root := repoRoot(t)
	chalDir := filepath.Join(root, "challenges")

	cat, err := catalog.Load(chalDir)
	if err != nil {
		t.Fatalf("catalog.Load(%s): %v", chalDir, err)
	}
	journeys, err := catalog.LoadJourneys(chalDir, cat)
	if err != nil {
		t.Fatalf("catalog.LoadJourneys(%s): %v", chalDir, err)
	}

	// overlapText pairs a journey.yaml text fragment (hint or step detail)
	// with a human-readable label identifying its field, so a failure
	// message can say exactly which field leaked, not just "some hint".
	type overlapText struct {
		field string // "hints[]" or "steps[].detail"
		text  string
	}
	var overlaps []overlapText
	for _, j := range journeys {
		for _, h := range j.Hints {
			if strings.TrimSpace(h.Text) == "" {
				continue
			}
			overlaps = append(overlaps, overlapText{field: "hints[]", text: h.Text})
		}
		for _, s := range j.Steps {
			if strings.TrimSpace(s.Detail) == "" {
				continue
			}
			overlaps = append(overlaps, overlapText{field: "steps[].detail", text: s.Detail})
		}
	}
	if len(overlaps) == 0 {
		t.Fatal("expected at least one journey.yaml hints[]/steps[].detail entry across challenges/ — 0 found, LoadJourneys may be broken or the repo layout changed")
	}

	checked := 0
	for _, sp := range TutorialChapters {
		t.Run(sp.ID, func(t *testing.T) {
			html, ok, err := RenderStaticPanel(root, sp)
			if err != nil {
				t.Fatalf("RenderStaticPanel(%s): %v", sp.ID, err)
			}
			if !ok {
				t.Skipf("chapter %s omitted (fail-soft: source/heading not found) — nothing to check", sp.ID)
			}
			checked++
			for _, o := range overlaps {
				if strings.Contains(html, o.text) {
					t.Errorf("chapter %q: journey.yaml %s text leaked verbatim into rendered HTML:\n  text: %q\n  html: %s", sp.ID, o.field, o.text, html)
				}
			}
		})
	}
	if checked == 0 {
		t.Fatal("expected at least one TutorialChapters entry to render and be checked — 0 found, TutorialChapters may be empty or every source missing")
	}
}
