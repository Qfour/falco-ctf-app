// Command gen-home-fragments is a GEN-TIME tool (like oapi-codegen's role
// for internal/*/oapi — see Dockerfile.gen) that renders the Portal Home
// tab's content panels from source markdown into sanitized, fixed HTML and
// writes them as a committed Go source file
// (internal/scoreboard/view/homefragments_gen.go). The scoreboard binary
// go:embeds that generated file's string constants at compile time and
// never runs markdown parsing or HTML sanitization itself — see
// internal/homefragments's package doc for why this split exists (goldmark
// + the sanitizer stay out of the served binary's runtime dependency graph;
// only cmd/gen-home-fragments imports internal/homefragments).
//
// Usage:
//
//	go run ./cmd/gen-home-fragments <repo-root>
//
// Wired to `make gen-home-fragments` (Dockerfile.gen-home-fragments, mirroring
// the existing `make gen` / Dockerfile.gen export-stage pattern for oapi
// types). Commit the generated output; there is no CI diff-check for this
// generator yet (unlike oapi's), so a stale commit is a manual-review risk —
// noted as a follow-up, not blocking for P23-5.
//
// Fail-soft policy (home-fragments.yaml): a missing source file, a missing
// heading section, or a missing challenges/<NN>-<slug>/rule-explain.md is
// NOT an error — that panel is simply omitted from the generated output.
// The only FATAL conditions are: the challenges/ directory itself cannot be
// listed (a structural break, not "content missing"), or a markdown/HTML
// render step itself errors (a bug in the pipeline, not absent content).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/homefragments"
)

type panel struct {
	ID     string // Go identifier-safe key, e.g. "intro", "rule_explain_01_initial_recon"
	Label  string
	HTML   string
	ChalNN string // "" for static panels; "01".."11" for rule-explain panels
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-home-fragments <repo-root>")
		os.Exit(2)
	}
	root := os.Args[1]

	var panels []panel

	for _, sp := range homefragments.StaticPanels {
		p, ok, err := renderStaticPanel(root, sp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen-home-fragments: FATAL rendering static panel %s: %v\n", sp.ID, err)
			os.Exit(1)
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "gen-home-fragments: omitting static panel %s (source/heading not found — fail-soft)\n", sp.ID)
			continue
		}
		panels = append(panels, p)
	}

	rulePanels, err := renderRuleExplainPanels(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-home-fragments: FATAL scanning challenges/: %v\n", err)
		os.Exit(1)
	}
	panels = append(panels, rulePanels...)

	out, err := generateGoSource(panels)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-home-fragments: FATAL generating Go source: %v\n", err)
		os.Exit(1)
	}

	destDir := filepath.Join(root, "internal", "scoreboard", "view")
	dest := filepath.Join(destDir, "homefragments_gen.go")
	if err := os.WriteFile(dest, []byte(out), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gen-home-fragments: FATAL writing %s: %v\n", dest, err)
		os.Exit(1)
	}
	fmt.Printf("gen-home-fragments: wrote %s (%d panels)\n", dest, len(panels))
}

// renderStaticPanel wraps the shared homefragments.RenderStaticPanel
// (REFACTORING.md P24 architect decision §1 — extracted so
// cmd/gen-tutorial-fragments can reuse the exact same markdown->HTML
// pipeline instead of a second copy) and shapes its result into this
// command's own panel struct (ID/Label/HTML, ChalNN left "" — static panels
// are never per-challenge).
func renderStaticPanel(root string, sp homefragments.StaticPanel) (panel, bool, error) {
	html, ok, err := homefragments.RenderStaticPanel(root, sp)
	if err != nil || !ok {
		return panel{}, ok, err
	}
	return panel{ID: goIdent(sp.ID), Label: sp.Label, HTML: html}, true, nil
}

func renderRuleExplainPanels(root string) ([]panel, error) {
	chalDir := filepath.Join(root, "challenges")
	entries, err := os.ReadDir(chalDir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var panels []panel
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// homefragments.ChallengeDirRe is shared with
		// internal/homefragments/manifest_verified_test.go so the directory-
		// scan shape has one definition, not two that could drift.
		m := homefragments.ChallengeDirRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		explainPath := filepath.Join(chalDir, e.Name(), homefragments.RuleExplainFilename)
		raw, err := os.ReadFile(explainPath)
		if err != nil {
			if os.IsNotExist(err) {
				// Fail-soft, expected steady-state (8/11 challenges have no
				// rule-explain.md today) — omit, do not synthesize filler.
				continue
			}
			return nil, fmt.Errorf("reading %s: %w", explainPath, err)
		}
		html, err := homefragments.RenderMarkdown(string(raw))
		if err != nil {
			return nil, fmt.Errorf("rendering %s: %w", explainPath, err)
		}
		panels = append(panels, panel{
			ID:     goIdent("rule_explain_" + e.Name()),
			Label:  homefragments.RuleExplainLabel,
			HTML:   html,
			ChalNN: m[1],
		})
	}
	return panels, nil
}

var nonIdentRe = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func goIdent(s string) string {
	return strings.Trim(nonIdentRe.ReplaceAllString(s, "_"), "_")
}

func generateGoSource(panels []panel) (string, error) {
	var b strings.Builder
	b.WriteString(`// Code generated by cmd/gen-home-fragments from docs-site/home-fragments.yaml
// sources. DO NOT EDIT BY HAND — re-run 'make gen-home-fragments'.
//
// Every HomeFragment.HTML value below has already been through
// internal/homefragments' gen-time markdown->HTML->sanitize pipeline: it
// contains ONLY elements from home-fragments.yaml's sanitize_allowlist, with
// zero attributes on any element. The scoreboard binary trusts this file's
// content verbatim at render time (see portal.go's Home pane wiring) BECAUSE
// it was produced by that pipeline, not because runtime code re-sanitizes it
// — there is no runtime sanitizer; re-running this generator is the only way
// this file's content changes.

package view

// HomeFragment is one sanitized content panel for the Portal Home tab.
// ChalNN is "" for any static (non-per-challenge) panel and the
// zero-padded challenge number ("01".."11") for a per-challenge
// rule-explain panel, so the Home pane renderer can group/order
// rule-explain panels by challenge without re-parsing the ID string.
// StaticPanels is empty as of P24 (REFACTORING.md P24 §2: intro/cheatsheet
// moved to internal/homefragments.TutorialChapters / the Tutorial tab), so
// today every HomeFragment in practice has ChalNN != "" — but the ChalNN==""
// shape stays supported for any future Home-only static panel.
type HomeFragment struct {
	ID     string
	Label  string
	HTML   string
	ChalNN string
}

// HomeFragments is every gen-time-rendered Home panel, in manifest order
// (static panels first, then rule-explain panels sorted by challenge
// number). A challenge with no rule-explain.md simply has no entry here —
// fail-soft, per home-fragments.yaml; the Home pane must not synthesize a
// placeholder for a missing entry.
var HomeFragments = []HomeFragment{
`)
	for _, p := range panels {
		fmt.Fprintf(&b, "\t{ID: %s, Label: %s, ChalNN: %s, HTML: %s},\n",
			strconv.Quote(p.ID), strconv.Quote(p.Label), strconv.Quote(p.ChalNN), strconv.Quote(p.HTML))
	}
	b.WriteString("}\n")
	return b.String(), nil
}
