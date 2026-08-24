package homefragments

import "regexp"

// ChallengeDirRe matches the canonical <NN>-<slug> challenge directory name
// shape (mirrors internal/catalog.Load / LoadJourneys' own discovery
// pattern). Exported so both cmd/gen-home-fragments (directory scan) and
// this package's own tests (manifest_verified_test.go, re-scanning the same
// challenges/ tree to verify real rule-explain.md content) use a single
// definition instead of two copies that could drift.
var ChallengeDirRe = regexp.MustCompile(`^(\d\d)-[a-z0-9-]+$`)

// StaticPanel is one non-per-challenge Home panel (intro/cheatsheet in
// docs-site/home-fragments.yaml — the `story` panel was removed 2026-08-17,
// see that file's header note). Source is a repo-root-relative path;
// Heading is "" for whole_file panels or a "## ..." selector for the intro
// panel. See home-fragments.yaml for the authoritative per-panel notes —
// this struct is a hand-synced Go mirror of that YAML (content-lead's
// contract), not a YAML parser: the manifest is a design document content-
// lead edits by hand and app-lead re-syncs this file against when the
// manifest changes (same relationship as internal/catalog's schema comments
// to the challenges/*/journey.yaml shape).
type StaticPanel struct {
	ID      string
	Label   string
	Source  string // repo-root-relative path
	Heading string // "" = whole_file; else a "## heading" selector
}

// StaticPanels mirrors home-fragments.yaml's `panels:` static entries, in
// manifest order. The `story` panel that used to be listed here was removed
// 2026-08-17 (see home-fragments.yaml's header note) — app-lead is dropping
// the corresponding Story-tab overview render from templates/portal.html in
// a parallel change, so this generator no longer needs to produce a
// "story" HomeFragment entry.
//
// The `intro`/`cheatsheet` entries that used to live here were REMOVED
// 2026-08-21 (REFACTORING.md P24 §2, "Home パネル移設") — they now live
// exclusively in TutorialChapters below, which points at the SAME source
// files (docs-site/docs/index.md / docs-site/docs/cheatsheet.md), so the
// content moved tabs rather than being duplicated. Home's static-panel list
// is intentionally empty as of this change; a future Home-only static
// panel would be added here again without affecting TutorialChapters.
var StaticPanels = []StaticPanel{}

// TutorialChapters mirrors docs-site/tutorial-chapters.yaml's `panels:`
// entries, in curriculum order (REFACTORING.md P24 architect decision §1).
// It reuses the SAME StaticPanel shape StaticPanels uses — a Tutorial
// chapter is, structurally, "a non-per-challenge, single-source, optional
// heading-selected" panel, which is exactly what StaticPanel already
// represents; no new struct type is introduced.
//
// The first ("intro") and last ("cheatsheet") entries point at the SAME
// source files StaticPanels' intro/cheatsheet entries used to point at
// (docs-site/docs/index.md / docs-site/docs/cheatsheet.md) — those two
// entries were REMOVED from StaticPanels as part of this same change (P24
// §2, "Home パネル移設"), so the content now appears only here, not twice.
// The middle four entries (architecture / condition-reading /
// predicting-rules / trigger-vs-evade) point at new sources under
// docs-site/tutorial/ (a sibling of docs-site/docs/, deliberately OUTSIDE
// mkdocs' docs_dir — see tutorial-chapters.yaml's header note for why).
var TutorialChapters = []StaticPanel{
	{
		ID:      "intro",
		Label:   "Falco CTF とは",
		Source:  "docs-site/docs/index.md",
		Heading: "## Falco とは",
	},
	{
		ID:     "architecture",
		Label:  "Falco のしくみ",
		Source: "docs-site/tutorial/architecture.md",
	},
	{
		ID:     "condition-reading",
		Label:  "ルール condition の読み方",
		Source: "docs-site/tutorial/condition-reading.md",
	},
	{
		ID:     "predicting-rules",
		Label:  "操作から Falco ルールを推測する",
		Source: "docs-site/tutorial/predicting-rules.md",
	},
	{
		ID:     "trigger-vs-evade",
		Label:  "trigger と evade の違い",
		Source: "docs-site/tutorial/trigger-vs-evade.md",
	},
	{
		ID:     "cheatsheet",
		Label:  "コマンド集",
		Source: "docs-site/docs/cheatsheet.md",
	},
}

// RuleExplainPanel describes the per-challenge "なぜ発火するか" panel
// (home-fragments.yaml's `rule-explain` entry, per_challenge: true).
// Label is shared across all challenges that have a rule-explain.md; the
// per-challenge SOURCE PATH is derived at gen time from the challenge
// directory name (challenges/<NN>-<slug>/rule-explain.md), not listed here,
// since the set of challenge directories is discovered by scanning
// challenges/ (see cmd/gen-home-fragments), matching how
// internal/catalog.Load and internal/catalog.LoadJourneys already discover
// challenges by directory scan rather than an enumerated list baked into
// app code.
const RuleExplainLabel = "🔍 なぜ発火するか"

// RuleExplainFilename is the per-challenge source filename
// (home-fragments.yaml: `source_pattern: "challenges/<NN>-<slug>/rule-explain.md"`).
const RuleExplainFilename = "rule-explain.md"
