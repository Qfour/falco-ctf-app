package homefragments

import "regexp"

// ChallengeDirRe matches the canonical <NN>-<slug> challenge directory name
// shape (mirrors internal/catalog.Load / LoadJourneys' own discovery
// pattern). Exported so both cmd/gen-home-fragments (directory scan) and
// this package's own tests (manifest_verified_test.go, re-scanning the same
// challenges/ tree to verify real rule-explain.md content) use a single
// definition instead of two copies that could drift.
var ChallengeDirRe = regexp.MustCompile(`^(\d\d)-[a-z0-9-]+$`)

// StaticPanel is one non-per-challenge Home panel (intro/story/cheatsheet in
// docs-site/home-fragments.yaml). Source is a repo-root-relative path;
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

// StaticPanels mirrors home-fragments.yaml's `panels:` static entries
// (intro, story, cheatsheet), in manifest order.
var StaticPanels = []StaticPanel{
	{
		ID:      "intro",
		Label:   "Falco CTF とは",
		Source:  "docs-site/docs/index.md",
		Heading: "## Falco とは",
	},
	{
		ID:     "story",
		Label:  "ストーリー",
		Source: "docs-site/docs/story.md",
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
