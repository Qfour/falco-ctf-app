package catalog_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

func writeJourney(t *testing.T, dir, name, yaml string) {
	t.Helper()
	cdir := filepath.Join(dir, name)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "journey.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
}

func journeyCatalog() catalog.Catalog {
	return catalog.Catalog{
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}},
		"05-silent-search": {ID: "05-silent-search", Type: "evade", ExpectedFlag: "FALCO{x}"},
	}
}

func TestLoadJourneys_ParsesAndKeysByChallengeID(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
tagline: obj
briefing: intro
steps:
  - label: step one
    detail: do the thing
hints:
  - hint one
  - hint two
docsUrl: /missions/01-initial-recon/
`)
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	j, ok := js["01-initial-recon"]
	if !ok {
		t.Fatalf("journey not loaded; got keys %v", js)
	}
	if j.Title != "潜入" || j.Tagline != "obj" || j.Briefing != "intro" {
		t.Fatalf("fields wrong: %+v", j)
	}
	if len(j.Steps) != 1 || j.Steps[0].Label != "step one" || j.Steps[0].Detail != "do the thing" {
		t.Fatalf("steps wrong: %+v", j.Steps)
	}
	if len(j.Hints) != 2 || j.Hints[1].Text != "hint two" {
		t.Fatalf("hints wrong: %+v", j.Hints)
	}
	// Backward-compat: legacy scalar-string hints get a Kind inferred from
	// their 0-based array position (hintKindForIndex: 0->rule, 1->command).
	if j.Hints[0].Kind != "rule" || j.Hints[1].Kind != "command" {
		t.Fatalf("legacy scalar hints should get inferred Kind by index: %+v", j.Hints)
	}
	if len(j.Hints[0].RuleRefs) != 0 || j.Hints[0].CheatsheetRef != "" {
		t.Fatalf("legacy scalar hints must carry no ruleRefs/cheatsheetRef: %+v", j.Hints[0])
	}
	if j.DocsURL != "/missions/01-initial-recon/" {
		t.Fatalf("docsUrl wrong: %q", j.DocsURL)
	}
}

func TestLoadJourneys_MissingFileGracefulDegrade(t *testing.T) {
	dir := t.TempDir()
	// Directory exists (a challenge dir) but has no journey.yaml.
	if err := os.MkdirAll(filepath.Join(dir, "01-initial-recon"), 0o755); err != nil {
		t.Fatal(err)
	}
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("missing journey.yaml must not error: %v", err)
	}
	if len(js) != 0 {
		t.Fatalf("expected no journeys, got %d", len(js))
	}
}

func TestLoadJourneys_MissingDirNoError(t *testing.T) {
	js, err := catalog.LoadJourneys(filepath.Join(t.TempDir(), "nope"), journeyCatalog())
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(js) != 0 {
		t.Fatalf("expected empty, got %d", len(js))
	}
}

func TestLoadJourneys_RestrictedOutChallengeIsSkipped(t *testing.T) {
	dir := t.TempDir()
	// RESTRICT-OUT case: a challenge directory whose name (= its id) is not in
	// the active, scenario-restricted catalog. Its declared challengeId MATCHES
	// its directory name (so it is NOT a typo) — it is simply outside the active
	// scenario. It must be silently skipped, not treated as an error, and a
	// valid in-catalog journey alongside it must still load.
	writeJourney(t, dir, "99-ghost", `
challengeId: 99-ghost
title: ghost
`)
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
`)
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("restricted-out challenge must be skipped, not error: %v", err)
	}
	if _, ok := js["99-ghost"]; ok {
		t.Fatalf("99-ghost is not in the catalog; it must be skipped, got %v", js)
	}
	if _, ok := js["01-initial-recon"]; !ok {
		t.Fatalf("in-catalog journey must still load; got %v", js)
	}
	if len(js) != 1 {
		t.Fatalf("expected exactly 1 journey loaded, got %d: %v", len(js), js)
	}
}

func TestLoadJourneys_ChallengeIDMismatchIsTypoError(t *testing.T) {
	dir := t.TempDir()
	// TYPO case: directory 01-initial-recon (a real, in-catalog challenge) but
	// journey.yaml declares a non-empty challengeId that does NOT match the
	// directory name. This is a content mistake that would silently drop the
	// mission from /journey under the old "is id in cat?" skip; it MUST be a
	// loud error (fail-closed), restoring the pre-tutorial fatal behaviour.
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recom
title: 潜入
`)
	_, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err == nil {
		t.Fatal("challengeId that mismatches its directory name must be a typo error, not a silent skip")
	}
	// The error must name the offending declared id and the directory so the
	// content author can find the typo.
	msg := err.Error()
	if !strings.Contains(msg, "01-initial-recom") || !strings.Contains(msg, "01-initial-recon") {
		t.Fatalf("typo error should name both the declared id and the directory; got: %v", err)
	}
}

func TestLoadJourneys_TypoErrorsEvenInFullCatalog(t *testing.T) {
	dir := t.TempDir()
	// A typo must be loud regardless of whether the catalog is a subset or the
	// full (unrestricted) catalog: skip keys off the directory name, so a full
	// catalog does not launder a mismatching challengeId into a silent load.
	full := catalog.Catalog{
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}},
		"01-initial-recom": {ID: "01-initial-recom", Type: "trigger", ExpectedRules: []string{"r"}},
	}
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recom
title: 潜入
`)
	if _, err := catalog.LoadJourneys(dir, full); err == nil {
		t.Fatal("typo must error even when the mistyped id happens to exist elsewhere in a full catalog")
	}
}

func TestLoadJourneys_DefaultsChallengeIDToDirName(t *testing.T) {
	dir := t.TempDir()
	// No challengeId field -> defaults to the directory name, which IS in cat.
	writeJourney(t, dir, "05-silent-search", `
title: 静かな探索
`)
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	if _, ok := js["05-silent-search"]; !ok {
		t.Fatalf("challengeId should default to dir name; got %v", js)
	}
}

func TestLoadJourneys_TitleRequired(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
tagline: no title here
`)
	if _, err := catalog.LoadJourneys(dir, journeyCatalog()); err == nil {
		t.Fatal("expected error when title is empty")
	}
}

// --- Unified hints Phase 1: structured JourneyHint decoding ---------------

func TestLoadJourneys_StructuredHints_DecodesKindRuleRefsCheatsheetRef(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
hints:
  - kind: rule
    text: watch for the recon rule
    ruleRefs: ["Read sensitive file untrusted"]
    cheatsheetRef: falco-rules-101
  - kind: command
    text: try find
`)
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	j := js["01-initial-recon"]
	if len(j.Hints) != 2 {
		t.Fatalf("expected 2 hints, got %d: %+v", len(j.Hints), j.Hints)
	}
	h0 := j.Hints[0]
	if h0.Kind != "rule" || h0.Text != "watch for the recon rule" {
		t.Fatalf("hint 0 fields wrong: %+v", h0)
	}
	if len(h0.RuleRefs) != 1 || h0.RuleRefs[0] != "Read sensitive file untrusted" {
		t.Fatalf("hint 0 ruleRefs wrong: %+v", h0.RuleRefs)
	}
	if h0.CheatsheetRef != "falco-rules-101" {
		t.Fatalf("hint 0 cheatsheetRef wrong: %q", h0.CheatsheetRef)
	}
	h1 := j.Hints[1]
	if h1.Kind != "command" || h1.Text != "try find" {
		t.Fatalf("hint 1 fields wrong: %+v", h1)
	}
	if len(h1.RuleRefs) != 0 || h1.CheatsheetRef != "" {
		t.Fatalf("hint 1 with no ruleRefs/cheatsheetRef declared should decode empty: %+v", h1)
	}
}

func TestLoadJourneys_MixedScalarAndStructuredHints(t *testing.T) {
	dir := t.TempDir()
	// Old scalar-string hints and the new mapping form may be freely mixed
	// within one journey.yaml (content is migrated mission-by-mission, not
	// all-at-once).
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
hints:
  - a plain legacy hint
  - kind: solution
    text: the structured hint
  - a third legacy hint
  - a fourth legacy hint
`)
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	j := js["01-initial-recon"]
	if len(j.Hints) != 4 {
		t.Fatalf("expected 4 hints, got %d: %+v", len(j.Hints), j.Hints)
	}
	if j.Hints[0].Kind != "rule" || j.Hints[0].Text != "a plain legacy hint" {
		t.Fatalf("hint 0 (legacy, index 0 -> rule) wrong: %+v", j.Hints[0])
	}
	if j.Hints[1].Kind != "solution" || j.Hints[1].Text != "the structured hint" {
		t.Fatalf("hint 1 (structured, explicit kind) wrong: %+v", j.Hints[1])
	}
	// Index 2 and 3 are BOTH legacy scalars; hintKindForIndex infers off each
	// element's own position in the array (2 and 3), not off some running
	// count of scalar-only elements, so both land on "solution" (index >= 2).
	if j.Hints[2].Kind != "solution" || j.Hints[2].Text != "a third legacy hint" {
		t.Fatalf("hint 2 (legacy, index 2 -> solution) wrong: %+v", j.Hints[2])
	}
	if j.Hints[3].Kind != "solution" || j.Hints[3].Text != "a fourth legacy hint" {
		t.Fatalf("hint 3 (legacy, index 3 -> solution, beyond the 3-tier schedule) wrong: %+v", j.Hints[3])
	}
}

func TestLoadJourneys_MalformedHintEntryIsLoudError(t *testing.T) {
	dir := t.TempDir()
	// A hint entry that is neither a scalar nor a mapping (here: a nested
	// sequence) must fail loudly at load, same posture as any other content
	// typo (TestLoadJourneys_TitleRequired) — never silently drop hints.
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
hints:
  - [not, a, valid, hint, entry]
`)
	if _, err := catalog.LoadJourneys(dir, journeyCatalog()); err == nil {
		t.Fatal("expected error for a hint entry that is neither scalar nor mapping")
	}
}

// --- ValidateHintRuleRefs ----------------------------------------------

func TestValidateHintRuleRefs_UnknownRefIsWarned(t *testing.T) {
	cat := catalog.Catalog{
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"Recon Rule"}},
	}
	journeys := catalog.Journeys{
		"01-initial-recon": {
			ChallengeID: "01-initial-recon",
			Title:       "潜入",
			Hints: catalog.JourneyHints{
				{Kind: "rule", Text: "ok", RuleRefs: []string{"Recon Rule"}},           // known (ExpectedRules)
				{Kind: "command", Text: "bad", RuleRefs: []string{"Nonexistent Rule"}}, // unknown
			},
		},
	}
	warnings := catalog.ValidateHintRuleRefs(journeys, cat, catalog.FalcoRuleExcerpts{})
	if len(warnings) != 1 {
		t.Fatalf("expected exactly 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "Nonexistent Rule") {
		t.Fatalf("warning should name the offending ref: %v", warnings[0])
	}
}

func TestValidateHintRuleRefs_KnownFromRuleYamlExcerpt(t *testing.T) {
	cat := catalog.Catalog{
		"02-evade": {ID: "02-evade", Type: "evade"},
	}
	journeys := catalog.Journeys{
		"02-evade": {
			ChallengeID: "02-evade",
			Title:       "回避",
			Hints: catalog.JourneyHints{
				{Kind: "rule", Text: "ok", RuleRefs: []string{"Read sensitive file untrusted"}},
			},
		},
	}
	rules := catalog.FalcoRuleExcerpts{
		"02-evade": {Rules: []catalog.FalcoRuleItem{{Name: "Read sensitive file untrusted"}}},
	}
	if warnings := catalog.ValidateHintRuleRefs(journeys, cat, rules); len(warnings) != 0 {
		t.Fatalf("ref present in rule.yaml excerpt must not warn: %v", warnings)
	}
}

func TestValidateHintRuleRefs_NoRefsNoWarnings(t *testing.T) {
	cat := journeyCatalog()
	journeys := catalog.Journeys{
		"01-initial-recon": {
			ChallengeID: "01-initial-recon",
			Title:       "潜入",
			Hints:       catalog.JourneyHints{{Kind: "rule", Text: "no refs here"}},
		},
	}
	if warnings := catalog.ValidateHintRuleRefs(journeys, cat, catalog.FalcoRuleExcerpts{}); len(warnings) != 0 {
		t.Fatalf("a hint with no ruleRefs must never warn: %v", warnings)
	}
}
