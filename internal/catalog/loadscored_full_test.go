package catalog

import (
	"path/filepath"
	"slices"
	"testing"
)

// ADR-0056 D19 A4a-3 (review #631 R2#1): Scored.FullCatalog is the tree BEFORE the
// scenario restriction, with the repository defaults (no flags file applied), and
// Scored.ChallengesDir is the directory LoadScored was given. edition.Load reads the
// practice answers of every challenge of the tree from them, so a FullCatalog that was
// the scored catalog (`FullCatalog: out.Catalog`) would silently drop the practice
// answers of the challenges outside the scenario from T6. The fixtures are the real
// tree and scenarios, with fake event flags like TestLoadScored_RealCatalogAndScenarios.
func TestLoadScored_FullCatalogIsTheTreeBeforeTheScenario(t *testing.T) {
	const challengesDir = "../../challenges"
	tree, err := Load(challengesDir)
	if err != nil {
		t.Fatal(err)
	}
	var pairs []string
	event := map[string]string{}
	for _, id := range tree.IDs() {
		if tree[id].Type == "evade" {
			event[id] = "FALCO{test-event-" + id + "}"
			pairs = append(pairs, id, event[id])
		}
	}
	if len(pairs) == 0 {
		t.Fatal("no evade challenges found in the real catalog; test would prove nothing")
	}
	flags := writeFlags(t, flagsBody(pairs...))

	scenarioFiles, err := filepath.Glob("../../scenarios/*/scenario.yaml")
	if err != nil {
		t.Fatal(err)
	}
	narrower := 0 // scenarios whose scope is smaller than the tree: the ones that can tell
	for _, scenarioFile := range append([]string{""}, scenarioFiles...) {
		for _, flagsFile := range []string{"", flags} {
			got, err := LoadScored(challengesDir, scenarioFile, flagsFile)
			if err != nil {
				t.Fatalf("LoadScored(%q, flags file given: %v): %v", scenarioFile, flagsFile != "", err)
			}
			where := "scenario " + scenarioFile + ", flags file none"
			if flagsFile != "" {
				where = "scenario " + scenarioFile + ", flags file given"
			}

			// (a) every challenge of the tree, scenario or not
			if !slices.Equal(got.FullCatalog.IDs(), tree.IDs()) {
				t.Errorf("%s: FullCatalog ids = %v, want the tree's %v", where, got.FullCatalog.IDs(), tree.IDs())
			}
			if len(got.Catalog) < len(tree) {
				narrower++
				if len(got.FullCatalog) == len(got.Catalog) {
					t.Errorf("%s: FullCatalog is as small as the scored catalog (%d)", where, len(got.Catalog))
				}
			}

			// (b) the repository defaults in FullCatalog, the event's values in Catalog
			// (the doc comment of Scored: FullCatalog is what catalog.Load returned)
			for id, ch := range got.FullCatalog {
				if ch.ExpectedFlag != tree[id].ExpectedFlag {
					t.Errorf("%s: %s: FullCatalog carries another flag than the repository default", where, id)
				}
			}
			for id, ch := range got.Catalog {
				if ch.Type != "evade" {
					continue
				}
				want := tree[id].ExpectedFlag
				if flagsFile != "" {
					want = event[id]
				}
				if ch.ExpectedFlag != want {
					t.Errorf("%s: %s: the scored catalog does not carry the expected flag", where, id)
				}
			}

			// (c) the directory LoadScored was given
			if got.ChallengesDir != challengesDir {
				t.Errorf("%s: ChallengesDir = %q, want %q", where, got.ChallengesDir, challengesDir)
			}
		}
	}
	if narrower == 0 {
		t.Fatal("no scenario is smaller than the tree; the test could not tell a FullCatalog that is the scored catalog")
	}
}
