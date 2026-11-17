package catalog_test

// ADR-0056 A4e-2c: catalog.LoadHintInputs, the one reader of the journeys, the scenario's
// narrative overrides and the rule excerpts (what the scoreboard shows and what the event
// validator's B5 checks). The cases: the override is applied and reported, no scenario reads
// no narrative, and each step's failure names its step and the path it read (the start-up logs
// the record of that step with that path: cmd/scoreboard/main.go, logHintInputsFailure).

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// hiTree is a challenges directory with two journeys and a scenario directory beside it; it
// returns the challenges directory, the scenario file (not written: only its directory is
// used) and the catalog.
func hiTree(t *testing.T) (string, string, catalog.Catalog) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "challenges")
	writeJourney(t, dir, "01-initial-recon", "challengeId: 01-initial-recon\ntitle: t1\nbriefing: \"local briefing one\"\nbridge: \"local bridge one\"\n")
	writeJourney(t, dir, "03-stealth-read", "challengeId: 03-stealth-read\ntitle: t3\nbriefing: \"local briefing three\"\n")
	if err := os.MkdirAll(filepath.Join(root, "scenario"), 0o755); err != nil {
		t.Fatal(err)
	}
	cat := catalog.Catalog{
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}},
		"03-stealth-read":  {ID: "03-stealth-read", Type: "evade", ExpectedFlag: "FALCO{x}"},
	}
	return dir, filepath.Join(root, "scenario", "scenario.yaml"), cat
}

func TestLoadHintInputs_AppliesTheNarrativeAndSaysWhatItOverrode(t *testing.T) {
	dir, scenarioFile, cat := hiTree(t)
	narrativeFile := filepath.Join(filepath.Dir(scenarioFile), "narrative.yaml")
	writeNarrative(t, narrativeFile, "overrides:\n  03-stealth-read:\n    briefing: \"scenario briefing three\"\n  01-initial-recon:\n    briefing: \"scenario briefing one\"\n")
	shown, err := catalog.LoadHintInputs(dir, scenarioFile, cat)
	if err != nil {
		t.Fatalf("LoadHintInputs: %v", err)
	}
	if got := shown.Journeys["03-stealth-read"].Briefing; got != "scenario briefing three" {
		t.Errorf("03's briefing = %q; want the narrative's", got)
	}
	if got := shown.Journeys["01-initial-recon"]; got.Briefing != "scenario briefing one" || got.Bridge != "" || got.Title != "t1" {
		t.Errorf("01 = %+v; want the narrative's briefing, the bridge cleared (no partial merge) and the title kept", got)
	}
	if want := []string{"01-initial-recon", "03-stealth-read"}; !slices.Equal(shown.Overridden, want) {
		t.Errorf("Overridden = %v; want %v, in byte order", shown.Overridden, want)
	}
	if shown.NarrativeFile != narrativeFile {
		t.Errorf("NarrativeFile = %q; want %q", shown.NarrativeFile, narrativeFile)
	}
	if shown.Excerpts == nil {
		t.Error("Excerpts is nil; want the (empty) excerpts of the scope")
	}
}

// The full catalog (no scenario) has no narrative: none is looked for and nothing is
// overridden.
func TestLoadHintInputs_NoScenarioReadsNoNarrative(t *testing.T) {
	dir, _, cat := hiTree(t)
	shown, err := catalog.LoadHintInputs(dir, "", cat)
	if err != nil {
		t.Fatalf("LoadHintInputs with no scenario: %v", err)
	}
	if shown.NarrativeFile != "" || len(shown.Overridden) != 0 {
		t.Errorf("NarrativeFile %q, Overridden %v; want none", shown.NarrativeFile, shown.Overridden)
	}
	if got := shown.Journeys["03-stealth-read"].Briefing; got != "local briefing three" {
		t.Errorf("03's briefing = %q; want the journey's own", got)
	}
}

// Each step's failure is a *HintInputsError that names the step, the path the step read and the
// loader's own error as the cause; nothing is returned with it.
func TestLoadHintInputs_EachStepsFailureNamesItsStepAndPath(t *testing.T) {
	cases := []struct {
		name      string
		brk       func(t *testing.T, dir, scenarioFile string)
		stage     catalog.HintInputsStage
		pathIsDir bool // the path is the challenges directory (else the narrative file)
		inMessage string
	}{
		{"a journey that does not parse", func(t *testing.T, dir, _ string) {
			writeJourney(t, dir, "01-initial-recon", "challengeId: [unclosed\n")
		}, catalog.HintStageJourneys, true, "journeys: "},
		{"a narrative that does not parse", func(t *testing.T, _, scenarioFile string) {
			writeNarrative(t, filepath.Join(filepath.Dir(scenarioFile), "narrative.yaml"), "overrides: [this, is, not, a, map]")
		}, catalog.HintStageNarrative, false, "narrative: "},
		{"an override of a challenge that is not in the scope", func(t *testing.T, _, scenarioFile string) {
			writeNarrative(t, filepath.Join(filepath.Dir(scenarioFile), "narrative.yaml"), "overrides:\n  99-ghost:\n    briefing: \"x\"\n")
		}, catalog.HintStageNarrativeOverrides, false, "narrative overrides: "},
		{"a rule.yaml that does not parse", func(t *testing.T, dir, _ string) {
			if err := os.WriteFile(filepath.Join(dir, "03-stealth-read", "rule.yaml"), []byte("- rule: [unclosed\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, catalog.HintStageRuleExcerpts, true, "rule excerpts: "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, scenarioFile, cat := hiTree(t)
			c.brk(t, dir, scenarioFile)
			shown, err := catalog.LoadHintInputs(dir, scenarioFile, cat)
			var he *catalog.HintInputsError
			if !errors.As(err, &he) {
				t.Fatalf("err = %v (%T); want a *HintInputsError", err, err)
			}
			want := filepath.Join(filepath.Dir(scenarioFile), "narrative.yaml")
			if c.pathIsDir {
				want = dir
			}
			if he.Stage != c.stage || he.Path != want || he.Err == nil || !errors.Is(err, he.Err) {
				t.Errorf("stage %q, path %q, cause %v; want %q, %q and the loader's error", he.Stage, he.Path, he.Err, c.stage, want)
			}
			if !strings.HasPrefix(err.Error(), c.inMessage) {
				t.Errorf("message %q; want it to start with %q", err.Error(), c.inMessage)
			}
			if shown.Journeys != nil || shown.Excerpts != nil || shown.Overridden != nil {
				t.Errorf("a failure returned inputs: %+v", shown)
			}
		})
	}
}
