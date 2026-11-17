package catalog

// hintinputs.go is the ONE reader of what a participant is shown of a scope's journeys and
// rules (ADR-0056 A4e-2c, V89): the journeys of the scope (LoadJourneys), the scenario's
// narrative overrides applied to them (LoadNarrative and ApplyNarrativeOverrides, ADR-0014),
// and the excerpts of the Falco rules (LoadRuleExcerpts). Three callers read them through
// LoadHintInputs and through nothing else:
//
//   - the scoreboard's start-up (cmd/scoreboard/main.go), which shows what it returns;
//   - the event validator (internal/edition/checkevent.go, hintInputs), whose B5 holds the
//     bundles to the hints and the free texts built from what it returns;
//   - the hint-leak tests of the real tree (internal/hintleak/content_test.go).
//
// So what B5 checks is what the server shows: an override that the server applies cannot be
// missing from what B5 is given. The overrides are applied here and nowhere else, in a test
// either (hintinputs_source_test.go). The callers that read the journeys or the rule excerpts
// alone, with no override (the e2e harness's seed and a few tests that build no hint and no
// free text), are not this function's business.

import (
	"path/filepath"
	"slices"
)

// HintInputsStage names the step of LoadHintInputs that failed.
type HintInputsStage string

// The steps of LoadHintInputs, in the order it runs them. The value is the prefix of
// HintInputsError's message.
const (
	HintStageJourneys           HintInputsStage = "journeys"
	HintStageNarrative          HintInputsStage = "narrative"
	HintStageNarrativeOverrides HintInputsStage = "narrative overrides"
	HintStageRuleExcerpts       HintInputsStage = "rule excerpts"
)

// HintInputsError is the error of LoadHintInputs: the step that failed, the path that step
// read (the challenges directory for the journeys and the rule excerpts, the narrative file
// for the two narrative steps), and the loader's own error, unchanged, as the cause. A caller
// that logs the failure can name the step and the file without parsing a message.
type HintInputsError struct {
	Stage HintInputsStage
	Path  string
	Err   error
}

func (e *HintInputsError) Error() string { return string(e.Stage) + ": " + e.Err.Error() }

func (e *HintInputsError) Unwrap() error { return e.Err }

// HintInputs is what LoadHintInputs read for a scope.
type HintInputs struct {
	// Journeys are the journeys of the scope, with the scenario's narrative overrides applied:
	// what the participant is shown.
	Journeys Journeys
	// Excerpts are the excerpts of the Falco rules of the scope (the Story tab's panel).
	Excerpts FalcoRuleExcerpts
	// NarrativeFile is the narrative file that was looked for, beside the scenario file; it
	// is "" when there is no scenario (the full catalog), and then nothing was overridden.
	NarrativeFile string
	// Overridden are the ids of the challenges whose briefing and bridge the narrative
	// replaced, in byte order.
	Overridden []string
}

// narrativeFileOf is scenarios/<name>/narrative.yaml, beside the scenario file.
func narrativeFileOf(scenarioFile string) string {
	return filepath.Join(filepath.Dir(scenarioFile), "narrative.yaml")
}

// LoadHintInputs reads the journeys of cat from challengesDir, applies the narrative overrides
// of the scenario (the narrative.yaml beside scenarioFile; scenarioFile "" is the full catalog,
// which has no narrative, and an absent narrative file is no override) and reads the excerpts
// of the Falco rules of cat, in that order, and stops at the first step that fails, with a
// *HintInputsError that names the step and the path it read.
func LoadHintInputs(challengesDir, scenarioFile string, cat Catalog) (HintInputs, error) {
	journeys, err := LoadJourneys(challengesDir, cat)
	if err != nil {
		return HintInputs{}, &HintInputsError{Stage: HintStageJourneys, Path: challengesDir, Err: err}
	}
	out := HintInputs{Journeys: journeys}
	if scenarioFile != "" {
		out.NarrativeFile = narrativeFileOf(scenarioFile)
		narrative, err := LoadNarrative(out.NarrativeFile)
		if err != nil {
			return HintInputs{}, &HintInputsError{Stage: HintStageNarrative, Path: out.NarrativeFile, Err: err}
		}
		if err := ApplyNarrativeOverrides(journeys, narrative); err != nil {
			return HintInputs{}, &HintInputsError{Stage: HintStageNarrativeOverrides, Path: out.NarrativeFile, Err: err}
		}
		for id := range narrative.Overrides {
			out.Overridden = append(out.Overridden, id)
		}
		slices.Sort(out.Overridden)
	}
	excerpts, err := LoadRuleExcerpts(challengesDir, cat)
	if err != nil {
		return HintInputs{}, &HintInputsError{Stage: HintStageRuleExcerpts, Path: challengesDir, Err: err}
	}
	out.Excerpts = excerpts
	return out, nil
}
