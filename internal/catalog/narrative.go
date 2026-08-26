package catalog

// narrative.go loads the optional, scenario-owned narrative overlay
// (ADR-0014: docs/adr/0014-journey-narrative-scenario-overlay.md).
//
// Problem this solves: challenges/<NN>-<slug>/journey.yaml's `briefing`/
// `bridge` are content contract fields (see journey.go's schema comment) that
// were authored assuming the single 01-10 killchain (scenario
// `nimbusbreach-full`). They directly reference other mission numbers (e.g.
// 03's briefing says "Mission 02 で..."). A scenario that selects a different
// subset/order (e.g. `tutorial-intro`: 00,01,03 — no 02) inherits those
// references verbatim and the narrative contradicts itself.
//
// Fix (ADR-0014 Option 2): a scenario may ship
// `scenarios/<name>/narrative.yaml` with a challengeId -> {briefing, bridge}
// map. If a challengeId appears here, it REPLACES that mission's
// briefing/bridge from journey.yaml wholesale — never a field-by-field merge
// with the challenge-local fallback (ADR-0014 Consequences: "静かな部分マージは
// 禁止"). All other Journey fields (title/tagline/steps/hints/docsUrl) still
// come from journey.yaml; narrative.yaml only ever speaks about the two
// fields that carry inter-mission references.
//
// No narrative.yaml (the common case today — neither nimbusbreach-full nor
// tutorial-intro ships one) is a no-op: LoadNarrative returns a zero-value
// Narrative and ApplyNarrativeOverrides does nothing, so existing scenario
// behavior is byte-for-byte unchanged.
//
// Schema (content contract, same governance as journey.yaml — VP approval to
// change):
//
//	overrides:
//	  <challengeId>:
//	    briefing: <replaces this mission's journey.yaml briefing entirely>
//	    bridge:   <replaces this mission's journey.yaml bridge entirely>

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// NarrativeOverride replaces a Journey's briefing/bridge pair. Both fields
// are always applied together (no partial merge) — an override that omits
// `bridge` sets it to "" (no teaser for that mission in this scenario), it
// does NOT fall back to the challenge-local bridge.
type NarrativeOverride struct {
	Briefing string `yaml:"briefing"`
	Bridge   string `yaml:"bridge"`
}

// Narrative is the parsed scenarios/<name>/narrative.yaml. A nil/empty
// Overrides map means "no overrides" (the file is absent or declares none).
type Narrative struct {
	Overrides map[string]NarrativeOverride `yaml:"overrides"`
}

// LoadNarrative reads scenarios/<name>/narrative.yaml. A missing file is not
// an error — narrative overlays are optional, and most scenarios (today: all
// of them) will not have one. A malformed file IS an error (content mistake,
// same fail-loud posture as LoadScenario/LoadJourneys for parse failures).
func LoadNarrative(path string) (Narrative, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Narrative{}, nil
		}
		return Narrative{}, fmt.Errorf("read narrative %q: %w", path, err)
	}
	var n Narrative
	if err := yaml.Unmarshal(data, &n); err != nil {
		return Narrative{}, fmt.Errorf("parse narrative %q: %w", path, err)
	}
	return n, nil
}

// ApplyNarrativeOverrides replaces the briefing/bridge of each journey named
// in n.Overrides, mutating j in place. Journeys not named in n.Overrides are
// left completely untouched — this is what guarantees zero behavior change
// for scenarios with no narrative.yaml (n.Overrides is nil, the loop body
// never runs).
//
// Fail-loud: an override naming a challengeId that has no entry in j (either
// because no such challenge/journey exists at all, or because it was
// restricted out of the active scenario's catalog before LoadJourneys ran)
// is an error. This mirrors Catalog.Restrict's "scenario references unknown
// challenge" posture — an orphan override is a content mistake (typo, or a
// leftover override for a mission the scenario no longer includes) that must
// not be silently dropped, matching the existing "orphan journey is loud"
// philosophy in journey.go.
func ApplyNarrativeOverrides(j Journeys, n Narrative) error {
	for id, ov := range n.Overrides {
		existing, ok := j[id]
		if !ok {
			return fmt.Errorf("narrative override references unknown or out-of-scenario challengeId %q", id)
		}
		existing.Briefing = ov.Briefing
		existing.Bridge = ov.Bridge
		j[id] = existing
	}
	return nil
}
