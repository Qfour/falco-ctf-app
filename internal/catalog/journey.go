package catalog

// journey.go loads the game-style mission narrative for the /journey UI from
// `challenges/<NN>-<slug>/journey.yaml`. This is participant-facing *content*
// only — it never influences scoring. A challenge with no journey.yaml simply
// has no journey entry, and the UI degrades gracefully ("ブリーフィング準備中").
//
// Schema (content contract — changing it requires VP approval):
//
//	challengeId: <must equal the challenge's catalog id>
//	title:       <mission name>
//	tagline:     <one-line objective>
//	briefing:    <2-4 sentence intro narrative>
//	steps:
//	  - label:   <short heading>
//	    detail:  <guidance; may include commands>
//	hints:
//	  - <staged hint; 1 -> N approaches the answer>
//	bridge:      <optional 1-2 sentence attacker-voice pull toward the *next*
//	              mission, shown when THIS mission clears (#47). The final
//	              mission's bridge is the closing beat. Purely narrative; omit
//	              it and the UI simply shows no teaser (fail-soft).>
//	docsUrl:     </missions/<NN>-<slug>/>

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// JourneyStep is one guided step of a mission. `label` is a short heading;
// `detail` is the how-to (commands allowed).
type JourneyStep struct {
	Label  string `yaml:"label" json:"label"`
	Detail string `yaml:"detail" json:"detail"`
}

// Journey is the narrative wrapper around a challenge for the /journey UI.
type Journey struct {
	ChallengeID string        `yaml:"challengeId" json:"challengeId"`
	Title       string        `yaml:"title" json:"title"`
	Tagline     string        `yaml:"tagline" json:"tagline"`
	Briefing    string        `yaml:"briefing" json:"briefing"`
	Steps       []JourneyStep `yaml:"steps" json:"steps"`
	Hints       []string      `yaml:"hints" json:"hints"`
	// Bridge is the narrative pull toward the next mission, surfaced when this
	// mission clears (#47). Optional and display-only — empty means "no teaser".
	Bridge  string `yaml:"bridge" json:"bridge"`
	DocsURL string `yaml:"docsUrl" json:"docsUrl"`
}

// Journeys maps challengeId -> Journey. Missing entries mean "no journey
// content authored yet"; callers must handle absence gracefully.
type Journeys map[string]Journey

// LoadJourneys scans <dir>/<NN>-<slug>/journey.yaml for every subdirectory and
// returns the parsed journeys keyed by challengeId. It validates each
// journey.yaml against `cat`:
//
//   - the declared challengeId must be non-empty (defaults to the directory
//     name when omitted, mirroring catalog.Load).
//
// A missing journey.yaml is not an error (graceful degrade). A malformed one
// (parse error, or empty title) IS an error so a content typo is loud rather
// than silently dropping the mission's briefing.
//
// A journey whose challengeId does not correspond to a challenge in `cat` is
// SKIPPED (not an error): `cat` may be a scenario-restricted catalog, in which
// case journeys for challenges outside the active scenario are simply not part
// of this run. Journeys already "graceful degrade when absent"; they degrade
// equally gracefully when the challenge is restricted out of the scenario.
// The full (unrestricted) catalog still maps every on-disk journey.
func LoadJourneys(dir string, cat Catalog) (Journeys, error) {
	out := make(Journeys)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("read journey dir %q: %w", dir, err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name(), "journey.yaml")
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			continue // no journey.yaml -> graceful degrade
		}
		j, err := parseJourney(path, e.Name())
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if _, ok := cat[j.ChallengeID]; !ok {
			// Challenge is not in the (possibly scenario-restricted) catalog:
			// this journey is not part of the active scenario. Skip it.
			continue
		}
		out[j.ChallengeID] = j
	}
	return out, nil
}

func parseJourney(path, dirName string) (Journey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Journey{}, err
	}
	var j Journey
	if err := yaml.Unmarshal(data, &j); err != nil {
		return Journey{}, err
	}
	if j.ChallengeID == "" {
		j.ChallengeID = dirName
	}
	if j.Title == "" {
		return Journey{}, fmt.Errorf("journey %q: title must not be empty", j.ChallengeID)
	}
	return j, nil
}
