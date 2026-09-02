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
//	    # OR the structured (unified hints Phase 1) form:
//	  - kind: rule | command | solution
//	    text: <staged hint; 1 -> N approaches the answer>
//	    ruleRefs: [<Falco rule name>, ...]      # optional, omit for "no link"
//	    cheatsheetRef: <cheatsheet anchor/id>    # optional, omit for "no link"
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

// JourneyHint is one staged hint (unified hints Phase 1: Hint1=Rule+link /
// Hint2=Command+link / Hint3=想定解). `Kind` is a display label only — it does
// NOT change the HINT1/HINT2/HINT3 point-cost tier, which stays keyed to the
// hint's 1-based array index (internal/scoreboard/scoring/points.go is
// unmodified by this type). `RuleRefs` names Falco rules from THIS mission's
// rule.yaml/falco-rule.yaml (portal renders them as links); `CheatsheetRef`
// points at a command cheatsheet entry. Both are optional — omitted means "no
// link", not an error.
type JourneyHint struct {
	Kind          string   `yaml:"kind" json:"kind"`
	Text          string   `yaml:"text" json:"text"`
	RuleRefs      []string `yaml:"ruleRefs,omitempty" json:"ruleRefs,omitempty"`
	CheatsheetRef string   `yaml:"cheatsheetRef,omitempty" json:"cheatsheetRef,omitempty"`
}

// hintKindForIndex infers a Kind for a legacy scalar-string hint from its
// 0-based position in the array, mirroring the historical HINT1/HINT2/HINT3
// staging: the 1st hint nudges toward the relevant rule, the 2nd toward the
// command, and the 3rd (and any further hint) toward the solution.
func hintKindForIndex(i int) string {
	switch i {
	case 0:
		return "rule"
	case 1:
		return "command"
	default:
		return "solution"
	}
}

// JourneyHints is Journey.Hints' type. It carries a custom UnmarshalYAML so a
// journey.yaml written in the OLD `hints: [<string>, ...]` form keeps
// decoding unchanged (back-compat — no existing journey.yaml needs to be
// rewritten by this change): each scalar element becomes a JourneyHint with
// Kind inferred from its index (hintKindForIndex) and no RuleRefs/
// CheatsheetRef. A mapping element (the new structured form) decodes as a
// JourneyHint directly. The two forms may be freely mixed within one file.
type JourneyHints []JourneyHint

func (hs *JourneyHints) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("hints: expected a YAML sequence, got kind %d", node.Kind)
	}
	out := make(JourneyHints, 0, len(node.Content))
	for i, item := range node.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			var text string
			if err := item.Decode(&text); err != nil {
				return fmt.Errorf("hints[%d]: %w", i, err)
			}
			out = append(out, JourneyHint{Kind: hintKindForIndex(i), Text: text})
		case yaml.MappingNode:
			var h JourneyHint
			if err := item.Decode(&h); err != nil {
				return fmt.Errorf("hints[%d]: %w", i, err)
			}
			out = append(out, h)
		default:
			return fmt.Errorf("hints[%d]: unsupported YAML node kind %d (want scalar or mapping)", i, item.Kind)
		}
	}
	*hs = out
	return nil
}

// Journey is the narrative wrapper around a challenge for the /journey UI.
type Journey struct {
	ChallengeID string        `yaml:"challengeId" json:"challengeId"`
	Title       string        `yaml:"title" json:"title"`
	Tagline     string        `yaml:"tagline" json:"tagline"`
	Briefing    string        `yaml:"briefing" json:"briefing"`
	Steps       []JourneyStep `yaml:"steps" json:"steps"`
	Hints       JourneyHints  `yaml:"hints" json:"hints"`
	// Bridge is the narrative pull toward the next mission, surfaced when this
	// mission clears (#47). Optional and display-only — empty means "no teaser".
	Bridge  string `yaml:"bridge" json:"bridge"`
	DocsURL string `yaml:"docsUrl" json:"docsUrl"`
}

// Journeys maps challengeId -> Journey. Missing entries mean "no journey
// content authored yet"; callers must handle absence gracefully.
type Journeys map[string]Journey

// LoadJourneys scans <dir>/<NN>-<slug>/journey.yaml for every subdirectory and
// returns the parsed journeys keyed by challengeId. Validation separates two
// distinct conditions that a single "is the id in cat?" check used to conflate:
//
//   - TYPO (loud error): a journey.yaml declares a non-empty challengeId that
//     does not equal its directory name. The directory IS the challenge; a
//     mismatching id is a content mistake that would silently drop the mission
//     from the /journey UI. This is an ERROR regardless of whether `cat` is the
//     full or a scenario-restricted catalog. An empty challengeId defaults to
//     the directory name (mirroring catalog.Load) and is not a typo.
//
//   - RESTRICT-OUT (silent skip): the directory name is not present in `cat`.
//     `cat` may be a scenario-restricted catalog, so a challenge outside the
//     active scenario is simply not part of this run and its journey is skipped.
//     Journeys "graceful degrade when absent"; they degrade equally gracefully
//     when the challenge is restricted out of the scenario.
//
// A missing journey.yaml is not an error (graceful degrade). A malformed one
// (parse error, or empty title) IS an error so a content typo is loud rather
// than silently dropping the mission's briefing.
//
// Note on the skip predicate: skip keys off the DIRECTORY name (e.Name()), not
// the declared challengeId. A declared id that disagrees with the directory is
// caught as a typo above; the directory name is the authoritative identity used
// to decide scenario membership. This is why a full catalog and a subset both
// surface typos as errors while only genuinely restricted-out challenges skip.
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
		// TYPO: a declared id that disagrees with the directory name is a
		// content mistake. parseJourney already defaulted an empty id to the
		// directory name, so at this point j.ChallengeID != e.Name() means the
		// author wrote a non-empty id that does not match the directory.
		if j.ChallengeID != e.Name() {
			return nil, fmt.Errorf(
				"journey %s: challengeId %q does not match directory name %q (typo?)",
				path, j.ChallengeID, e.Name())
		}
		// RESTRICT-OUT: the directory (= this challenge) is not in the active,
		// possibly scenario-restricted catalog. Skip it, not part of this run.
		if _, ok := cat[e.Name()]; !ok {
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

// ValidateHintRuleRefs checks that every JourneyHint.RuleRefs entry names a
// Falco rule that actually belongs to THAT mission — either its display-only
// rule.yaml excerpt (catalog.LoadRuleExcerpts) or its scoring metadata's
// ExpectedRules/ForbiddenRules (falco-rule.yaml, via cat). A ref outside both
// sets is very likely a content typo (a rule name copied from the wrong
// mission, or misspelled) that would silently render a dead/misleading link
// in the portal.
//
// Deliberately advisory (warn), not fail-closed (error): a bad ruleRef is a
// content-authoring mistake in participant-facing copy, not a scoring or
// security defect (hints never carry flag values, conventions I10), so it
// must not be able to take the whole scoreboard down at boot — unlike a
// missing/malformed journey.yaml (LoadJourneys' TYPO case), which IS loud
// because it silently drops an entire mission's briefing. Callers log the
// returned warnings; they are ordered by challengeId then hint index for
// determinism. A challenge with no rule.yaml and no catalog entry (should not
// happen — journeys is already restricted to `cat`'s membership) simply
// yields "ref not found" for every ruleRef, same as any other typo.
func ValidateHintRuleRefs(journeys Journeys, cat Catalog, rules FalcoRuleExcerpts) []string {
	var warnings []string
	ids := make([]string, 0, len(journeys))
	for id := range journeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		j := journeys[id]
		known := make(map[string]struct{})
		for _, r := range rules[id].Rules {
			known[r.Name] = struct{}{}
		}
		if ch, ok := cat[id]; ok {
			for _, r := range ch.ExpectedRules {
				known[r] = struct{}{}
			}
			for _, r := range ch.ForbiddenRules {
				known[r] = struct{}{}
			}
		}
		for i, h := range j.Hints {
			for _, ref := range h.RuleRefs {
				if _, ok := known[ref]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"journey %s hint[%d]: ruleRef %q not found in this mission's rule.yaml or falco-rule.yaml expected/forbidden rules",
						id, i+1, ref))
				}
			}
		}
	}
	return warnings
}
