package catalog

// rules.go loads the DISPLAY-ONLY Falco rule excerpt for the Story tab's
// "Falco Rule" panel (P23 Story-as-docs redesign) from
// `challenges/<NN>-<slug>/rule.yaml`. This is the SAME source file the old
// docs-site (docs-site/gen-pages.py) has always rendered after the mission
// briefing — see .claude/rules/falco-ctf-app-conventions.md's "課題ドキュメント用
// rule.yaml" section: it is extracted from the ruleset the event actually
// deploys, and is explicitly NOT falco-rule.yaml (the scoring metadata:
// expectedRules/forbiddenRules/expectedFlag). Surfacing it in the portal is
// not a new fairness hole — the old docs site already showed it to every
// participant, and it carries no flag/answer text (I10; verified by the
// design spike's grep audit across all 12 rule.yaml files).
//
// Falco's real rule-file grammar is a flat YAML sequence of maps, each one
// being exactly one of:
//
//	- rule: <name>
//	  desc: <string>
//	  condition: <string>
//	  output: <string>
//	  priority: <string>
//	  tags: [<string>, ...]
//
//	- macro: <name>
//	  condition: <string>
//
//	- list: <name>
//	  items: [<string>, ...]
//
// A single rule.yaml may freely interleave list/macro/rule entries (Falco
// itself requires no particular order). This loader classifies each element
// by which key it carries and buckets it into the corresponding slice, never
// assuming any one entry type is present — see FalcoRuleExcerpt's doc for the
// current-state note (all 12 committed rule.yaml files as of this writing
// carry ONLY `rule:` entries; Lists/Macros are empty until content-lead adds
// list:/macro: definitions for the macros/lists the conditions reference,
// e.g. protected_shell_spawner, grep_commands, private_key_or_password).
// Fail-soft in both directions: an entry matching none of the three keys is
// skipped (forward-compatible with a future Falco YAML feature), and a
// missing rule.yaml file for a challenge is not an error — it simply yields
// no excerpt for that mission (same posture as journey.yaml).

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// FalcoRuleItem is one `- rule: ...` entry.
type FalcoRuleItem struct {
	Name      string   `yaml:"rule" json:"name"`
	Desc      string   `yaml:"desc" json:"desc"`
	Condition string   `yaml:"condition" json:"condition"`
	Output    string   `yaml:"output" json:"output"`
	Priority  string   `yaml:"priority" json:"priority"`
	Tags      []string `yaml:"tags" json:"tags"`
}

// FalcoMacroItem is one `- macro: ...` entry.
type FalcoMacroItem struct {
	Name      string `yaml:"macro" json:"name"`
	Condition string `yaml:"condition" json:"condition"`
}

// FalcoListItem is one `- list: ...` entry.
type FalcoListItem struct {
	Name  string   `yaml:"list" json:"name"`
	Items []string `yaml:"items" json:"items"`
}

// FalcoRuleExcerpt is the parsed, display-only Falco rule excerpt for one
// challenge. Lists/Macros are commonly empty (see package doc's current-state
// note) — callers must render a List/Macro section as absent, not as an
// error, when its slice is empty; only Rules is expected to be non-empty for
// any challenge that has a rule.yaml at all.
type FalcoRuleExcerpt struct {
	Lists  []FalcoListItem  `json:"lists"`
	Macros []FalcoMacroItem `json:"macros"`
	Rules  []FalcoRuleItem  `json:"rules"`
}

// FalcoRuleExcerpts maps challengeId -> excerpt. Missing entries mean "no
// rule.yaml authored for this challenge"; callers must handle absence
// gracefully (same fail-soft contract as Journeys).
type FalcoRuleExcerpts map[string]FalcoRuleExcerpt

// rawRuleEntry mirrors one raw YAML map element before classification. Using
// yaml.Node (rather than a fixed struct) lets a single entry be tested for
// which of rule:/macro:/list: it carries without eagerly committing to one
// shape, then re-decoded into the right typed struct — the same "sniff, then
// decode" approach used for genuinely polymorphic YAML sequences.
type rawRuleEntry struct {
	Rule  *string `yaml:"rule"`
	Macro *string `yaml:"macro"`
	List  *string `yaml:"list"`
}

// LoadRuleExcerpts scans <dir>/<NN>-<slug>/rule.yaml for every subdirectory
// and returns the parsed excerpts keyed by challengeId. Mirrors
// LoadJourneys' shape and error posture:
//   - a missing challenges dir, or a challenge dir with no rule.yaml, is NOT
//     an error (fail-soft; the Story tab's Falco Rule panel is simply omitted
//     for that mission);
//   - a rule.yaml that fails to PARSE (malformed YAML) IS an error — a
//     content mistake should be loud at boot, not silently drop the panel;
//   - directories not present in `cat` are skipped (RESTRICT-OUT, same
//     scenario-membership rule LoadJourneys uses) — cat may be a
//     scenario-restricted catalog, and a rule.yaml for a challenge outside
//     the active scenario is simply not part of this run.
//
// Unlike journey.yaml, rule.yaml carries no challengeId field of its own (it
// is a raw Falco rule-file excerpt, not app-authored content) — identity is
// always the directory name, so there is no typo/mismatch case to detect
// here.
func LoadRuleExcerpts(dir string, cat Catalog) (FalcoRuleExcerpts, error) {
	out := make(FalcoRuleExcerpts)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("read rule excerpt dir %q: %w", dir, err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// RESTRICT-OUT: skip challenges outside the active (possibly
		// scenario-restricted) catalog, exactly like LoadJourneys.
		if _, ok := cat[e.Name()]; !ok {
			continue
		}
		path := filepath.Join(dir, e.Name(), "rule.yaml")
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			continue // no rule.yaml -> graceful degrade
		}
		excerpt, err := parseRuleExcerpt(path)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		out[e.Name()] = excerpt
	}
	return out, nil
}

func parseRuleExcerpt(path string) (FalcoRuleExcerpt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FalcoRuleExcerpt{}, err
	}
	var raw []yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return FalcoRuleExcerpt{}, err
	}
	var out FalcoRuleExcerpt
	for _, node := range raw {
		var sniff rawRuleEntry
		if err := node.Decode(&sniff); err != nil {
			return FalcoRuleExcerpt{}, fmt.Errorf("decode entry: %w", err)
		}
		switch {
		case sniff.Rule != nil:
			var r FalcoRuleItem
			if err := node.Decode(&r); err != nil {
				return FalcoRuleExcerpt{}, fmt.Errorf("decode rule %q: %w", *sniff.Rule, err)
			}
			out.Rules = append(out.Rules, r)
		case sniff.Macro != nil:
			var m FalcoMacroItem
			if err := node.Decode(&m); err != nil {
				return FalcoRuleExcerpt{}, fmt.Errorf("decode macro %q: %w", *sniff.Macro, err)
			}
			out.Macros = append(out.Macros, m)
		case sniff.List != nil:
			var l FalcoListItem
			if err := node.Decode(&l); err != nil {
				return FalcoRuleExcerpt{}, fmt.Errorf("decode list %q: %w", *sniff.List, err)
			}
			out.Lists = append(out.Lists, l)
		default:
			// Forward-compatible skip: an entry with none of rule:/macro:/list:
			// (e.g. a bare comment-only map, or a future Falco YAML feature) is
			// simply not part of this display excerpt.
		}
	}
	// Normalise nil slices to non-nil empty so JSON always marshals `[]`, never
	// `null` — matches the api projection's convention elsewhere (expectedRules/
	// detectedRules in api.go's missionDetail).
	if out.Lists == nil {
		out.Lists = []FalcoListItem{}
	}
	if out.Macros == nil {
		out.Macros = []FalcoMacroItem{}
	}
	if out.Rules == nil {
		out.Rules = []FalcoRuleItem{}
	}
	return out, nil
}
