package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"
)

// Scenario is an event composition: an ordered subset of challenges run as one
// event (e.g. a 2-hour beginner killchain vs the full 10-mission track). The
// challenge content lives in challenges/; a scenario just selects + names them.
type Scenario struct {
	ID         string   `yaml:"id"`
	Title      string   `yaml:"title"`
	Challenges []string `yaml:"challenges"`
}

// LoadScenario reads a scenario manifest (scenarios/<name>/scenario.yaml).
//
// Fail-closed: a manifest that lists no challenge, or lists the same challenge
// id twice, is an error (a duplicate would put the mission twice in the order
// the scoreboard walks while the restricted catalog holds it once). The decode
// is deliberately NOT strict: scenario.yaml carries an advisory `tactics:` key
// that Go ignores (P27-3), so rejecting unknown keys would break every shipped
// manifest. The id of a manifest is checked against the other manifests by
// LoadScenarios, which sees them all; this function sees one file.
func LoadScenario(path string) (Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Scenario{}, fmt.Errorf("read scenario %q: %w", path, err)
	}
	var s Scenario
	if err := yaml.Unmarshal(data, &s); err != nil {
		return Scenario{}, fmt.Errorf("parse scenario %q: %w", path, err)
	}
	if len(s.Challenges) == 0 {
		return Scenario{}, fmt.Errorf("scenario %q: no challenges listed", path)
	}
	seen := make(map[string]struct{}, len(s.Challenges))
	for _, id := range s.Challenges {
		if _, dup := seen[id]; dup {
			return Scenario{}, fmt.Errorf("scenario %q: challenge %q is listed more than once", path, id)
		}
		seen[id] = struct{}{}
	}
	return s, nil
}

// LoadScenarios reads every <root>/<name>/scenario.yaml (root is the
// scenarios/ directory) in path order and returns them. It is fail-closed:
//   - any manifest LoadScenario rejects is an error;
//   - a manifest with an empty id is an error;
//   - two manifests declaring the same id are an error naming both paths (the
//     id is what the scoreboard reports as the scenario, and the platform
//     derives a workspace's scope from the directory name: two directories
//     answering to one id make "which scenario is this" ambiguous);
//   - no manifest at all is an error (a wrong root must not read as "nothing
//     to check").
func LoadScenarios(root string) ([]Scenario, error) {
	paths, err := filepath.Glob(filepath.Join(root, "*", "scenario.yaml"))
	if err != nil {
		return nil, fmt.Errorf("list scenarios under %q: %w", root, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no <name>/scenario.yaml found under %q", root)
	}
	slices.Sort(paths)
	firstPath := make(map[string]string, len(paths))
	out := make([]Scenario, 0, len(paths))
	for _, p := range paths {
		s, err := LoadScenario(p)
		if err != nil {
			return nil, err
		}
		if s.ID == "" {
			return nil, fmt.Errorf("scenario %q: id is empty", p)
		}
		if prev, dup := firstPath[s.ID]; dup {
			return nil, fmt.Errorf("scenario id %q is declared by both %q and %q", s.ID, prev, p)
		}
		firstPath[s.ID] = p
		out = append(out, s)
	}
	return out, nil
}

// Restrict returns a new Catalog containing only the named challenges. It is
// fail-closed: an id with no matching challenge is an error, so a typo'd
// scenario manifest is loud rather than silently dropping a mission.
func (c Catalog) Restrict(ids []string) (Catalog, error) {
	out := make(Catalog, len(ids))
	for _, id := range ids {
		ch, ok := c[id]
		if !ok {
			return nil, fmt.Errorf("scenario references unknown challenge %q", id)
		}
		out[id] = ch
	}
	return out, nil
}
