package catalog

import (
	"fmt"
	"os"

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
	return s, nil
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
