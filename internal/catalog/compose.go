package catalog

// compose.go flattens a course (ADR-0055 D4), or a module's course of itself alone (D6),
// into the Scenario the generator writes (D5), and holds the composition to C1. It is
// pure: its input is its arguments; it reads no file and no environment and logs
// nothing, so the generator (S2b) and a test run the same function on the same values.

import (
	"fmt"
	"slices"
)

// The values of a composed scenario's source.kind (D5).
const (
	KindModule = "module"
	KindCourse = "course"
)

// Compose flattens course c into the Scenario its scenario.yaml holds (scenario.go). modules is the pool of modules by id (holding more than the
// course uses is fine); cat is the pool of challenges (challenges/). It is fail-closed,
// and every error names the course and the module or challenge at fault:
//   - c and each module it uses must pass the checks LoadCourse and LoadModule make;
//   - every module of c is in modules, under its own id, and an edition c names is one
//     the module declares;
//   - C1: every mission is a challenge of cat; a challenge two modules hold is shown once,
//     at its first place, and only when c lists it in shared; a shared id that no two
//     modules hold is an error too.
func Compose(c Course, modules map[string]Module, cat Catalog) (Scenario, error) {
	if err := c.validate(); err != nil {
		return Scenario{}, fmt.Errorf("course %q: %w", c.ID, err)
	}
	parts := make([]Module, 0, len(c.Modules))
	src := ScenarioSource{Kind: KindCourse}
	for _, ref := range c.Modules {
		m, ok := modules[ref.ID]
		if !ok {
			return Scenario{}, fmt.Errorf("course %q: module %q is not in the module pool", c.ID, ref.ID)
		}
		if m.ID != ref.ID {
			return Scenario{}, fmt.Errorf("course %q: the module pool holds module %q under the key %q", c.ID, m.ID, ref.ID)
		}
		if _, ok := m.Editions[ref.Edition]; ref.Edition != "" && !ok {
			return Scenario{}, fmt.Errorf("course %q: module %q has no edition %q", c.ID, ref.ID, ref.Edition)
		}
		parts = append(parts, m)
		src.Modules = append(src.Modules, ScenarioModule{ID: m.ID, Version: m.Version, Edition: ref.Edition})
	}
	challenges, err := flatten(parts, c.Shared, cat)
	if err != nil {
		return Scenario{}, fmt.Errorf("course %q: %w", c.ID, err)
	}
	return Scenario{ID: c.ID, Title: c.Title, Challenges: challenges, Source: src}, nil
}

// ComposeSolo is the course of module m alone (D6): its directory's own scenario.
func ComposeSolo(m Module, cat Catalog) (Scenario, error) {
	challenges, err := flatten([]Module{m}, nil, cat)
	if err != nil {
		return Scenario{}, err
	}
	src := ScenarioSource{Kind: KindModule, Modules: []ScenarioModule{{ID: m.ID, Version: m.Version}}}
	return Scenario{ID: m.ID, Title: m.Title, Challenges: challenges, Source: src}, nil
}

// flatten is the missions of parts in order, each challenge once (C1).
func flatten(parts []Module, shared []string, cat Catalog) ([]string, error) {
	// firstIn maps a challenge id to the module it first appears in.
	firstIn := make(map[string]string)
	// repeated holds the shared ids a second module holds.
	repeated := make(map[string]bool)
	var out []string
	for _, m := range parts {
		if err := m.validate(); err != nil {
			return nil, fmt.Errorf("module %q: %w", m.ID, err)
		}
		for _, id := range m.Missions {
			if _, ok := cat[id]; !ok {
				return nil, fmt.Errorf("module %q: mission %q is not a challenge of the pool", m.ID, id)
			}
			prev, seen := firstIn[id]
			if !seen {
				firstIn[id] = m.ID
				out = append(out, id)
				continue
			}
			if !slices.Contains(shared, id) {
				return nil, fmt.Errorf("challenge %q is in module %q and in module %q: a course shows a challenge once; "+
					"list it in shared to keep it at its first place (ADR-0055 C1)", id, prev, m.ID)
			}
			repeated[id] = true
		}
	}
	for _, id := range shared {
		if !repeated[id] {
			return nil, fmt.Errorf("shared lists %q, but no two modules of the course hold it (ADR-0055 C1)", id)
		}
	}
	return out, nil
}
