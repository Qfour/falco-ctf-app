package hintleak_test

// content_test.go assembles hintleak.Input for each scope from the REAL
// challenges/ and scenarios/ trees (ADR-0026 D5-1 / D5-5), and is shared by the
// V5 test (fixtures_test.go) and the V6 replica mutation tests (hintleak_test.go).

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// content is the loaded text of the whole repo, in memory, so a test can
// mutate a deep copy (clone) without touching the tree.
type content struct {
	ids       []string                   // full catalog, sorted
	journeys  catalog.Journeys           // id -> journey (as authored)
	ruleYAML  map[string]string          // id -> raw rule.yaml ("" when absent)
	fixtures  []hintleak.Item            // EVERY fixture file of EVERY challenge (never narrowed by scope)
	scenarios map[string]scenarioContent // scenario name -> manifest + narrative
}

type scenarioContent struct {
	ids       []string
	narrative catalog.Narrative
}

// scope is one evaluation scope: "full" or "scenario/<name>".
type scope struct {
	name      string
	ids       []string
	narrative catalog.Narrative
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	// Not a Skip: a scan that silently covers nothing is exactly the failure
	// mode V5 exists to prevent (ADR-0026 V5: "走査 0 件は fail").
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root not found at %s: %v", root, err)
	}
	return root
}

func loadContent(t *testing.T) content {
	t.Helper()
	root := repoRoot(t)
	chalDir := filepath.Join(root, "challenges")

	cat, err := catalog.Load(chalDir)
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	c := content{
		ids:       cat.IDs(),
		ruleYAML:  map[string]string{},
		scenarios: map[string]scenarioContent{},
	}
	if c.journeys, err = catalog.LoadJourneys(chalDir, cat); err != nil {
		t.Fatalf("catalog.LoadJourneys: %v", err)
	}
	// D5-1 says "challenges/*/fixtures/**": walk by DIRECTORY, not by challengeId.
	// journeys/rule.yaml are keyed by directory name too (catalog.LoadJourneys), so a
	// challengeId that differs from its directory would silently drop that challenge
	// from this check — make it loud instead.
	for _, id := range c.ids {
		if cat[id].Dir() != id {
			t.Fatalf("challenge %q lives in directory %q: challengeId must equal the directory name (V5 reads journeys/fixtures by directory)", id, cat[id].Dir())
		}
	}
	dirEntries, err := os.ReadDir(chalDir)
	if err != nil {
		t.Fatalf("read %s: %v", chalDir, err)
	}
	var dirs []string
	for _, e := range dirEntries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	for _, id := range dirs {
		if b, err := os.ReadFile(filepath.Join(chalDir, id, "rule.yaml")); err == nil {
			c.ruleYAML[id] = string(b) // raw bytes; hintleak.Check enforces UTF-8
		} else if !os.IsNotExist(err) {
			t.Fatalf("read rule.yaml of %s: %v", id, err)
		}
		fxDir := filepath.Join(chalDir, id, "fixtures")
		if _, err := os.Stat(fxDir); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(fxDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("%s is not a regular file (symlink/special)", p)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(chalDir, p)
			c.fixtures = append(c.fixtures, hintleak.Item{Source: filepath.ToSlash(rel), Text: string(b)})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", fxDir, err)
		}
	}

	manifests, err := filepath.Glob(filepath.Join(root, "scenarios", "*", "scenario.yaml"))
	if err != nil {
		t.Fatalf("glob scenarios: %v", err)
	}
	for _, m := range manifests {
		sc, err := catalog.LoadScenario(m)
		if err != nil {
			t.Fatalf("LoadScenario %s: %v", m, err)
		}
		nar, err := catalog.LoadNarrative(filepath.Join(filepath.Dir(m), "narrative.yaml"))
		if err != nil {
			t.Fatalf("LoadNarrative for %s: %v", m, err)
		}
		c.scenarios[filepath.Base(filepath.Dir(m))] = scenarioContent{ids: sc.Challenges, narrative: nar}
	}
	return c
}

// scopes returns the full catalog plus every scenarios/*/scenario.yaml (D5-5).
func (c content) scopes() []scope {
	out := []scope{{name: "full", ids: c.ids}}
	names := make([]string, 0, len(c.scenarios))
	for n := range c.scenarios {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, scope{name: "scenario/" + n, ids: c.scenarios[n].ids, narrative: c.scenarios[n].narrative})
	}
	return out
}

// input assembles the D5-1 inputs for one scope. Fixtures are always ALL
// challenges' fixtures (a scenario scope does not narrow them: the platform
// falls back to `all` when scenario auto-derivation fails).
func (c content) input(s scope) (hintleak.Input, error) {
	journeys := catalog.Journeys{}
	for _, id := range s.ids {
		if j, ok := c.journeys[id]; ok {
			journeys[id] = j
		}
	}
	// briefing: a scenario narrative override REPLACES it (never appends).
	if err := catalog.ApplyNarrativeOverrides(journeys, s.narrative); err != nil {
		return hintleak.Input{}, fmt.Errorf("scope %s: %w", s.name, err)
	}
	in := hintleak.Input{Targets: c.fixtures}
	for _, id := range s.ids {
		if j, ok := journeys[id]; ok {
			for i, h := range j.Hints {
				in.Hints = append(in.Hints, hintleak.Item{Source: fmt.Sprintf("%s hints[%d]", id, i+1), Text: h.Text})
			}
			in.Free = append(in.Free, hintleak.Item{Source: id + " briefing", Text: j.Briefing})
			for i, st := range j.Steps {
				in.Free = append(in.Free,
					hintleak.Item{Source: fmt.Sprintf("%s steps[%d].label", id, i+1), Text: st.Label},
					hintleak.Item{Source: fmt.Sprintf("%s steps[%d].detail", id, i+1), Text: st.Detail})
			}
		}
		if r, ok := c.ruleYAML[id]; ok {
			in.Free = append(in.Free, hintleak.Item{Source: id + " rule.yaml", Text: r})
		}
	}
	return in, nil
}

// clone deep-copies the parts a mutation test may edit.
func (c content) clone() content {
	out := c
	out.journeys = catalog.Journeys{}
	for id, j := range c.journeys {
		j.Steps = append([]catalog.JourneyStep(nil), j.Steps...)
		j.Hints = append(catalog.JourneyHints(nil), j.Hints...)
		out.journeys[id] = j
	}
	out.fixtures = append([]hintleak.Item(nil), c.fixtures...)
	return out
}

// describe renders violations for a failure message: one line per fixture.
func describe(vs []hintleak.Violation) string {
	byFixture := map[string][]string{}
	for _, v := range vs {
		byFixture[v.Target] = append(byFixture[v.Target], fmt.Sprintf("%q (hint: %s)", v.Gram, strings.Join(v.HintSources, ", ")))
	}
	var lines []string
	for f, gs := range byFixture {
		lines = append(lines, fmt.Sprintf("  %s: %d distinct n-gram(s), first %s", f, len(gs), gs[0]))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
