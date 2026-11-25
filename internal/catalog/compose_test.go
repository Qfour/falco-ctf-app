package catalog

// ADR-0055 S2a, C1: Compose flattens a course over the module and challenge pools.

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// composeFixture is a course of two modules sharing 02-b, over sampleCatalog (01-a,
// 02-b, 03-c), with an unused module in the pool. mod-b lists 02-b after 03-c, so the
// flattened order shows the shared challenge kept at its first place, not moved.
func composeFixture() (Course, map[string]Module, Catalog) {
	mod := func(id string, missions ...string) Module {
		return Module{
			ID:       id,
			Title:    "Title " + id,
			Summary:  "s",
			Outcomes: []string{"a", "b", "c"},
			Version:  1,
			Level:    1,
			Duration: Duration{HandsOnMinutes: 10},
			Missions: missions,
		}
	}
	a := mod("mod-a", "01-a", "02-b")
	a.Editions = map[string]Edition{"2h": {Duration: Duration{HandsOnMinutes: 60}, Playbook: "playbook-2h.md"}}
	c := Course{
		ID:      "course-x",
		Title:   "Course X",
		Timebox: Timebox{Minutes: 120},
		Modules: []CourseModule{{ID: "mod-a", Edition: "2h"}, {ID: "mod-b"}},
		Shared:  []string{"02-b"},
	}
	pool := map[string]Module{"mod-a": a, "mod-b": mod("mod-b", "03-c", "02-b"), "mod-z": mod("mod-z", "01-a")}
	return c, pool, sampleCatalog()
}

func TestCompose_FlattensInCourseOrder(t *testing.T) {
	c, pool, cat := composeFixture()
	got, err := Compose(c, pool, cat)
	if err != nil {
		t.Fatal(err)
	}
	wantSrc := ScenarioSource{Kind: KindCourse, Modules: []ScenarioModule{{ID: "mod-a", Version: 1, Edition: "2h"}, {ID: "mod-b", Version: 1}}}
	if got.ID != "course-x" || got.Title != "Course X" || !reflect.DeepEqual(got.Source, wantSrc) {
		t.Fatalf("composed = %+v", got)
	}
	if want := []string{"01-a", "02-b", "03-c"}; !slices.Equal(got.Challenges, want) {
		t.Fatalf("challenges = %v, want %v", got.Challenges, want)
	}
}

// One defect per case. The untouched fixture composes in every case first (the paired
// positive), so a red row is the defect's and not the fixture's.
func TestCompose_OneDefectOneCase(t *testing.T) {
	cases := []struct {
		name string
		bad  func(c *Course, pool map[string]Module)
		want string
	}{
		{"mission not in the pool", func(_ *Course, p map[string]Module) {
			m := p["mod-b"]
			m.Missions = []string{"03-c", "99-x", "02-b"}
			p["mod-b"] = m
		}, `module "mod-b": mission "99-x" is not a challenge of the pool`},
		{"mission twice in one module", func(_ *Course, p map[string]Module) {
			m := p["mod-a"]
			m.Missions = []string{"01-a", "02-b", "01-a"}
			p["mod-a"] = m
		}, `module "mod-a": mission "01-a" is listed more than once`},
		{"two modules hold a challenge shared does not list", func(c *Course, _ map[string]Module) {
			c.Shared = nil
		}, `challenge "02-b" is in module "mod-a" and in module "mod-b"`},
		{"shared lists a challenge no two modules hold", func(c *Course, _ map[string]Module) {
			c.Shared = []string{"02-b", "01-a"}
		}, `shared lists "01-a"`},
		{"shared lists an id twice", func(c *Course, _ map[string]Module) {
			c.Shared = []string{"02-b", "02-b"}
		}, `shared id "02-b" is listed more than once`},
		{"module not in the pool", func(c *Course, _ map[string]Module) {
			c.Modules = append(c.Modules, CourseModule{ID: "mod-q"})
		}, `module "mod-q" is not in the module pool`},
		{"module twice in the course", func(c *Course, _ map[string]Module) {
			c.Modules = append(c.Modules, CourseModule{ID: "mod-a"})
		}, `module "mod-a" is listed more than once`},
		{"edition the module does not declare", func(c *Course, _ map[string]Module) {
			c.Modules[0].Edition = "3h"
		}, `module "mod-a" has no edition "3h"`},
		{"pool key is not the module id", func(_ *Course, p map[string]Module) {
			m := p["mod-b"]
			m.ID = "mod-q"
			p["mod-b"] = m
		}, `holds module "mod-q" under the key "mod-b"`},
		{"a module that LoadModule would refuse", func(_ *Course, p map[string]Module) {
			m := p["mod-b"]
			m.Version = 0
			p["mod-b"] = m
		}, `module "mod-b": version must be at least 1`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, pool, cat := composeFixture()
			if _, err := Compose(c, pool, cat); err != nil {
				t.Fatalf("the untouched fixture was rejected: %v", err)
			}
			tc.bad(&c, pool)
			_, err := Compose(c, pool, cat)
			if err == nil {
				t.Fatal("the defect was accepted")
			}
			for _, w := range []string{tc.want, `course "course-x"`} {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("error %q does not name %q", err, w)
				}
			}
		})
	}
}

// D6: a module is the course of itself alone, with the same C1 checks.
func TestComposeSolo(t *testing.T) {
	_, pool, cat := composeFixture()
	got, err := ComposeSolo(pool["mod-b"], cat)
	if err != nil {
		t.Fatal(err)
	}
	wantSrc := ScenarioSource{Kind: KindModule, Modules: []ScenarioModule{{ID: "mod-b", Version: 1}}}
	if got.ID != "mod-b" || got.Title != "Title mod-b" || !slices.Equal(got.Challenges, []string{"03-c", "02-b"}) || !reflect.DeepEqual(got.Source, wantSrc) {
		t.Fatalf("solo course of mod-b = %+v", got)
	}
	bad := pool["mod-b"]
	bad.Missions = []string{"03-c", "99-x"}
	if _, err := ComposeSolo(bad, cat); err == nil || !strings.Contains(err.Error(), `module "mod-b": mission "99-x"`) {
		t.Fatalf("a mission outside the pool: %v", err)
	}
}
