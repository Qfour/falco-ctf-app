package catalog

// ADR-0055 S2c (V4): the scenario.yaml loader is strict and takes a generated file only.
// Every fixture is under t.TempDir(), built by catalogtest (the one fixture helper) and, for a
// defect, by one edit of its text.

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog/catalogtest"
)

func sampleCatalog() Catalog {
	return Catalog{
		"01-a": {ID: "01-a", Type: "trigger", ExpectedRules: []string{"r"}},
		"02-b": {ID: "02-b", Type: "trigger", ExpectedRules: []string{"r"}},
		"03-c": {ID: "03-c", Type: "evade", ExpectedFlag: "FALCO{x}"},
	}
}

// putFile writes body at <dir>/<name> (and dir) and returns the path.
func putFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// edit is s with the first old replaced by repl; the test fails when old is not in s (the
// fixture changed and the case would test nothing).
func edit(t *testing.T, s, old, repl string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("the fixture has no %q: update the case", old)
	}
	return strings.Replace(s, old, repl, 1)
}

func TestLoadScenario_TheGeneratedFormLoads(t *testing.T) {
	p := catalogtest.WriteScenario(t, t.TempDir(), "demo", "02-b", "01-a")
	s, err := LoadScenario(p)
	if err != nil {
		t.Fatal(err)
	}
	want := Scenario{ID: "demo", Title: "Title demo", Challenges: []string{"02-b", "01-a"},
		Source:       ScenarioSource{Kind: KindModule, Modules: []ScenarioModule{{ID: "demo", Version: 1}}},
		Requirements: ScenarioRequirements{Answers: []string{}, Rules: []string{}}}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("LoadScenario = %+v, want %+v", s, want)
	}
}

// One defect per case, each on the generator's form of a module alone (accepted first); a
// course's form with an edition is accepted too.
func TestDecodeScenario_OneDefectOneCase(t *testing.T) {
	good := catalogtest.Scenario("demo", "01-a", "02-b")
	const mod = "    - id: demo\n      version: 1\n"
	course := edit(t, edit(t, good, "kind: module", "kind: course"), mod, "    - id: mod-a\n      version: 2\n      edition: 2h\n    - id: mod-b\n      version: 1\n")
	for _, ok := range []string{good, course} {
		if _, err := DecodeScenario([]byte(ok)); err != nil {
			t.Fatalf("the control was refused (the cases below would prove nothing): %v\n%s", err, ok)
		}
	}
	cases := []struct{ name, body, want string }{
		{"the key tactics (D6)", good + "tactics:\n  - Discovery\n", "field tactics not found"},
		{"the key flags (C6)", good + "flags:\n  01-a: FALCO{dev-x}\n", "field flags not found"},
		{"the key requirements twice (S3a; its own cases: requirements_test.go)", good + "requirements: {detect: false}\n", `"requirements" already defined`},
		{"the key hints", good + "hints: [x]\n", "field hints not found"},
		{"an unknown key in source", edit(t, good, "  kind: module\n", "  kind: module\n  by: x\n"), "field by not found"},
		{"an unknown key in a source module", edit(t, good, "      version: 1\n", "      version: 1\n      title: x\n"), "field title not found"},
		{"a repeated key", good + "id: demo\n", `"id" already defined`},
		{"an anchor", edit(t, good, "challenges:\n", "challenges: &c\n"), "is not allowed"},
		{"a merge key", edit(t, good, "  kind: module\n", "  <<: {kind: module}\n"), "is not allowed"},
		{"a second document", good + "---\nid: demo\n", "more than one document"},
		{"no document", "", "no document"},
		{"an id that is not a scenario name", edit(t, good, "id: demo\n", "id: Demo\n"), "is not a scenario name"},
		{"an empty title", edit(t, good, "title: Title demo\n", "title: \"\"\n"), "title is empty"},
		{"no challenges", edit(t, good, "challenges:\n  - 01-a\n  - 02-b\n", "challenges: []\n"), "no challenges listed"},
		{"a challenge twice", edit(t, good, "  - 02-b\n", "  - 01-a\n"), `challenge "01-a" is listed more than once`},
		{"a challenge that is not a challenge id", edit(t, good, "  - 02-b\n", "  - b\n"), `challenge "b" is not a challenge id`},
		{"no source", edit(t, good, "source:\n  kind: module\n  modules:\n"+mod, ""), `source.kind "" is neither`},
		{"an unknown kind", edit(t, good, "kind: module", "kind: bundle"), `source.kind "bundle" is neither`},
		{"no source module", edit(t, good, "  modules:\n"+mod, "  modules: []\n"), "source.modules is empty"},
		{"a source module that is not a scenario name", edit(t, good, mod, "    - id: Demo\n      version: 1\n"), "source.modules id"},
		{"a source module of version 0", edit(t, good, "version: 1", "version: 0"), "version must be at least 1"},
		{"a source module of an invalid edition", edit(t, course, "edition: 2h", "edition: Two_h"), "edition name"},
		{"a source module twice", edit(t, course, "- id: mod-b", "- id: mod-a"), `source.modules id "mod-a" is listed more than once`},
		{"kind module, of another module", edit(t, good, "- id: demo", "- id: other"), "alone, with no edition"},
		{"kind module, of two modules", edit(t, good, mod, mod+"    - id: other\n      version: 1\n"), "alone, with no edition"},
		{"kind module, with an edition", edit(t, good, mod, mod+"      edition: 2h\n"), "alone, with no edition"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeScenario([]byte(c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("DecodeScenario = %v, want an error containing %q\n%s", err, c.want, c.body)
			}
		})
	}
}

// What LoadScenario holds a file to beyond DecodeScenario, on the path the scoreboard starts
// from (LoadScored): the file name, a regular file, id = directory name, and a source beside
// it of the kind the file names. A file without the generator's header loads: the source
// file is what makes a scenario generated, not a comment.
func TestLoadScenario_OnlyAGeneratedFileOfItsDirectory(t *testing.T) {
	const course = "id: alpha\ntitle: Course\ntimebox: {minutes: 60}\nmodules:\n  - id: mod-a\n"
	// setup gets dir = <root>/alpha and returns the path to load; want "" is: it loads.
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string) string
		want  string
	}{
		{"the generated file of a module (control)", func(t *testing.T, dir string) string {
			return catalogtest.WriteScenario(t, filepath.Dir(dir), "alpha", "01-a")
		}, ""},
		{"no header (it is not looked at)", func(t *testing.T, dir string) string {
			catalogtest.WriteScenario(t, filepath.Dir(dir), "alpha", "01-a")
			_, body, _ := strings.Cut(catalogtest.Scenario("alpha", "01-a"), "\nid: ")
			return putFile(t, dir, ScenarioFile, "id: "+body)
		}, ""},
		{"a hand-written file: no source in its directory", func(t *testing.T, dir string) string {
			return putFile(t, dir, ScenarioFile, catalogtest.Scenario("alpha", "01-a"))
		}, "holds neither module.yaml nor course.yaml"},
		{"both sources in its directory", func(t *testing.T, dir string) string {
			putFile(t, dir, CourseFile, course)
			return catalogtest.WriteScenario(t, filepath.Dir(dir), "alpha", "01-a")
		}, "holds both"},
		{"a source the strict parser refuses", func(t *testing.T, dir string) string {
			p := catalogtest.WriteScenario(t, filepath.Dir(dir), "alpha", "01-a")
			putFile(t, dir, ModuleFile, catalogtest.Module("alpha", "01-a")+"tactics: [x]\n")
			return p
		}, "field tactics not found"},
		{"an id that is another name", func(t *testing.T, dir string) string {
			putFile(t, dir, ModuleFile, catalogtest.Module("alpha", "01-a"))
			return putFile(t, dir, ScenarioFile, catalogtest.Scenario("beta", "01-a"))
		}, `id "beta" is not the name of its directory "alpha"`},
		{"an id that differs only in case", func(t *testing.T, dir string) string {
			putFile(t, dir, ModuleFile, catalogtest.Module("alpha", "01-a"))
			return putFile(t, dir, ScenarioFile, edit(t, catalogtest.Scenario("alpha", "01-a"), "id: alpha\n", "id: Alpha\n"))
		}, `id "Alpha" is not a scenario name`},
		{"a file of another name", func(t *testing.T, dir string) string {
			putFile(t, dir, ModuleFile, catalogtest.Module("alpha", "01-a"))
			return putFile(t, dir, "other.yaml", catalogtest.Scenario("alpha", "01-a"))
		}, `named "other.yaml", not scenario.yaml`},
		{"a symlink", func(t *testing.T, dir string) string {
			p := catalogtest.WriteScenario(t, filepath.Dir(dir), "alpha", "01-a")
			if err := os.Rename(p, p+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".real", p); err != nil {
				t.Fatal(err)
			}
			return p
		}, "not a regular file"},
		{"kind course beside a module.yaml", func(t *testing.T, dir string) string {
			catalogtest.WriteScenario(t, filepath.Dir(dir), "alpha", "01-a")
			return putFile(t, dir, ScenarioFile, edit(t, catalogtest.Scenario("alpha", "01-a"), "kind: module", "kind: course"))
		}, `source.kind is "course", but its directory holds a module`},
		{"kind module beside a course.yaml", func(t *testing.T, dir string) string {
			putFile(t, dir, CourseFile, course)
			return putFile(t, dir, ScenarioFile, catalogtest.Scenario("alpha", "01-a"))
		}, `source.kind is "module", but its directory holds a course`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.setup(t, filepath.Join(t.TempDir(), "alpha"))
			s, err := LoadScenario(p)
			if c.want == "" {
				if err != nil || s.ID != "alpha" || !slices.Equal(s.Challenges, []string{"01-a"}) {
					t.Fatalf("LoadScenario = %+v, %v; want alpha [01-a]", s, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), p) {
				t.Fatalf("LoadScenario = %+v, %v; want an error naming %s and containing %q", s, err, p, c.want)
			}
		})
	}
}

// The scoreboard's start (LoadScored) refuses a scenario whose id is not its directory's
// name, and loads the same scenario in a directory of its name.
func TestLoadScored_ScenarioIDMustBeTheDirectoryName(t *testing.T) {
	chal := t.TempDir()
	putFile(t, filepath.Join(chal, "01-a"), "falco-rule.yaml", "type: trigger\nexpectedRules: [r]\n")
	root := t.TempDir()
	good := WriteScenarioFor(t, root, chal, "alpha", "01-a")
	if scored, err := LoadScored(chal, good, ""); err != nil || scored.ScenarioID != "alpha" {
		t.Fatalf("LoadScored(%s) = %+v, %v; want the scenario alpha", good, scored, err)
	}
	dir := filepath.Join(root, "beta")
	putFile(t, dir, ModuleFile, catalogtest.Module("beta", "01-a"))
	bad := putFile(t, dir, ScenarioFile, catalogtest.Scenario("alpha", "01-a"))
	if _, err := LoadScored(chal, bad, ""); err == nil || !strings.Contains(err.Error(), `id "alpha" is not the name of its directory "beta"`) {
		t.Fatalf("LoadScored(%s) = %v; want the id refused", bad, err)
	}
}

// LoadScenarios loads every scenario of a root in path order, and any file LoadScenario
// refuses fails the whole set: two directories declaring one id (each id must be its
// directory's), a copy whose id was left behind next to its good sibling, a sibling with no
// challenges. A root with no scenario.yaml is an error, never "nothing to check".
func TestLoadScenarios(t *testing.T) {
	root := t.TempDir()
	catalogtest.WriteScenario(t, root, "beta", "02-b")
	catalogtest.WriteScenario(t, root, "alpha", "01-a")
	got, err := LoadScenarios(root)
	if err != nil || len(got) != 2 || got[0].ID != "alpha" || got[1].ID != "beta" {
		t.Fatalf("LoadScenarios = %+v, %v; want alpha then beta", got, err)
	}
	cases := []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   string
	}{
		{"two directories declaring one id", func(t *testing.T, root string) {
			putFile(t, filepath.Join(root, "beta"), ScenarioFile, catalogtest.Scenario("alpha", "02-b"))
		}, `id "alpha" is not the name of its directory "beta"`},
		{"a copy whose id was left behind", func(t *testing.T, root string) {
			dir := filepath.Join(root, "gamma")
			putFile(t, dir, ModuleFile, catalogtest.Module("gamma", "02-b"))
			putFile(t, dir, ScenarioFile, catalogtest.Scenario("alpha-copy", "02-b"))
		}, `id "alpha-copy" is not the name of its directory "gamma"`},
		{"a sibling with no challenges", func(t *testing.T, root string) {
			putFile(t, filepath.Join(root, "beta"), ScenarioFile, edit(t, catalogtest.Scenario("beta", "02-b"), "challenges:\n  - 02-b\n", ""))
		}, "no challenges listed"},
		{"a sibling with an empty id", func(t *testing.T, root string) {
			putFile(t, filepath.Join(root, "beta"), ScenarioFile, edit(t, catalogtest.Scenario("beta", "02-b"), "id: beta\n", "id: \"\"\n"))
		}, `id "" is not a scenario name`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			catalogtest.WriteScenario(t, root, "alpha", "01-a")
			catalogtest.WriteScenario(t, root, "beta", "02-b")
			c.mutate(t, root)
			if got, err := LoadScenarios(root); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("LoadScenarios = %+v, %v; want an error containing %q", got, err, c.want)
			}
		})
	}
	for _, r := range []string{t.TempDir(), filepath.Join(t.TempDir(), "does-not-exist")} {
		if _, err := LoadScenarios(r); err == nil {
			t.Fatalf("LoadScenarios(%s): expected an error for a root with no scenario.yaml", r)
		}
	}
}

func TestRestrict_SubsetOnly(t *testing.T) {
	c := sampleCatalog()
	got, err := c.Restrict([]string{"02-b", "03-c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 challenges, got %d", len(got))
	}
	if _, ok := got["01-a"]; ok {
		t.Fatal("01-a should be excluded")
	}
}

func TestRestrict_UnknownFailsClosed(t *testing.T) {
	c := sampleCatalog()
	if _, err := c.Restrict([]string{"02-b", "99-missing"}); err == nil {
		t.Fatal("expected error for unknown challenge id")
	}
}
