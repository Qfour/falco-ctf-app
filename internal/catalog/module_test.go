package catalog

// ADR-0055 S2a, V4: the strict parser of module.yaml / course.yaml. Fixtures are written
// under t.TempDir(), never in the real scenarios/ tree.

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/casetable"
)

const moduleBase = `id: mod-a
title: Module A
summary: What module A teaches.
outcomes:
  - first outcome
  - second outcome
  - third outcome
version: 1
level: 2
duration: {handsOnMinutes: 30, debriefMinutes: 10}
editions:
  2h: {handsOnMinutes: 90, debriefMinutes: 20, playbook: playbook-2h.md}
requires: {modules: [mod-0]}
missions:
  - 01-a
  - 02-b
`

const courseBase = `id: course-x
title: Course X
timebox: {minutes: 120, introMinutes: 5, closingMinutes: 5}
modules:
  - id: mod-a
    edition: 2h
  - id: mod-b
shared:
  - 02-b
`

// writeSource writes <TempDir>/<dir>/<file> and returns its path.
func writeSource(t *testing.T, dir, file, body string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), dir)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, file)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// sourceCase is one defect: the base with from replaced by bad must fail with an error
// naming want and the file, and with from replaced by good (the nearest correct text)
// must load, so the check is shown to be more than always red.
type sourceCase struct {
	name, from, bad, good, want string
}

func runSourceCases(t *testing.T, dir, file, base string, cases []sourceCase, load func(string) error) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if strings.Count(base, c.from) != 1 {
				t.Fatalf("fixture: %q is not in the base exactly once", c.from)
			}
			if err := load(writeSource(t, dir, file, strings.Replace(base, c.from, c.good, 1))); err != nil {
				t.Fatalf("the corrected text was rejected: %v", err)
			}
			bad := writeSource(t, dir, file, strings.Replace(base, c.from, c.bad, 1))
			err := load(bad)
			if err == nil {
				t.Fatal("the defect was accepted")
			}
			for _, w := range []string{c.want, bad} {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("error %q does not name %q", err, w)
				}
			}
		})
	}
}

func TestLoadModule_OneDefectOneCase(t *testing.T) {
	runSourceCases(t, "mod-a", ModuleFile, moduleBase, []sourceCase{
		{"unknown key", "level: 2\n", "level: 2\nlevle: 3\n", "level: 2\n", "levle"},
		{"unknown key inside duration", "debriefMinutes: 10}", "debriefMinutes: 10, extra: 1}", "debriefMinutes: 10}", "extra"},
		{"flags key (C6)", "missions:", "flags: {}\nmissions:", "missions:", "flags"},
		{"repeated key", "level: 2\n", "level: 2\nlevel: 3\n", "level: 2\n", "level"},
		{"anchor", "duration: {", "duration: &d {", "duration: {", "anchor"},
		{"merge key without an anchor", "duration: {handsOnMinutes: 30, debriefMinutes: 10}",
			"duration:\n  <<: {handsOnMinutes: 30, debriefMinutes: 10}", "duration:\n  handsOnMinutes: 30\n  debriefMinutes: 10",
			"an anchor, an alias or a merge key"},
		{"edition name outside the grammar", "  2h: {", "  2H: {", "  3h: {", `edition name "2H" is not valid`},
		{"second document", "  - 02-b\n", "  - 02-b\n---\nid: mod-a\n", "  - 02-b\n", "more than one document"},
		{"id outside the grammar", "id: mod-a\n", "id: Mod-A\n", "id: mod-a\n", "not a scenario name"},
		{"id is not the directory", "id: mod-a\n", "id: mod-b\n", "id: mod-a\n", `id "mod-b" is not the name of its directory "mod-a"`},
		{"version 0", "version: 1\n", "version: 0\n", "version: 1\n", "version must be at least 1"},
		{"level above 5", "level: 2\n", "level: 6\n", "level: 5\n", "level must be 1..5"},
		{"level below 1", "level: 2\n", "level: 0\n", "level: 1\n", "level must be 1..5"},
		{"two outcomes", "  - third outcome\n", "", "  - third outcome\n", "outcomes: want 3 to 5, got 2"},
		{"six outcomes", "  - third outcome\n", "  - c\n  - d\n  - e\n  - f\n", "  - c\n  - d\n  - e\n", "got 6"},
		{"empty title", "title: Module A\n", "title: \" \"\n", "title: A\n", "title is empty"},
		{"no missions", "missions:\n  - 01-a\n  - 02-b\n", "missions: []\n", "missions: [01-a]\n", "missions is empty"},
		{"negative debrief", "debriefMinutes: 10}", "debriefMinutes: -1}", "debriefMinutes: 0}", "duration: handsOnMinutes"},
		{"playbook outside the directory", "playbook-2h.md}", "../x.md}", "x.md}", `playbook "../x.md"`},
		{"requires itself", "[mod-0]", "[mod-a]", "[mod-0, mod-1]", "lists the module itself"},
		{"mission twice (C1)", "  - 02-b\n", "  - 02-b\n  - 01-a\n", "  - 02-b\n  - 03-c\n", `mission "01-a" is listed more than once`},
	}, func(p string) error { _, err := LoadModule(p); return err })
}

func TestLoadCourse_OneDefectOneCase(t *testing.T) {
	runSourceCases(t, "course-x", CourseFile, courseBase, []sourceCase{
		{"unknown key", "title: Course X\n", "title: Course X\ntitel: y\n", "title: Course X\n", "titel"},
		{"flags key (C6)", "shared:", "flags: {}\nshared:", "shared:", "flags"},
		{"challenges key (C6)", "shared:", "challenges: [01-a]\nshared:", "shared:", "challenges"},
		{"hints key (C6)", "shared:", "hints: []\nshared:", "shared:", "hints"},
		{"flags key in a module entry (C6)", "  - id: mod-b\n", "  - id: mod-b\n    flags: {}\n", "  - id: mod-b\n", "flags"},
		{"id is not the directory", "id: course-x\n", "id: course-y\n", "id: course-x\n", `id "course-y" is not the name`},
		{"timebox of 0 minutes", "minutes: 120,", "minutes: 0,", "minutes: 1,", "timebox: minutes"},
		{"merge key without an anchor", "timebox: {minutes: 120, introMinutes: 5, closingMinutes: 5}",
			"timebox:\n  <<: {minutes: 120, introMinutes: 5, closingMinutes: 5}", "timebox:\n  minutes: 120\n  introMinutes: 5\n  closingMinutes: 5",
			"an anchor, an alias or a merge key"},
		{"no modules", "modules:\n  - id: mod-a\n    edition: 2h\n  - id: mod-b\n", "modules: []\n", "modules: [{id: mod-b}]\n", "modules is empty"},
		{"module twice", "  - id: mod-b\n", "  - id: mod-b\n  - id: mod-a\n", "  - id: mod-b\n  - id: mod-c\n", `module "mod-a" is listed more than once`},
		{"shared id twice", "  - 02-b\n", "  - 02-b\n  - 02-b\n", "  - 02-b\n  - 03-c\n", `shared id "02-b" is listed more than once`},
	}, func(p string) error { _, err := LoadCourse(p); return err })
}

// V4: a directory is one module or one course; both or neither is an error.
func TestLoadSource_ExactlyOneOfModuleAndCourse(t *testing.T) {
	modDir := filepath.Dir(writeSource(t, "mod-a", ModuleFile, moduleBase))
	if s, err := LoadSource(modDir); err != nil || s.Module == nil || s.Course != nil || s.Module.ID != "mod-a" {
		t.Fatalf("a module directory: %+v, %v", s, err)
	}
	courseDir := filepath.Dir(writeSource(t, "course-x", CourseFile, courseBase))
	if s, err := LoadSource(courseDir); err != nil || s.Course == nil || s.Module != nil || s.Course.ID != "course-x" {
		t.Fatalf("a course directory: %+v, %v", s, err)
	}
	if err := os.WriteFile(filepath.Join(modDir, CourseFile), []byte(courseBase), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSource(modDir); err == nil || !strings.Contains(err.Error(), "holds both") {
		t.Fatalf("a directory with both files: %v", err)
	}
	if _, err := LoadSource(t.TempDir()); err == nil || !strings.Contains(err.Error(), "holds neither") {
		t.Fatalf("a directory with neither file: %v", err)
	}
}

// A symlink is refused whichever loader is the entry; the file it points at loads.
func TestLoadModuleAndCourse_RefuseASymlink(t *testing.T) {
	for _, c := range []struct {
		dir, file, body string
		load            func(string) error
	}{
		{"mod-a", ModuleFile, moduleBase, func(p string) error { _, err := LoadModule(p); return err }},
		{"course-x", CourseFile, courseBase, func(p string) error { _, err := LoadCourse(p); return err }},
	} {
		target := writeSource(t, c.dir, "target.yaml", c.body)
		if err := c.load(target); err != nil {
			t.Fatalf("%s: the regular file was rejected: %v", c.file, err)
		}
		link := filepath.Join(filepath.Dir(target), c.file)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := c.load(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("%s as a symlink: %v", c.file, err)
		}
	}
}

// C6 / V4: the keys are exactly D3's and D4's at every depth, and the composed scenario's
// are D5's, which has no tactics (D5, D6). A flags, challenges, hints or tactics field added
// to any of these types would make the strict decode accept it, or the generator write it.
func TestSourceSchemas_AreTheADRKeys(t *testing.T) {
	for _, c := range []struct {
		typ  reflect.Type
		want []string
	}{
		{reflect.TypeOf(Module{}), []string{"id", "title", "summary", "outcomes", "version", "level", "duration", "editions", "requires", "missions"}},
		{reflect.TypeOf(Course{}), []string{"id", "title", "timebox", "modules", "shared"}},
		{reflect.TypeOf(CourseModule{}), []string{"id", "edition"}},
		{reflect.TypeOf(Duration{}), []string{"handsOnMinutes", "debriefMinutes"}},
		{reflect.TypeOf(Edition{}), []string{",inline", "playbook"}},
		{reflect.TypeOf(Requires{}), []string{"modules"}},
		{reflect.TypeOf(Timebox{}), []string{"minutes", "introMinutes", "closingMinutes"}},
		{reflect.TypeOf(Composed{}), []string{"id", "title", "challenges", "source"}},
		{reflect.TypeOf(ComposedSource{}), []string{"kind", "modules"}},
		{reflect.TypeOf(ComposedModule{}), []string{"id", "version", "edition"}},
	} {
		var got []string
		for i := range c.typ.NumField() {
			got = append(got, c.typ.Field(i).Tag.Get("yaml"))
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s yaml keys = %v, want %v", c.typ.Name(), got, c.want)
		}
	}
}

// The id grammar is the scenario name's: every row of the shared case table goes through
// ValidScenarioName, so dnsname.Label bounded by MaxScenarioNameLen cannot drift from
// deploy-user.sh's SCENARIO_PATTERN (scenario_name_test.go holds that one to the table).
func TestValidScenarioName_SharedCaseTable(t *testing.T) {
	rows, err := casetable.Read(filepath.Join("testdata", "scenario-name-cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 40 {
		t.Fatalf("scenario-name-cases.tsv has %d rows, want at least 40: the table was truncated or misread", len(rows))
	}
	for _, r := range rows {
		if got := ValidScenarioName(r.Input); got != r.Accept {
			t.Errorf("scenario-name-cases.tsv:%d: ValidScenarioName(%q) = %v, want %v", r.Line, r.Input, got, r.Accept)
		}
	}
}
