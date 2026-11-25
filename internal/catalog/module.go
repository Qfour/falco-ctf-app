package catalog

// module.go is the source side of ADR-0055 S2a: the parser of scenarios/<id>/module.yaml
// (D3) and scenarios/<id>/course.yaml (D4). cmd/gen-scenarios composes them into
// scenario.yaml (S2b), and LoadScenario requires one of them beside every scenario.yaml it
// loads (S2c, LoadSource).
//
// Both files, and the generated scenario.yaml (DecodeScenario), are decoded strictly by
// decodeSource: a regular file (not a symlink), one document, no anchor, alias or merge
// key, and an unknown or repeated key at any depth is an error.
// Those rules are the ones edition.ParseSpec applies to edition.yaml; its size limit,
// UTF-8 check and invisible / bidi character check (sourcehygiene.Hidden) are NOT applied
// here. A module or a course has no flags, challenges or hints key, so a file that writes
// one is refused by the same decode (C6).

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/dnsname"
)

// ModuleFile and CourseFile are the two source files a scenarios/<id>/ directory may
// hold; it holds exactly one of them (D2).
const (
	ModuleFile = "module.yaml"
	CourseFile = "course.yaml"
)

// The closed ranges of D3: 3 to 5 outcomes, and the level of the existing stars.
const (
	MinOutcomes = 3
	MaxOutcomes = 5
	MinLevel    = 1
	MaxLevel    = 5
)

// scenarioLabelPrefix is what deploy-user.sh puts before a scenario name to make the
// value of the falco-ctf/challenge-id namespace label (scenario-name-cases.tsv).
const scenarioLabelPrefix = "scenario-"

// MaxScenarioNameLen is the longest scenario name: a label value is at most 63
// characters, and scenarioLabelPrefix takes 9 of them.
const MaxScenarioNameLen = 63 - len(scenarioLabelPrefix)

// scenarioNameRE is one DNS label (dnsname.Label: the first and the last a letter or
// digit, a-z 0-9 and - between), composed and not spelled again.
var scenarioNameRE = regexp.MustCompile("^" + dnsname.Label + "$")

// ValidScenarioName reports whether s is a scenario name: the name of a directory under
// scenarios/, and so the id of a module or a course (D2). It is the grammar of
// scenario-name-cases.tsv (deploy-user.sh's SCENARIO_PATTERN); module_test.go runs every
// row of that table through it.
func ValidScenarioName(s string) bool {
	return len(s) <= MaxScenarioNameLen && scenarioNameRE.MatchString(s)
}

// Module is a scenarios/<id>/module.yaml (D3): a self-contained unit of learning. Its
// directory is also the course of that module alone (D6, ComposeSolo).
type Module struct {
	ID       string             `yaml:"id"`
	Title    string             `yaml:"title"`
	Summary  string             `yaml:"summary"`
	Outcomes []string           `yaml:"outcomes"`
	Version  int                `yaml:"version"`
	Level    int                `yaml:"level"`
	Duration Duration           `yaml:"duration"`
	Editions map[string]Edition `yaml:"editions"`
	Requires Requires           `yaml:"requires"`
	Missions []string           `yaml:"missions"`
}

// Duration is a time in minutes: a module's `duration`, and an edition's.
type Duration struct {
	HandsOnMinutes int `yaml:"handsOnMinutes"`
	DebriefMinutes int `yaml:"debriefMinutes"`
}

// Edition is one entry of `editions`: the same missions in another time and playbook
// (D3: an edition never changes the scope, so it has no missions).
type Edition struct {
	Duration `yaml:",inline"`
	Playbook string `yaml:"playbook"`
}

// Requires names the modules a course must place before this one (C3 is S3b's).
type Requires struct {
	Modules []string `yaml:"modules"`
}

// Course is a scenarios/<id>/course.yaml (D4): modules in order. It has no flags,
// challenges or hints (C6).
type Course struct {
	ID      string         `yaml:"id"`
	Title   string         `yaml:"title"`
	Timebox Timebox        `yaml:"timebox"`
	Modules []CourseModule `yaml:"modules"`
	Shared  []string       `yaml:"shared"`
}

// Timebox is the course's time frame, in minutes (C2 is S3b's).
type Timebox struct {
	Minutes        int `yaml:"minutes"`
	IntroMinutes   int `yaml:"introMinutes"`
	ClosingMinutes int `yaml:"closingMinutes"`
}

// CourseModule is one entry of a course's `modules`. An empty Edition means the
// module's own duration.
type CourseModule struct {
	ID      string `yaml:"id"`
	Edition string `yaml:"edition"`
}

// Source is the one source file of a scenarios/<id>/ directory: exactly one of Module
// and Course is set.
type Source struct {
	Dir    string
	Module *Module
	Course *Course
}

// LoadSource reads the source of dir (a scenarios/<id>/ directory). A directory that
// holds both module.yaml and course.yaml, or neither, is an error (D2, V4).
func LoadSource(dir string) (Source, error) {
	hasModule, err := regularFile(filepath.Join(dir, ModuleFile))
	if err != nil {
		return Source{}, err
	}
	hasCourse, err := regularFile(filepath.Join(dir, CourseFile))
	if err != nil {
		return Source{}, err
	}
	switch {
	case hasModule && hasCourse:
		return Source{}, fmt.Errorf("scenario directory %q holds both %s and %s: it is one module or one course (ADR-0055 D2)", dir, ModuleFile, CourseFile)
	case hasModule:
		m, err := LoadModule(filepath.Join(dir, ModuleFile))
		if err != nil {
			return Source{}, err
		}
		return Source{Dir: dir, Module: &m}, nil
	case hasCourse:
		c, err := LoadCourse(filepath.Join(dir, CourseFile))
		if err != nil {
			return Source{}, err
		}
		return Source{Dir: dir, Course: &c}, nil
	}
	return Source{}, fmt.Errorf("scenario directory %q holds neither %s nor %s (ADR-0055 D2)", dir, ModuleFile, CourseFile)
}

// regularFile reports whether path is a regular file. A missing path is false; a
// symlink, a directory or a stat error is an error (fail-closed).
func regularFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("stat %q: %w", path, err)
	case !info.Mode().IsRegular():
		return false, fmt.Errorf("%q is not a regular file", path)
	}
	return true, nil
}

// LoadModule reads and checks the module.yaml at path. Its id must be the name of the
// directory that holds it.
func LoadModule(path string) (Module, error) {
	var m Module
	if err := readSource(path, &m); err != nil {
		return Module{}, err
	}
	err := m.validate()
	if err == nil {
		err = idIsDir(m.ID, path)
	}
	if err != nil {
		return Module{}, fmt.Errorf("module %q: %w", path, err)
	}
	return m, nil
}

// LoadCourse reads and checks the course.yaml at path. Its id must be the name of the
// directory that holds it.
func LoadCourse(path string) (Course, error) {
	var c Course
	if err := readSource(path, &c); err != nil {
		return Course{}, err
	}
	err := c.validate()
	if err == nil {
		err = idIsDir(c.ID, path)
	}
	if err != nil {
		return Course{}, fmt.Errorf("course %q: %w", path, err)
	}
	return c, nil
}

// readSource reads path, which must be a regular file (a symlink is refused, whichever of
// LoadSource, LoadModule and LoadCourse is the entry), and decodes it strictly into out.
func readSource(path string, out any) error {
	data, err := readRegular(path)
	if err != nil {
		return err
	}
	if err := decodeSource(data, out); err != nil {
		return fmt.Errorf("parse %q: %w", path, err)
	}
	return nil
}

// readRegular is the bytes of path, which must be a regular file: a symlink is refused.
func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("read %q: not a regular file (a symlink is refused)", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return data, nil
}

// decodeSource is the strict decode of a module.yaml or course.yaml: exactly one
// document, no anchor, alias or merge key, then KnownFields(true) on the bytes.
func decodeSource(data []byte, out any) error {
	if _, err := sourceDocument(data); err != nil {
		return err
	}
	return decodeStrictBytes(data, out)
}

// sourceDocument is the node checks of decodeSource: the one document of data, with no
// anchor, alias or merge key. DecodeScenario looks at the nodes of the requirements block
// (requirementsShape) between it and the strict decode.
func sourceDocument(data []byte) (*yaml.Node, error) {
	nodes := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := nodes.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the file holds no document")
		}
		return nil, err
	}
	var extra yaml.Node
	if err := nodes.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("the file holds more than one document")
	}
	if n := findAnchorOrAlias(&doc); n != nil {
		return nil, fmt.Errorf("line %d: an anchor, an alias or a merge key is not allowed", n.Line)
	}
	return &doc, nil
}

// findAnchorOrAlias is the first node, in document order, that carries an anchor, is an
// alias, or is a merge key. It is a copy of internal/edition's findAnchorOrAlias (which is
// unexported); a shared helper is a follow-up.
func findAnchorOrAlias(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || (n.Kind == yaml.ScalarNode && n.ShortTag() == "!!merge") {
		return n
	}
	for _, c := range n.Content {
		if f := findAnchorOrAlias(c); f != nil {
			return f
		}
	}
	return nil
}

// idIsDir is an error when id is not the name of the directory that holds path (D2).
func idIsDir(id, path string) error {
	if dir := filepath.Base(filepath.Dir(path)); id != dir {
		return fmt.Errorf("id %q is not the name of its directory %q (ADR-0055 D2)", id, dir)
	}
	return nil
}

// validate holds a module to D3, and to C1's "no challenge twice in a module". Whether
// its missions are challenges of the pool is Compose's (it needs the pool).
func (m Module) validate() error {
	if err := checkName("id", m.ID); err != nil {
		return err
	}
	switch {
	case strings.TrimSpace(m.Title) == "":
		return errors.New("title is empty")
	case strings.TrimSpace(m.Summary) == "":
		return errors.New("summary is empty")
	case len(m.Outcomes) < MinOutcomes || len(m.Outcomes) > MaxOutcomes:
		return fmt.Errorf("outcomes: want %d to %d, got %d", MinOutcomes, MaxOutcomes, len(m.Outcomes))
	case m.Version < 1:
		return fmt.Errorf("version must be at least 1, got %d", m.Version)
	case m.Level < MinLevel || m.Level > MaxLevel:
		return fmt.Errorf("level must be %d..%d, got %d", MinLevel, MaxLevel, m.Level)
	case len(m.Missions) == 0:
		return errors.New("missions is empty")
	}
	for i, o := range m.Outcomes {
		if strings.TrimSpace(o) == "" {
			return fmt.Errorf("outcomes[%d] is empty", i)
		}
	}
	if err := checkDuration("duration", m.Duration); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(m.Editions)) {
		e := m.Editions[name]
		if err := checkEditionName(name); err != nil {
			return err
		}
		if err := checkDuration(fmt.Sprintf("editions %q", name), e.Duration); err != nil {
			return err
		}
		if p := e.Playbook; p == "" || p == "." || p == ".." || strings.ContainsAny(p, `/\`) {
			return fmt.Errorf("editions %q: playbook %q is not a file name of the module directory", name, p)
		}
	}
	for _, r := range m.Requires.Modules {
		if err := checkName("requires.modules id", r); err != nil {
			return err
		}
	}
	if slices.Contains(m.Requires.Modules, m.ID) {
		return errors.New("requires.modules lists the module itself")
	}
	if err := noRepeat("requires.modules id", m.Requires.Modules); err != nil {
		return err
	}
	return noRepeat("mission", m.Missions)
}

// validate holds a course to D4: every module listed once, every shared id listed once.
// Whether the modules exist and the shared ids are shared is Compose's.
func (c Course) validate() error {
	if err := checkName("id", c.ID); err != nil {
		return err
	}
	t := c.Timebox
	switch {
	case strings.TrimSpace(c.Title) == "":
		return errors.New("title is empty")
	case t.Minutes < 1 || t.IntroMinutes < 0 || t.ClosingMinutes < 0:
		return fmt.Errorf("timebox: minutes must be at least 1, introMinutes and closingMinutes at least 0, got %d, %d, %d",
			t.Minutes, t.IntroMinutes, t.ClosingMinutes)
	case len(c.Modules) == 0:
		return errors.New("modules is empty")
	}
	ids := make([]string, 0, len(c.Modules))
	for _, m := range c.Modules {
		if err := checkName("module", m.ID); err != nil {
			return err
		}
		if m.Edition != "" {
			if err := checkEditionName(m.Edition); err != nil {
				return err
			}
		}
		ids = append(ids, m.ID)
	}
	if err := noRepeat("module", ids); err != nil {
		return err
	}
	return noRepeat("shared id", c.Shared)
}

// checkName is an error naming what and s when s is not a scenario name.
func checkName(what, s string) error {
	if !ValidScenarioName(s) {
		return fmt.Errorf("%s %q is not a scenario name (1 to %d of a-z, 0-9 and -, the first and the last a letter or digit: scenario-name-cases.tsv)",
			what, s, MaxScenarioNameLen)
	}
	return nil
}

// checkEditionName is an error naming s when s is not an edition name. ADR-0055 gives an
// edition name no grammar of its own; this one borrows the scenario name's.
func checkEditionName(s string) error {
	if !ValidScenarioName(s) {
		return fmt.Errorf("edition name %q is not valid (1 to %d of a-z, 0-9 and -, the first and the last a letter or digit)",
			s, MaxScenarioNameLen)
	}
	return nil
}

// checkDuration is an error when d has no hands-on time or a negative debrief.
func checkDuration(what string, d Duration) error {
	if d.HandsOnMinutes < 1 || d.DebriefMinutes < 0 {
		return fmt.Errorf("%s: handsOnMinutes must be at least 1 and debriefMinutes at least 0, got %d and %d",
			what, d.HandsOnMinutes, d.DebriefMinutes)
	}
	return nil
}

// noRepeat is an error naming the first element of list that is there twice.
func noRepeat(what string, list []string) error {
	seen := make(map[string]bool, len(list))
	for _, s := range list {
		if seen[s] {
			return fmt.Errorf("%s %q is listed more than once", what, s)
		}
		seen[s] = true
	}
	return nil
}
