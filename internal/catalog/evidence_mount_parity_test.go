package catalog_test

// ADR-0056 V53 (A5d, review R4#3): the mount directories of the investigate challenges have
// two derivations, the Go catalog (investigate.evidence.mountDir, loaded strictly) and
// challenges/gen-values.sh (which writes them into the generated values files as the
// plant.mounts entries marked `evidence: true`). scripts/check-flag-isolation.sh takes the
// 1-4 allowlist of those directories from gen-values.sh itself, so a mistake the two
// derivations make together would pass every shell check. This test is the independent
// third reading: it loads the catalog in Go, decodes the COMMITTED values files as YAML (it
// never runs gen-values.sh), and holds the two to each other, scope by scope:
//
//   - all:               challenges/values-all.yaml = every investigate challenge;
//   - scenario:<name>:   challenges/values-scenario-<name>.yaml = the investigate challenges
//     that scenarios/<name>/scenario.yaml lists;
//   - one challenge:     challenges/<id>/values.yaml = that challenge's own mount if it is an
//     investigate challenge (the file must exist then), nothing otherwise.
//
// What is compared is the map challenge id -> mount directory, so the set of paths is held
// (V53's wording) and so is which challenge each path belongs to (the chart mounts the
// Secret ctf-evidence-<cid> of the entry's `challenge`).
//
// From A5d to A7 no challenge under challenges/ was of the investigate type and every scope
// compared an empty map with an empty map. Since A7 (50-nimbus-desk-triage) the real-tree test
// also requires at least one evidence mount to have been compared, so a tree that lost its
// investigate challenges on both sides at once is red, not "no difference".
// TestEvidenceMounts_ParityFailsOnOneSideChanged shows on a synthetic tree that the rule turns
// red when one side alone changes.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/catalogtest"
)

// generatedValues is the part of a generated values file this test reads. evidence and
// challenge are decoded as `any` so that an `evidence` key holding anything but the boolean
// true is an error, never "not an evidence mount".
type generatedValues struct {
	Plant struct {
		Mounts []generatedMount `yaml:"mounts"`
	} `yaml:"plant"`
}

type generatedMount struct {
	Path      string `yaml:"path"`
	Evidence  any    `yaml:"evidence"`
	Challenge any    `yaml:"challenge"`
}

// evidenceMountsOf reads one values file: its evidence mounts (challenge id -> path) and
// the number of plant.mounts entries it holds (evidence or not).
func evidenceMountsOf(path string) (map[string]string, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var v generatedValues
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	out := map[string]string{}
	for i, m := range v.Plant.Mounts {
		if m.Path == "" {
			return nil, 0, fmt.Errorf("%s: plant.mounts[%d] has no path", path, i)
		}
		if m.Evidence == nil {
			if m.Challenge != nil {
				return nil, 0, fmt.Errorf("%s: plant.mounts[%d] (%s) has a challenge but no `evidence: true`", path, i, m.Path)
			}
			continue
		}
		if b, ok := m.Evidence.(bool); !ok || !b {
			return nil, 0, fmt.Errorf("%s: plant.mounts[%d] (%s) has evidence %v, not the boolean true", path, i, m.Path, m.Evidence)
		}
		cid, ok := m.Challenge.(string)
		if !ok || cid == "" {
			return nil, 0, fmt.Errorf("%s: plant.mounts[%d] (%s) is an evidence mount without a challenge id", path, i, m.Path)
		}
		if prev, dup := out[cid]; dup {
			return nil, 0, fmt.Errorf("%s: challenge %s has two evidence mounts (%s, %s)", path, cid, prev, m.Path)
		}
		out[cid] = m.Path
	}
	return out, len(v.Plant.Mounts), nil
}

func mountsText(m map[string]string) string {
	if len(m) == 0 {
		return "[]"
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id + "=" + m[id]
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func sameMounts(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// parityRead counts what evidenceMountParity read, so that a caller can refuse a run that
// read nothing (an empty extraction must never read as "no difference").
type parityRead struct {
	files  int
	mounts int

	// evidence is how many evidence mounts the files held in all (every scope counted).
	evidence int
}

// evidenceMountParity is V53's whole rule over one tree. It returns the first difference.
func evidenceMountParity(challengesDir, scenariosDir string) (parityRead, error) {
	var read parityRead
	cat, err := catalog.Load(challengesDir)
	if err != nil {
		return read, err
	}
	if len(cat) == 0 {
		return read, fmt.Errorf("the catalog under %s is empty: the path is wrong", challengesDir)
	}
	all := map[string]string{}
	for _, id := range cat.IDs() {
		ch := cat[id]
		if ch.Type == catalog.TypeInvestigate && ch.Investigate != nil {
			all[id] = ch.Investigate.Evidence.MountDir
		}
	}
	check := func(label, file string, want map[string]string, required bool) error {
		got, n, err := evidenceMountsOf(file)
		if errors.Is(err, fs.ErrNotExist) && !required {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		read.files++
		read.mounts += n
		read.evidence += len(got)
		if !sameMounts(got, want) {
			return fmt.Errorf("%s: %s has the evidence mounts %s, the catalog's investigate challenges of this scope have %s", label, file, mountsText(got), mountsText(want))
		}
		return nil
	}

	if err := check("all", filepath.Join(challengesDir, "values-all.yaml"), all, true); err != nil {
		return read, err
	}

	paths, err := filepath.Glob(filepath.Join(scenariosDir, "*", "scenario.yaml"))
	if err != nil {
		return read, err
	}
	if len(paths) == 0 {
		return read, fmt.Errorf("no <name>/scenario.yaml under %s: the path is wrong", scenariosDir)
	}
	sort.Strings(paths)
	for _, p := range paths {
		s, err := catalog.LoadScenario(p)
		if err != nil {
			return read, err
		}
		name := filepath.Base(filepath.Dir(p))
		want := map[string]string{}
		for _, id := range s.Challenges {
			if dir, ok := all[id]; ok {
				want[id] = dir
			}
		}
		if err := check("scenario:"+name, filepath.Join(challengesDir, "values-scenario-"+name+".yaml"), want, true); err != nil {
			return read, err
		}
	}

	for _, id := range cat.IDs() {
		dirName := cat[id].Dir()
		if dirName == "" {
			dirName = id
		}
		want := map[string]string{}
		dir, inv := all[id]
		if inv {
			want[id] = dir
		}
		if err := check(id, filepath.Join(challengesDir, dirName, "values.yaml"), want, inv); err != nil {
			return read, err
		}
	}
	return read, nil
}

func TestEvidenceMounts_GeneratedValuesMatchTheCatalog(t *testing.T) {
	read, err := evidenceMountParity("../../challenges", "../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	// values-all.yaml and at least one scenario's file were read, and they hold mounts (the
	// evade challenges' today): the files were found and decoded, so "no difference" means
	// something. Not pinned to today's numbers (adding a challenge must not turn this red).
	if read.files < 2 || read.mounts < 1 {
		t.Fatalf("V53 read %d values file(s) holding %d plant.mounts entries: the generated files were not found or not decoded, so the comparison is vacuous", read.files, read.mounts)
	}
	// ADR-0056 A7 (V53 made non-empty): the real tree has an investigate challenge, so the
	// comparison must have held at least one evidence mount on each side. 0 here means both
	// sides lost the investigate challenges together, which "no difference" would hide.
	if read.evidence < 1 {
		t.Fatalf("V53 compared %d values file(s) and found no evidence mount: the real tree's investigate challenges (ADR-0056 A7) are missing from both the catalog and the generated values", read.files)
	}
}

// v53Tree writes a synthetic tree: a trigger challenge and two investigate challenges, the
// generated values of every scope (as gen-values.sh writes them), and two scenarios, one
// listing an investigate challenge and one listing none. It returns the two roots.
func v53Tree(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	ch := filepath.Join(root, "challenges")
	sc := filepath.Join(root, "scenarios")
	writeChallenge(t, ch, "01-a", "type: trigger\nexpectedRules: [r]\n")
	writeChallenge(t, ch, "14-ir-demo", inv("", evMount("/opt/fx/ev-a"), invHexQ))
	writeChallenge(t, ch, "15-ir-more", inv("", evMount("/opt/fx/ev-b"), invHexQ))
	v53Write(t, filepath.Join(ch, "values-all.yaml"), v53Values([2]string{"/opt/fx/ev-a", "14-ir-demo"}, [2]string{"/opt/fx/ev-b", "15-ir-more"}))
	v53Write(t, filepath.Join(ch, "14-ir-demo", "values.yaml"), v53Values([2]string{"/opt/fx/ev-a", "14-ir-demo"}))
	v53Write(t, filepath.Join(ch, "15-ir-more", "values.yaml"), v53Values([2]string{"/opt/fx/ev-b", "15-ir-more"}))
	catalogtest.WriteScenario(t, sc, "one", "01-a", "14-ir-demo")
	v53Write(t, filepath.Join(ch, "values-scenario-one.yaml"), v53Values([2]string{"/opt/fx/ev-a", "14-ir-demo"}))
	catalogtest.WriteScenario(t, sc, "none", "01-a")
	v53Write(t, filepath.Join(ch, "values-scenario-none.yaml"), v53Values())
	return ch, sc
}

// v53Values renders a values file in gen-values.sh's shape: one evade mount, then an
// evidence mount per {path, challenge}.
func v53Values(ev ...[2]string) string {
	var b strings.Builder
	b.WriteString("plant:\n  seedScript:\n    - sh\n    - -c\n    - |\n      set -eu\n  mounts:\n")
	b.WriteString("    - path: /opt/fx/vault\n      readOnly: true\n")
	for _, e := range ev {
		b.WriteString("    - path: " + e[0] + "\n      readOnly: true\n      evidence: true\n      challenge: " + e[1] + "\n")
	}
	return b.String()
}

func v53Write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func v53Replace(t *testing.T, path, old, repl string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), old) != 1 {
		t.Fatalf("the mutation's text %q must occur exactly once in %s (the fixture changed: update the case)", old, path)
	}
	v53Write(t, path, strings.Replace(string(raw), old, repl, 1))
}

// The rule must be able to fail: the synthetic tree passes, and a copy with ONE side changed
// (a generated file, or the catalog) is red, whichever scope it is in.
func TestEvidenceMounts_ParityFailsOnOneSideChanged(t *testing.T) {
	ch, sc := v53Tree(t)
	read, err := evidenceMountParity(ch, sc)
	if err != nil {
		t.Fatalf("the synthetic tree must pass, or the negative cases below prove nothing: %v", err)
	}
	// values-all, two scenarios, two investigate challenges' own files
	if read.files != 5 {
		t.Fatalf("read %d values files of the synthetic tree, want 5", read.files)
	}

	cases := map[string]func(t *testing.T, ch, sc string){
		"values-all: a mount path changed": func(t *testing.T, ch, _ string) {
			v53Replace(t, filepath.Join(ch, "values-all.yaml"), "/opt/fx/ev-b", "/opt/fx/ev-c")
		},
		"values-all: an evidence mount removed": func(t *testing.T, ch, _ string) {
			v53Write(t, filepath.Join(ch, "values-all.yaml"), v53Values([2]string{"/opt/fx/ev-a", "14-ir-demo"}))
		},
		"values-all: an evidence mount added": func(t *testing.T, ch, _ string) {
			v53Write(t, filepath.Join(ch, "values-all.yaml"), v53Values([2]string{"/opt/fx/ev-a", "14-ir-demo"}, [2]string{"/opt/fx/ev-b", "15-ir-more"}, [2]string{"/opt/fx/ev-z", "16-ir-ghost"}))
		},
		"values-all: the same paths with the challenges swapped": func(t *testing.T, ch, _ string) {
			v53Write(t, filepath.Join(ch, "values-all.yaml"), v53Values([2]string{"/opt/fx/ev-a", "15-ir-more"}, [2]string{"/opt/fx/ev-b", "14-ir-demo"}))
		},
		"values-all: evidence is the string true": func(t *testing.T, ch, _ string) {
			v53Replace(t, filepath.Join(ch, "values-all.yaml"), "evidence: true\n      challenge: 15-ir-more", "evidence: \"true\"\n      challenge: 15-ir-more")
		},
		"values-all: an evidence mount without a challenge": func(t *testing.T, ch, _ string) {
			v53Replace(t, filepath.Join(ch, "values-all.yaml"), "\n      challenge: 15-ir-more", "")
		},
		"values-all: one challenge with two evidence mounts": func(t *testing.T, ch, _ string) {
			v53Replace(t, filepath.Join(ch, "values-all.yaml"), "challenge: 15-ir-more", "challenge: 14-ir-demo")
		},
		"values-all: missing": func(t *testing.T, ch, _ string) {
			if err := os.Remove(filepath.Join(ch, "values-all.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"catalog: a mountDir changed": func(t *testing.T, ch, _ string) {
			writeChallenge(t, ch, "15-ir-more", inv("", evMount("/opt/fx/ev-q"), invHexQ))
		},
		"catalog: a new investigate challenge the values do not carry": func(t *testing.T, ch, _ string) {
			writeChallenge(t, ch, "16-ir-new", inv("", evMount("/opt/fx/ev-n"), invHexQ))
		},
		"scenario values: its evidence mount removed": func(t *testing.T, ch, _ string) {
			v53Write(t, filepath.Join(ch, "values-scenario-one.yaml"), v53Values())
		},
		"scenario values: a challenge the scenario does not list": func(t *testing.T, ch, _ string) {
			v53Write(t, filepath.Join(ch, "values-scenario-none.yaml"), v53Values([2]string{"/opt/fx/ev-a", "14-ir-demo"}))
		},
		"scenario values: missing": func(t *testing.T, ch, _ string) {
			if err := os.Remove(filepath.Join(ch, "values-scenario-one.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"scenario: now lists the second investigate challenge": func(t *testing.T, _, sc string) {
			catalogtest.WriteScenario(t, sc, "one", "01-a", "14-ir-demo", "15-ir-more")
		},
		"one challenge: an investigate challenge's values missing": func(t *testing.T, ch, _ string) {
			if err := os.Remove(filepath.Join(ch, "15-ir-more", "values.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"one challenge: an investigate challenge's values with another path": func(t *testing.T, ch, _ string) {
			v53Replace(t, filepath.Join(ch, "14-ir-demo", "values.yaml"), "/opt/fx/ev-a", "/opt/fx/ev-x")
		},
		"one challenge: a trigger challenge's values with an evidence mount": func(t *testing.T, ch, _ string) {
			v53Write(t, filepath.Join(ch, "01-a", "values.yaml"), v53Values([2]string{"/opt/fx/ev-a", "14-ir-demo"}))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ch, sc := v53Tree(t)
			mutate(t, ch, sc)
			if _, err := evidenceMountParity(ch, sc); err == nil {
				t.Errorf("one side changed (%s) and no difference was reported", name)
			}
		})
	}

	// an empty tree is not "no difference"
	empty := t.TempDir()
	if _, err := evidenceMountParity(empty, empty); err == nil {
		t.Error("an empty tree was accepted")
	}
}
