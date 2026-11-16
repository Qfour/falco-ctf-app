package edition

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// ADR-0056 D19 A4a-1 / V34, the parts that need the unexported reader: loadPractice
// itself (the external tests reach it through Load, in the event mode) and the check
// of the tree that CI runs. Values are synthetic.

const practiceFixtureYAML = `type: investigate
investigate:
  evidence: {mountDir: /opt/ctf/evidence}
  questions:
    - id: who
      format: name
    - id: hx
      format: hexid
      params: {length: 12}
`

// practiceTree writes one investigate challenge per entry of tables (cid -> the
// content of its practice/answers.tsv; "" = the challenge has no practice edition).
func practiceTree(t *testing.T, tables map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for cid, table := range tables {
		cdir := filepath.Join(dir, cid)
		if err := os.MkdirAll(cdir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cdir, "falco-rule.yaml"), []byte(practiceFixtureYAML), 0o644); err != nil {
			t.Fatal(err)
		}
		if table == "" {
			continue
		}
		pdir := filepath.Join(cdir, editionDirName, practiceDirName)
		if err := os.MkdirAll(pdir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pdir, practiceTable), []byte(table), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// No practice edition, an empty tree and a tree that does not exist are the EMPTY
// set, and it is not nil: Check refuses to run T6 in the event mode on a nil set
// ("not supplied"), and "there are none" must not read as that.
func TestLoadPractice_NoneIsTheEmptyNonNilSet(t *testing.T) {
	cases := []struct{ name, dir string }{
		{"an empty tree", t.TempDir()},
		{"a tree that does not exist", filepath.Join(t.TempDir(), "nope")},
		{"a challenge with no practice", practiceTree(t, map[string]string{"01-demo": ""})},
		{"a practice table with no rows", practiceTree(t, map[string]string{"01-demo": "# falco-ctf answers v1 run=" + PracticeRunID + "\n"})},
	}
	for _, c := range cases {
		set, _, err := loadPractice(c.dir)
		if err != nil {
			t.Errorf("%s: loadPractice: %v", c.name, err)
			continue
		}
		if set == nil || len(set) != 0 {
			t.Errorf("%s: set = %#v, want the empty, non-nil set", c.name, set)
		}
	}
}

// The set holds the values the tables carry, normalised, by the format of the
// question, and nothing else: Add is given normalised values only (loadPractice
// refuses the others), so Has answers for the normalised form a Judge compares.
func TestLoadPractice_HoldsNormalisedValuesByFormat(t *testing.T) {
	const table = "# falco-ctf answers v1 run=" + PracticeRunID + "\n" +
		"*\t01-demo\twho\tpractice-who\n" +
		"*\t01-demo\thx\taaaaaaaaaaaa\n"
	set, tables, err := loadPractice(practiceTree(t, map[string]string{"01-demo": table, "02-other": ""}))
	if err != nil {
		t.Fatalf("loadPractice: %v", err)
	}
	for _, c := range []struct {
		format, value string
		want          bool
	}{
		{"hexid", "aaaaaaaaaaaa", true},
		{"name", "practice-who", true},
		{"hexid", "AAAAAAAAAAAA", false},
		{"name", "aaaaaaaaaaaa", false},
		{"hexid", "practice-who", false},
		{"hexid", "bbbbbbbbbbbb", false},
	} {
		if got := set.Has(c.format, c.value); got != c.want {
			t.Errorf("Has(%q, %q) = %v, want %v", c.format, c.value, got, c.want)
		}
	}
	if got := len(set["hexid"]) + len(set["name"]); got != 2 || len(set) != 2 {
		t.Errorf("the set holds %v, want exactly the two values of the table", set)
	}
	// The tables are keyed by challenge: the one that has an edition, and not the one
	// that has none (the practice mode's Judge is made from these, A4a-2).
	if len(tables) != 1 || tables["01-demo"] == nil {
		t.Errorf("tables = %d entries (01-demo present: %v), want exactly 01-demo's", len(tables), tables["01-demo"] != nil)
	}
}

// missingPractice are the investigate challenges of cat (read from dir) that have no
// edition/practice/answers.tsv, sorted.
func missingPractice(dir string, cat catalog.Catalog) []string {
	var out []string
	for _, id := range cat.IDs() {
		ch := cat[id]
		if ch.Type != catalog.TypeInvestigate {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, ch.Dir(), editionDirName, practiceDirName, practiceTable))
		if err != nil || !info.Mode().IsRegular() {
			out = append(out, id)
		}
	}
	return out
}

// CI fixes "every investigate challenge of the image has a practice edition" (A4a-1),
// and that the practice editions that are there load: it runs loadPractice, the
// reader the event-mode start-up uses, on the real tree. The real tree has no
// investigate challenge until A7, so the check is shown on a synthetic tree too
// (a check that finds nothing is not a pass).
func TestPracticeEditions_EveryInvestigateChallengeHasOne(t *testing.T) {
	const realTree = "../../challenges"
	cat, err := catalog.Load(realTree)
	if err != nil {
		t.Fatalf("catalog.Load(%s): %v", realTree, err)
	}
	if len(cat) == 0 {
		t.Fatalf("catalog.Load(%s) found no challenge: the path is wrong", realTree)
	}
	if missing := missingPractice(realTree, cat); len(missing) != 0 {
		t.Errorf("investigate challenges without edition/practice/answers.tsv: %v (ADR-0056 D19 A4a-1)", missing)
	}
	if _, _, err := loadPractice(realTree); err != nil {
		t.Errorf("the practice editions of the image do not load: %v", err)
	}
	// V47 (A4a-2): the whole tree as the scope, in the practice mode, is what a local
	// scoreboard does. Load makes the practice Judge of every investigate challenge
	// (T4: a row for every question), so a challenge whose practice edition lacks a
	// question, not only one that has no file, is red here.
	// The real tree has 0 investigate challenges today, so this passes on 0 (Load
	// returns no Judge, no error). From A7 (the first investigate challenge) this test
	// must also require a non-empty set: count the investigate challenges of cat and fail
	// on 0, so that a tree that lost them all cannot pass.
	if _, _, err := Load(cat, realTree, "", false); err != nil {
		t.Errorf("the practice mode does not accept the image's own tree: %v", err)
	}

	// The check itself, on a tree with one edition and one without.
	good := "# falco-ctf answers v1 run=" + PracticeRunID + "\n*\t01-has\thx\taaaaaaaaaaaa\n"
	dir := practiceTree(t, map[string]string{"01-has": good, "02-lacks": ""})
	synth, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := missingPractice(dir, synth); !slices.Equal(got, []string{"02-lacks"}) {
		t.Errorf("missingPractice on the synthetic tree = %v, want [02-lacks]", got)
	}
}
