package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleCatalog() Catalog {
	return Catalog{
		"01-a": {ID: "01-a", Type: "trigger", ExpectedRules: []string{"r"}},
		"02-b": {ID: "02-b", Type: "trigger", ExpectedRules: []string{"r"}},
		"03-c": {ID: "03-c", Type: "evade", ExpectedFlag: "FALCO{x}"},
	}
}

func TestLoadScenario(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scenario.yaml")
	os.WriteFile(p, []byte("id: demo\ntitle: Demo\nchallenges:\n  - 02-b\n  - 01-a\n"), 0o600)
	s, err := LoadScenario(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "demo" || len(s.Challenges) != 2 || s.Challenges[0] != "02-b" {
		t.Fatalf("unexpected scenario: %+v", s)
	}
}

func TestLoadScenario_EmptyFails(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(p, []byte("id: x\ntitle: y\n"), 0o600)
	if _, err := LoadScenario(p); err == nil {
		t.Fatal("expected error for scenario with no challenges")
	}
}

// writeScenarioDir writes <root>/<name>/scenario.yaml (the layout LoadScenarios
// reads) and returns the file's path. Fixtures live under t.TempDir(), never in
// the real scenarios/ tree.
func writeScenarioDir(t *testing.T, root, name, body string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "scenario.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The same challenge twice in one scenario is refused at load: the scoreboard
// would walk it twice (the order is the manifest's list) while the restricted
// catalog holds it once. The control row proves the check is not simply red.
func TestLoadScenario_DuplicateChallengeFails(t *testing.T) {
	root := t.TempDir()
	dup := writeScenarioDir(t, root, "dup", "id: dup\ntitle: Dup\nchallenges:\n  - 01-a\n  - 02-b\n  - 01-a\n")
	_, err := LoadScenario(dup)
	if err == nil {
		t.Fatal("expected an error for a challenge listed twice")
	}
	if !strings.Contains(err.Error(), `"01-a"`) || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("error does not name the duplicated challenge: %v", err)
	}
	ok := writeScenarioDir(t, root, "ok", "id: ok\ntitle: Ok\nchallenges:\n  - 01-a\n  - 02-b\n")
	if _, err := LoadScenario(ok); err != nil {
		t.Fatalf("control scenario with distinct challenges was rejected: %v", err)
	}
}

// The tactics: key is advisory (P27-3) and ignored by Go; the decode must stay
// non-strict so a shipped manifest carrying it keeps loading.
func TestLoadScenario_AdvisoryTacticsKeyStillLoads(t *testing.T) {
	root := t.TempDir()
	p := writeScenarioDir(t, root, "adv", "id: adv\ntitle: Adv\nchallenges:\n  - 01-a\ntactics:\n  - Discovery\n")
	if _, err := LoadScenario(p); err != nil {
		t.Fatalf("a manifest with the advisory tactics key was rejected: %v", err)
	}
}

// Two scenario directories answering to one id are refused, naming both paths.
func TestLoadScenarios_DuplicateIDFails(t *testing.T) {
	root := t.TempDir()
	writeScenarioDir(t, root, "alpha", "id: same\ntitle: A\nchallenges:\n  - 01-a\n")
	writeScenarioDir(t, root, "beta", "id: same\ntitle: B\nchallenges:\n  - 02-b\n")
	_, err := LoadScenarios(root)
	if err == nil {
		t.Fatal("expected an error for two scenarios with the same id")
	}
	for _, want := range []string{`"same"`, "alpha", "beta", "declared by both"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

// Control for the test above: distinct ids load, in path order.
func TestLoadScenarios_DistinctIDsLoadInPathOrder(t *testing.T) {
	root := t.TempDir()
	writeScenarioDir(t, root, "beta", "id: beta\ntitle: B\nchallenges:\n  - 02-b\n")
	writeScenarioDir(t, root, "alpha", "id: alpha\ntitle: A\nchallenges:\n  - 01-a\n")
	got, err := LoadScenarios(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "alpha" || got[1].ID != "beta" {
		t.Fatalf("unexpected scenarios: %+v", got)
	}
}

func TestLoadScenarios_EmptyIDFails(t *testing.T) {
	root := t.TempDir()
	writeScenarioDir(t, root, "noid", "title: No id\nchallenges:\n  - 01-a\n")
	if _, err := LoadScenarios(root); err == nil {
		t.Fatal("expected an error for a scenario with no id")
	}
}

// A root with no manifests (a wrong path, a moved tree) is an error, never an
// empty "nothing to check".
func TestLoadScenarios_NoManifestsFails(t *testing.T) {
	if _, err := LoadScenarios(t.TempDir()); err == nil {
		t.Fatal("expected an error for a root with no scenario.yaml")
	}
	if _, err := LoadScenarios(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected an error for a missing root")
	}
}

// A manifest LoadScenario rejects makes the whole set fail: a broken sibling
// must not be skipped.
func TestLoadScenarios_PropagatesManifestError(t *testing.T) {
	root := t.TempDir()
	writeScenarioDir(t, root, "good", "id: good\ntitle: G\nchallenges:\n  - 01-a\n")
	writeScenarioDir(t, root, "empty", "id: empty\ntitle: E\n")
	if _, err := LoadScenarios(root); err == nil {
		t.Fatal("expected the empty sibling manifest to fail the load")
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
