package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

func sampleCatalog() Catalog {
	return Catalog{
		"01-a": {ID: "01-a", Type: "trigger", ExpectedRules: []string{"r"}},
		"02-b": {ID: "02-b", Type: "trigger", ExpectedRules: []string{"r"}},
		"03-c": {ID: "03-c", Type: "evade", ExpectedFlag: "FALCO{x}", WindowSeconds: 10},
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
