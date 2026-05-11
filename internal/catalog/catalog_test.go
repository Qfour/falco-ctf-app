package catalog_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

func writeChallenge(t *testing.T, dir, name, yaml string) {
	t.Helper()
	cdir := filepath.Join(dir, name)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "falco-rule.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_Empty(t *testing.T) {
	dir := t.TempDir()
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cat) != 0 {
		t.Fatalf("expected empty catalog, got %d entries", len(cat))
	}
}

func TestLoad_MissingDir_NoError(t *testing.T) {
	cat, err := catalog.Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing dir should not error, got: %v", err)
	}
	if len(cat) != 0 {
		t.Fatalf("expected empty catalog, got %d entries", len(cat))
	}
}

func TestLoad_TriggerChallenge(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "01-read-shadow", `
challengeId: "01-read-shadow"
type: trigger
expectedRules:
  - "Read sensitive file untrusted"
`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ch, ok := cat["01-read-shadow"]
	if !ok {
		t.Fatal("challenge not loaded")
	}
	if ch.Type != "trigger" {
		t.Errorf("type: got %q, want trigger", ch.Type)
	}
	if len(ch.ExpectedRules) != 1 || ch.ExpectedRules[0] != "Read sensitive file untrusted" {
		t.Errorf("expectedRules: %v", ch.ExpectedRules)
	}
	if ch.WindowSeconds != 10 {
		t.Errorf("windowSeconds default: got %d, want 10", ch.WindowSeconds)
	}
}

func TestLoad_EvadeChallenge(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "02-evade", `
challengeId: "02-evade"
type: evade
forbiddenRules:
  - "Read sensitive file untrusted"
expectedFlag: "FALCO{abc}"
windowSeconds: 15
`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ch := cat["02-evade"]
	if ch.Type != "evade" || ch.ExpectedFlag != "FALCO{abc}" || ch.WindowSeconds != 15 {
		t.Errorf("got %+v", ch)
	}
}

func TestLoad_TypeInference(t *testing.T) {
	dir := t.TempDir()
	// no `type:`, has expectedRules → trigger
	writeChallenge(t, dir, "a", `expectedRules: ["X"]`)
	// no `type:`, no expectedRules → evade
	writeChallenge(t, dir, "b", `forbiddenRules: ["Y"]
expectedFlag: "F"`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cat["a"].Type != "trigger" {
		t.Errorf("a: expected trigger from inference, got %q", cat["a"].Type)
	}
	if cat["b"].Type != "evade" {
		t.Errorf("b: expected evade from inference, got %q", cat["b"].Type)
	}
}

func TestLoad_IDFallbackToDirName(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "07-no-id", `expectedRules: ["Z"]`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cat["07-no-id"]; !ok {
		t.Fatalf("expected id to fall back to directory name; got keys: %v", cat.IDs())
	}
}

func TestLoad_SkipsDirsWithoutFalcoRule(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "empty-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat) != 0 {
		t.Errorf("expected empty, got %d", len(cat))
	}
}

func TestIDs_Sorted(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "03-c", `expectedRules: ["a"]`)
	writeChallenge(t, dir, "01-a", `expectedRules: ["a"]`)
	writeChallenge(t, dir, "02-b", `expectedRules: ["a"]`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids := cat.IDs()
	want := []string{"01-a", "02-b", "03-c"}
	for i, id := range ids {
		if id != want[i] {
			t.Errorf("IDs[%d]: got %q, want %q", i, id, want[i])
		}
	}
}
