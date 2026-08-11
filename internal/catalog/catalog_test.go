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

func TestLoad_TypeRequired(t *testing.T) {
	dir := t.TempDir()
	// no `type:` field — must return an error (inference was removed)
	writeChallenge(t, dir, "a", `expectedRules: ["X"]`)
	_, err := catalog.Load(dir)
	if err == nil {
		t.Fatal("expected error for missing type:, got nil")
	}
}

func TestLoad_UnknownTypeError(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "a", `type: unknown
expectedRules: ["X"]`)
	_, err := catalog.Load(dir)
	if err == nil {
		t.Fatal("expected error for unknown type value, got nil")
	}
}

func TestLoad_InvalidFlag(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "bad-flag", `
type: evade
expectedFlag: "invalid-flag-format"
`)
	_, err := catalog.Load(dir)
	if err == nil {
		t.Fatal("expected error for invalid expectedFlag format, got nil")
	}
}

func TestLoad_IDFallbackToDirName(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "07-no-id", `type: trigger
expectedRules: ["Z"]`)
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
	writeChallenge(t, dir, "03-c", `type: trigger
expectedRules: ["a"]`)
	writeChallenge(t, dir, "01-a", `type: trigger
expectedRules: ["a"]`)
	writeChallenge(t, dir, "02-b", `type: trigger
expectedRules: ["a"]`)
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

// TestLoad_RealChallenges verifies the production challenges/ tree parses
// cleanly. Pins the CTF Company mission set (10 attack missions + the
// 03-stealth-read-detect defender twin).
func TestLoad_RealChallenges(t *testing.T) {
	cat, err := catalog.Load("../../challenges")
	if err != nil {
		t.Fatalf("failed to load real challenges: %v", err)
	}
	want := []string{
		"01-initial-recon",
		"02-credential-files",
		"03-stealth-read",
		"03-stealth-read-detect",
		"04-key-search",
		"05-silent-search",
		"06-web-rce-shell",
		"07-persist",
		"08-c2-beacon",
		"09-hidden-cache",
		"10-final-exfil",
	}
	ids := cat.IDs()
	if len(ids) != len(want) {
		t.Fatalf("expected %d challenges, got %d: %v", len(want), len(ids), ids)
	}
	for i, id := range ids {
		if id != want[i] {
			t.Errorf("IDs[%d]: got %q, want %q", i, id, want[i])
		}
	}
}
