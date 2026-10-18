package catalog_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// app#437: a challenge directory whose name is outside the challenge-id grammar
// (internal/catalog/challengeid) makes Load fail, so the process does not start
// with a challenge it would list and then 404 on every submit.
func TestLoad_RefusesADirectoryOutsideTheChallengeIDGrammar(t *testing.T) {
	const trigger = "type: trigger\nexpectedRules: [r]\n"
	for _, name := range []string{"mission-x", "1-short", "01_underscore", "01-Upper", "01-dot.dot", "001-three", "01-" + strings.Repeat("a", 61), "_unknown"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeChallenge(t, dir, name, trigger)
			_, err := catalog.Load(dir)
			if err == nil {
				t.Fatalf("Load accepted the challenge directory %q", name)
			}
			if !strings.Contains(err.Error(), "not a valid challenge id") {
				t.Fatalf("catalog.Load(%q) = %v, want the grammar refusal", name, err)
			}
		})
	}
}

// A directory without a falco-rule.yaml is not a challenge, whatever its name.
func TestLoad_IgnoresANonChallengeDirectoryWhateverItsName(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "01-ok", "type: trigger\nexpectedRules: [r]\n")
	if err := os.MkdirAll(filepath.Join(dir, "not a challenge"), 0o755); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(dir)
	if err != nil || len(cat) != 1 {
		t.Fatalf("Load = %v, %v; want the one valid challenge", cat, err)
	}
}
