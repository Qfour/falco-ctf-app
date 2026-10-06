package hintleak_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// independentFixtureCount counts fixture files by a path that does not share
// code with the loader: `git ls-files` in a checkout, otherwise a walk of each
// challenges/*/fixtures tree.
func independentFixtureCount(t *testing.T, root string) int {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		b, err := exec.Command("git", "-C", root, "ls-files", "challenges/*/fixtures/**").Output()
		if err != nil {
			t.Fatalf("git ls-files: %v", err)
		}
		return len(strings.Fields(string(b)))
	}
	dirs, _ := filepath.Glob(filepath.Join(root, "challenges", "*", "fixtures"))
	n := 0
	for _, d := range dirs {
		_ = filepath.Walk(d, func(_ string, fi os.FileInfo, err error) error {
			if err == nil && fi.Mode().IsRegular() {
				n++
			}
			return nil
		})
	}
	return n
}

// TestFixtures_CarryNoHintOnlyNgrams is ADR-0026 V5 (the second sentence of the
// proposed Hard Invariant I16, ADR-0026 D4 — not yet promoted; promotion is a
// later PR): in every scope — the full catalog and each
// scenarios/*/scenario.yaml — no challenges/*/fixtures/** file contains a
// 10-rune n-gram that appears in a hint but in no free-display text of that
// scope. A violation is fixed by rewording the fixture; there is no exclusion
// list.
func TestFixtures_CarryNoHintOnlyNgrams(t *testing.T) {
	root := repoRoot(t)
	r := loadRepo(t, root)
	if len(r.scopes) < 2 {
		t.Fatalf("scanned %d scope(s); want the full catalog plus at least one scenarios/*/scenario.yaml", len(r.scopes))
	}
	want := independentFixtureCount(t, root)
	if r.fixtureCount == 0 || r.fixtureCount != want {
		t.Fatalf("fixture files scanned = %d, but %d are tracked under challenges/*/fixtures/** (0 or a mismatch means the scan is not covering what ships)", r.fixtureCount, want)
	}
	for _, s := range r.scopes {
		t.Run(s.name, func(t *testing.T) {
			vs, err := hintleak.Check(s.in)
			if err != nil {
				t.Fatalf("hintleak.Check: %v", err)
			}
			t.Logf("scope %s: %d hint items, %d free items, fixture files scanned = %d (tracked = %d), %d violation(s)",
				s.name, len(s.in.Hints), len(s.in.Free), r.fixtureCount, want, len(vs))
			if len(vs) > 0 {
				t.Fatalf("%d (fixture file, distinct n-gram) violation(s) in scope %s — reword the fixture (ADR-0026 D5; no exclusions):\n%s",
					len(vs), s.name, describe(vs))
			}
		})
	}
}
