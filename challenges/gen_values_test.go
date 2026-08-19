// Package challenges hosts the source data (Falco rules, plant.sh, generated
// values.yaml) `make gen-values` derives from and validates
// (challenges/gen-values.sh). This file is ADR-0007's mandated
// Verification 2: a permanent negative test proving gen-values.sh's
// Verification 1 assert (plant.mounts must be directory granularity)
// actually rejects a violation, rather than trusting the assert's presence
// alone (docs/adr/0007 §Verification 2 — "この negative test が無い assert
// は「永久に緑」になりうるので、assert 本体と同一 PR で入れる").
//
// gen-values.sh's own `--check` only ever exercises the real, committed
// catalog, which is directory-granularity by construction after ADR-0007
// and so can never exercise the failure path on its own. These tests drive
// the same underlying assert (assert_mount_is_dir, in gen-values.sh) via its
// file-based entrypoint, `--check-mounts-file <values.yaml> <seed-tree-root>`,
// against a deliberately-violating fixture values.yaml plus a matching seed
// tree — the exact defect class (a file-granularity bind mount onto a Falco
// sensitive_files destination) that made mission 02 auto-solve on every
// deploy (docs/adr/0007 §C1/§C2).
//
// Rides on the required `test` CI check (go-test.yaml / Dockerfile.test) per
// ADR-0007 §Verification 2's explicit instruction to land this on `make
// test`. Dockerfile.test installs `bash` for exactly this purpose — the
// script's shebang and its use of arrays require it.
package challenges

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// runCheckMountsFile invokes `gen-values.sh --check-mounts-file <values> <seedRoot>`
// (relative to this package's own directory, where gen-values.sh lives) and
// returns (exitCode, combinedOutput). Judged by exit status only, never by
// scanning output for a substring (shell-expert: "exit status を直接見る").
func runCheckMountsFile(t *testing.T, valuesPath, seedRoot string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", "gen-values.sh", "--check-mounts-file", valuesPath, seedRoot)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), string(out)
	}
	t.Fatalf("failed to invoke gen-values.sh --check-mounts-file: %v\noutput:\n%s", err, out)
	return -1, string(out)
}

// writeValuesFixture writes a minimal values.yaml in the shape
// render_plant_block() emits (only the `plant.mounts:` list matters to the
// check under test; seedScript is left empty).
func writeValuesFixture(t *testing.T, dir string, mounts []string) string {
	t.Helper()
	path := filepath.Join(dir, "values.yaml")
	content := "plant:\n  seedScript: []\n  mounts:\n"
	for _, m := range mounts {
		content += "    - " + m + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture values.yaml: %v", err)
	}
	return path
}

// TestGenValuesRejectsFileGranularityMount is ADR-0007 Verification 2's
// mandated negative test: a fixture values.yaml declaring a FILE (not
// directory) as a plant.mounts entry — materialized for real on a scratch
// seed tree — must make the Verification 1 assert fail closed (non-zero
// exit). This is the pre-ADR-0007 B1 shape (docs/adr/0007 §C2 probe (a)).
func TestGenValuesRejectsFileGranularityMount(t *testing.T) {
	dir := t.TempDir()
	seedRoot := filepath.Join(dir, "seed")
	if err := os.MkdirAll(filepath.Join(seedRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The violation: /etc/shadow materialized as a FILE at the mount
	// destination.
	if err := os.WriteFile(filepath.Join(seedRoot, "etc", "shadow"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values := writeValuesFixture(t, dir, []string{"/etc/shadow"})

	code, out := runCheckMountsFile(t, values, seedRoot)
	if code == 0 {
		t.Fatalf("gen-values.sh --check-mounts-file ACCEPTED a file-granularity mount (/etc/shadow) — ADR-0007 Verification 1 regression\noutput:\n%s", out)
	}
	t.Logf("correctly rejected (exit %d):\n%s", code, out)
}

// TestGenValuesAcceptsDirectoryGranularityMount is the positive control:
// without it, TestGenValuesRejectsFileGranularityMount above could pass for
// the wrong reason (an assert that rejects everything, not specifically
// files). Same fixture shape, but the mount destination is a real directory.
func TestGenValuesAcceptsDirectoryGranularityMount(t *testing.T) {
	dir := t.TempDir()
	seedRoot := filepath.Join(dir, "seed")
	if err := os.MkdirAll(filepath.Join(seedRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	values := writeValuesFixture(t, dir, []string{"/etc"})

	code, out := runCheckMountsFile(t, values, seedRoot)
	if code != 0 {
		t.Fatalf("gen-values.sh --check-mounts-file rejected a legitimate directory-granularity mount (/etc) (exit %d)\noutput:\n%s", code, out)
	}
}

// TestGenValuesRejectsEmptyMounts covers the ADR-0007 Verification 1
// sub-clause that an empty plant.mounts must never read as "no violation".
func TestGenValuesRejectsEmptyMounts(t *testing.T) {
	dir := t.TempDir()
	seedRoot := filepath.Join(dir, "seed")
	if err := os.MkdirAll(seedRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	values := writeValuesFixture(t, dir, nil)

	code, out := runCheckMountsFile(t, values, seedRoot)
	if code == 0 {
		t.Fatalf("gen-values.sh --check-mounts-file accepted an empty plant.mounts list\noutput:\n%s", out)
	}
}

// TestGenValuesRejectsSeedRootMount covers the ADR-0001 F5 sub-clause
// carried into ADR-0007 Verification 1: the seed root itself must never be
// a mountable entry.
func TestGenValuesRejectsSeedRootMount(t *testing.T) {
	dir := t.TempDir()
	seedRoot := filepath.Join(dir, "seed")
	if err := os.MkdirAll(seedRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	values := writeValuesFixture(t, dir, []string{"/plant-seed"})

	code, out := runCheckMountsFile(t, values, seedRoot)
	if code == 0 {
		t.Fatalf("gen-values.sh --check-mounts-file accepted the seed root itself as a mount\noutput:\n%s", out)
	}
}
