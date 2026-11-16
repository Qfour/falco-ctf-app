package catalog

// ADR-0056 V28: reservedMountRoots (investigate.go) mirrors two constants of
// challenges/gen-values.sh, SEED_ROOT (the seed volume as the `plant` initContainer
// sees it) and SNAPSHOT_ROOT (the build-time snapshot baked into the challenge
// image). A change to one of them in the script and not in Go would let an
// evidence bundle be mounted over the new seed root, and nothing would say so until
// a deploy. This test reads the script as text and holds both values to the list.
//
// Same style as typeset_parity_test.go (the shell source is data to a Go test): an
// extraction that finds nothing, or finds an assignment twice, is a failure, never
// "no difference".

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var genValuesPath = filepath.Join("..", "..", "challenges", "gen-values.sh")

// a top-level assignment, single or double quoted: SEED_ROOT='/plant-seed'
var mountRootAssignRE = regexp.MustCompile(`(?m)^(SEED_ROOT|SNAPSHOT_ROOT)=(?:'([^']*)'|"([^"]*)")[ \t]*(?:#.*)?$`)

// mountRootsInScript returns the value of each of the two assignments, and an error
// unless each appears exactly once.
func mountRootsInScript(src string) (map[string]string, error) {
	found := map[string][]string{}
	for _, m := range mountRootAssignRE.FindAllStringSubmatch(src, -1) {
		v := m[2]
		if v == "" {
			v = m[3]
		}
		found[m[1]] = append(found[m[1]], v)
	}
	out := map[string]string{}
	for _, name := range []string{"SEED_ROOT", "SNAPSHOT_ROOT"} {
		vals := found[name]
		switch {
		case len(vals) == 0:
			return nil, fmt.Errorf("no top-level %s='...' assignment was found: the extraction is broken or the script moved", name)
		case len(vals) > 1:
			return nil, fmt.Errorf("%s is assigned %d times (%v): which one is the value is ambiguous", name, len(vals), vals)
		case !strings.HasPrefix(vals[0], "/") || vals[0] == "/":
			return nil, fmt.Errorf("%s = %q is not an absolute directory other than /", name, vals[0])
		}
		out[name] = vals[0]
	}
	return out, nil
}

// checkMountRoots is the whole rule: both script values are in roots.
func checkMountRoots(src string, roots []string) error {
	vals, err := mountRootsInScript(src)
	if err != nil {
		return err
	}
	for _, name := range []string{"SEED_ROOT", "SNAPSHOT_ROOT"} {
		if !slices.Contains(roots, vals[name]) {
			return fmt.Errorf("gen-values.sh %s = %q is not in reservedMountRoots %v: an evidence bundle could be mounted over it", name, vals[name], roots)
		}
	}
	return nil
}

func TestReservedMountRoots_MatchGenValues(t *testing.T) {
	raw, err := os.ReadFile(genValuesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkMountRoots(string(raw), reservedMountRoots); err != nil {
		t.Error(err)
	}
}

// The check itself must be able to fail: a copy of the real script with one of the
// two values changed is red, an extraction that finds nothing is red, and so is an
// assignment that appears twice.
func TestReservedMountRoots_ParityCheckFailsOnADriftedCopy(t *testing.T) {
	raw, err := os.ReadFile(genValuesPath)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	vals, err := mountRootsInScript(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SEED_ROOT", "SNAPSHOT_ROOT"} {
		old := name + "='" + vals[name] + "'"
		if strings.Count(src, old) != 1 {
			t.Fatalf("the negative test's text %q must occur exactly once in gen-values.sh (rewording the assignment makes this check vacuous: update it)", old)
		}
		drifted := strings.Replace(src, old, name+"='"+vals[name]+"-moved'", 1)
		if err := checkMountRoots(drifted, reservedMountRoots); err == nil {
			t.Errorf("changing only %s in the script was not detected", name)
		}
		// the same value in double quotes still reads (the rule is the value, not the quoting)
		dq := strings.Replace(src, old, name+`="`+vals[name]+`"`, 1)
		if err := checkMountRoots(dq, reservedMountRoots); err != nil {
			t.Errorf("%s in double quotes: %v", name, err)
		}
		// an assignment that moved out of the top level reads as missing, not as equal
		indented := strings.Replace(src, old, "  "+old, 1)
		if err := checkMountRoots(indented, reservedMountRoots); err == nil {
			t.Errorf("%s no longer at the top level was accepted: an empty extraction must fail", name)
		}
		twice := src + "\n" + name + "='/elsewhere'\n"
		if err := checkMountRoots(twice, reservedMountRoots); err == nil {
			t.Errorf("%s assigned twice was accepted", name)
		}
	}
	// the Go side drifting is red too: drop each of the two roots from the list
	for _, name := range []string{"SEED_ROOT", "SNAPSHOT_ROOT"} {
		without := slices.DeleteFunc(slices.Clone(reservedMountRoots), func(r string) bool { return r == vals[name] })
		if len(without) != len(reservedMountRoots)-1 {
			t.Errorf("%s = %q is not in reservedMountRoots to begin with", name, vals[name])
			continue
		}
		if err := checkMountRoots(src, without); err == nil {
			t.Errorf("reservedMountRoots without %s was not detected", name)
		}
	}
	for name, s := range map[string]string{"empty": "", "no assignments": "echo SEED_ROOT SNAPSHOT_ROOT\n"} {
		if err := checkMountRoots(s, reservedMountRoots); err == nil {
			t.Errorf("%s source was accepted: an empty extraction must fail", name)
		}
	}
}
