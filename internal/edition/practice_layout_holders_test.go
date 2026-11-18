package edition_test

// ADR-0056 V85, the part that A4e-4 holds (amendment 16): the set of the shell files that spell a
// name of practicelayout.go is CLOSED. The parity tests of A5c-2 and A5d
// (practice_deploy_layout_test.go, practice_flagisolation_layout_test.go) hold the literals of the
// two scripts they read to the Go definitions; a third script that builds a path of the layout by
// hand would be held by nothing, and a rename in practicelayout.go would not reach it. So this
// test reads every shell file of charts/ and scripts/ (a *.sh file, or a file whose first line is a
// shell's #!), finds the ones that spell a name of either layout of practicelayout.go (the
// practice directory's and the event's --out: layoutNames and eventLayoutNames of
// layout_source_test.go, which holds practicelayout.go to exactly those constants), and requires
// that set to be exactly the keys of layoutHolders below, both ways:
//
//   - a file that spells a name and is not listed is red (hold it and list it);
//   - a listed file that spells no name any more is red (take it out: the list stays the set);
//   - no file found at all is red (the scan sees nothing).
//
// A spelling is what practice_deploy_layout_test.go calls one (a name next to a `/`), or an
// assignment whose whole value is a name (X='evidence'), on a line that is not a comment. A path
// into this Go package's own directory (internal/edition/...) is not the layout's edition/ and is
// not a spelling.
//
// Each entry says what holds the file: a parity test of this directory (it must name the file),
// or the script the file is the self-test of (the file builds fixture trees for that script, so a
// rename that the script's parity test makes the script follow turns the self-test red in its own
// CI job; the file must name the script). Which files are listed, and why, is in the PR of A4e-4.

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// layoutHolder is what holds one shell file's spelling of the layout: exactly one of parity (a
// test file of internal/edition that holds the file's literals to practicelayout.go) and
// harnessOf (the shell file, slash path from the repo root, that this file is the self-test of).
type layoutHolder struct {
	parity    string
	harnessOf string
}

// layoutHolders is every shell file of charts/ and scripts/ that spells a name of
// practicelayout.go (slash path from the repo root), and what holds it.
var layoutHolders = map[string]layoutHolder{
	// the practice path of A5c-2: five literals, held by V85 (A5c-2)
	"charts/ctf-user/deploy-user.sh": {parity: "practice_deploy_layout_test.go"},
	// the names of the public practice bundle of A5d: five literals, held by V85 (A5d)
	"scripts/check-flag-isolation.sh": {parity: "practice_flagisolation_layout_test.go"},
	// EVIDENCE_DIR (EventEvidenceDirName) of V93, held by its parity test; the other spellings are
	// paths of the self-test's scratch repositories
	"scripts/check-edition-headers.sh": {parity: "flagguard_evidence_internal_test.go"},
	// the stub-cluster test of deploy-user.sh: it builds the practice trees deploy-user.sh reads
	"scripts/check-deploy-user-evidence.sh": {harnessOf: "charts/ctf-user/deploy-user.sh"},
	// the mutation test of check-image-hygiene.sh: a synthetic challenge with an edition/ directory
	"scripts/test-check-image-hygiene.sh": {harnessOf: "scripts/check-image-hygiene.sh"},
}

// goPackageDir is this Go package's directory, which is named edition too.
const goPackageDir = "internal/edition/"

// shellShebang is the first line of a shell script without the .sh suffix.
var shellShebang = regexp.MustCompile(`^#![^\n]*[/\s](?:ba|da|k|z)?sh(?:\s|$)`)

// isShellFile reports whether the file at the slash path p, with the content data, is a shell file.
func isShellFile(p string, data []byte) bool {
	if strings.HasSuffix(p, ".sh") {
		return true
	}
	first, _, _ := strings.Cut(string(data), "\n")
	return shellShebang.MatchString(first)
}

// layoutSpelling finds a spelling of a name of names on a line.
type layoutSpelling struct {
	path   *regexp.Regexp
	assign *regexp.Regexp
}

func newLayoutSpelling(names []string) layoutSpelling {
	var alts []string
	for _, n := range names {
		alts = append(alts, regexp.QuoteMeta(n))
	}
	ns := "(?:" + strings.Join(alts, "|") + ")"
	return layoutSpelling{
		path:   regexp.MustCompile(`/` + ns + `(?:[/"'\s]|$)|(?:^|[^A-Za-z0-9_.-])` + ns + `/`),
		assign: regexp.MustCompile(`^\s*(?:(?:local|readonly|export|declare)\s+)?[A-Za-z_][A-Za-z0-9_]*=['"]?` + ns + `['"]?\s*$`),
	}
}

// first is the number (1-based) and the spelling of the first line of src that is not a comment
// and spells a name; 0 when there is none.
func (s layoutSpelling) first(src string) (int, string) {
	for i, ln := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimLeft(ln, " \t"), "#") {
			continue
		}
		ln = strings.ReplaceAll(ln, goPackageDir, "internal/-/")
		if m := s.path.FindString(ln); m != "" {
			return i + 1, m
		}
		if s.assign.MatchString(ln) {
			return i + 1, strings.TrimSpace(ln)
		}
	}
	return 0, ""
}

// baseName is the last element of a slash path.
func baseName(p string) string { return p[strings.LastIndex(p, "/")+1:] }

// layoutHolderProblems is the whole rule. files are the shell files (slash path -> content),
// names the layout's names, holders the list, and tests the parity test files the list names
// (file name -> content).
func layoutHolderProblems(files map[string]string, names []string, holders map[string]layoutHolder, tests map[string]string) []string {
	if len(names) == 0 {
		return []string{"practicelayout.go has no name: the scan would find nothing"}
	}
	var out []string
	sp := newLayoutSpelling(names)
	found := map[string]bool{}
	for _, p := range slices.Sorted(maps.Keys(files)) {
		line, what := sp.first(files[p])
		if line == 0 {
			continue
		}
		found[p] = true
		if _, ok := holders[p]; !ok {
			out = append(out, p+":"+strconv.Itoa(line)+" spells a name of practicelayout.go ("+strconv.Quote(what)+") and nothing holds it: hold its literals to practicelayout.go (as practice_deploy_layout_test.go does) and list it in layoutHolders")
		}
	}
	if len(found) == 0 {
		out = append(out, "no shell file of charts/ or scripts/ spells a name of practicelayout.go: the scan sees nothing")
	}
	for _, p := range slices.Sorted(maps.Keys(holders)) {
		h := holders[p]
		if !found[p] {
			out = append(out, p+" is in layoutHolders and spells no name of practicelayout.go: take it out of the list")
		}
		switch {
		case (h.parity == "") == (h.harnessOf == ""):
			out = append(out, p+": its entry names both, or neither, of a parity test and a script it is the self-test of")
		case h.parity != "":
			src, ok := tests[h.parity]
			switch {
			case !ok:
				out = append(out, p+": its parity test "+h.parity+" is not a test file of internal/edition")
			case !strings.Contains(src, baseName(p)):
				out = append(out, p+": its parity test "+h.parity+" does not name "+baseName(p))
			}
		default:
			script, ok := files[h.harnessOf]
			switch {
			case !ok || script == "":
				out = append(out, p+": "+h.harnessOf+" (the script it is the self-test of) is not a shell file of charts/ or scripts/")
			case !strings.Contains(files[p], baseName(h.harnessOf)):
				out = append(out, p+" does not name "+baseName(h.harnessOf)+", the script it is listed as the self-test of")
			}
		}
	}
	return out
}

// shellFiles reads the shell files of charts/ and scripts/ (slash path from the repo root ->
// content). Every regular file is looked at; links are not followed.
func shellFiles(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	files := map[string]string{}
	for _, dir := range []string{"charts", "scripts"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if isShellFile(rel, data) {
				files[rel] = string(data)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 10 {
		t.Fatalf("read only %d shell files of charts/ and scripts/: the walk is not seeing the tree", len(files))
	}
	return files
}

// parityTests reads the parity test files that layoutHolders names (file name -> content).
func parityTests(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, h := range layoutHolders {
		if h.parity == "" {
			continue
		}
		data, err := os.ReadFile(h.parity)
		if err != nil {
			t.Fatalf("the parity test %s: %v", h.parity, err)
		}
		out[h.parity] = string(data)
	}
	return out
}

// allLayoutNames are the names of both layouts of practicelayout.go.
func allLayoutNames() []string { return slices.Concat(layoutNames, eventLayoutNames) }

func TestPracticeLayoutHolders_TheSetIsClosed(t *testing.T) {
	for _, p := range layoutHolderProblems(shellFiles(t), allLayoutNames(), layoutHolders, parityTests(t)) {
		t.Error(p)
	}
}

// The rule must be able to fail: a new script that spells the layout, an entry taken out, an entry
// for a file that spells nothing, a parity test that does not name its file, a malformed entry, no
// name and no file are each red; a comment, a path into this package and a longer word are not
// spellings.
func TestPracticeLayoutHolders_CheckFailsOnADriftedCopy(t *testing.T) {
	files, names, tests := shellFiles(t), allLayoutNames(), parityTests(t)
	if p := layoutHolderProblems(files, names, layoutHolders, tests); len(p) != 0 {
		t.Fatalf("the real tree already has problems, so the cases below prove nothing: %v", p)
	}
	withFile := func(p, src string) map[string]string {
		c := maps.Clone(files)
		c[p] = src
		return c
	}
	withHolder := func(p string, h layoutHolder) map[string]layoutHolder {
		c := maps.Clone(layoutHolders)
		c[p] = h
		return c
	}
	without := maps.Clone(layoutHolders)
	delete(without, "scripts/check-deploy-user-evidence.sh")
	brokenTests := maps.Clone(tests)
	brokenTests["practice_deploy_layout_test.go"] = "package edition_test\n"
	for _, c := range []struct {
		name    string
		files   map[string]string
		names   []string
		holders map[string]layoutHolder
		tests   map[string]string
	}{
		{"a new script that builds the practice directory by hand", withFile("scripts/new-tool.sh", "#!/usr/bin/env bash\nd=\"${root}/edition/practice\"\n"), names, layoutHolders, tests},
		{"a new script that assigns a name of the layout", withFile("charts/ctf-user/new.sh", "#!/bin/sh\nX='digests.tsv'\n"), names, layoutHolders, tests},
		{"a new script that reads edition.yaml", withFile("scripts/new-tool.sh", "#!/usr/bin/env bash\ncat \"${cid}/edition.yaml\"\n"), names, layoutHolders, tests},
		{"a new script that reads the render record of --out", withFile("scripts/new-tool.sh", "#!/usr/bin/env bash\ncat \"${out}/render-record.tsv\"\n"), names, layoutHolders, tests},
		{"a new script that lists the evidence directory", withFile("scripts/new-tool", "#!/usr/bin/env bash\nls \"${p}/evidence/\"\n"), names, layoutHolders, tests},
		{"an entry taken out", files, names, without, tests},
		{"an entry for a file that spells no name", files, names, withHolder("scripts/check-evidence-digest.sh", layoutHolder{harnessOf: "charts/ctf-user/deploy-user.sh"}), tests},
		{"a parity test that does not name its file", files, names, layoutHolders, brokenTests},
		{"an entry with both", files, names, withHolder("scripts/check-flag-isolation.sh", layoutHolder{parity: "practice_flagisolation_layout_test.go", harnessOf: "charts/ctf-user/deploy-user.sh"}), tests},
		{"an entry with neither", files, names, withHolder("scripts/check-flag-isolation.sh", layoutHolder{}), tests},
		{"a self-test of a script that is not there", files, names, withHolder("scripts/test-check-image-hygiene.sh", layoutHolder{harnessOf: "scripts/no-such-script.sh"}), tests},
		{"no name of the layout", files, nil, layoutHolders, tests},
		{"no shell file", map[string]string{}, names, layoutHolders, tests},
	} {
		if len(layoutHolderProblems(c.files, c.names, c.holders, c.tests)) == 0 {
			t.Errorf("%s: no problem was reported", c.name)
		}
	}
	for name, src := range map[string]string{
		"a comment":                   "#!/usr/bin/env bash\n  # ${root}/edition/practice/evidence/ and digests.tsv\n",
		"a path into the Go package":  "#!/usr/bin/env bash\nT=\"${REPO_ROOT}/internal/edition/testdata/bundle-digest\"\n",
		"longer words and no slashes": "#!/usr/bin/env bash\nhelm template charts/ctf-user/templates/pod.yaml --evidence-dir x\nEVIDENCE_MODE=practices\n",
	} {
		if p := layoutHolderProblems(withFile("scripts/new-tool.sh", src), names, layoutHolders, tests); len(p) != 0 {
			t.Errorf("%s was read as a spelling: %v", name, p)
		}
	}
}

// A shell file is a *.sh file or a file whose first line is a shell's #!; a Python script is not.
func TestPracticeLayoutHolders_IsShellFile(t *testing.T) {
	for _, c := range []struct {
		path, data string
		want       bool
	}{
		{"scripts/a.sh", "anything\n", true},
		{"scripts/a", "#!/usr/bin/env bash\n", true},
		{"scripts/a", "#!/bin/sh -e\n", true},
		{"scripts/a", "#!/bin/bash\n", true},
		{"scripts/a.py", "#!/usr/bin/env python3\n", false},
		{"scripts/a", "#!/usr/bin/env python3\n", false},
		{"scripts/a.yaml", "key: value\n", false},
		{"scripts/a", "", false},
	} {
		if got := isShellFile(c.path, []byte(c.data)); got != c.want {
			t.Errorf("isShellFile(%q, %q) = %v, want %v", c.path, c.data, got, c.want)
		}
	}
}
