package edition_test

// ADR-0056 V85, the part that A4e-4 holds (amendment 16): the set of the SHELL FILES OF charts/ AND
// scripts/ that spell a name of practicelayout.go is CLOSED. The parity tests of A5c-2 and A5d
// (practice_deploy_layout_test.go, practice_flagisolation_layout_test.go) hold the literals of the
// two scripts they read to the Go definitions; a third script that builds a path of the layout by
// hand would be held by nothing, and a rename in practicelayout.go would not reach it. So this
// test reads every shell file of charts/ and scripts/ (a *.sh file, or a file whose first line is a
// shell's #!), finds the ones that spell a name of either layout of practicelayout.go (the
// practice directory's and the event's --out: layoutNames and eventLayoutNames of
// layout_source_test.go, which holds practicelayout.go to exactly those constants), and requires
// that set to be exactly the keys of layoutHolders and layoutIgnored below, both ways:
//
//   - a file that spells a name and is in neither list is red (hold it and list it, or list it as
//     ignored with the reason);
//   - a listed file that spells no name any more is red (take it out: the lists stay the set);
//   - a file in both lists, or an ignored file with an empty reason, is red;
//   - no file found at all is red (the scan sees nothing).
//
// What this test guarantees is THAT SET and nothing more: that every shell file of the scope that
// spells the layout is named in one of the two lists. That a held file's literals equal the Go
// constants is the guarantee of the parity test its entry names (this test only checks that the
// parity test names the file), and an ignored file is not held to the layout at all.
//
// A spelling is what practice_deploy_layout_test.go calls one (a name next to a `/`), or an
// assignment whose whole value is a name (X='evidence'), on a line that is not a comment. A path
// into this Go package's own directory (internal/edition/...) is not the layout's edition/ and is
// not a spelling.
//
// Each entry of layoutHolders says what holds the file: a parity test of this directory (it must
// name the file), or the script the file is the self-test of. A self-test entry is only for a file
// whose spellings are the inputs of a script that a parity test holds, so that a rename which the
// parity test makes the script follow leaves the self-test's fixtures on the old name and turns
// the self-test red in its own CI job (the file must name the script; see the entry for the names
// it covers).
//
// The two files that are not shell and spell the practice layout, the recipe of `make
// edition-practice` (the Makefile's edition-practice target) and Dockerfile.edition-practice, are
// in the scope too (ADR-0056 amendment 19, A4e-6b): no CI job runs them, so a rename in
// practicelayout.go would leave them broken without a red. No other test holds them, so this test
// holds their spellings to the constants itself (practiceRecipeProblems): every path of the
// challenge's edition they build is the layout's (EditionDirName, then PracticeDirName), and each
// file still spells both (a file that no longer builds that path is red: it is no longer the
// practice edition's path, and the scope must be changed with it). Go files are not in the scope
// (layout_source_test.go holds those of package edition). Which files are listed, and why, is in the
// PR of A4e-4.

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
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
	// the stub-cluster test of deploy-user.sh (CI flag-guard): it builds by hand the practice tree
	// of 41-ev (<cid>/edition/practice/ with evidence/ and digests.tsv) and copies the golden's
	// practice/digests.tsv. A rename of EditionDirName, PracticeDirName, PracticeEvidenceDirName or
	// PracticeDigestsFileName is followed by deploy-user.sh (its parity test) and by the golden
	// (V67), not by these fixtures, so its practice accept case goes red. Not covered: its
	// answers.tsv is a sentinel of what must not reach a call, which deploy-user.sh does not read,
	// so a rename of PracticeAnswersFileName leaves that check passing on the old name.
	"scripts/check-deploy-user-evidence.sh": {harnessOf: "charts/ctf-user/deploy-user.sh"},
}

// layoutIgnored is every shell file of charts/ and scripts/ that spells a name of
// practicelayout.go with a spelling that is NOT the layout (slash path from the repo root ->
// why). Nothing holds such a file to practicelayout.go, and a rename there does not reach it; the
// reason must say why it need not.
var layoutIgnored = map[string]string{
	"scripts/test-check-image-hygiene.sh": "a synthetic challenge's edition/ directory for check-image-hygiene.sh's V1 reference set, which treats every tracked non-fixture file of a challenge alike: the name is a fixture's, not a path the script reads",
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
// names the layout's names, holders and ignored the two lists, and tests the parity test files
// the holders name (file name -> content).
func layoutHolderProblems(files map[string]string, names []string, holders map[string]layoutHolder, ignored map[string]string, tests map[string]string) []string {
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
		_, held := holders[p]
		_, skip := ignored[p]
		if !held && !skip {
			out = append(out, p+":"+strconv.Itoa(line)+" spells a name of practicelayout.go ("+strconv.Quote(what)+") and is in neither list: hold its literals to practicelayout.go (as practice_deploy_layout_test.go does) and list it in layoutHolders, or, when the spelling is not the layout, list it in layoutIgnored with the reason")
		}
	}
	if len(found) == 0 {
		out = append(out, "no shell file of charts/ or scripts/ spells a name of practicelayout.go: the scan sees nothing")
	}
	for _, p := range slices.Sorted(maps.Keys(ignored)) {
		if !found[p] {
			out = append(out, p+" is in layoutIgnored and spells no name of practicelayout.go: take it out of the list")
		}
		if _, held := holders[p]; held {
			out = append(out, p+" is in both layoutHolders and layoutIgnored")
		}
		if strings.TrimSpace(ignored[p]) == "" {
			out = append(out, p+" is in layoutIgnored with no reason")
		}
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

// The scope is the shell files of charts/ and scripts/ (the header lists what is outside it).
func TestPracticeLayoutHolders_ShellFilesOfChartsAndScripts_TheSetIsClosed(t *testing.T) {
	for _, p := range layoutHolderProblems(shellFiles(t), allLayoutNames(), layoutHolders, layoutIgnored, parityTests(t)) {
		t.Error(p)
	}
}

// The rule must be able to fail: a new script that spells the layout, an entry taken out (of
// either list), an entry for a file that spells nothing, a parity test that does not name its
// file, a malformed entry, a file in both lists, an ignored file without a reason, no name and no
// file are each red; a comment, a path into this package and a longer word are not spellings.
func TestPracticeLayoutHolders_CheckFailsOnADriftedCopy(t *testing.T) {
	files, names, tests := shellFiles(t), allLayoutNames(), parityTests(t)
	if p := layoutHolderProblems(files, names, layoutHolders, layoutIgnored, tests); len(p) != 0 {
		t.Fatalf("the real tree already has problems, so the cases below prove nothing: %v", p)
	}
	withIgnored := func(p, why string) map[string]string {
		c := maps.Clone(layoutIgnored)
		c[p] = why
		return c
	}
	noIgnored := maps.Clone(layoutIgnored)
	delete(noIgnored, "scripts/test-check-image-hygiene.sh")
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
		ignored map[string]string
		tests   map[string]string
	}{
		{"a new script that builds the practice directory by hand", withFile("scripts/new-tool.sh", "#!/usr/bin/env bash\nd=\"${root}/edition/practice\"\n"), names, layoutHolders, layoutIgnored, tests},
		{"a new script that assigns a name of the layout", withFile("charts/ctf-user/new.sh", "#!/bin/sh\nX='digests.tsv'\n"), names, layoutHolders, layoutIgnored, tests},
		{"a new script that reads edition.yaml", withFile("scripts/new-tool.sh", "#!/usr/bin/env bash\ncat \"${cid}/edition.yaml\"\n"), names, layoutHolders, layoutIgnored, tests},
		{"a new script that reads the render record of --out", withFile("scripts/new-tool.sh", "#!/usr/bin/env bash\ncat \"${out}/render-record.tsv\"\n"), names, layoutHolders, layoutIgnored, tests},
		{"a new script that lists the evidence directory", withFile("scripts/new-tool", "#!/usr/bin/env bash\nls \"${p}/evidence/\"\n"), names, layoutHolders, layoutIgnored, tests},
		{"an entry taken out", files, names, without, layoutIgnored, tests},
		{"an ignored entry taken out", files, names, layoutHolders, noIgnored, tests},
		{"an entry for a file that spells no name", files, names, withHolder("scripts/check-evidence-digest.sh", layoutHolder{harnessOf: "charts/ctf-user/deploy-user.sh"}), layoutIgnored, tests},
		{"an ignored entry for a file that spells no name", files, names, layoutHolders, withIgnored("scripts/check-evidence-digest.sh", "a reason"), tests},
		{"an ignored entry with no reason", files, names, layoutHolders, withIgnored("scripts/test-check-image-hygiene.sh", " "), tests},
		{"a file in both lists", files, names, layoutHolders, withIgnored("charts/ctf-user/deploy-user.sh", "a reason"), tests},
		{"a parity test that does not name its file", files, names, layoutHolders, layoutIgnored, brokenTests},
		{"an entry with both", files, names, withHolder("scripts/check-flag-isolation.sh", layoutHolder{parity: "practice_flagisolation_layout_test.go", harnessOf: "charts/ctf-user/deploy-user.sh"}), layoutIgnored, tests},
		{"an entry with neither", files, names, withHolder("scripts/check-flag-isolation.sh", layoutHolder{}), layoutIgnored, tests},
		{"a self-test of a script that is not there", files, names, withHolder("scripts/check-deploy-user-evidence.sh", layoutHolder{harnessOf: "scripts/no-such-script.sh"}), layoutIgnored, tests},
		{"no name of the layout", files, nil, layoutHolders, layoutIgnored, tests},
		{"no shell file", map[string]string{}, names, layoutHolders, layoutIgnored, tests},
	} {
		if len(layoutHolderProblems(c.files, c.names, c.holders, c.ignored, c.tests)) == 0 {
			t.Errorf("%s: no problem was reported", c.name)
		}
	}
	for name, src := range map[string]string{
		"a comment":                   "#!/usr/bin/env bash\n  # ${root}/edition/practice/evidence/ and digests.tsv\n",
		"a path into the Go package":  "#!/usr/bin/env bash\nT=\"${REPO_ROOT}/internal/edition/testdata/bundle-digest\"\n",
		"longer words and no slashes": "#!/usr/bin/env bash\nhelm template charts/ctf-user/templates/pod.yaml --evidence-dir x\nEVIDENCE_MODE=practices\n",
	} {
		if p := layoutHolderProblems(withFile("scripts/new-tool.sh", src), names, layoutHolders, layoutIgnored, tests); len(p) != 0 {
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

// ---- the recipe of `make edition-practice` and Dockerfile.edition-practice (A4e-6b) ----

const (
	practiceDockerfile = "Dockerfile.edition-practice"
	practiceMakeTarget = "edition-practice"
)

// practiceRecipePath is a path of a challenge's edition that the two files build: the challenge,
// written ${CID} (the Dockerfile's build-arg) or $(CID) (the Makefile's variable), followed by the
// segments of its edition's directory; or the recipe's $$ed (that edition directory, in the
// recipe's shell) followed by the segments under it. A segment begins with no dot, so a temporary
// name beside practice/ (.practice.tmp-...) is not a path of the layout.
var practiceRecipePath = regexp.MustCompile(`(\$\{CID\}|\$\(CID\)|\$\$ed)((?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+)`)

// makeRecipe is the recipe of target in makefile: the lines after the line `<target>:` that begin
// with a tab. The target must be there once and have a recipe.
func makeRecipe(makefile, target string) (string, error) {
	lines := strings.Split(makefile, "\n")
	at := -1
	for i, ln := range lines {
		if ln == target+":" {
			if at >= 0 {
				return "", fmt.Errorf("the Makefile has the target %s twice", target)
			}
			at = i
		}
	}
	if at < 0 {
		return "", fmt.Errorf("the Makefile has no target %s: if `make %s` is gone, take it out of the scope of this test", target, target)
	}
	var recipe []string
	for _, ln := range lines[at+1:] {
		if !strings.HasPrefix(ln, "\t") {
			break
		}
		recipe = append(recipe, ln)
	}
	if len(recipe) == 0 {
		return "", fmt.Errorf("the target %s of the Makefile has no recipe", target)
	}
	return strings.Join(recipe, "\n"), nil
}

// practiceRecipeProblems holds the paths that text (the file what) builds to the layout of
// practicelayout.go, given as editionDir and practiceDir: after the challenge, the segments are
// editionDir and then practiceDir (or the first of them only); after the recipe's edition
// directory, practiceDir. The file must build at least one such path and spell both names (a file
// that no longer does is red: it is no longer the practice edition's path).
func practiceRecipeProblems(what, text, editionDir, practiceDir string) []string {
	var out []string
	seen := map[string]bool{}
	n := 0
	for i, ln := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimLeft(ln, " \t"), "#") {
			continue
		}
		for _, m := range practiceRecipePath.FindAllStringSubmatch(ln, -1) {
			n++
			want := []string{editionDir, practiceDir}
			if m[1] == "$$ed" {
				want = []string{practiceDir}
			}
			segs := strings.Split(strings.TrimPrefix(m[2], "/"), "/")
			if len(segs) > len(want) || !slices.Equal(segs, want[:len(segs)]) {
				out = append(out, what+":"+strconv.Itoa(i+1)+" builds "+strconv.Quote(m[0])+", which is not the layout of practicelayout.go ("+editionDir+"/"+practiceDir+"/)")
				continue
			}
			for _, s := range segs {
				seen[s] = true
			}
		}
	}
	if n == 0 {
		return append(out, what+" builds no path of a challenge's edition: if it no longer renders the practice edition, take it out of the scope of this test")
	}
	for _, name := range []string{editionDir, practiceDir} {
		if !seen[name] {
			out = append(out, what+" never spells "+name+" in a path of a challenge's edition: the practice edition's path is "+editionDir+"/"+practiceDir+"/")
		}
	}
	return out
}

// practiceRecipes are the recipe of `make edition-practice` and Dockerfile.edition-practice, as
// (what, text) pairs.
func practiceRecipes(t *testing.T) [][2]string {
	t.Helper()
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatalf("%s: %v (is it in the test build context?)", name, err)
		}
		return string(b)
	}
	recipe, err := makeRecipe(read("Makefile"), practiceMakeTarget)
	if err != nil {
		t.Fatal(err)
	}
	return [][2]string{{"the recipe of make " + practiceMakeTarget, recipe}, {practiceDockerfile, read(practiceDockerfile)}}
}

func TestPracticeLayoutHolders_MakeRecipeAndDockerfileSpellTheConstants(t *testing.T) {
	for _, r := range practiceRecipes(t) {
		for _, p := range practiceRecipeProblems(r[0], r[1], edition.EditionDirName, edition.PracticeDirName) {
			t.Error(p)
		}
	}
}

// The check must be able to fail: a constant changed (the files keep the old spelling), a segment
// of a path changed in a copy of either file, a file that no longer builds the path or spells only
// one of the names, and a Makefile without the target are each red; a comment is not a path.
func TestPracticeLayoutHolders_MakeRecipeAndDockerfileCheckFails(t *testing.T) {
	recipes := practiceRecipes(t)
	for _, r := range recipes {
		if p := practiceRecipeProblems(r[0], r[1], edition.EditionDirName, edition.PracticeDirName); len(p) != 0 {
			t.Fatalf("the real files already have problems, so the cases below prove nothing: %v", p)
		}
		for name, names := range map[string][2]string{
			"EditionDirName changed":  {edition.EditionDirName + "s", edition.PracticeDirName},
			"PracticeDirName changed": {edition.EditionDirName, "public"},
		} {
			if len(practiceRecipeProblems(r[0], r[1], names[0], names[1])) == 0 {
				t.Errorf("%s, %s: no problem was reported", r[0], name)
			}
		}
	}
	recipe, docker := recipes[0][1], recipes[1][1]
	replaceOnce := func(src, old, repl string) string {
		t.Helper()
		if n := strings.Count(src, old); n != 1 {
			t.Fatalf("%q is in the file %d times, want once: the case would not change what it says", old, n)
		}
		return strings.Replace(src, old, repl, 1)
	}
	replaceAll := func(src, old, repl string) string {
		t.Helper()
		if strings.Count(src, old) == 0 {
			t.Fatalf("%q is not in the file: the case would not change what it says", old)
		}
		return strings.ReplaceAll(src, old, repl)
	}
	for _, c := range []struct{ name, what, text string }{
		{"a segment of the Dockerfile's path changed", practiceDockerfile, replaceOnce(docker, `/edition/practice"`, `/edition/practise"`)},
		{"the recipe's practice/ changed", "recipe", replaceOnce(recipe, `dest="$$ed/practice"`, `dest="$$ed/practise"`)},
		{"the recipe's edition/ changed", "recipe", replaceOnce(recipe, `new="$$out/challenges/$(CID)/edition/practice"`, `new="$$out/challenges/$(CID)/editions/practice"`)},
		{"the Dockerfile no longer builds the path", practiceDockerfile, replaceAll(docker, "${CID}/edition/practice", "${CID}")},
		{"the recipe spells edition/ only", "recipe", replaceAll(recipe, "/practice", "")},
	} {
		if len(practiceRecipeProblems(c.what, c.text, edition.EditionDirName, edition.PracticeDirName)) == 0 {
			t.Errorf("%s: no problem was reported", c.name)
		}
	}
	if p := practiceRecipeProblems("recipe", recipe+"\n\t# ${CID}/elsewhere/x", edition.EditionDirName, edition.PracticeDirName); len(p) != 0 {
		t.Errorf("a comment was read as a path: %v", p)
	}
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := makeRecipe(replaceOnce(string(makefile), "\n"+practiceMakeTarget+":\n", "\nedition-practise:\n"), practiceMakeTarget); err == nil {
		t.Error("a Makefile without the target: no error")
	}
	if _, err := makeRecipe(string(makefile)+"\n"+practiceMakeTarget+":\n\t@true\n", practiceMakeTarget); err == nil {
		t.Error("a Makefile with the target twice: no error")
	}
}
