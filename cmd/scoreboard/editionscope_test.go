package main

// ADR-0056 V96 (A4e-5, amendment 18): the scope of `edition check` and of `edition render` (the
// event's) is exactly one of --scenario <file> and --all-challenges. Each alone is taken; neither,
// both, and an empty --scenario (an empty value is never "every challenge") are exit 2 and write
// nothing. --all-challenges is the scope of catalog.LoadScored with no scenario (a scoreboard
// whose SCENARIO_FILE is empty): the challenges a render with it writes and a check with it
// accepts are the investigate challenges of that call, compared on the fixture's event, and a
// render -> check round trip with it exits 0. The tree is internal/edition/editiontest's; every
// value is a placeholder with no meaning.

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

// withAllChallenges is args with --scenario <file> replaced by --all-challenges.
func withAllChallenges(args []string) []string {
	return append(without(args, scenarioFlag), allChallengesFlag)
}

// The four ways of giving the scope, for both subcommands: --scenario alone and --all-challenges
// alone are read into the input (the scenario path, or AllChallenges and no path); neither, both,
// an empty --scenario (with or without --all-challenges), --all-challenges twice and with a
// value are exit 2, print nothing on stdout and write nothing.
func TestEditionScope_ExactlyOneOfScenarioAndAllChallenges(t *testing.T) {
	cf := newEcFix(t)
	check := cf.args()
	if in, err := parseCheckArgs(check); err != nil || in.AllChallenges || in.ScenarioFile == "" {
		t.Errorf("check with --scenario: %+v, %v; want the scenario path and not AllChallenges", in.ScenarioFile, err)
	}
	if in, err := parseCheckArgs(withAllChallenges(check)); err != nil || !in.AllChallenges || in.ScenarioFile != "" {
		t.Errorf("check with --all-challenges: %q, %v; want AllChallenges and no scenario path", in.ScenarioFile, err)
	}

	rf := newErFix(t)
	render := rf.args(rf.out())
	if in, err := parseRenderArgs(render); err != nil || in.AllChallenges || in.ScenarioFile == "" {
		t.Errorf("render with --scenario: %q, %v; want the scenario path and not AllChallenges", in.ScenarioFile, err)
	}
	if in, err := parseRenderArgs(withAllChallenges(render)); err != nil || !in.AllChallenges || in.ScenarioFile != "" {
		t.Errorf("render with --all-challenges: %q, %v; want AllChallenges and no scenario path", in.ScenarioFile, err)
	}

	type usage struct {
		name string
		args []string
	}
	refused := func(good []string) []usage {
		return []usage{
			{"neither --scenario nor --all-challenges", without(good, scenarioFlag)},
			{"both --scenario and --all-challenges", append(slices.Clone(good), allChallengesFlag)},
			{"an empty --scenario= value", append(without(good, scenarioFlag), scenarioFlag+"=")},
			{"an empty --scenario word", append(without(good, scenarioFlag), scenarioFlag, "")},
			{"an empty --scenario and --all-challenges", append(withAllChallenges(good), scenarioFlag+"=")},
			{"--all-challenges twice", append(withAllChallenges(good), allChallengesFlag)},
			{"--all-challenges with a value", append(without(good, scenarioFlag), allChallengesFlag+"=yes")},
		}
	}
	for _, c := range refused(check) {
		code, stdout, stderr := runEd(append([]string{subcommandCheck}, c.args...)...)
		if code != exitUsage || stdout != "" {
			t.Errorf("check, %s: exit %d, stdout %q, stderr %q; want exit 2 and no stdout", c.name, code, stdout, stderr)
		}
		if cf.digestsOutExists() {
			t.Fatalf("check, %s: a digests file was written", c.name)
		}
	}
	for _, c := range refused(render) {
		code, stdout, stderr := runEd(append([]string{subcommandRender}, c.args...)...)
		if code != exitUsage || stdout != "" {
			t.Errorf("render, %s: exit %d, stdout %q, stderr %q; want exit 2 and no stdout", c.name, code, stdout, stderr)
		}
		rf.nothingAt("render, "+c.name, rf.out())
	}
}

// The scope of --all-challenges is catalog.LoadScored's with no scenario, compared on what a
// render and a check of the fixture's event do: the fixture's scenario is made to name the evade
// challenge only, so the scope it gives has no investigate challenge (the render of it is exit 2),
// while --all-challenges, which reads no scenario, takes the investigate challenge of the tree. The
// round trip render -> check with --all-challenges exits 0, and the challenges of its bundles and
// of its digests are exactly the investigate challenges of catalog.LoadScored(challenges, "",
// flags), the call of a scoreboard whose SCENARIO_FILE is empty (cmd/scoreboard/catalog.go).
func TestEditionScope_AllChallengesIsTheScopeOfNoScenario(t *testing.T) {
	f := newErFix(t)
	f.tree.Put(editiontest.ScenarioRel, "id: fixture\ntitle: Fixture\nchallenges: ["+editiontest.Evade+"]\n")
	p := f.tree.Paths()
	all, err := catalog.LoadScored(p.Challenges, "", p.Flags)
	if err != nil {
		t.Fatalf("catalog.LoadScored with no scenario: %v", err)
	}
	want := slices.Sorted(maps.Keys(edition.ScopeOf(all.Catalog)))
	if len(want) == 0 {
		t.Fatal("the tree has no investigate challenge: the comparison below would prove nothing")
	}
	narrow, err := catalog.LoadScored(p.Challenges, p.Scenario, p.Flags)
	if err != nil {
		t.Fatalf("catalog.LoadScored with the scenario: %v", err)
	}
	if n := len(edition.ScopeOf(narrow.Catalog)); n != 0 {
		t.Fatalf("the scenario's scope has %d investigate challenges, want 0: the two scopes would not differ", n)
	}

	out := f.out()
	if code, stdout, stderr := runEd(append([]string{subcommandRender}, f.args(out)...)...); code != exitUsage {
		t.Fatalf("render of the evade-only scenario: exit %d, stdout %q, stderr %q; want exit 2 (no investigate challenge)", code, stdout, stderr)
	}
	f.nothingAt("render of the evade-only scenario", out)

	code, stdout, stderr := runEd(append([]string{subcommandRender}, withAllChallenges(f.args(out))...)...)
	if code != exitAccepted {
		t.Fatalf("render with --all-challenges: exit %d, stdout %q, stderr %q; want exit 0", code, stdout, stderr)
	}
	entries, err := os.ReadDir(filepath.Join(out, edition.EventEvidenceDirName, editiontest.Seats()[0]))
	if err != nil {
		t.Fatal(err)
	}
	var rendered []string
	for _, e := range entries {
		rendered = append(rendered, e.Name())
	}
	if !slices.Equal(rendered, want) {
		t.Errorf("render with --all-challenges wrote the bundles of %q, want the investigate challenges of LoadScored with no scenario %q", rendered, want)
	}

	digests := f.tree.Path(editiontest.DigestsRel)
	args := withAllChallenges(f.checkArgs(out, f.tree.Path(editiontest.SeatsRel), digests))
	code, stdout, stderr = runEd(append([]string{subcommandCheck}, args...)...)
	if code != exitAccepted {
		t.Fatalf("check with --all-challenges of the render: exit %d, stdout %q, stderr %q; want exit 0", code, stdout, stderr)
	}
	data, err := os.ReadFile(digests)
	if err != nil {
		t.Fatalf("the digests file of the check: %v", err)
	}
	_, rows, err := edition.ParseDigests(data)
	if err != nil {
		t.Fatalf("the digests file of the check: %v", err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.CID] = true
	}
	if checked := slices.Sorted(maps.Keys(seen)); !slices.Equal(checked, want) {
		t.Errorf("check with --all-challenges accepted the challenges %q, want the investigate challenges of LoadScored with no scenario %q", checked, want)
	}
}
