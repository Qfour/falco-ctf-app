package catalog_test

// app#494: a scenario name (scenarios/<name>/, `scenario:<name>` in
// charts/ctf-user/deploy-user.sh) has no Go definition: deploy-user.sh is the only
// code that takes one from an operator, and it checks it with SCENARIO_PATTERN
// before any kubectl / helm call. This test holds that shell literal equal to the
// header of the shared case table (internal/catalog/testdata/scenario-name-cases.tsv),
// runs every row through it, and requires every real scenarios/<name>/ to be
// accepted, so a grammar tightened past a shipped scenario is red here and not at a
// stand-up. scripts/check-deploy-user-ids.sh runs the same rows through the script.

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/casetable"
)

const minScenarioCases = 40

func TestScenarioNameGrammar_SharedCaseTable(t *testing.T) {
	table := filepath.Join("testdata", "scenario-name-cases.tsv")
	raw, err := os.ReadFile(table)
	if err != nil {
		t.Fatal(err)
	}
	header, ok := casetable.Header(string(raw))
	if !ok {
		t.Fatalf("scenario-name-cases.tsv line 1 must be %q followed by the regex", casetable.HeaderPrefix)
	}
	script, err := os.ReadFile(filepath.Join("..", "..", "charts", "ctf-user", "deploy-user.sh"))
	if err != nil {
		t.Fatal(err)
	}
	shell, ok := casetable.ShellAssign(string(script), "SCENARIO_PATTERN")
	if !ok {
		t.Fatal("deploy-user.sh must define SCENARIO_PATTERN='...' exactly once on its own line")
	}
	if shell != header {
		t.Fatalf("deploy-user.sh SCENARIO_PATTERN = %q, want the table's header pattern %q", shell, header)
	}
	re := regexp.MustCompile(shell)

	rows, err := casetable.Parse("scenario-name-cases.tsv", string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < minScenarioCases {
		t.Fatalf("scenario-name-cases.tsv has %d rows, want at least %d: the table was truncated or misread", len(rows), minScenarioCases)
	}
	accepted, rejected := 0, 0
	for _, r := range rows {
		if r.Accept {
			accepted++
		} else {
			rejected++
		}
		if got := re.MatchString(r.Input); got != r.Accept {
			t.Errorf("scenario-name-cases.tsv:%d: %q matches SCENARIO_PATTERN = %v, want %v", r.Line, r.Input, got, r.Accept)
		}
	}
	if accepted < 10 || rejected < 25 {
		t.Fatalf("scenario-name-cases.tsv has %d accept / %d reject rows: too few of one kind to hold the grammar", accepted, rejected)
	}
}

func TestScenarioNameGrammar_EveryShippedScenarioIsAccepted(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "charts", "ctf-user", "deploy-user.sh"))
	if err != nil {
		t.Fatal(err)
	}
	shell, ok := casetable.ShellAssign(string(script), "SCENARIO_PATTERN")
	if !ok {
		t.Fatal("deploy-user.sh must define SCENARIO_PATTERN='...' exactly once on its own line")
	}
	re := regexp.MustCompile(shell)
	dirs, err := filepath.Glob(filepath.Join("..", "..", "scenarios", "*", "scenario.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) < 3 {
		t.Fatalf("found %d scenarios/*/scenario.yaml, want at least 3: the glob is wrong or the tree moved", len(dirs))
	}
	for _, f := range dirs {
		name := filepath.Base(filepath.Dir(f))
		if !re.MatchString(name) {
			t.Errorf("scenarios/%s does not match SCENARIO_PATTERN %q: deploy-user.sh would refuse it", name, shell)
		}
	}
}
