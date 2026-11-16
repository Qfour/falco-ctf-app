package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// ADR-0056 stage A2b at start-up (V1 start-up part, V13 behaviour, V15 start-up
// part): startEdition against the real catalog wiring (scoredFromEnv) when there is
// no investigate challenge, and against a catalog made by catalog.Load when there is
// one (investigate_boot_test.go runs the whole start-up with one, since A3b-3). Every
// value is synthetic.

const (
	edRunID    = "0123456789abcdef0123456789abcdef"
	edCID      = "01-demo"
	edSentinel = "SENTINEL-zzzz"
	edTutorial = "../../scenarios/tutorial-intro/scenario.yaml" // evade in scope: 03 only
	edFlag03   = "FALCO{test-edition-03}"
)

const edFixtureYAML = `type: investigate
investigate:
  evidence: {mountDir: /opt/ctf/evidence}
  questions:
    - id: who
      format: name
    - id: hx
      format: hexid
      params: {length: 12}
`

var edGoodRows = []string{
	"seat-a\t" + edCID + "\twho\t" + edSentinel + "-a",
	"seat-a\t" + edCID + "\thx\taaaaaaaaaaaa",
	"seat-b\t" + edCID + "\twho\t" + edSentinel + "-b",
	"seat-b\t" + edCID + "\thx\tbbbbbbbbbbbb",
}

// edValues are the table values of edGoodRows: none may appear in a log line.
var edValues = []string{edSentinel, "aaaaaaaaaaaa", "bbbbbbbbbbbb"}

// edInvestigateCatalog is the scored value of a tree with one investigate challenge
// and no practice edition: the scope is the whole tree, as with no scenario (what
// catalog.LoadScored returns, built by catalog.Load here so that no flags file is
// needed). Its FullCatalog and ChallengesDir are that tree's.
func edInvestigateCatalog(t *testing.T) catalog.Scored {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, edCID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, edCID, "falco-rule.yaml"), []byte(edFixtureYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	return catalog.Scored{Catalog: cat, FullCatalog: cat, ChallengesDir: dir, Order: cat.IDs()}
}

func edAnswersFile(t *testing.T, runID string, rows []string) string {
	t.Helper()
	body := "# falco-ctf answers v1 run=" + runID + "\n" + strings.Join(rows, "\n") + "\n"
	p := filepath.Join(t.TempDir(), "answers.tsv")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// bootEdition runs startEdition with a JSON logger on a buffer, as main() builds
// it, and returns what it logged.
func bootEdition(t *testing.T, cfg catalogEnv, scored catalog.Scored) (*edition.Judge, string, []map[string]any, error) {
	t.Helper()
	var buf bytes.Buffer
	j, err := startEdition(slog.New(slog.NewJSONHandler(&buf, nil)), cfg, scored)
	text := buf.String()
	var recs []map[string]any
	if strings.TrimSpace(text) != "" {
		for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("log line is not JSON: %q: %v", line, err)
			}
			recs = append(recs, m)
		}
	}
	return j, text, recs, err
}

func noValueInLog(t *testing.T, what, text string) {
	t.Helper()
	for _, v := range edValues {
		if strings.Contains(text, v) {
			t.Errorf("%s: the boot log holds a table value (%q): %s", what, v, text)
		}
	}
}

// No investigate challenge in scope and no ANSWERS_FILE: every environment that
// exists today. Nothing changes: no judge, no error, and not one log line, with or
// without the event mode.
func TestStartEdition_NoInvestigateNoTable_ChangesNothing(t *testing.T) {
	flags := writeFlagsFile(t, "03-stealth-read", edFlag03)
	for name, env := range map[string]map[string]string{
		"not the event mode": {"CHALLENGES_DIR": "../../challenges", "SCENARIO_FILE": edTutorial},
		"the event mode":     {"CHALLENGES_DIR": "../../challenges", "SCENARIO_FILE": edTutorial, "FLAGS_FILE": flags},
	} {
		cfg, scored, err := scoredFromEnv(fakeEnv(env))
		if err != nil {
			t.Fatalf("%s: scoredFromEnv: %v", name, err)
		}
		j, text, recs, err := bootEdition(t, cfg, scored)
		if err != nil || j != nil || len(recs) != 0 {
			t.Errorf("%s: judge %v, err %v, log %q; want nothing at all", name, j, err, text)
		}
	}
}

// V1 / V3 (start-up): ANSWERS_FILE with nothing to judge, in the event mode, is
// refused; outside the event mode it is refused as a mismatch of the two signals.
func TestStartEdition_RefusesAnAnswersFileThroughScoredFromEnv(t *testing.T) {
	flags := writeFlagsFile(t, "03-stealth-read", edFlag03)
	table := edAnswersFile(t, edRunID, edGoodRows)

	env := map[string]string{"CHALLENGES_DIR": "../../challenges", "SCENARIO_FILE": edTutorial, "FLAGS_FILE": flags, "ANSWERS_FILE": table}
	cfg, scored, err := scoredFromEnv(fakeEnv(env))
	if err != nil {
		t.Fatalf("scoredFromEnv: %v", err)
	}
	if cfg.answersFile != table {
		t.Fatalf("ANSWERS_FILE was not read into the config: %q", cfg.answersFile)
	}
	j, text, recs, err := bootEdition(t, cfg, scored)
	if err == nil || j != nil {
		t.Fatalf("the event mode, an answers file and no investigate challenge: judge %v, err %v; want a refusal", j, err)
	}
	if len(recs) != 1 || recs[0]["msg"] != "edition check failed" || recs[0]["level"] != "ERROR" {
		t.Errorf("want exactly one ERROR record \"edition check failed\", got %s", text)
	}
	noValueInLog(t, "no investigate challenge", text)

	delete(env, "FLAGS_FILE")
	cfg, scored, err = scoredFromEnv(fakeEnv(env))
	if err != nil {
		t.Fatalf("scoredFromEnv: %v", err)
	}
	j, text, recs, err = bootEdition(t, cfg, scored)
	if !errors.Is(err, edition.ErrTableOutsideEventMode) || j != nil {
		t.Fatalf("an answers file without the event mode: judge %v, err %v; want ErrTableOutsideEventMode", j, err)
	}
	if len(recs) != 1 || recs[0]["msg"] != "edition check failed" || recs[0]["level"] != "ERROR" {
		t.Errorf("want exactly one ERROR record \"edition check failed\", got %s", text)
	}
}

// An investigate challenge in scope (built by catalog.Load): the accepted table
// gives a judge and exactly one INFO record carrying the run id; each refusal gives
// exactly one ERROR record and no table value anywhere in the log.
func TestStartEdition_InvestigateInScope(t *testing.T) {
	cat := edInvestigateCatalog(t)
	event := catalogEnv{flagsFile: "flags.yaml"} // only "is it set" matters to startEdition

	t.Run("accepted", func(t *testing.T) {
		cfg := event
		cfg.answersFile = edAnswersFile(t, edRunID, edGoodRows)
		j, text, recs, err := bootEdition(t, cfg, cat)
		if err != nil || j == nil {
			t.Fatalf("judge %v, err %v; want a judge", j, err)
		}
		if len(recs) != 1 || recs[0]["msg"] != "edition loaded" || recs[0]["level"] != "INFO" || recs[0]["run_id"] != edRunID {
			t.Errorf("want exactly one INFO record \"edition loaded\" with run_id %s, got %s", edRunID, text)
		}
		noValueInLog(t, "accepted", text)
		if ok, known := j.Match("seat-a", edCID, "who", edSentinel+"-a"); !ok || !known {
			t.Errorf("the judge does not know seat-a's answer: %v, %v", ok, known)
		}
	})

	dup := append([]string(nil), edGoodRows...)
	dup[2] = "seat-b\t" + edCID + "\twho\t" + edSentinel + "-a" // two seats, one value
	cases := []struct {
		name   string
		answer string
		want   error
	}{
		{"no ANSWERS_FILE (D8 (i))", "", edition.ErrTableMissing},
		{"the practice run id in the event mode (V15)", edAnswersFile(t, edition.PracticeRunID, edGoodRows), nil},
		{"a row missing", edAnswersFile(t, edRunID, edGoodRows[:3]), nil},
		{"two seats share a value", edAnswersFile(t, edRunID, dup), nil},
		{"not a table", edAnswersFile(t, "not-a-run-id", edGoodRows), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := event
			cfg.answersFile = c.answer
			j, text, recs, err := bootEdition(t, cfg, cat)
			if err == nil || j != nil {
				t.Fatalf("judge %v, err %v; want a refusal", j, err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
			if len(recs) != 1 || recs[0]["msg"] != "edition check failed" || recs[0]["level"] != "ERROR" {
				t.Errorf("want exactly one ERROR record \"edition check failed\", got %s", text)
			}
			noValueInLog(t, c.name, text)
			noValueInLog(t, c.name, err.Error())
		})
	}
}

// ADR-0056 D8 (ii) for an investigate scope without the event mode: the table is
// refused too (the two signals disagree); and without a table the practice answers
// of the image are used (D8 (iv)): edInvestigateCatalog has none (and catalogEnv{} no
// challengesDir), so the start-up is refused, with one ERROR record.
func TestStartEdition_InvestigateWithoutTheEventMode(t *testing.T) {
	cat := edInvestigateCatalog(t)
	j, _, recs, err := bootEdition(t, catalogEnv{answersFile: edAnswersFile(t, edition.PracticeRunID, edGoodRows)}, cat)
	if !errors.Is(err, edition.ErrTableOutsideEventMode) || j != nil || len(recs) != 1 {
		t.Errorf("a table without the event mode: judge %v, err %v, %d record(s); want ErrTableOutsideEventMode and one record", j, err, len(recs))
	}
	j, text, recs, err := bootEdition(t, catalogEnv{}, cat)
	if err == nil || j != nil || len(recs) != 1 || recs[0]["msg"] != "edition check failed" || recs[0]["level"] != "ERROR" {
		t.Errorf("no event mode, no table, no practice edition: judge %v, err %v, log %q; want a refusal and one ERROR record \"edition check failed\"", j, err, text)
	}
}
