package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ADR-0056 A4f / V105 at start-up: the three kinds of start (the event table, the
// practice mode, no table needed) run main()'s steps (ibStart: scoredFromEnv,
// LoadJourneys, LoadRuleExcerpts, startEdition) and the handler main() builds from
// them (ibHandler: WithEditionJudge and WithEditionRunID with what startEdition
// returned). GET /metrics of that handler has exactly one series of
// scoreboard_edition_loaded_info, at 1, whose run_id is the run id of the `edition
// loaded` record (the same variable: startEdition returns the one it logs), and no
// table value. A start that startEdition refuses exits before the handler is built,
// so before /metrics is served: TestBootLogContract_EditionCheckFailed_ExitsRightAfter
// (bootlog_contract_test.go) pins `os.Exit(1)` right after the call, and
// TestEditionGauge_MainWiresTheRunID below that the handler is built after it.

const edGaugeFamily = "scoreboard_edition_loaded_info"

// edGauge is GET /metrics of h: the whole body and the sample lines of the family.
func edGauge(t *testing.T, h http.Handler) (string, []string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	var series []string
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(ln, edGaugeFamily) {
			series = append(series, ln)
		}
	}
	return body, series
}

func TestEditionGauge_TheThreeStarts(t *testing.T) {
	practiceTree := func(t *testing.T) string {
		dir := ibTree(t)
		ibWritePractice(t, dir, ibPracticeTable(ibPracticeRows...))
		return dir
	}
	cases := []struct {
		name string
		env  func(t *testing.T) map[string]string
		// record: the start logs `edition loaded` (with the run id want)
		record bool
		want   string
	}{
		{"the event table", func(t *testing.T) map[string]string {
			return map[string]string{
				"CHALLENGES_DIR": ibTree(t),
				"FLAGS_FILE":     writeFlagsFile(t, ibEvade, edFlag03),
				"ANSWERS_FILE":   edAnswersFile(t, edRunID, edGoodRows),
			}
		}, true, edRunID},
		{"the practice mode", func(t *testing.T) map[string]string {
			return map[string]string{"CHALLENGES_DIR": practiceTree(t)}
		}, true, ibZeroRunID},
		{"no table needed, not the event mode", func(t *testing.T) map[string]string {
			return map[string]string{"CHALLENGES_DIR": "../../challenges", "SCENARIO_FILE": edTutorial}
		}, false, "none"},
		{"no table needed, the event mode", func(t *testing.T) map[string]string {
			return map[string]string{"CHALLENGES_DIR": "../../challenges", "SCENARIO_FILE": edTutorial, "FLAGS_FILE": writeFlagsFile(t, "03-stealth-read", edFlag03)}
		}, false, "none"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := ibStart(t, c.env(t))
			if b.err != nil {
				t.Fatalf("startEdition: %v", b.err)
			}
			if c.record {
				if b.judge == nil || len(b.recs) != 1 || b.recs[0]["msg"] != "edition loaded" || b.recs[0]["run_id"] != c.want || b.runID != c.want {
					t.Fatalf("want a Judge and one `edition loaded` record with run_id %s, and that run id returned; got judge %v, run id %q, log %s", c.want, b.judge, b.runID, b.log)
				}
			} else if b.judge != nil || len(b.recs) != 0 || b.runID != "" {
				t.Fatalf("want no Judge, no record and no run id; got judge %v, run id %q, log %s", b.judge, b.runID, b.log)
			}
			// The record's run_id, the returned run id and the gauge's run_id are each
			// c.want: one value, from the one variable startEdition logs and returns.
			h, _ := ibHandler(t, b)
			body, series := edGauge(t, h)
			want := edGaugeFamily + `{run_id="` + c.want + `"} 1`
			if len(series) != 1 || series[0] != want {
				t.Errorf("the series of %s = %q, want exactly [%s]", edGaugeFamily, series, want)
			}
			noValueInLog(t, c.name+": GET /metrics", body)
			noPracticeValueInLog(t, c.name+": GET /metrics", body)
		})
	}
}

// main() hands the handler the run id startEdition returned, the variable the record
// carries, and builds the handler after the exit on a refusal. Source-string test, as
// bootlog_contract_test.go's: the three-start test above runs ibHandler, which mirrors
// main(); this pins that main() itself passes the same variable.
func TestEditionGauge_MainWiresTheRunID(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	const call = "editionJudge, editionRunID, err := startEdition(logger, catCfg, scored)"
	const opt = "scoreboard.WithEditionRunID(editionRunID),"
	for _, want := range []string{call, opt, "WithEditionRunID(", "scoreboard.NewHandler("} {
		if c := strings.Count(code, want); c != 1 {
			t.Fatalf("main.go has %q %d time(s), want exactly 1", want, c)
		}
	}
	if strings.Index(code, call) > strings.Index(code, "scoreboard.NewHandler(") {
		t.Fatal("main.go builds the handler before startEdition: /metrics could be served by a start that startEdition refuses")
	}
	if strings.Index(code, opt) < strings.Index(code, "scoreboard.NewHandler(") {
		t.Fatal("scoreboard.WithEditionRunID(editionRunID) is not among the options of scoreboard.NewHandler")
	}
}
