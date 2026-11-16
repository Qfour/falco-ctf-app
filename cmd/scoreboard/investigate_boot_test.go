package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// ADR-0056 A3b-3 (V21 reversed): a scoreboard STARTS with an investigate challenge in
// scope. These tests run the start-up steps of main() in its order, with the same
// functions: scoredFromEnv (catalog.LoadScored), catalog.LoadJourneys,
// catalog.LoadRuleExcerpts, startEdition, then scoreboard.NewHandler with the Judge,
// and they answer through the real route. The challenge tree is synthetic and written
// under t.TempDir() (no investigate challenge exists under challenges/ until A7).

const (
	ibOrigin = "https://journey.ctf.local"
	ibSeatA  = "seat-a"
	ibEvade  = "02-evade"
)

// block form with quoted prompts: a flow mapping with a bare "?" in a value is not valid YAML.
const ibJourney = "challengeId: " + edCID + "\ntitle: IR demo\nquestions:\n" +
	"  - id: who\n    prompt: \"Which account ran it?\"\n" +
	"  - id: hx\n    prompt: \"Which id was used?\"\n"

// ibTree writes the synthetic challenges: the investigate challenge (edCID, with its
// journey.yaml) and an evade challenge, so the event mode has a flag to supply.
func ibTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		filepath.Join(edCID, "falco-rule.yaml"):   edFixtureYAML,
		filepath.Join(edCID, "journey.yaml"):      ibJourney,
		filepath.Join(ibEvade, "falco-rule.yaml"): "type: evade\nexpectedFlag: FALCO{dev-ib}\nforbiddenRules: [r]\n",
	}
	for rel, body := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// ibBooted is what main() holds after the start-up steps that matter here.
type ibBooted struct {
	cfg      catalogEnv
	scored   catalog.Scored
	journeys catalog.Journeys
	rules    catalog.FalcoRuleExcerpts
	judge    *edition.Judge
	log      string
	recs     []map[string]any
	err      error // startEdition's
}

// ibStart is main()'s sequence up to the handler. A failure before startEdition is a
// failure of the test: the point of A3b-3 is that those steps accept the scope.
func ibStart(t *testing.T, env map[string]string) ibBooted {
	t.Helper()
	var b ibBooted
	var err error
	b.cfg, b.scored, err = scoredFromEnv(fakeEnv(env))
	if err != nil {
		t.Fatalf("scoredFromEnv refused a scope with an investigate challenge: %v", err)
	}
	if b.journeys, err = catalog.LoadJourneys(b.cfg.challengesDir, b.scored.Catalog); err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	if b.rules, err = catalog.LoadRuleExcerpts(b.cfg.challengesDir, b.scored.Catalog); err != nil {
		t.Fatalf("LoadRuleExcerpts: %v", err)
	}
	b.judge, b.log, b.recs, b.err = bootEdition(t, b.cfg, b.scored.Catalog)
	return b
}

// ibHandler is the handler main() builds from a booted scoreboard (only the options
// this test needs). A nil Judge is passed as main() passes it.
func ibHandler(t *testing.T, b ibBooted) (*scoreboard.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ib.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := scoreboard.NewHandler(b.scored.Catalog, st, slog.New(slog.NewTextHandler(io.Discard, nil)),
		scoreboard.WithJourneys(b.journeys),
		scoreboard.WithFalcoRules(b.rules),
		scoreboard.WithOrder(b.scored.Order),
		scoreboard.WithExpectedEmailDomain("ctf.local"),
		scoreboard.WithAllowedOrigins([]string{ibOrigin}),
		scoreboard.WithEditionJudge(b.judge),
	)
	return h, st
}

// ibAnswer is seat answering one question as itself, from the allowed origin.
func ibAnswer(t *testing.T, h *scoreboard.Handler, seat, qid, answer string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"answer": answer})
	r := httptest.NewRequest("POST", "/api/users/"+seat+"/challenges/"+edCID+"/questions/"+qid+"/answer", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", ibOrigin)
	r.Header.Set("X-Auth-Request-Email", seat+"@ctf.local")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("answer %s/%s: body is not JSON: %q: %v", seat, qid, w.Body.String(), err)
	}
	return w.Code, got
}

// (a) The event mode and a table that answers the scope: the scoreboard starts, logs
// `edition loaded` once, and a participant solves the challenge through the route.
func TestBoot_InvestigateScope_EventModeWithTable_StartsAndGrades(t *testing.T) {
	env := map[string]string{
		"CHALLENGES_DIR": ibTree(t),
		"FLAGS_FILE":     writeFlagsFile(t, ibEvade, edFlag03),
		"ANSWERS_FILE":   edAnswersFile(t, edRunID, edGoodRows),
	}
	b := ibStart(t, env)
	if b.err != nil || b.judge == nil {
		t.Fatalf("startEdition: judge %v, err %v; want a judge", b.judge, b.err)
	}
	if len(b.recs) != 1 || b.recs[0]["msg"] != "edition loaded" || b.recs[0]["level"] != "INFO" || b.recs[0]["run_id"] != edRunID {
		t.Errorf("want exactly one INFO record \"edition loaded\" with run_id %s, got %s", edRunID, b.log)
	}
	noValueInLog(t, "accepted", b.log)
	if got := strings.Join(b.scored.Order, ","); got != edCID+","+ibEvade {
		t.Errorf("Order = %s, want %s,%s (the investigate challenge is first and current)", got, edCID, ibEvade)
	}

	h, st := ibHandler(t, b)
	if code, got := ibAnswer(t, h, ibSeatA, "who", "TYPED-answer-yyyy"); code != http.StatusOK || got["status"] != "incorrect" || got["solved"] != false {
		t.Fatalf("a wrong answer: %d %v, want 200 incorrect, not solved", code, got)
	}
	if code, got := ibAnswer(t, h, ibSeatA, "who", edSentinel+"-a"); code != http.StatusOK || got["status"] != "correct" || got["solved"] != false {
		t.Fatalf("the first right answer: %d %v, want 200 correct, not solved yet", code, got)
	}
	if st.IsSolved(ibSeatA, edCID) {
		t.Fatal("solved after one of two questions")
	}
	if code, got := ibAnswer(t, h, ibSeatA, "hx", "aaaaaaaaaaaa"); code != http.StatusOK || got["status"] != "correct" || got["solved"] != true {
		t.Fatalf("the last right answer: %d %v, want 200 correct and solved", code, got)
	}
	if !st.IsSolved(ibSeatA, edCID) {
		t.Fatal("the challenge is not solved in the store after both answers")
	}
	// the table is per seat: seat-a's value is not seat-b's answer
	if code, got := ibAnswer(t, h, "seat-b", "who", edSentinel+"-a"); code != http.StatusOK || got["status"] != "incorrect" {
		t.Fatalf("seat-b with seat-a's value: %d %v, want 200 incorrect", code, got)
	}
	if st.IsSolved("seat-b", edCID) {
		t.Fatal("seat-b solved with seat-a's values")
	}
}

// (b) The event mode with an investigate challenge in scope and no answers table:
// the scoreboard does not start (D8 (i)). catalog.LoadScored accepts the scope, so
// the refusal is edition.Load's, with the record platform's verify.sh reads.
func TestBoot_InvestigateScope_EventModeWithoutTable_IsRefused(t *testing.T) {
	env := map[string]string{
		"CHALLENGES_DIR": ibTree(t),
		"FLAGS_FILE":     writeFlagsFile(t, ibEvade, edFlag03),
	}
	b := ibStart(t, env)
	if !errors.Is(b.err, edition.ErrTableMissing) || b.judge != nil {
		t.Fatalf("startEdition: judge %v, err %v; want ErrTableMissing and no judge", b.judge, b.err)
	}
	if len(b.recs) != 1 || b.recs[0]["msg"] != "edition check failed" || b.recs[0]["level"] != "ERROR" {
		t.Errorf("want exactly one ERROR record \"edition check failed\", got %s", b.log)
	}
	noValueInLog(t, "refused", b.log)
}

// (c) NOT the event mode, an investigate challenge in scope and no answers table (the
// practice edition): TODAY the scoreboard starts, silently, with no Judge, and every
// answer is a 500 that spends nothing. The practice answers of the image are A4a's
// (edition.Load: "The practice answers of the image are not read here"); until A4a
// this is the pinned behaviour, and no real challenge can be in this state before A7
// (D19: A4a is a prerequisite of A7). When A4a lands this test changes with it.
func TestBoot_InvestigateScope_PracticeWithoutTable_StartsAndCannotGradeYet(t *testing.T) {
	b := ibStart(t, map[string]string{"CHALLENGES_DIR": ibTree(t)})
	if b.err != nil || b.judge != nil || len(b.recs) != 0 {
		t.Fatalf("startEdition: judge %v, err %v, log %q; want no judge, no error, no record", b.judge, b.err, b.log)
	}
	h, st := ibHandler(t, b)
	code, got := ibAnswer(t, h, ibSeatA, "who", edSentinel+"-a")
	if code != http.StatusInternalServerError || len(got) != 1 || got["error"] != "could not grade the answer" {
		t.Fatalf("an answer without a Judge: %d %v, want 500 {\"error\": \"could not grade the answer\"}", code, got)
	}
	rows, err := st.AnswerAttempts(ibSeatA, edCID)
	if err != nil || len(rows) != 0 {
		t.Fatalf("attempts after an ungradable answer: %v (err %v), want none (nothing is spent)", rows, err)
	}
	if st.IsSolved(ibSeatA, edCID) {
		t.Fatal("solved without a table")
	}
}

// The real catalog (no investigate challenge, no scenario, no table) starts exactly
// as before: the same steps, no Judge, no error, not one boot record from
// startEdition, with and without the event mode.
func TestBoot_RealCatalog_UnchangedByAcceptingTheInvestigateType(t *testing.T) {
	cfg, scored, err := scoredFromEnv(fakeEnv(map[string]string{"CHALLENGES_DIR": "../../challenges"}))
	if err != nil {
		t.Fatalf("scoredFromEnv on the real tree: %v", err)
	}
	for _, c := range scored.Catalog {
		if c.Type == catalog.TypeInvestigate {
			t.Fatalf("%s is an investigate challenge: this test is about a tree without one (A7 changes it)", c.ID)
		}
	}
	for name, event := range map[string]bool{"not the event mode": false, "the event mode": true} {
		c := cfg
		if event {
			c.flagsFile = "flags.yaml" // only "is it set" matters to startEdition
		}
		j, text, recs, err := bootEdition(t, c, scored.Catalog)
		if err != nil || j != nil || len(recs) != 0 {
			t.Errorf("%s: judge %v, err %v, log %q; want nothing at all", name, j, err, text)
		}
	}
}
