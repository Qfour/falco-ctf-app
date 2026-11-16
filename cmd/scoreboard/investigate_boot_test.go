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
)

// ibEvade is "00-...": it sorts BEFORE the investigate challenge (edCID, 01-demo). With
// no scenario the order is the sorted ids, and catalog.LoadScored refuses an evade
// challenge after an investigate one (ADR-0056 A3b-5 / V39), so the evade challenge
// goes first.
const ibEvade = "00-evade"

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
	b.judge, b.log, b.recs, b.err = bootEdition(t, b.cfg, b.scored)
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
	if got := strings.Join(b.scored.Order, ","); got != ibEvade+","+edCID {
		t.Errorf("Order = %s, want %s,%s (the evade challenge comes before the investigate one: V39)", got, ibEvade, edCID)
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

// (b2) ADR-0056 A4a-1 / V34 at start-up: startEdition hands the Scored that
// scoredFromEnv returned (it carries CHALLENGES_DIR's tree, A4a-3) to edition.Load,
// which reads the practice answers of that tree for T6. An event table that
// repeats a published practice answer is refused (one ERROR record, no value in it);
// the same tree with a practice edition of other values starts. The practice edition
// here is synthetic (no investigate challenge, so no practice edition, is in the repo).
func TestBoot_InvestigateScope_EventTableRepeatingAPracticeAnswer_IsRefused(t *testing.T) {
	practice := func(hx string) string {
		return "# falco-ctf answers v1 run=" + edition.PracticeRunID + "\n*\t" + edCID + "\thx\t" + hx + "\n"
	}
	cases := []struct {
		name    string
		hx      string
		refused bool
	}{
		{"a practice answer equal to the event's (seat-a's hx)", "aaaaaaaaaaaa", true},
		{"a practice answer that differs", "cccccccccccc", false},
	}
	for _, c := range cases {
		name := c.name
		dir := ibTree(t)
		pdir := filepath.Join(dir, edCID, "edition", "practice")
		if err := os.MkdirAll(pdir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pdir, "answers.tsv"), []byte(practice(c.hx)), 0o644); err != nil {
			t.Fatal(err)
		}
		b := ibStart(t, map[string]string{
			"CHALLENGES_DIR": dir,
			"FLAGS_FILE":     writeFlagsFile(t, ibEvade, edFlag03),
			"ANSWERS_FILE":   edAnswersFile(t, edRunID, edGoodRows),
		})
		if !c.refused {
			if b.err != nil || b.judge == nil {
				t.Errorf("%s: judge %v, err %v; want a judge", name, b.judge, b.err)
			}
			continue
		}
		if b.err == nil || b.judge != nil || !strings.Contains(b.err.Error(), "T6") {
			t.Errorf("%s: judge %v, err %v; want a T6 refusal and no judge", name, b.judge, b.err)
		}
		if len(b.recs) != 1 || b.recs[0]["msg"] != "edition check failed" || b.recs[0]["level"] != "ERROR" {
			t.Errorf("%s: want exactly one ERROR record \"edition check failed\", got %s", name, b.log)
		}
		noValueInLog(t, name, b.log)
	}
}

// The synthetic practice edition of edCID (ADR-0056 D8 (iv), A4a-2): the answers the
// image publishes, run id all zeros, seat *. Made-up values.
const (
	ibPracticeWho = "practice-who"
	ibPracticeHx  = "cccccccccccc"
	ibZeroRunID   = "00000000000000000000000000000000" // spelled out, not edition.PracticeRunID: the boot record's value is the contract
)

// ibPracticeTable is a practice answers.tsv for edCID with the given rows (the header
// is the practice run id).
func ibPracticeTable(rows ...string) string {
	// one "\n" per row: no rows is the header line alone (a Join + "\n" would add an empty line)
	var b strings.Builder
	b.WriteString("# falco-ctf answers v1 run=" + ibZeroRunID + "\n")
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	return b.String()
}

var ibPracticeRows = []string{
	"*\t" + edCID + "\twho\t" + ibPracticeWho,
	"*\t" + edCID + "\thx\t" + ibPracticeHx,
}

// ibWritePractice writes content as edCID's edition/practice/answers.tsv under dir.
func ibWritePractice(t *testing.T, dir, content string) {
	t.Helper()
	pdir := filepath.Join(dir, edCID, "edition", "practice")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "answers.tsv"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func noPracticeValueInLog(t *testing.T, what, text string) {
	t.Helper()
	for _, v := range []string{ibPracticeWho, ibPracticeHx} {
		if strings.Contains(text, v) {
			t.Errorf("%s: the boot log holds a practice value (%q): %s", what, v, text)
		}
	}
}

// (c) NOT the event mode, an investigate challenge in scope, no answers table, and the
// image's practice edition (ADR-0056 D8 (iv), A4a-2; the reversal of the #622 test
// "starts and cannot grade yet"): the scoreboard starts, logs `edition loaded` once
// with the practice run id (all zeros), and a participant is graded from the image's
// practice answers: a right answer is correct, a wrong one is incorrect and costs an
// attempt, both questions right solve the challenge, and the seat * answers for every seat.
func TestBoot_InvestigateScope_PracticeMode_GradesFromThePracticeEdition(t *testing.T) {
	dir := ibTree(t)
	ibWritePractice(t, dir, ibPracticeTable(ibPracticeRows...))
	b := ibStart(t, map[string]string{"CHALLENGES_DIR": dir})
	if b.err != nil || b.judge == nil {
		t.Fatalf("startEdition: judge %v, err %v; want a judge", b.judge, b.err)
	}
	if len(b.recs) != 1 || b.recs[0]["msg"] != "edition loaded" || b.recs[0]["level"] != "INFO" || b.recs[0]["run_id"] != ibZeroRunID {
		t.Errorf("want exactly one INFO record \"edition loaded\" with run_id %s, got %s", ibZeroRunID, b.log)
	}
	noPracticeValueInLog(t, "accepted", b.log)

	h, st := ibHandler(t, b)
	code, first := ibAnswer(t, h, ibSeatA, "who", "wrong-answer-one")
	if code != http.StatusOK || first["status"] != "incorrect" || first["correct"] != false || first["solved"] != false {
		t.Fatalf("a wrong answer: %d %v, want 200 incorrect, not solved", code, first)
	}
	code, second := ibAnswer(t, h, ibSeatA, "who", "wrong-answer-two")
	if code != http.StatusOK || second["status"] != "incorrect" {
		t.Fatalf("a second wrong answer: %d %v, want 200 incorrect", code, second)
	}
	r1, ok1 := first["remaining"].(float64)
	r2, ok2 := second["remaining"].(float64)
	if !ok1 || !ok2 || r2 != r1-1 {
		t.Errorf("remaining after the first wrong answer = %v, after the second = %v; want one fewer", first["remaining"], second["remaining"])
	}
	rows, err := st.AnswerAttempts(ibSeatA, edCID)
	// AnswerAttempts is by question id: both wrong answers were on `who`, so one entry
	// whose count is 2 (not two entries), and it is not marked correct.
	if st1, ok := rows["who"]; err != nil || len(rows) != 1 || !ok || st1.N != 2 || st1.Correct {
		t.Fatalf("attempts after two wrong answers on who: %v (err %v), want {who: 2 attempts, not correct}", rows, err)
	}
	if code, got := ibAnswer(t, h, ibSeatA, "who", ibPracticeWho); code != http.StatusOK || got["status"] != "correct" || got["solved"] != false {
		t.Fatalf("the practice answer: %d %v, want 200 correct, not solved yet", code, got)
	}
	if code, got := ibAnswer(t, h, ibSeatA, "hx", ibPracticeHx); code != http.StatusOK || got["status"] != "correct" || got["solved"] != true {
		t.Fatalf("the last practice answer: %d %v, want 200 correct and solved", code, got)
	}
	if !st.IsSolved(ibSeatA, edCID) {
		t.Fatal("not solved in the store after both practice answers")
	}
	// seat * answers for every seat: the practice edition is the same for the room
	if code, got := ibAnswer(t, h, "seat-b", "who", ibPracticeWho); code != http.StatusOK || got["status"] != "correct" {
		t.Fatalf("seat-b with the practice answer: %d %v, want 200 correct", code, got)
	}
}

// (c2) The practice mode needs a practice edition for every investigate challenge in
// scope (T4, D8 (iv)): without one, or with one that lacks a question or is not a
// table, the scoreboard does not start, with one `edition check failed` record that
// carries no value. The good tree is the one of (c); each case damages a copy of it.
func TestBoot_InvestigateScope_PracticeMode_IncompletePracticeIsRefused(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, dir string)
		rule  string
	}{
		{"no practice edition at all", func(t *testing.T, dir string) {}, "T4"},
		{"the practice table removed from a good tree", func(t *testing.T, dir string) {
			ibWritePractice(t, dir, ibPracticeTable(ibPracticeRows...))
			if err := os.Remove(filepath.Join(dir, edCID, "edition", "practice", "answers.tsv")); err != nil {
				t.Fatal(err)
			}
		}, "T4"},
		{"a practice table without the row of one question", func(t *testing.T, dir string) {
			ibWritePractice(t, dir, ibPracticeTable(ibPracticeRows[0]))
		}, "T4"},
		{"a practice table without any row", func(t *testing.T, dir string) {
			ibWritePractice(t, dir, ibPracticeTable())
		}, "T4"},
		{"a value that is not normalised", func(t *testing.T, dir string) {
			ibWritePractice(t, dir, ibPracticeTable(ibPracticeRows[0], "*\t"+edCID+"\thx\tCCCCCCCCCCCC"))
		}, "T5"},
		{"not a table", func(t *testing.T, dir string) {
			ibWritePractice(t, dir, "this is not a table\n")
		}, "T3"},
	}
	for _, c := range cases {
		dir := ibTree(t)
		c.build(t, dir)
		b := ibStart(t, map[string]string{"CHALLENGES_DIR": dir})
		if b.err == nil || b.judge != nil {
			t.Errorf("%s: judge %v, err %v; want a refusal and no judge", c.name, b.judge, b.err)
			continue
		}
		if !strings.Contains(b.err.Error(), c.rule+":") {
			t.Errorf("%s: err = %v, want it to name rule %s", c.name, b.err, c.rule)
		}
		if len(b.recs) != 1 || b.recs[0]["msg"] != "edition check failed" || b.recs[0]["level"] != "ERROR" {
			t.Errorf("%s: want exactly one ERROR record \"edition check failed\", got %s", c.name, b.log)
		}
		noPracticeValueInLog(t, c.name, b.log)
		noPracticeValueInLog(t, c.name, b.err.Error())
	}
}

// (c3) D8 (iii): the event mode never grades from the practice edition. With the
// image's practice edition present, the event mode and no ANSWERS_FILE is still
// refused (D8 (i)), with no Judge and one ERROR record.
func TestBoot_InvestigateScope_EventModeNeverUsesThePracticeEdition(t *testing.T) {
	dir := ibTree(t)
	ibWritePractice(t, dir, ibPracticeTable(ibPracticeRows...))
	b := ibStart(t, map[string]string{
		"CHALLENGES_DIR": dir,
		"FLAGS_FILE":     writeFlagsFile(t, ibEvade, edFlag03),
	})
	if !errors.Is(b.err, edition.ErrTableMissing) || b.judge != nil {
		t.Fatalf("startEdition: judge %v, err %v; want ErrTableMissing and no judge", b.judge, b.err)
	}
	if len(b.recs) != 1 || b.recs[0]["msg"] != "edition check failed" || b.recs[0]["level"] != "ERROR" {
		t.Errorf("want exactly one ERROR record \"edition check failed\", got %s", b.log)
	}
	noPracticeValueInLog(t, "refused", b.log)
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
		j, text, recs, err := bootEdition(t, c, scored)
		if err != nil || j != nil || len(recs) != 0 {
			t.Errorf("%s: judge %v, err %v, log %q; want nothing at all", name, j, err, text)
		}
	}
}
