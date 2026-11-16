package scoreboard_test

// ADR-0056 A3b-2: what the answer route's neighbours say about an investigate
// challenge. (1) MissionDetail.questions (D4: the 22nd key; V9), projected from the
// catalog, the journey's prompts and the caller's own row of the attempt budget.
// (2) The metrics of D5: the five `answer_*` outcomes of
// scoreboard_api_submissions_total and `investigate` in scoreboard_solves_total,
// the latter on the Grader's Newly only. (3) The spec's closed format enum against
// answerformat.
//
// The handler is handed the catalog directly, as answer_route_test.go does:
// catalog.LoadScored still refuses an investigate scope at startup (A3b-3), so on a
// real scoreboard `questions` is always [] and no `answer_*` series moves yet. The
// challenges are 02-evade (current, since it sorts first and is unsolved), then
// 90-ir-demo and 91-ir-two, both of them `locked` in the journey; a locked mission's
// questions are projected like its hints are (the projection is a function of the
// store, not of the status).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
)

const (
	qPromptWho  = "Which account ran the command?"
	qPromptHost = "Which host did it run on?"
)

// qJourneys carries the prompts of the two investigate challenges. 02-evade has no
// journey on purpose: its detail must still carry `questions: []`.
func qJourneys() catalog.Journeys {
	return catalog.Journeys{
		ansOne: {
			ChallengeID: ansOne, Title: "one", Tagline: "t1", Briefing: "b1",
			Questions: []catalog.JourneyQuestion{{ID: "who", Prompt: qPromptWho}},
		},
		ansTwo: {
			ChallengeID: ansTwo, Title: "two", Tagline: "t2", Briefing: "b2",
			Questions: []catalog.JourneyQuestion{{ID: "who", Prompt: qPromptWho}, {ID: "host", Prompt: qPromptHost}},
		},
	}
}

func qFixture(t *testing.T, withJudge bool) *ansFixture {
	t.Helper()
	return newAnswerFixture(t, withJudge, scoreboard.WithJourneys(qJourneys()))
}

// journeyAs is GET /api/users/{user}/journey?mission={cid} as that seat. The body
// is kept for the leak check.
func (f *ansFixture) journeyAs(user, cid string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest("GET", "/api/users/"+user+"/journey?mission="+cid, nil)
	r.Header.Set("X-Auth-Request-Email", user+"@"+fixtureEmailDomain)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	f.bodies = append(f.bodies, w.Body.String())
	return w
}

// detailAs is the `detail` (MissionDetail) of that journey response.
func (f *ansFixture) detailAs(user, cid string) map[string]any {
	f.t.Helper()
	w := f.journeyAs(user, cid)
	if w.Code != http.StatusOK {
		f.t.Fatalf("journey status = %d, want 200 (body=%s)", w.Code, w.Body)
	}
	det, ok := decode(f.t, w)["detail"].(map[string]any)
	if !ok {
		f.t.Fatalf("journey response has no detail object: %s", w.Body)
	}
	return det
}

type wantQ struct {
	id, prompt, format  string
	attempts, remaining int
	correct             bool
}

// checkQuestions holds detail.questions to exactly these elements, in this order,
// each with exactly the six keys of the spec's MissionQuestion.
func checkQuestions(t *testing.T, det map[string]any, want []wantQ) {
	t.Helper()
	raw, ok := det["questions"].([]any)
	if !ok {
		t.Fatalf("detail.questions is %T (%v), want an array (null would not do)", det["questions"], det["questions"])
	}
	if len(raw) != len(want) {
		t.Fatalf("detail.questions has %d element(s), want %d: %v", len(raw), len(want), raw)
	}
	for i, w := range want {
		q, ok := raw[i].(map[string]any)
		if !ok {
			t.Fatalf("questions[%d] is %T, want an object", i, raw[i])
		}
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if got := strings.Join(keys, ","); got != "attempts,correct,format,id,prompt,remaining" {
			t.Fatalf("questions[%d] keys = %s, want exactly attempts,correct,format,id,prompt,remaining", i, got)
		}
		if q["id"] != w.id || q["prompt"] != w.prompt || q["format"] != w.format ||
			q["attempts"] != float64(w.attempts) || q["remaining"] != float64(w.remaining) || q["correct"] != w.correct {
			t.Fatalf("questions[%d] = %v, want %+v", i, q, w)
		}
	}
}

// V9: MissionDetail has 22 keys, for an investigate mission and for any other type.
// The element shape is the spec's (CompareResponse looks at the first element, so a
// non-empty list is what makes the comparison real).
func TestMissionDetail_Has22KeysIncludingQuestions(t *testing.T) {
	spec := loadScoreboardSpec(t)
	schema := spec.SchemaByName("MissionDetail")
	if schema == nil {
		t.Fatal("spec has no components.schemas.MissionDetail")
	}
	if n := len(spec.PropertyNames(schema)); n != 22 {
		t.Fatalf("MissionDetail declares %d properties, want 22 (ADR-0056 V9: 21 + questions)", n)
	}
	f := qFixture(t, true)
	f.send(f.own(ansTwo, "who", ansTyped)) // a row exists for one of the two questions
	for _, cid := range []string{ansTwo, ansOne, ansEvade} {
		det := f.detailAs(ansAlice, cid)
		if len(det) != 22 {
			t.Errorf("%s: detail has %d keys, want 22: %v", cid, len(det), det)
		}
		if _, ok := det["questions"]; !ok {
			t.Errorf("%s: detail has no `questions` key", cid)
		}
		if det["type"] != map[string]string{ansTwo: "investigate", ansOne: "investigate", ansEvade: "evade"}[cid] {
			t.Errorf("%s: detail.type = %v", cid, det["type"])
		}
		for _, m := range specparity.CompareResponse(spec, schema, det, "MissionDetail") {
			t.Errorf("%s: %s: extra=%v missing=%v", cid, m.Path, m.Extra, m.Missing)
		}
	}
}

// Every type that is not investigate carries `questions: []`: an empty array, never
// null and never absent (the portal iterates it unconditionally).
func TestMissionDetail_QuestionsIsAnEmptyArrayForOtherTypes(t *testing.T) {
	f := qFixture(t, true)
	w := f.journeyAs(ansAlice, ansEvade)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"questions":[]`) {
		t.Fatalf("the evade mission's detail does not carry the JSON `\"questions\":[]`: %s", w.Body)
	}
	checkQuestions(t, decode(t, w)["detail"].(map[string]any), nil)
}

// The elements follow the catalog's order and the prompts come from the journey; a
// question nobody has answered has its whole budget; the numbers follow the answer
// route, before and after every kind of answer.
func TestMissionDetail_QuestionsFollowTheCatalogAndTheStore(t *testing.T) {
	f := qFixture(t, true)
	who, host := ansValue(ansAlice, ansTwo+"-who"), ansValue(ansAlice, ansTwo+"-host")
	q := func(whoRemaining int, whoCorrect bool, hostRemaining int, hostCorrect bool) []wantQ {
		return []wantQ{
			{"who", qPromptWho, "name", 3, whoRemaining, whoCorrect},
			{"host", qPromptHost, "name", 2, hostRemaining, hostCorrect},
		}
	}
	checkQuestions(t, f.detailAs(ansAlice, ansTwo), q(3, false, 2, false))

	f.send(f.own(ansTwo, "who", ansTyped)) // incorrect: one attempt spent
	checkQuestions(t, f.detailAs(ansAlice, ansTwo), q(2, false, 2, false))

	f.send(f.own(ansTwo, "who", who)) // correct: another attempt spent, answered
	checkQuestions(t, f.detailAs(ansAlice, ansTwo), q(1, true, 2, false))

	f.send(f.own(ansTwo, "who", ansTyped)) // already-correct: free
	checkQuestions(t, f.detailAs(ansAlice, ansTwo), q(1, true, 2, false))

	f.send(f.own(ansTwo, "host", ansTyped))
	f.send(f.own(ansTwo, "host", ansTyped+"2")) // the budget of `host` is gone
	checkQuestions(t, f.detailAs(ansAlice, ansTwo), q(1, true, 0, false))
	f.send(f.own(ansTwo, "host", host)) // exhausted: the right answer is not compared
	checkQuestions(t, f.detailAs(ansAlice, ansTwo), q(1, true, 0, false))

	// the other investigate challenge is untouched by any of it
	checkQuestions(t, f.detailAs(ansAlice, ansOne), []wantQ{{"who", qPromptWho, "name", 3, 3, false}})
}

// After every question is answered the challenge is solved, and the projection says
// the same of each question (a solved mission keeps its numbers).
func TestMissionDetail_QuestionsOfASolvedMission(t *testing.T) {
	f := qFixture(t, true)
	f.send(f.own(ansTwo, "who", ansValue(ansAlice, ansTwo+"-who")))
	f.send(f.own(ansTwo, "host", ansValue(ansAlice, ansTwo+"-host")))
	det := f.detailAs(ansAlice, ansTwo)
	if det["status"] != "solved" {
		t.Fatalf("detail.status = %v, want solved", det["status"])
	}
	checkQuestions(t, det, []wantQ{
		{"who", qPromptWho, "name", 3, 2, true},
		{"host", qPromptHost, "name", 2, 1, true},
	})
}

// remaining never goes below 0: a row whose count is over the catalog's budget (the
// catalog's `attempts` was lowered after answers were spent) reads 0, not negative.
// The rows are written with a larger limit than ansOne's 3 attempts.
func TestMissionDetail_RemainingIsClampedAtZero(t *testing.T) {
	f := qFixture(t, true)
	for i := 0; i < 5; i++ {
		if _, _, err := f.st.TryAnswerAttempt(ansAlice, ansOne, "who", 10); err != nil {
			t.Fatal(err)
		}
	}
	checkQuestions(t, f.detailAs(ansAlice, ansOne), []wantQ{{"who", qPromptWho, "name", 3, 0, false}})
}

// A question the journey carries no prompt for is projected with an empty prompt,
// and the rest of it is intact. Unreachable on a started scoreboard
// (catalog.LoadJourneys requires an investigate challenge's journey with an equal id
// set); this holds the branch, so the projection never fails or invents text.
func TestMissionDetail_QuestionWithoutAPrompt(t *testing.T) {
	f := newAnswerFixture(t, true, scoreboard.WithJourneys(catalog.Journeys{
		ansTwo: {
			ChallengeID: ansTwo, Title: "two",
			Questions: []catalog.JourneyQuestion{{ID: "who", Prompt: qPromptWho}}, // no prompt for `host`
		},
	}))
	checkQuestions(t, f.detailAs(ansAlice, ansTwo), []wantQ{
		{"who", qPromptWho, "name", 3, 3, false},
		{"host", "", "name", 2, 2, false},
	})
	// no journey at all for ansOne
	checkQuestions(t, f.detailAs(ansAlice, ansOne), []wantQ{{"who", "", "name", 3, 3, false}})
}

// Only the caller's own row: bob's answers move nothing in alice's detail, and what
// bob reads is his own.
func TestMissionDetail_QuestionsAreTheCallersOwn(t *testing.T) {
	f := qFixture(t, true)
	f.send(f.as(ansBob, ansTwo, "who", ansValue(ansBob, ansTwo+"-who")))
	f.send(f.as(ansBob, ansTwo, "host", ansTyped))
	untouched := []wantQ{
		{"who", qPromptWho, "name", 3, 3, false},
		{"host", qPromptHost, "name", 2, 2, false},
	}
	checkQuestions(t, f.detailAs(ansAlice, ansTwo), untouched)
	checkQuestions(t, f.detailAs(ansBob, ansTwo), []wantQ{
		{"who", qPromptWho, "name", 3, 2, true},
		{"host", qPromptHost, "name", 2, 1, false},
	})
}

// D13: no answer reaches a MissionDetail response, or any response of the session:
// not the typed text, not a table value (every value holds ansSecret), and the
// response of the journey names no field that could carry one.
func TestMissionDetail_NoAnswerInTheResponse(t *testing.T) {
	f := qFixture(t, true)
	f.send(f.own(ansTwo, "who", ansTyped))
	f.send(f.own(ansTwo, "who", ansValue(ansBob, ansTwo+"-who"))) // another seat's value
	f.send(f.own(ansTwo, "who", ansValue(ansAlice, ansTwo+"-who")))
	for _, cid := range []string{ansTwo, ansOne, ansEvade} {
		f.detailAs(ansAlice, cid)
	}
	f.detailAs(ansBob, ansTwo)
	journeyBodies := 0
	for _, b := range f.bodies {
		if strings.Contains(b, `"detail"`) {
			journeyBodies++
		}
		for _, needle := range []string{ansTyped, strings.ToLower(ansTyped), ansSecret, "SENTINEL"} {
			if strings.Contains(b, needle) {
				t.Fatalf("%q reached a response:\n%.600s", needle, b)
			}
		}
	}
	if journeyBodies < 4 {
		t.Fatalf("only %d journey bodies were checked", journeyBodies)
	}
}

// A store read that fails is a 500 with a fixed body, never a guess (a `remaining`
// that was not read would invite an attempt the budget has already taken). Every
// other type is unaffected: it reads nothing from that table. The other reads of a
// journey are in memory, so this is the one that fails.
func TestMissionDetail_QuestionsStoreFailureIs500(t *testing.T) {
	f := qFixture(t, true)
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.journeyAs(ansAlice, ansTwo)
	wantAnswerError(t, w, http.StatusInternalServerError, "could not read the mission")
	if !strings.Contains(f.logs.String(), "journey: could not read the mission's questions") {
		t.Fatalf("the operator's log has no line for the 500:\n%s", f.logs)
	}
	if w := f.journeyAs(ansAlice, ansEvade); w.Code != http.StatusOK {
		t.Fatalf("an evade mission's journey = %d, want 200: it reads nothing from the answer budget (%s)", w.Code, w.Body)
	}
}

// The spec's `format` enum IS the closed list of answerformat (D2), and the budget's
// bounds are the catalog's.
func TestMissionQuestionSpec_FormatEnumIsAnswerformat(t *testing.T) {
	spec := loadScoreboardSpec(t)
	sch := spec.SchemaByName("MissionQuestion")
	if sch == nil {
		t.Fatal("spec has no components.schemas.MissionQuestion")
	}
	raw, _ := spec.PropertySchema(sch, "format")["enum"].([]any)
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		got = append(got, s)
	}
	sort.Strings(got)
	want := answerformat.Formats() // sorted
	if len(got) == 0 || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("spec MissionQuestion.format enum = %v, answerformat.Formats() = %v", got, want)
	}
	req := requiredSet(sch)
	for _, k := range []string{"id", "prompt", "format", "attempts", "remaining", "correct"} {
		if !req[k] {
			t.Errorf("MissionQuestion does not require %q", k)
		}
	}
	if len(req) != 6 || len(spec.PropertyNames(sch)) != 6 {
		t.Errorf("MissionQuestion has %d required / %d properties, want 6 / 6 (ADR-0056 D4)", len(req), len(spec.PropertyNames(sch)))
	}
	attempts := spec.PropertySchema(sch, "attempts")
	if attempts["maximum"] == nil || attempts["minimum"] == nil {
		t.Fatalf("MissionQuestion.attempts declares no minimum / maximum (%v): the comparison would be vacuous", attempts)
	}
	if fmt.Sprint(attempts["maximum"]) != fmt.Sprint(answerformat.MaxAttempts) || fmt.Sprint(attempts["minimum"]) != "1" {
		t.Errorf("MissionQuestion.attempts is %v..%v, want 1..%d", attempts["minimum"], attempts["maximum"], answerformat.MaxAttempts)
	}
}

// ---- metrics (D5) ----

var answerOutcomes = []string{
	"answer_correct", "answer_incorrect", "answer_exhausted", "answer_already_correct", "answer_store_error",
}

// ansSeries reads the five outcomes and the investigate solves of one challenge
// label (the series are process-wide, so a test compares before and after).
func ansSeries(cid string) map[string]float64 {
	out := map[string]float64{"solves": testutil.ToFloat64(metrics.SolvesTotal.WithLabelValues(cid, "investigate"))}
	for _, o := range answerOutcomes {
		out[o] = testutil.ToFloat64(metrics.SubmissionsTotal.WithLabelValues(cid, o))
	}
	return out
}

// wantMoved fails unless the series moved by exactly want (missing = 0).
func wantMoved(t *testing.T, cid string, before map[string]float64, want map[string]float64) {
	t.Helper()
	after := ansSeries(cid)
	for k := range after {
		if got := after[k] - before[k]; got != want[k] {
			t.Errorf("%s: %s moved by %v, want %v (all: before=%v after=%v)", cid, k, got, want[k], before, after)
		}
	}
	for k := range want {
		if _, ok := after[k]; !ok {
			t.Errorf("%s: the test names a series %q that does not exist", cid, k)
		}
	}
}

func TestAnswerMetrics_EachStatusIsOneOutcome(t *testing.T) {
	f := qFixture(t, true)
	who, host := ansValue(ansAlice, ansTwo+"-who"), ansValue(ansAlice, ansTwo+"-host")
	step := func(name string, a ansReq, want map[string]float64) {
		t.Helper()
		before := ansSeries(ansTwo)
		if w := f.send(a); w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d body=%s", name, w.Code, w.Body)
		}
		wantMoved(t, ansTwo, before, want)
	}
	step("a wrong answer", f.own(ansTwo, "who", ansTyped), map[string]float64{"answer_incorrect": 1})
	// answered, but `host` is not: the challenge is not solved, so no solve is counted
	step("a right answer", f.own(ansTwo, "who", who), map[string]float64{"answer_correct": 1})
	step("an answer to an answered question", f.own(ansTwo, "who", ansTyped), map[string]float64{"answer_already_correct": 1})
	step("a first wrong answer to host", f.own(ansTwo, "host", ansTyped), map[string]float64{"answer_incorrect": 1})
	step("the last wrong answer to host", f.own(ansTwo, "host", ansTyped+"2"), map[string]float64{"answer_incorrect": 1})
	step("the right answer once the budget is gone", f.own(ansTwo, "host", host), map[string]float64{"answer_exhausted": 1})
}

// The solve is counted once, on the answer that records it (Newly), as `investigate`
// and under the challenge's own label; an answer after the solve counts an outcome
// and no second solve.
func TestAnswerMetrics_SolveIsCountedOnceOnNewly(t *testing.T) {
	f := qFixture(t, true)
	before := ansSeries(ansTwo)
	f.send(f.own(ansTwo, "who", ansValue(ansAlice, ansTwo+"-who")))
	wantMoved(t, ansTwo, before, map[string]float64{"answer_correct": 1})

	before = ansSeries(ansTwo)
	w := f.send(f.own(ansTwo, "host", ansValue(ansAlice, ansTwo+"-host")))
	wantAnswerResult(t, w, "correct", true, true, 1)
	wantMoved(t, ansTwo, before, map[string]float64{"answer_correct": 1, "solves": 1})

	before = ansSeries(ansTwo)
	wantAnswerResult(t, f.send(f.own(ansTwo, "who", ansTyped)), "already-correct", true, true, 2)
	wantAnswerResult(t, f.send(f.own(ansTwo, "host", ansValue(ansAlice, ansTwo+"-host"))), "already-correct", true, true, 1)
	wantMoved(t, ansTwo, before, map[string]float64{"answer_already_correct": 2})

	// another seat's solve is its own solve
	before = ansSeries(ansOne)
	f.send(f.as(ansBob, ansOne, "who", ansValue(ansBob, ansOne+"-who")))
	wantMoved(t, ansOne, before, map[string]float64{"answer_correct": 1, "solves": 1})
}

// Several correct answers at once: every one is a 200 and an outcome, and the solve
// is counted exactly once (Newly is true for the one call that recorded it).
func TestAnswerMetrics_ConcurrentCorrectAnswersCountOneSolve(t *testing.T) {
	const n = 4 // under the bucket's burst of 5, the clock held
	f := qFixture(t, true)
	right := f.own(ansOne, "who", ansValue(ansAlice, ansOne+"-who"))
	before := ansSeries(ansOne)

	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "/api/users/"+ansAlice+"/challenges/"+ansOne+"/questions/who/answer", strings.NewReader(right.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", allowedOrigin)
			r.Header.Set("X-Auth-Request-Email", right.email)
			w := httptest.NewRecorder()
			f.srv.ServeHTTP(w, r)
			codes[i] = w.Code
		}()
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i, c)
		}
	}
	if !f.st.IsSolved(ansAlice, ansOne) {
		t.Fatal("the challenge is not solved")
	}
	after := ansSeries(ansOne)
	if got := after["solves"] - before["solves"]; got != 1 {
		t.Errorf("solves moved by %v, want exactly 1 (Newly is true for one call only)", got)
	}
	sum := 0.0
	for _, o := range answerOutcomes {
		sum += after[o] - before[o]
	}
	if sum != n {
		t.Errorf("outcomes moved by %v in all, want %d (one per request)", sum, n)
	}
	if after["answer_correct"]-before["answer_correct"] < 1 {
		t.Errorf("no answer_correct was counted: %v -> %v", before, after)
	}
	if after["answer_store_error"] != before["answer_store_error"] {
		t.Errorf("answer_store_error moved: %v -> %v", before, after)
	}
}

// answer_store_error is the outcome of a 500: a store that cannot be written, and a
// scoreboard started without an answers table.
func TestAnswerMetrics_ServerErrorIsStoreError(t *testing.T) {
	t.Run("a store that fails", func(t *testing.T) {
		f := qFixture(t, true)
		before := ansSeries(ansOne)
		if err := f.st.Close(); err != nil {
			t.Fatal(err)
		}
		wantAnswerError(t, f.send(f.own(ansOne, "who", ansValue(ansAlice, ansOne+"-who"))), http.StatusInternalServerError, "could not grade the answer")
		wantMoved(t, ansOne, before, map[string]float64{"answer_store_error": 1})
	})
	t.Run("no answers table", func(t *testing.T) {
		f := qFixture(t, false)
		before := ansSeries(ansOne)
		wantAnswerError(t, f.send(f.own(ansOne, "who", ansTyped)), http.StatusInternalServerError, "could not grade the answer")
		wantMoved(t, ansOne, before, map[string]float64{"answer_store_error": 1})
	})
}

// A request the route refuses (400, 403, 404, and an answer whose format is wrong,
// which costs nothing) moves none of the five outcomes and no solve, under the
// challenge's label or under `_unknown`: those are in the request duration and the
// identity denials, not here.
func TestAnswerMetrics_RefusedRequestsCountNothing(t *testing.T) {
	f := qFixture(t, true)
	cids := []string{ansOne, ansTwo, ansEvade, "_unknown"}
	before := map[string]map[string]float64{}
	for _, cid := range cids {
		before[cid] = ansSeries(cid)
	}
	right := ansValue(ansAlice, ansOne+"-who")
	badOrigin := f.own(ansOne, "who", right)
	badOrigin.origin = "https://evil.example.com"
	otherSeat := f.own(ansOne, "who", right)
	otherSeat.email = ansBob + "@" + fixtureEmailDomain
	notJSON := f.own(ansOne, "who", right)
	notJSON.ctype, notJSON.body = "text/plain", "x"
	for _, tc := range []struct {
		name string
		req  ansReq
	}{
		{"a format that does not fit", f.own(ansTwo, "who", "two words")},
		{"an unknown question", f.own(ansOne, "nope-zzzz", right)},
		{"a question of the other challenge", f.own(ansOne, "host", right)},
		{"an unknown challenge", f.own("99-nope", "who", right)},
		{"not an investigate challenge", f.own(ansEvade, "who", right)},
		{"a foreign origin", badOrigin},
		{"another seat's identity", otherSeat},
		{"a body that is not JSON", notJSON},
	} {
		if w := f.send(tc.req); w.Code < 400 || w.Code >= 500 {
			t.Fatalf("%s: status = %d, want a 4xx (body=%s)", tc.name, w.Code, w.Body)
		}
	}
	for _, cid := range cids {
		wantMoved(t, cid, before[cid], nil)
	}
}
