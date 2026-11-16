package scoreboard_test

// ADR-0056 A3b-3 (V21 reversed): with catalog.LoadScored accepting an investigate
// scope, every path that was written for the three older types now runs with an
// investigate challenge in the catalog. This file fixes, in one scoreboard that
// holds all four types, that an investigate challenge is solved by the answer route
// and by nothing else, and is never made dirty:
//
//   - a flag submission (POST /api/challenges/{cid}/submit) is a 400;
//   - a detect submission (submit-detect) is a 400 and the grader runner is not run;
//   - a rule fire (the ingest: taint, expected-rule fire, trigger solve) neither
//     solves nor taints it, even while it is the participant's current mission;
//   - reset-dirty is a 400, and the collector's exfil sink is a 400 that records
//     no receipt;
//   - the auto-solve sweeper does not solve it even for a receipt the sink would
//     never have recorded (written straight into the store);
//   - hints and step ticks work as for any mission and cost / solve nothing else.
//
// Each refusal is paired with the same request on a challenge of the type the route
// is for (a 200 there), so a harness that stopped reaching the route would turn a
// test red instead of passing on a 404. The catalog is made of the investigate
// challenges of answer_route_test.go (loaded by catalog.Load) and literals of the
// other three types. Every value is synthetic.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

const (
	inertTrig      = "01-trig"
	inertEvade     = "02-evade"
	inertExfil     = "03-exfil"
	inertDetect    = "04-detect"
	inertRuleTrig  = "Inert Trigger Rule"
	inertRuleForb  = "Inert Forbidden Rule"
	inertFlagEvade = "FALCO{dev-inert-evade}"
	inertFlagExfil = "FALCO{dev-inert-exfil}"
)

// inertOrder puts an investigate challenge first, so it is the participants'
// current mission, then the second one, then one of each of the other types.
var inertOrder = []string{ansOne, ansTwo, inertTrig, inertEvade, inertExfil, inertDetect}

func inertCatalog(t *testing.T) catalog.Catalog {
	t.Helper()
	cat := catalog.Catalog{}
	for id, ch := range ansCatalog(t) {
		if ch.Type == catalog.TypeInvestigate {
			cat[id] = ch
		}
	}
	if len(cat) != 2 {
		t.Fatalf("the investigate fixtures are %d, want 2", len(cat))
	}
	cat[inertTrig] = catalog.Challenge{ID: inertTrig, Type: "trigger", ExpectedRules: []string{inertRuleTrig}}
	cat[inertEvade] = catalog.Challenge{ID: inertEvade, Type: "evade", ForbiddenRules: []string{inertRuleForb}, ExpectedFlag: inertFlagEvade}
	cat[inertExfil] = catalog.Challenge{ID: inertExfil, Type: "evade", ForbiddenRules: []string{inertRuleForb}, ExpectedFlag: inertFlagExfil, RequireExfil: true}
	cat[inertDetect] = catalog.Challenge{ID: inertDetect, Type: "detect"}
	return cat
}

// inertRunner is a DetectRunner that counts its calls: the grader Job a refused
// submission must not start. It never fires on the evasion capture ("missed"), so
// the detect submission that reaches it does not solve the detect challenge and the
// solve counts below stay about the investigate challenges.
type inertRunner struct{ calls int }

func (r *inertRunner) Grade(context.Context, string, string) (int, int, bool, error) {
	r.calls++
	return 0, 0, false, nil
}

type inertFixture struct {
	*ansFixture
	cat    catalog.Catalog
	runner *inertRunner
}

func newInertFixture(t *testing.T) *inertFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "inert.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &inertFixture{
		ansFixture: &ansFixture{t: t, st: st, clock: newTestClock(), logs: &bytes.Buffer{}},
		cat:        inertCatalog(t),
		runner:     &inertRunner{},
	}
	journeys := qJourneys()
	one := journeys[ansOne]
	one.Steps = []catalog.JourneyStep{{Label: "look", Detail: "read the bundle"}}
	one.Hints = catalog.JourneyHints{{Kind: "rule", Text: "hint one"}, {Kind: "command", Text: "hint two"}}
	journeys[ansOne] = one
	f.srv = scoreboard.NewHandler(f.cat, st, slog.New(slog.NewTextHandler(f.logs, nil)),
		scoreboard.WithNow(f.clock.now),
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain),
		scoreboard.WithAdminEmails([]string{ansAdmin}),
		scoreboard.WithAllowedOrigins([]string{allowedOrigin}),
		scoreboard.WithOrder(inertOrder),
		scoreboard.WithJourneys(journeys),
		scoreboard.WithEditionJudge(ansJudge(t)),
		scoreboard.WithDetect(api.DetectConfig{Runner: f.runner}),
	)
	return f
}

// req sends one request. An empty email / origin sends no such header; a nil body
// sends none.
func (f *inertFixture) req(method, target, email, origin string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, target, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	f.clock.advance(time.Second) // a token back for the limiters
	return w
}

func (f *inertFixture) want(w *httptest.ResponseRecorder, code int, errContains string) {
	f.t.Helper()
	if w.Code != code {
		f.t.Fatalf("status = %d, want %d (body=%s)", w.Code, code, w.Body)
	}
	if errContains != "" && !strings.Contains(w.Body.String(), errContains) {
		f.t.Fatalf("body = %s, want it to contain %q", w.Body, errContains)
	}
}

// fire posts one Falco event for rule, attributed to user's workspace.
func (f *inertFixture) fire(rule, user string) {
	f.t.Helper()
	w := f.req("POST", "/falco/events", "", "", map[string]any{
		"rule": rule,
		"output_fields": map[string]any{
			"k8s.ns.name":                "ctf-" + user,
			"k8s.pod.name":               "workspace",
			"container.image.repository": "docker.io/falco-ctf/challenge",
		},
	})
	f.want(w, http.StatusOK, "")
}

func (f *inertFixture) alice(method, target string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.req(method, target, ansAlice+"@"+fixtureEmailDomain, allowedOrigin, body)
}

// untouched: neither investigate challenge is solved or dirty for user, and the
// answer budget of the first is unspent.
func (f *inertFixture) untouched(when, user string) {
	f.t.Helper()
	for _, cid := range []string{ansOne, ansTwo} {
		if f.st.IsSolved(user, cid) {
			f.t.Fatalf("%s: %s is solved for %s", when, cid, user)
		}
		if d := f.st.DirtyRules(user, cid); len(d) != 0 {
			f.t.Fatalf("%s: %s is dirty for %s: %v", when, cid, user, d)
		}
		// Not checked here: an exfil receipt. The test below writes stray receipts into
		// the store itself (for the sweeper), so that check is made where only the sink
		// could have written one (see "after exfil deliveries").
		if f.st.HasExpectedRuleFire(user, cid) {
			f.t.Fatalf("%s: an expected-rule-fire record exists for %s / %s", when, user, cid)
		}
	}
}

func (f *inertFixture) journeyOf(user string) map[string]any {
	f.t.Helper()
	w := f.journeyAs(user, ansOne)
	f.want(w, http.StatusOK, "")
	return decode(f.t, w)
}

func missionStatus(t *testing.T, j map[string]any, cid string) (typ, status string) {
	t.Helper()
	ms, _ := j["missions"].([]any)
	for _, m := range ms {
		mm, _ := m.(map[string]any)
		if mm["id"] == cid {
			typ, _ = mm["type"].(string)
			status, _ = mm["status"].(string)
			return typ, status
		}
	}
	t.Fatalf("journey has no mission %s: %v", cid, ms)
	return "", ""
}

func TestInvestigateInScope_NoOtherPathSolvesOrTaintsIt(t *testing.T) {
	f := newInertFixture(t)
	const bob = ansBob

	// the starting point: an investigate challenge is the first, current mission
	j := f.journeyOf(ansAlice)
	if j["current"] != ansOne || j["total"] != float64(len(inertOrder)) || j["solved_count"] != float64(0) {
		t.Fatalf("journey: current=%v total=%v solved_count=%v, want %s / %d / 0", j["current"], j["total"], j["solved_count"], ansOne, len(inertOrder))
	}
	if typ, status := missionStatus(t, j, ansOne); typ != "investigate" || status != "current" {
		t.Fatalf("mission %s: type=%s status=%s, want investigate / current", ansOne, typ, status)
	}

	// rule fires, while the investigate challenge is alice's CURRENT mission: the
	// forbidden rule taints nobody (the current mission is not evade), the trigger
	// rule solves the trigger challenge as it always does, and neither touches it
	f.fire(inertRuleForb, ansAlice)
	f.untouched("after a forbidden-rule fire", ansAlice)
	// ADR-0003 W2 / ADR-0056 V39 (the reason a course must not put an evade challenge
	// after an investigate challenge): the evade challenges that come LATER in this
	// order are not tainted either, because only the current mission is tainted. This
	// order is the shape LoadScored refuses; the Handler takes any order, so it is built
	// here on purpose (investigate_w2_test.go in ingest fixes the same for the overflow
	// path).
	for _, cid := range []string{inertEvade, inertExfil} {
		if d := f.st.DirtyRules(ansAlice, cid); len(d) != 0 {
			t.Fatalf("%s is tainted by a fire while an investigate challenge is current: %v (W2 changed: revisit V39 and ADR-0003)", cid, d)
		}
	}
	f.fire(inertRuleTrig, ansAlice)
	if !f.st.IsSolved(ansAlice, inertTrig) {
		t.Fatal("the trigger challenge was not solved by its rule: the ingest path is not live")
	}
	f.untouched("after a trigger-rule fire", ansAlice)
	if j := f.journeyOf(ansAlice); j["current"] != ansOne {
		t.Fatalf("current moved to %v on a trigger solve; the investigate challenge is first and unsolved", j["current"])
	}

	// flag submissions
	f.want(f.req("POST", "/api/challenges/"+ansOne+"/submit", "", "", map[string]string{"user": ansAlice, "flag": inertFlagEvade}),
		http.StatusBadRequest, "is not an evade challenge")
	f.want(f.req("POST", "/api/challenges/"+ansTwo+"/submit", "", "", map[string]string{"user": ansAlice, "flag": inertFlagExfil}),
		http.StatusBadRequest, "is not an evade challenge")
	f.want(f.req("POST", "/api/challenges/"+inertEvade+"/submit", "", "", map[string]string{"user": ansAlice, "flag": "FALCO{wrong}"}),
		http.StatusOK, `"correct":false`) // the route is live
	f.untouched("after flag submissions", ansAlice)

	// detect submissions: no grader Job for an investigate challenge
	det := func(cid string) *httptest.ResponseRecorder {
		return f.alice("POST", "/api/challenges/"+cid+"/submit-detect", map[string]string{"user": ansAlice, "condition": "evt.type=open"})
	}
	f.want(det(ansOne), http.StatusBadRequest, "is not a detect challenge")
	f.want(det(ansTwo), http.StatusBadRequest, "is not a detect challenge")
	if f.runner.calls != 0 {
		t.Fatalf("the detect runner ran %d time(s) for an investigate challenge", f.runner.calls)
	}
	f.want(det(inertDetect), http.StatusOK, "") // the route is live
	if f.runner.calls != 1 {
		t.Fatalf("the detect runner ran %d time(s) for one detect submission, want 1", f.runner.calls)
	}
	f.untouched("after detect submissions", ansAlice)

	// reset-dirty
	f.want(f.alice("POST", "/api/users/"+ansAlice+"/challenges/"+ansOne+"/reset-dirty", nil), http.StatusBadRequest, "is not an evade challenge")
	f.want(f.alice("POST", "/api/users/"+ansAlice+"/challenges/"+inertEvade+"/reset-dirty", nil), http.StatusOK, "")

	// the collector's exfil sink records nothing for it
	exfil := func(cid, flag string) *httptest.ResponseRecorder {
		return f.req("POST", "/internal/exfil/"+cid, "", "", map[string]string{"user": ansAlice, "flag": flag})
	}
	f.want(exfil(ansOne, inertFlagExfil), http.StatusBadRequest, "does not accept exfil")
	f.want(exfil(ansTwo, inertFlagExfil), http.StatusBadRequest, "does not accept exfil")
	f.want(exfil(inertExfil, inertFlagExfil), http.StatusOK, `"received":true`) // the route is live
	if !f.st.HasExfilAny(ansAlice, inertExfil) {
		t.Fatal("the exfil receipt of the exfil challenge was not recorded: the sink is not live")
	}
	for _, cid := range []string{ansOne, ansTwo} {
		if f.st.HasExfilAny(ansAlice, cid) {
			t.Fatalf("the exfil sink recorded a receipt for the investigate challenge %s", cid)
		}
	}
	f.untouched("after exfil deliveries", ansAlice)

	// the sweeper: a receipt for an investigate challenge that the sink would never
	// have recorded (written straight into the store) is not a solve; the genuine
	// receipt of the exfil challenge is
	if err := f.st.RecordExfil(ansAlice, ansOne, inertFlagExfil, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := f.st.RecordExfil(ansAlice, ansTwo, "", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	// The pass runs through the handler's own sweeper (Handler.Sweeper, the one
	// cmd/scoreboard runs), so it is the handler's Grader that is swept, not a second
	// Grader built here (#622 LOW). Sweeper.Run sweeps once on entry and only then
	// looks at its context, and its tick (5 s) is far off: with the context already
	// cancelled, Run does exactly one pass and returns.
	if f.st.IsSolved(ansAlice, inertExfil) {
		t.Fatal("the exfil challenge was already solved before the sweep: the sweep proves nothing")
	}
	sweepCtx, stopSweep := context.WithCancel(context.Background())
	stopSweep()
	f.srv.Sweeper().Run(sweepCtx)
	if !f.st.IsSolved(ansAlice, inertExfil) {
		t.Fatalf("the handler's sweeper did not solve the genuine exfil receipt of %s: the sweep is not live", inertExfil)
	}
	for _, cid := range []string{ansOne, ansTwo} {
		if f.st.IsSolved(ansAlice, cid) {
			t.Fatalf("the sweeper solved %s", cid)
		}
	}
	if d := f.st.DirtyRules(ansAlice, ansOne); len(d) != 0 {
		t.Fatalf("dirty after the sweep: %v", d)
	}

	// hints and steps are as for any mission: they cost a penalty and solve nothing
	f.want(f.alice("POST", "/api/users/"+ansAlice+"/challenges/"+ansOne+"/hints/1", nil), http.StatusOK, `"hint":"hint one"`)
	f.want(f.alice("POST", "/api/users/"+ansAlice+"/challenges/"+ansOne+"/hints/2", nil), http.StatusOK, `"hint":"hint two"`)
	f.want(f.alice("POST", "/api/users/"+ansAlice+"/challenges/"+ansOne+"/steps/0/check", map[string]bool{"checked": true}), http.StatusOK, "")
	f.want(f.alice("POST", "/api/users/"+ansAlice+"/challenges/"+ansOne+"/hints/3", nil), http.StatusBadRequest, "invalid hint index")
	det0 := f.detailAs(ansAlice, ansOne)
	hints, _ := det0["hints"].(map[string]any)
	if opened, _ := hints["opened"].([]any); len(opened) != 2 || hints["total"] != float64(2) || hints["lockedCount"] != float64(0) {
		t.Fatalf("detail.hints = %v, want 2 opened of 2", hints)
	}
	if det0["exfilReceived"] != false || det0["dirty"] != false {
		t.Fatalf("detail.exfilReceived=%v dirty=%v, want false / false for an investigate mission with a stray receipt", det0["exfilReceived"], det0["dirty"])
	}
	checkQuestions(t, det0, []wantQ{{"who", qPromptWho, "name", 3, 3, false}})
	f.untouched("after hints and a step tick", ansAlice)
	if n := f.spent(ansOne); n != 0 {
		t.Fatalf("%d answer attempt(s) spent by paths that are not the answer route", n)
	}

	// another participant is untouched by all of it
	f.untouched("bob", bob)

	// the answer route is the way: alice solves it
	wantAnswerResult(t, f.send(f.own(ansOne, "who", ansValue(ansAlice, ansOne+"-who"))), "correct", true, true, 2)
	if !f.st.IsSolved(ansAlice, ansOne) {
		t.Fatal("a right answer did not solve the challenge")
	}
	j = f.journeyOf(ansAlice)
	// solved: the trigger, the exfil (by the sweeper) and the investigate challenge
	if j["solved_count"] != float64(3) || j["total"] != float64(len(inertOrder)) || j["current"] != ansTwo {
		t.Fatalf("journey after the solve: solved_count=%v total=%v current=%v, want 3 / %d / %s", j["solved_count"], j["total"], j["current"], len(inertOrder), ansTwo)
	}
	if typ, status := missionStatus(t, j, ansOne); typ != "investigate" || status != "solved" {
		t.Fatalf("mission %s after the solve: type=%s status=%s, want investigate / solved", ansOne, typ, status)
	}
	if want := scoring.ComputeScore(scoring.DefaultPointsPolicy(), 3, []int{1, 2}); j["score"] != float64(want) {
		t.Fatalf("score = %v, want %d (3 solves, hints 1 and 2 opened)", j["score"], want)
	}

	// the operator's state counts it, under its type
	st := decode(t, f.req("GET", "/api/state", ansAdmin, "", nil))
	var found bool
	for _, c := range st["challenges"].([]any) {
		cm := c.(map[string]any)
		if cm["id"] == ansOne {
			found = true
			if cm["type"] != "investigate" || cm["solved_count"] != float64(1) {
				t.Fatalf("/api/state %s = %v, want type investigate, solved_count 1", ansOne, cm)
			}
			if rules, _ := cm["expectedRules"].([]any); len(rules) != 0 {
				t.Fatalf("/api/state %s carries expectedRules %v", ansOne, rules)
			}
		}
	}
	if !found {
		t.Fatalf("/api/state has no %s", ansOne)
	}
	if got := f.logs.String(); strings.Contains(got, "level=ERROR") {
		t.Fatalf("an ERROR line was logged on the way:\n%s", got)
	}
}

// Solving an investigate challenge moves the progression on, and the taint of the
// next evade challenge works as for any participant: bob answers both investigate
// challenges, solves the trigger, and then a forbidden rule taints the evade
// challenge that is now his current mission (and only it).
func TestInvestigateInScope_SolvingItAdvancesProgressionToTheNextTypes(t *testing.T) {
	f := newInertFixture(t)
	bob := func(cid, qid string) ansReq { return f.as(ansBob, cid, qid, ansValue(ansBob, cid+"-"+qid)) }

	wantAnswerResult(t, f.send(bob(ansOne, "who")), "correct", true, true, 2)
	wantAnswerResult(t, f.send(bob(ansTwo, "who")), "correct", true, false, 2)
	wantAnswerResult(t, f.send(bob(ansTwo, "host")), "correct", true, true, 1)

	w := f.journeyAs(ansBob, ansOne)
	f.want(w, http.StatusOK, "")
	j := decode(t, w)
	if j["current"] != inertTrig || j["solved_count"] != float64(2) {
		t.Fatalf("after the investigate challenges: current=%v solved_count=%v, want %s / 2", j["current"], j["solved_count"], inertTrig)
	}

	f.fire(inertRuleForb, ansBob) // current is the trigger: nobody is tainted
	for _, cid := range []string{inertEvade, inertExfil} {
		if d := f.st.DirtyRules(ansBob, cid); len(d) != 0 {
			t.Fatalf("%s tainted while the current mission was the trigger: %v", cid, d)
		}
	}
	f.fire(inertRuleTrig, ansBob)
	if !f.st.IsSolved(ansBob, inertTrig) {
		t.Fatal("the trigger challenge was not solved")
	}
	f.fire(inertRuleForb, ansBob) // current is now the evade challenge
	if d := f.st.DirtyRules(ansBob, inertEvade); len(d) != 1 || d[0] != inertRuleForb {
		t.Fatalf("the evade challenge's dirty rules = %v, want [%s]", d, inertRuleForb)
	}
	if d := f.st.DirtyRules(ansBob, inertExfil); len(d) != 0 {
		t.Fatalf("the taint reached a mission that is not current: %v", d)
	}
	for _, cid := range []string{ansOne, ansTwo} {
		if d := f.st.DirtyRules(ansBob, cid); len(d) != 0 {
			t.Fatalf("an investigate challenge is dirty: %s %v", cid, d)
		}
		if !f.st.IsSolved(ansBob, cid) {
			t.Fatalf("a taint un-solved %s", cid)
		}
	}
}
