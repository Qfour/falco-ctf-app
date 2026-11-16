package scoreboard_test

// ADR-0056 D4 / D5 / D6 / D13 at the route (V9, and V1 for the response and the
// log): POST /api/users/{user}/challenges/{cid}/questions/{qid}/answer, through
// scoreboard.NewHandler with a real store and a real answers-table Judge. The
// catalog comes from catalog.Load (the real strict decode of an investigate
// challenge), not from a literal; catalog.LoadScored, which still refuses an
// investigate scope at startup (A3b-3), is not involved: the handler is handed
// the catalog directly. Every value is synthetic. ansSecret is inside every table
// value and ansTyped is what a participant types in the leak checks, so a body or a
// log line that carries either shows up as a match.
//
// The identity / origin / rate-limit properties of the route as a member of the
// derived tables (Authz self, og -> limiter order, the "answer" bucket row, the
// 16 origin-guarded routes) are in authz_test.go, origin_guard_test.go and
// identity_bucket_test.go; this file holds what only this route says.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

const (
	ansOne    = "90-ir-demo" // one question: who (3 attempts)
	ansTwo    = "91-ir-two"  // two questions: who (3 attempts), host (2 attempts)
	ansEvade  = "02-evade"   // not an investigate challenge
	ansRun    = "0123456789abcdef0123456789abcdef"
	ansSecret = "SENTINEL-answer-zzzz"
	ansTyped  = "TYPED-answer-yyyy"
	ansAlice  = "alice"
	ansBob    = "bob"
	ansAdmin  = "admin@ctf.local"
)

const ansOneYAML = `type: investigate
investigate:
  evidence: {mountDir: /opt/ctf/evidence}
  questions:
    - id: who
      format: name
      attempts: 3
`

const ansTwoYAML = `type: investigate
investigate:
  evidence: {mountDir: /opt/ctf/evidence}
  questions:
    - id: who
      format: name
      attempts: 3
    - id: host
      format: name
      attempts: 2
`

const ansEvadeYAML = "type: evade\nexpectedFlag: FALCO{dev-ans}\nforbiddenRules: [r]\n"

// ansValue is the table's value for (seat, question): it holds ansSecret.
func ansValue(seat, qid string) string { return ansSecret + "-" + seat + "-" + qid }

// ansCatalog writes the three challenges under t.TempDir() and loads them with
// catalog.Load.
func ansCatalog(t *testing.T) catalog.Catalog {
	t.Helper()
	dir := t.TempDir()
	for id, yaml := range map[string]string{ansOne: ansOneYAML, ansTwo: ansTwoYAML, ansEvade: ansEvadeYAML} {
		if err := os.MkdirAll(filepath.Join(dir, id), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, id, "falco-rule.yaml"), []byte(yaml), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	if cat[ansOne].Type != catalog.TypeInvestigate || cat[ansTwo].Type != catalog.TypeInvestigate {
		t.Fatalf("the fixture challenges did not load as investigate: %v %v", cat[ansOne].Type, cat[ansTwo].Type)
	}
	return cat
}

// ansJudge builds a Judge the way a test can (edition.Parse / edition.NewJudge are
// called from non-test code by edition.Load only). Both seats have a row for every
// question, with values that differ per seat.
func ansJudge(t *testing.T) *edition.Judge {
	t.Helper()
	var b strings.Builder
	b.WriteString("# falco-ctf answers v1 run=" + ansRun + "\n")
	for _, seat := range []string{ansAlice, ansBob} {
		for _, q := range [][2]string{{ansOne, "who"}, {ansTwo, "who"}, {ansTwo, "host"}} {
			b.WriteString(strings.Join([]string{seat, q[0], q[1], ansValue(seat, q[0]+"-"+q[1])}, "\t") + "\n")
		}
	}
	tbl, err := edition.Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("edition.Parse: %v", err)
	}
	j, err := edition.NewJudge(tbl)
	if err != nil {
		t.Fatalf("edition.NewJudge: %v", err)
	}
	return j
}

type ansFixture struct {
	t      *testing.T
	srv    *scoreboard.Handler
	st     *store.Store
	clock  *testClock
	logs   *bytes.Buffer
	bodies []string // every response body, for the leak checks
}

// newAnswerFixture: withJudge=false is a scoreboard started without an answers
// table (no WithEditionJudge).
// extra options are applied last (e.g. another ADMIN_EMAILS).
func newAnswerFixture(t *testing.T, withJudge bool, extra ...scoreboard.Option) *ansFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ans.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &ansFixture{t: t, st: st, clock: newTestClock(), logs: &bytes.Buffer{}}
	opts := []scoreboard.Option{
		scoreboard.WithNow(f.clock.now),
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain),
		scoreboard.WithAdminEmails([]string{ansAdmin}),
		scoreboard.WithAllowedOrigins([]string{allowedOrigin}),
	}
	if withJudge {
		opts = append(opts, scoreboard.WithEditionJudge(ansJudge(t)))
	}
	opts = append(opts, extra...)
	f.srv = scoreboard.NewHandler(ansCatalog(t), st, slog.New(slog.NewTextHandler(f.logs, nil)), opts...)
	return f
}

// ansReq is one request. A zero email / origin / ctype sends no such header.
type ansReq struct {
	user, cid, qid string
	email, origin  string
	ctype, body    string
	hold           bool // do not advance the clock afterwards (the bucket does not refill)
}

// own is alice answering as herself, from the allowed origin, as JSON.
func (f *ansFixture) own(cid, qid, answer string) ansReq {
	body, _ := json.Marshal(map[string]string{"answer": answer})
	return ansReq{
		user: ansAlice, cid: cid, qid: qid,
		email: ansAlice + "@" + fixtureEmailDomain, origin: allowedOrigin,
		ctype: "application/json", body: string(body),
	}
}

// as is the same answer sent as seat (its own identity, its own path).
func (f *ansFixture) as(seat, cid, qid, answer string) ansReq {
	a := f.own(cid, qid, answer)
	a.user, a.email = seat, seat+"@"+fixtureEmailDomain
	return a
}

func (f *ansFixture) send(a ansReq) *httptest.ResponseRecorder {
	f.t.Helper()
	target := "/api/users/" + a.user + "/challenges/" + a.cid + "/questions/" + a.qid + "/answer"
	r := httptest.NewRequest("POST", target, strings.NewReader(a.body))
	if a.ctype != "" {
		r.Header.Set("Content-Type", a.ctype)
	}
	if a.origin != "" {
		r.Header.Set("Origin", a.origin)
	}
	if a.email != "" {
		r.Header.Set("X-Auth-Request-Email", a.email)
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	f.bodies = append(f.bodies, w.Body.String())
	if !a.hold {
		f.clock.advance(time.Second) // one token back: the bucket is not what these tests measure
	}
	return w
}

// spent is the attempts the store holds for alice on cid, all questions.
func (f *ansFixture) spent(cid string) int {
	f.t.Helper()
	rows, err := f.st.AnswerAttempts(ansAlice, cid)
	if err != nil {
		f.t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		n += r.N
	}
	return n
}

func wantAnswerError(t *testing.T, w *httptest.ResponseRecorder, code int, msg string) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status = %d, want %d (body=%s)", w.Code, code, w.Body)
	}
	got := decode(t, w)
	if len(got) != 1 || got["error"] != msg {
		t.Fatalf("body = %s, want exactly {\"error\":%q}", w.Body, msg)
	}
}

// wantAnswerResult checks the 200 body: exactly the four fields of D6, with these values.
func wantAnswerResult(t *testing.T, w *httptest.ResponseRecorder, status string, correct, solved bool, remaining int) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body)
	}
	got := decode(t, w)
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "correct,remaining,solved,status" {
		t.Fatalf("response keys = %v, want exactly correct, remaining, solved, status (D6; Newly is Go-only) — body=%s", keys, w.Body)
	}
	if got["status"] != status || got["correct"] != correct || got["solved"] != solved || got["remaining"] != float64(remaining) {
		t.Fatalf("response = %s, want status=%s correct=%v solved=%v remaining=%d", w.Body, status, correct, solved, remaining)
	}
}

// V9: only the seat itself. An answer that would be CORRECT is sent in every case,
// so a 200 anywhere would also show as a solve; none is, and nothing is spent.
func TestAnswerRoute_OnlyTheSeatItself(t *testing.T) {
	for _, tc := range []struct{ name, email string }{
		{"another seat", ansBob + "@" + fixtureEmailDomain},
		{"an ADMIN_EMAILS identity (no admin override, unlike self-or-admin)", ansAdmin},
		{"no identity header", ""},
		{"a blank identity header", "   "},
		{"the same seat on another domain", ansAlice + "@evil.example"},
		{"a seat that merely starts with alice", "alice2@" + fixtureEmailDomain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnswerFixture(t, true)
			a := f.own(ansOne, "who", ansValue(ansAlice, ansOne+"-who"))
			a.email = tc.email
			wantAnswerError(t, f.send(a), http.StatusForbidden, "forbidden")
			if n := f.spent(ansOne); n != 0 {
				t.Fatalf("a refused request spent %d attempt(s)", n)
			}
			if f.st.IsSolved(ansAlice, ansOne) {
				t.Fatal("a refused request solved the challenge")
			}
		})
	}
}

// The recorded reason (scoreboard_identity_denials_total, which the platform's alert
// reads): an ADMIN_EMAILS identity refused here is an intended refusal, a mismatch,
// even when it is on another domain than the seats' (so it is not a canonical
// <seat>@<domain>); non_canonical stays for a non-admin identity that is no seat's
// form, which is a configuration fault and must stay 0 in a healthy production.
func TestAnswerRoute_RefusedAdminIsAMismatchNotNonCanonical(t *testing.T) {
	const staff = "ops@staff.example"
	for _, tc := range []struct {
		name, email string
		want        identityobs.Reason
	}{
		{"an admin on another domain", staff, identityobs.ReasonMismatch},
		{"an admin on the seat domain", ansAdmin, identityobs.ReasonMismatch},
		{"another seat", ansBob + "@" + fixtureEmailDomain, identityobs.ReasonMismatch},
		{"a non-admin on another domain", "carol@evil.example", identityobs.ReasonNonCanonical},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnswerFixture(t, true, scoreboard.WithAdminEmails([]string{ansAdmin, staff}))
			before := denialCounts()
			a := f.own(ansOne, "who", ansTyped)
			a.email = tc.email
			wantAnswerError(t, f.send(a), http.StatusForbidden, "forbidden")
			got := moved(before, denialCounts())
			want := identityobs.Pair{Gate: identityobs.GateSelfOrAdmin, Reason: tc.want}
			if len(got) != 1 || got[want] != 1 {
				t.Fatalf("series moved = %v, want exactly %v by 1 (a refused admin is a mismatch, never non_canonical)", got, want)
			}
		})
	}
}

// D4: the identity gate answers BEFORE the rate limiter, so a wrong identity spends
// no token. bob (a proven seat) names alice's path ten times, with the clock held (no
// refill); he still has the whole burst of 5 on his own path afterwards, and the 6th
// is the limiter's 429.
func TestAnswerRoute_AWrongIdentitySpendsNoToken(t *testing.T) {
	f := newAnswerFixture(t, true)
	for i := 0; i < 10; i++ {
		a := f.own(ansOne, "who", ansTyped)
		a.email, a.hold = ansBob+"@"+fixtureEmailDomain, true
		wantAnswerError(t, f.send(a), http.StatusForbidden, "forbidden")
	}
	own := func() ansReq {
		a := f.as(ansBob, ansOne, "who", ansTyped)
		a.hold = true
		return a
	}
	for i := 1; i <= 5; i++ {
		if w := f.send(own()); w.Code != http.StatusOK {
			t.Fatalf("request %d on bob's own path: status=%d body=%s, want 200 (the refused ones spent a token)", i, w.Code, w.Body)
		}
	}
	wantAnswerError(t, f.send(own()), http.StatusTooManyRequests, "rate limit exceeded")
}

// D4: origin-guarded. The seat's own identity, so only the guard can say 403; the
// answer would be correct.
func TestAnswerRoute_OriginGuarded(t *testing.T) {
	for _, tc := range []struct{ name, origin string }{
		{"a foreign Origin", "https://evil.example.com"},
		{"neither Origin nor Referer (a terminal's curl)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnswerFixture(t, true)
			a := f.own(ansOne, "who", ansValue(ansAlice, ansOne+"-who"))
			a.origin = tc.origin
			wantAnswerError(t, f.send(a), http.StatusForbidden, "forbidden")
			if n := f.spent(ansOne); n != 0 {
				t.Fatalf("a request the guard refused spent %d attempt(s)", n)
			}
		})
	}
}

// D4: 404 for an unknown challenge or question (a fixed body, the id never echoed),
// 400 for a challenge that is not an investigate one. None of them spends an attempt.
func TestAnswerRoute_UnknownAndNotInvestigate(t *testing.T) {
	for _, tc := range []struct {
		name, cid, qid string
		code           int
		msg            string
	}{
		{"unknown challenge", "99-nope", "who", 404, "unknown challenge"},
		{"a challenge id outside the grammar", "bad%20id", "who", 404, "unknown challenge"},
		{"unknown question", ansOne, "nope-zzzz", 404, "unknown question"},
		{"a question id outside the grammar", ansOne, "Q1", 404, "unknown question"},
		{"a question of the other challenge", ansOne, "host", 404, "unknown question"},
		{"not an investigate challenge", ansEvade, "who", 400, "not an investigate challenge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnswerFixture(t, true)
			w := f.send(f.own(tc.cid, tc.qid, ansTyped))
			wantAnswerError(t, w, tc.code, tc.msg)
			for _, id := range []string{tc.cid, tc.qid, ansTyped} {
				if len(id) >= 4 && strings.Contains(w.Body.String(), id) {
					t.Fatalf("the body echoes %q: %s", id, w.Body)
				}
			}
			for _, cid := range []string{ansOne, ansTwo} {
				if n := f.spent(cid); n != 0 {
					t.Fatalf("%s: %d attempt(s) spent", cid, n)
				}
			}
		})
	}
}

// V9: a body that is not exactly {"answer": <string>} as JSON is a 400 and costs
// nothing; so is an answer that does not fit the question's format. The first
// object of the trailing-data case is the CORRECT answer: a 400 means it was not read as one.
func TestAnswerRoute_BadRequestsAreFreeAnd400(t *testing.T) {
	right := ansValue(ansAlice, ansOne+"-who")
	obj := func(a string) string { b, _ := json.Marshal(map[string]string{"answer": a}); return string(b) }
	const invalid, format = "invalid request body", "answer does not fit the question's format"
	for _, tc := range []struct {
		name, ctype, body, msg string
	}{
		{"not JSON", "application/json", "not json", invalid},
		{"an empty body", "application/json", "", invalid},
		{"a truncated body", "application/json", `{"answer":`, invalid},
		{"an unknown field next to the answer", "application/json", `{"answer":"` + right + `","extra":1}`, invalid},
		{"another key instead of the answer", "application/json", `{"reply":"` + right + `"}`, invalid},
		{"a number as the answer", "application/json", `{"answer":5}`, invalid},
		{"an array", "application/json", `["` + right + `"]`, invalid},
		{"data after the object", "application/json", obj(right) + obj(right), invalid},
		{"more than 256 characters", "application/json", obj(strings.Repeat("a", 257)), invalid},
		// The limit is 256 BYTES of UTF-8 (answerformat.MaxAnswerLen, the format's
		// own): at it, the adapter lets the answer through and the `name` format
		// refuses it (the format message); one byte over, the adapter refuses it.
		{"256 bytes of ASCII (the adapter passes it, the format refuses it)", "application/json", obj(strings.Repeat("a", 256)), format},
		{"128 two-byte characters = 256 bytes (the same)", "application/json", obj(strings.Repeat("é", 128)), format},
		{"129 two-byte characters = 258 bytes, only 129 characters", "application/json", obj(strings.Repeat("é", 129)), invalid},
		{"86 three-byte characters = 258 bytes, only 86 characters", "application/json", obj(strings.Repeat("あ", 86)), invalid},
		{"a body over the size cap", "application/json", `{"answer":"` + strings.Repeat("a", 8<<10) + `"}`, invalid},
		{"form encoded, not JSON", "application/x-www-form-urlencoded", "answer=" + right, invalid},
		{"no Content-Type", "", obj(right), invalid},
		{"a missing answer", "application/json", `{}`, format},
		{"a null answer", "application/json", `{"answer":null}`, format},
		{"an empty answer", "application/json", obj(""), format},
		{"an answer with a space (not a name)", "application/json", obj("two words"), format},
		{"an answer with a character outside the format", "application/json", obj("a/b;c"), format},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnswerFixture(t, true)
			a := f.own(ansOne, "who", "")
			a.ctype, a.body = tc.ctype, tc.body
			w := f.send(a)
			wantAnswerError(t, w, http.StatusBadRequest, tc.msg)
			if n := f.spent(ansOne); n != 0 {
				t.Fatalf("a 400 spent %d attempt(s)", n)
			}
			if f.st.IsSolved(ansAlice, ansOne) {
				t.Fatal("a 400 solved the challenge")
			}
		})
	}
}

// The four statuses (D6), the attempt count (D5, D7) and an answer to a question that
// is already correct (the route must accept it: D5's self-repair).
func TestAnswerRoute_TheFourStatuses(t *testing.T) {
	f := newAnswerFixture(t, true)
	who, host := ansValue(ansAlice, ansTwo+"-who"), ansValue(ansAlice, ansTwo+"-host")

	wantAnswerResult(t, f.send(f.own(ansTwo, "who", ansTyped)), "incorrect", false, false, 2)
	wantAnswerResult(t, f.send(f.own(ansTwo, "who", who)), "correct", true, false, 1)
	// an answer to a question that is already correct: a 200, not compared, not counted
	wantAnswerResult(t, f.send(f.own(ansTwo, "who", ansTyped)), "already-correct", true, false, 1)
	wantAnswerResult(t, f.send(f.own(ansTwo, "who", who)), "already-correct", true, false, 1)
	if n := f.spent(ansTwo); n != 2 {
		t.Fatalf("attempts spent = %d, want 2 (the two on `who`; an already-correct answer is free)", n)
	}

	// `host` has 2 attempts: two wrong ones, then even the right answer is not compared
	wantAnswerResult(t, f.send(f.own(ansTwo, "host", ansTyped)), "incorrect", false, false, 1)
	wantAnswerResult(t, f.send(f.own(ansTwo, "host", ansTyped+"2")), "incorrect", false, false, 0)
	wantAnswerResult(t, f.send(f.own(ansTwo, "host", host)), "exhausted", false, false, 0)
	wantAnswerResult(t, f.send(f.own(ansTwo, "host", host)), "exhausted", false, false, 0)
	if n := f.spent(ansTwo); n != 4 {
		t.Fatalf("attempts spent = %d, want 4 (the limit is never passed)", n)
	}
	if f.st.IsSolved(ansAlice, ansTwo) {
		t.Fatal("the challenge is solved although `host` was never answered")
	}
}

// Every question answered solves the challenge; the seat's own row is what is compared
// (bob's value is not alice's answer); afterwards an answer is already-correct and solved.
func TestAnswerRoute_AllQuestionsSolve(t *testing.T) {
	f := newAnswerFixture(t, true)
	bobWho := ansValue(ansBob, ansTwo+"-who")
	wantAnswerResult(t, f.send(f.own(ansTwo, "who", bobWho)), "incorrect", false, false, 2)

	wantAnswerResult(t, f.send(f.own(ansTwo, "who", ansValue(ansAlice, ansTwo+"-who"))), "correct", true, false, 1)
	wantAnswerResult(t, f.send(f.own(ansTwo, "host", ansValue(ansAlice, ansTwo+"-host"))), "correct", true, true, 1)
	if !f.st.IsSolved(ansAlice, ansTwo) {
		t.Fatal("every question is answered but the challenge is not solved")
	}
	wantAnswerResult(t, f.send(f.own(ansTwo, "who", ansTyped)), "already-correct", true, true, 1)

	// bob is a different seat: alice's solve is not his, and his answers are his own
	if f.st.IsSolved(ansBob, ansTwo) {
		t.Fatal("alice's answers solved bob's challenge")
	}
	wantAnswerResult(t, f.send(f.as(ansBob, ansTwo, "who", ansValue(ansBob, ansTwo+"-who"))), "correct", true, false, 2)
}

// D5: a scoreboard started without an answers table (no Judge) answers 500 with a fixed
// body and writes no row (answer_attempts stays empty), whatever the text is. (review #616 R2#4)
func TestAnswerRoute_NoJudgeIs500AndWritesNothing(t *testing.T) {
	f := newAnswerFixture(t, false)
	w := f.send(f.own(ansOne, "who", ansValue(ansAlice, ansOne+"-who")))
	wantAnswerError(t, w, http.StatusInternalServerError, "could not grade the answer")
	rows, err := f.st.AnswerAttempts(ansAlice, ansOne)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("answer_attempts holds %d row(s) after a refused start, want 0: %v", len(rows), rows)
	}
	if f.st.IsSolved(ansAlice, ansOne) {
		t.Fatal("the challenge was solved without an answers table")
	}
	if !strings.Contains(f.logs.String(), "answer: could not grade") {
		t.Fatalf("the operator's log has no line for the 500:\n%s", f.logs)
	}
}

// 429 is the limiter's, with the one error shape, once the burst of 5 is spent (the
// clock held, so no token comes back).
func TestAnswerRoute_RateLimited429(t *testing.T) {
	f := newAnswerFixture(t, true)
	for i := 1; i <= 5; i++ {
		a := f.own(ansOne, "who", ansTyped)
		a.hold = true
		if w := f.send(a); w.Code != http.StatusOK {
			t.Fatalf("request %d: status=%d body=%s, want 200 (burst 5)", i, w.Code, w.Body)
		}
	}
	a := f.own(ansOne, "who", ansTyped)
	a.hold = true
	w := f.send(a)
	wantAnswerError(t, w, http.StatusTooManyRequests, "rate limit exceeded")
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("a 429 without Retry-After")
	}
}

// D13: nothing a participant typed, and no table value, reaches a response body or a
// log line, across a session that exercises every outcome: a wrong answer, an answer
// equal to ANOTHER seat's value (the operator-only audit line), the right answer, an
// exhausted question, a format error, an unknown question, a refused origin.
func TestAnswerRoute_NoAnswerInAnyBodyOrLog(t *testing.T) {
	f := newAnswerFixture(t, true)

	// incorrect
	f.send(f.own(ansOne, "who", ansTyped))
	// incorrect, and equal to bob's value: only the operator's audit line knows
	f.send(f.own(ansOne, "who", ansValue(ansBob, ansOne+"-who")))
	// correct (the table value itself is what is typed)
	f.send(f.own(ansOne, "who", ansValue(ansAlice, ansOne+"-who")))
	// already-correct
	f.send(f.own(ansOne, "who", ansTyped))
	// incorrect twice, then exhausted
	f.send(f.own(ansTwo, "host", ansTyped))
	f.send(f.own(ansTwo, "host", ansTyped+"2"))
	f.send(f.own(ansTwo, "host", ansValue(ansAlice, ansTwo+"-host")))
	// 400 (format), 404 (unknown question whose id is the typed text), 403 (origin)
	f.send(f.own(ansTwo, "host", ansTyped+" two words"))
	f.send(f.own(ansTwo, "nope-"+strings.ToLower(ansTyped), ansTyped))
	a := f.own(ansTwo, "who", ansTyped)
	a.origin = "https://evil.example.com"
	f.send(a)

	if len(f.bodies) < 10 {
		t.Fatalf("only %d responses were collected", len(f.bodies))
	}
	hay := append([]string{f.logs.String()}, f.bodies...)
	for _, h := range hay {
		for _, needle := range []string{ansTyped, strings.ToLower(ansTyped), ansSecret} {
			if strings.Contains(h, needle) {
				t.Fatalf("%q reached a response or the log:\n%.600s", needle, h)
			}
		}
	}
	// the audit line the operator needs (D5 6) is there, with the seat and no value
	if !strings.Contains(f.logs.String(), "answer matched another seat") || !strings.Contains(f.logs.String(), "seat=bob") {
		t.Fatalf("the operator's audit line for an answer equal to bob's value is missing:\n%s", f.logs)
	}
}

// V5 for the new operation: a real 200's keys are exactly AnswerResult's properties,
// and the four statuses the Grader can return are exactly the schema's enum (the
// handler converts the Grader's string, so a rename would otherwise compile).
func TestAPISpec_V5_AnswerResultFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	schema := spec.SchemaByName("AnswerResult")
	if schema == nil {
		t.Fatal("spec has no components.schemas.AnswerResult")
	}
	f := newAnswerFixture(t, true)
	w := f.send(f.own(ansOne, "who", ansValue(ansAlice, ansOne+"-who")))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body)
	}
	actual := decode(t, w)
	if len(actual) == 0 {
		t.Fatal("empty response: the comparison would be vacuous")
	}
	if n := len(spec.PropertyNames(schema)); n != 4 {
		t.Fatalf("AnswerResult declares %d properties, want 4 (D6)", n)
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "AnswerResult") {
		t.Errorf("%s: extra=%v missing=%v", m.Path, m.Extra, m.Missing)
	}

	statusSchema := spec.PropertySchema(schema, "status")
	enum, _ := statusSchema["enum"].([]any)
	var got []string
	for _, v := range enum {
		got = append(got, v.(string))
	}
	want := []string{string(scoring.AnswerCorrect), string(scoring.AnswerIncorrect), string(scoring.AnswerExhausted), string(scoring.AnswerAlreadyCorrect)}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("AnswerResult.status enum = %v, want the Grader's statuses %v", got, want)
	}
}
