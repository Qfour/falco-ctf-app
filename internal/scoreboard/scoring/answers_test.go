package scoring_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// ADR-0056 D5 / D6 / D7 / D13 at the Grader (V5, and V1 for the store and the log).
// Every value here is synthetic. tableSecret is inside every table value of the
// per-seat name answers and typedSecret is what a participant types in the
// leak tests, so a message, a log line or a stored row that carries either shows up
// as a match.

const (
	tblRun      = "0123456789abcdef0123456789abcdef"
	oneCID      = "90-investigate"
	twoCID      = "91-two-questions"
	tableSecret = "SENTINEL-zzzz"
	typedSecret = "TYPED-yyyy"
)

// invCatalog: oneCID asks one question (3 attempts); twoCID asks two (3 and 2).
func invCatalog() catalog.Catalog {
	name := func(id string, attempts int) catalog.Question {
		return catalog.Question{ID: id, Format: answerformat.Name, Attempts: attempts}
	}
	return catalog.Catalog{
		oneCID: catalog.Challenge{ID: oneCID, Type: catalog.TypeInvestigate, Investigate: &catalog.Investigate{
			Questions: []catalog.Question{name("who", 3)},
		}},
		twoCID: catalog.Challenge{ID: twoCID, Type: catalog.TypeInvestigate, Investigate: &catalog.Investigate{
			Questions: []catalog.Question{name("who", 3), name("host", 2)},
		}},
		"01-trigger": catalog.Challenge{ID: "01-trigger", Type: "trigger", ExpectedRules: []string{"Some Rule"}},
	}
}

func answerRows() [][]string {
	return [][]string{
		{"seat-a", oneCID, "who", tableSecret + "-a"},
		{"seat-b", oneCID, "who", tableSecret + "-b"},
		{"seat-a", twoCID, "who", tableSecret + "-a2"},
		{"seat-a", twoCID, "host", "host-a"},
		{"seat-b", twoCID, "who", tableSecret + "-b2"},
		{"seat-b", twoCID, "host", "host-b"},
	}
}

// buildJudge makes a Judge from rows the way a test can (edition.Parse and
// edition.NewJudge are called from non-test code by edition.Load only; the source
// scan of internal/edition reads non-test files).
func buildJudge(rows [][]string, run string) (*edition.Judge, error) {
	var b strings.Builder
	b.WriteString("# falco-ctf answers v1 run=" + run + "\n")
	for _, r := range rows {
		b.WriteString(strings.Join(r, "\t") + "\n")
	}
	tbl, err := edition.Parse([]byte(b.String()))
	if err != nil {
		return nil, err
	}
	return edition.NewJudge(tbl)
}

func realJudge(t *testing.T, rows [][]string) *edition.Judge {
	t.Helper()
	j, err := buildJudge(rows, tblRun)
	if err != nil {
		t.Fatalf("building the judge: %v", err)
	}
	return j
}

// eventLog is the order in which the fakes were called.
type eventLog struct {
	mu sync.Mutex
	ev []string
}

func (l *eventLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, s)
}

func (l *eventLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.ev)
}

// spyJudge wraps a Judge and counts the comparisons.
type spyJudge struct {
	inner      scoring.AnswerJudge
	events     *eventLog
	onMatch    func()
	matchCalls atomic.Int32
	otherCalls atomic.Int32
}

func (s *spyJudge) Match(seat, cid, qid, in string) (bool, bool) {
	s.matchCalls.Add(1)
	s.events.add("match")
	if s.onMatch != nil {
		s.onMatch()
	}
	return s.inner.Match(seat, cid, qid, in)
}

func (s *spyJudge) OtherSeat(own, cid, qid, in string) (string, bool) {
	s.otherCalls.Add(1)
	s.events.add("other")
	return s.inner.OtherSeat(own, cid, qid, in)
}

// fakeAnswers is an in-memory AnswerStore with the real store's semantics
// (solved first, then answered, then the limit), a call log and injectable
// failures. It reads solves from the fakeStore the Grader also uses.
type fakeAnswers struct {
	fs     *fakeStore
	events *eventLog
	rows   map[string]store.AnswerState

	tryErr  error
	markErr error
	readErr error

	// forceOutcome, when set, is what TryAnswerAttempt returns whatever the rows say
	// (a value the Grader does not know, to prove it refuses rather than compares).
	forceOutcome *store.AnswerAttempt
}

func newFakeAnswers(fs *fakeStore, events *eventLog) *fakeAnswers {
	return &fakeAnswers{fs: fs, events: events, rows: map[string]store.AnswerState{}}
}

func answerKey(user, cid, q string) string { return user + "|" + cid + "|" + q }

func (f *fakeAnswers) state(user, cid, q string) store.AnswerState {
	return f.rows[answerKey(user, cid, q)]
}

func (f *fakeAnswers) TryAnswerAttempt(user, cid, q string, limit int) (store.AnswerAttempt, int, error) {
	f.fs.answerStoreCalls++
	f.events.add("count")
	if f.tryErr != nil {
		return 0, 0, f.tryErr
	}
	if f.forceOutcome != nil {
		return *f.forceOutcome, 0, nil
	}
	k := answerKey(user, cid, q)
	st := f.rows[k]
	switch {
	case f.fs.IsSolved(user, cid):
		return store.AnswerAttemptChallengeSolved, st.N, nil
	case st.Correct:
		return store.AnswerAttemptAlreadyCorrect, st.N, nil
	case st.N >= limit:
		return store.AnswerAttemptExhausted, st.N, nil
	}
	st.N++
	f.rows[k] = st
	return store.AnswerAttemptCounted, st.N, nil
}

func (f *fakeAnswers) MarkAnswerCorrect(user, cid, q string) error {
	f.fs.answerStoreCalls++
	f.events.add("mark")
	if f.markErr != nil {
		return f.markErr
	}
	k := answerKey(user, cid, q)
	st := f.rows[k]
	if st.N < 1 {
		return store.ErrNoAnswerAttempt
	}
	st.Correct = true
	f.rows[k] = st
	return nil
}

func (f *fakeAnswers) AnswerAttempts(user, cid string) (map[string]store.AnswerState, error) {
	f.fs.answerStoreCalls++
	if f.readErr != nil {
		return nil, f.readErr
	}
	out := map[string]store.AnswerState{}
	prefix := user + "|" + cid + "|"
	for k, v := range f.rows {
		if q, ok := strings.CutPrefix(k, prefix); ok {
			out[q] = v
		}
	}
	return out, nil
}

// invFixture is a Grader over the fakes, a real Judge behind a spy, and a log
// capture at debug level.
type invFixture struct {
	fs     *fakeStore
	fa     *fakeAnswers
	spy    *spyJudge
	events *eventLog
	logs   *bytes.Buffer
	g      *scoring.Grader
}

func newInvFixture(t *testing.T) *invFixture {
	t.Helper()
	fs := newFakeStore()
	events := &eventLog{}
	fa := newFakeAnswers(fs, events)
	spy := &spyJudge{inner: realJudge(t, answerRows()), events: events}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	g := scoring.New(invCatalog(), fs, fixedClock(time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC))).WithAnswers(fa, spy, logger)
	return &invFixture{fs: fs, fa: fa, spy: spy, events: events, logs: logs, g: g}
}

func (f *invFixture) submit(user, cid, qid, in string) (scoring.AnswerResult, error) {
	return f.g.SubmitAnswer(context.Background(), user, cid, qid, in)
}

func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", ln, err)
		}
		out = append(out, m)
	}
	return out
}

// answerEntryGrader is the Grader of the graderEntries row for SubmitAnswer: one
// investigate challenge whose practice table (seat *) answers for every seat.
func answerEntryGrader(fs *fakeStore) *scoring.Grader {
	j, err := buildJudge([][]string{{edition.AnySeat, oneCID, "who", "practice-name"}}, edition.PracticeRunID)
	if err != nil {
		panic(err)
	}
	cat := invCatalog()
	return scoring.New(cat, fs, fixedClock(time.Now())).
		WithAnswers(newFakeAnswers(fs, &eventLog{}), j, slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

// ---- V5: the count is committed before anything is compared ----

func TestSubmitAnswer_CountsBeforeItCompares(t *testing.T) {
	f := newInvFixture(t)
	nAtMatch := -1
	f.spy.onMatch = func() { nAtMatch = f.fa.state("seat-a", oneCID, "who").N }

	res, err := f.submit("seat-a", oneCID, "who", "not-the-answer")
	if err != nil {
		t.Fatal(err)
	}
	if want := (scoring.AnswerResult{Status: scoring.AnswerIncorrect, Remaining: 2}); res != want {
		t.Fatalf("result = %+v, want %+v", res, want)
	}
	if got, want := f.events.all(), []string{"count", "match", "other"}; !slices.Equal(got, want) {
		t.Fatalf("call order = %v, want %v: the count must come before the comparison", got, want)
	}
	if nAtMatch != 1 {
		t.Fatalf("the stored count was %d when the comparison ran, want 1 (counted first)", nAtMatch)
	}
}

func TestSubmitAnswer_StoreFailureNeverCompares(t *testing.T) {
	f := newInvFixture(t)
	boom := errors.New("disk I/O error")
	f.fa.tryErr = boom

	// The right answer: even it is not compared when the count did not commit.
	res, err := f.submit("seat-a", oneCID, "who", tableSecret+"-a")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the store's error", err)
	}
	if res != (scoring.AnswerResult{}) {
		t.Fatalf("result = %+v on an error, want the zero value", res)
	}
	if got := f.spy.matchCalls.Load(); got != 0 {
		t.Fatalf("Match was called %d time(s) after a failed count, want 0", got)
	}
	if got := f.spy.otherCalls.Load(); got != 0 {
		t.Fatalf("OtherSeat was called %d time(s) after a failed count, want 0", got)
	}
	if got, want := f.events.all(), []string{"count"}; !slices.Equal(got, want) {
		t.Fatalf("call order = %v, want %v", got, want)
	}
	if f.fs.IsSolved("seat-a", oneCID) || f.fs.markSolvedCalls != 0 {
		t.Fatal("a failed count led to a solve")
	}
}

func TestSubmitAnswer_NothingIsComparedAfterTheLimitOrAfterTheAnswerOrTheSolve(t *testing.T) {
	f := newInvFixture(t)
	// Three wrong answers spend the budget of 3.
	for i, wantRemaining := range []int{2, 1, 0} {
		res, err := f.submit("seat-a", oneCID, "who", fmt.Sprintf("wrong-%d", i))
		if err != nil || res.Status != scoring.AnswerIncorrect || res.Remaining != wantRemaining {
			t.Fatalf("attempt %d: %+v, %v, want incorrect with %d left", i, res, err, wantRemaining)
		}
	}
	compared := f.spy.matchCalls.Load()
	if compared != 3 {
		t.Fatalf("Match was called %d times for 3 counted attempts", compared)
	}
	// The budget is spent: even the right answer is refused, and not compared.
	for _, in := range []string{"wrong-9", tableSecret + "-a"} {
		res, err := f.submit("seat-a", oneCID, "who", in)
		if err != nil || res != (scoring.AnswerResult{Status: scoring.AnswerExhausted}) {
			t.Fatalf("after the limit: %+v, %v, want exhausted, not correct, 0 left", res, err)
		}
	}
	if f.fs.IsSolved("seat-a", oneCID) {
		t.Fatal("an answer after the limit solved the challenge")
	}

	// seat-b answers once and solves; after that nothing is compared either.
	res, err := f.submit("seat-b", oneCID, "who", tableSecret+"-b")
	if err != nil || res != (scoring.AnswerResult{Status: scoring.AnswerCorrect, Correct: true, Solved: true, Newly: true, Remaining: 2}) {
		t.Fatalf("seat-b: %+v, %v, want correct and newly solved", res, err)
	}
	before := f.spy.matchCalls.Load()
	for _, in := range []string{tableSecret + "-b", "wrong-x"} {
		res, err := f.submit("seat-b", oneCID, "who", in)
		if err != nil || res != (scoring.AnswerResult{Status: scoring.AnswerAlreadyCorrect, Correct: true, Solved: true, Remaining: 2}) {
			t.Fatalf("after the solve: %+v, %v, want already-correct and solved", res, err)
		}
	}
	if got := f.spy.matchCalls.Load(); got != before {
		t.Fatalf("Match ran %d time(s) after the solve, want 0", got-before)
	}
}

func TestSubmitAnswer_MisformedInputCostsNothingAndIsNotCompared(t *testing.T) {
	f := newInvFixture(t)
	for _, in := range []string{
		"",
		"   ",
		typedSecret + " has a space",
		strings.Repeat("a", 300) + typedSecret,
	} {
		res, err := f.submit("seat-a", oneCID, "who", in)
		if !errors.Is(err, scoring.ErrAnswerFormat) {
			t.Fatalf("input of %d bytes: err = %v, want ErrAnswerFormat", len(in), err)
		}
		if res != (scoring.AnswerResult{}) {
			t.Fatalf("result = %+v on an error", res)
		}
		if strings.Contains(err.Error(), typedSecret) {
			t.Fatalf("the error echoes the input: %q", err.Error())
		}
	}
	if f.fs.answerStoreCalls != 0 || len(f.fa.rows) != 0 {
		t.Fatalf("a misformed input reached the budget store (%d calls, rows %v)", f.fs.answerStoreCalls, f.fa.rows)
	}
	if f.spy.matchCalls.Load() != 0 {
		t.Fatal("a misformed input was compared")
	}
}

// ---- D5 5: the solve ----

func TestSubmitAnswer_SolvesWhenEveryQuestionIsAnswered(t *testing.T) {
	f := newInvFixture(t)
	res, err := f.submit("seat-a", twoCID, "who", tableSecret+"-a2")
	if err != nil || res != (scoring.AnswerResult{Status: scoring.AnswerCorrect, Correct: true, Remaining: 2}) {
		t.Fatalf("first question: %+v, %v, want correct, not solved, 2 left", res, err)
	}
	if f.fs.markSolvedCalls != 0 || f.fs.IsSolved("seat-a", twoCID) {
		t.Fatal("one answered question of two solved the challenge")
	}
	res, err = f.submit("seat-a", twoCID, "host", "host-a")
	if err != nil || res != (scoring.AnswerResult{Status: scoring.AnswerCorrect, Correct: true, Solved: true, Newly: true, Remaining: 1}) {
		t.Fatalf("second question: %+v, %v, want correct and solved, 1 left", res, err)
	}
	if f.fs.markSolvedCalls != 1 || !f.fs.IsSolved("seat-a", twoCID) {
		t.Fatalf("MarkSolved calls = %d, solved = %v, want one solve", f.fs.markSolvedCalls, f.fs.IsSolved("seat-a", twoCID))
	}
	if f.fs.IsSolved("seat-b", twoCID) {
		t.Fatal("seat-a's answers solved seat-b's challenge")
	}
}

func TestSubmitAnswer_AFailedWriteDoesNotSolveAndTheNextSubmissionFinishesIt(t *testing.T) {
	t.Run("MarkSolved fails", func(t *testing.T) {
		f := newInvFixture(t)
		boom := errors.New("db locked")
		f.fs.markSolvedErr = boom
		res, err := f.submit("seat-a", oneCID, "who", tableSecret+"-a")
		if !errors.Is(err, boom) || res != (scoring.AnswerResult{}) {
			t.Fatalf("%+v, %v, want the store's error", res, err)
		}
		if f.fs.IsSolved("seat-a", oneCID) {
			t.Fatal("the challenge is solved although MarkSolved failed")
		}
		if got := f.fa.state("seat-a", oneCID, "who"); got != (store.AnswerState{N: 1, Correct: true}) {
			t.Fatalf("state = %+v, want the attempt spent and the question answered", got)
		}

		// The answer is recorded; the next submission (any text) finishes the solve
		// and compares nothing.
		f.fs.markSolvedErr = nil
		res, err = f.submit("seat-a", oneCID, "who", "anything")
		if err != nil || res != (scoring.AnswerResult{Status: scoring.AnswerAlreadyCorrect, Correct: true, Solved: true, Newly: true, Remaining: 2}) {
			t.Fatalf("retry: %+v, %v, want already-correct and newly solved (the retry records the solve)", res, err)
		}
		if got := f.spy.matchCalls.Load(); got != 1 {
			t.Fatalf("Match ran %d times, want 1 (the retry compares nothing)", got)
		}
		// Once solved, a further submission does not report a new solve.
		res, err = f.submit("seat-a", oneCID, "who", "anything")
		if err != nil || res.Newly || !res.Solved {
			t.Fatalf("after the solve: %+v, %v, want solved and not newly", res, err)
		}
	})
	t.Run("marking the question fails", func(t *testing.T) {
		f := newInvFixture(t)
		boom := errors.New("db locked")
		f.fa.markErr = boom
		res, err := f.submit("seat-a", oneCID, "who", tableSecret+"-a")
		if !errors.Is(err, boom) || res != (scoring.AnswerResult{}) {
			t.Fatalf("%+v, %v, want the store's error", res, err)
		}
		if f.fs.markSolvedCalls != 0 || f.fs.IsSolved("seat-a", oneCID) {
			t.Fatal("a question that could not be marked led to a solve")
		}
	})
	t.Run("reading the answers fails", func(t *testing.T) {
		f := newInvFixture(t)
		boom := errors.New("db locked")
		f.fa.readErr = boom
		res, err := f.submit("seat-a", oneCID, "who", tableSecret+"-a")
		if !errors.Is(err, boom) || res != (scoring.AnswerResult{}) {
			t.Fatalf("%+v, %v, want the store's error", res, err)
		}
		if f.fs.markSolvedCalls != 0 {
			t.Fatal("an unreadable answer record led to a solve")
		}
	})
}

// ---- D5 4 / 6: the table ----

func TestSubmitAnswer_AnotherSeatsValueIsAuditedAndAnswersNothingElse(t *testing.T) {
	f := newInvFixture(t)
	res1, err := f.submit("seat-a", oneCID, "who", tableSecret+"-b") // seat-b's value
	if err != nil {
		t.Fatal(err)
	}
	res2, err := f.submit("seat-a", oneCID, "who", "nobody-has-this")
	if err != nil {
		t.Fatal(err)
	}
	if res1.Status != scoring.AnswerIncorrect || res1.Correct || res1.Solved {
		t.Fatalf("another seat's value = %+v, want an ordinary incorrect", res1)
	}
	if res1.Status != res2.Status || res1.Correct != res2.Correct || res1.Solved != res2.Solved || res1.Remaining != 2 || res2.Remaining != 1 {
		t.Fatalf("the response tells another seat's value apart from any other wrong answer: %+v vs %+v", res1, res2)
	}
	var audit []map[string]any
	for _, r := range logRecords(t, f.logs) {
		if r["msg"] == "answer matched another seat" {
			audit = append(audit, r)
		}
	}
	if len(audit) != 1 {
		t.Fatalf("%d audit lines, want exactly 1 (only the other-seat value)", len(audit))
	}
	a := audit[0]
	if a["user"] != "seat-a" || a["cid"] != oneCID || a["qid"] != "who" || a["seat"] != "seat-b" || a["level"] != "WARN" {
		t.Fatalf("audit line = %v, want user seat-a, cid %s, qid who, seat seat-b, WARN", a, oneCID)
	}
	if strings.Contains(f.logs.String(), tableSecret) {
		t.Fatalf("the log carries a value: %s", f.logs.String())
	}
}

func TestSubmitAnswer_ASeatWithNoRowIsAnErrorLoggedWithIdsOnly(t *testing.T) {
	f := newInvFixture(t)
	res, err := f.submit("seat-z", oneCID, "who", typedSecret)
	if !errors.Is(err, scoring.ErrAnswerCellMissing) || res != (scoring.AnswerResult{}) {
		t.Fatalf("%+v, %v, want ErrAnswerCellMissing", res, err)
	}
	if f.fa.state("seat-z", oneCID, "who").N != 1 {
		t.Fatal("the attempt was not counted before the comparison found the row missing")
	}
	recs := logRecords(t, f.logs)
	if len(recs) != 1 || recs[0]["level"] != "ERROR" || recs[0]["user"] != "seat-z" || recs[0]["cid"] != oneCID || recs[0]["qid"] != "who" {
		t.Fatalf("log = %v, want one ERROR line with user, cid and qid", recs)
	}
	if strings.Contains(f.logs.String(), typedSecret) || strings.Contains(err.Error(), typedSecret) {
		t.Fatal("the input is in the log or in the error")
	}
}

// ---- fail-closed on missing wiring and on bad ids ----

func TestSubmitAnswer_WithoutATableOrAStoreRefusesAndSpendsNothing(t *testing.T) {
	fs := newFakeStore()
	fa := newFakeAnswers(fs, &eventLog{})
	j := realJudge(t, answerRows())
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	clock := fixedClock(time.Now())
	cases := []struct {
		name string
		g    *scoring.Grader
	}{
		{"never wired", scoring.New(invCatalog(), fs, clock)},
		{"no judge", scoring.New(invCatalog(), fs, clock).WithAnswers(fa, nil, logger)},
		{"no store", scoring.New(invCatalog(), fs, clock).WithAnswers(nil, j, logger)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := c.g.SubmitAnswer(context.Background(), "seat-a", oneCID, "who", tableSecret+"-a")
			if !errors.Is(err, scoring.ErrAnswersUnavailable) || res != (scoring.AnswerResult{}) {
				t.Fatalf("%+v, %v, want ErrAnswersUnavailable", res, err)
			}
			if fs.answerStoreCalls != 0 || fs.markSolvedCalls != 0 {
				t.Fatal("an unwired Grader reached a store")
			}
		})
	}
}

func TestSubmitAnswer_UnknownIdsAndOtherTypesSpendNothing(t *testing.T) {
	f := newInvFixture(t)
	type idCase struct {
		name string
		cid  string
		qid  string
		want error
	}
	cases := []idCase{
		{"unknown challenge", "99-nope", "who", scoring.ErrUnknownChallenge},
		{"not an investigate challenge", "01-trigger", "who", scoring.ErrNotInvestigate},
		{"unknown question", oneCID, "nope", scoring.ErrUnknownQuestion},
		{"a question of another challenge", oneCID, "host", scoring.ErrUnknownQuestion},
	}
	for _, c := range cases {
		res, err := f.submit("seat-a", c.cid, c.qid, tableSecret+"-a")
		if !errors.Is(err, c.want) || res != (scoring.AnswerResult{}) {
			t.Errorf("%s: %+v, %v, want %v", c.name, res, err, c.want)
		}
	}
	if f.fs.answerStoreCalls != 0 || f.spy.matchCalls.Load() != 0 {
		t.Fatalf("an unknown id reached the budget store (%d calls) or the judge", f.fs.answerStoreCalls)
	}
}

// The Grader does not guess what a store outcome it does not know means: it is an
// error, and nothing is compared or solved (fail-closed).
func TestSubmitAnswer_AnUnknownStoreOutcomeIsAnErrorAndNothingIsCompared(t *testing.T) {
	for _, outcome := range []store.AnswerAttempt{0, 99, -1} {
		f := newInvFixture(t)
		forced := outcome
		f.fa.forceOutcome = &forced
		res, err := f.submit("seat-a", oneCID, "who", tableSecret+"-a")
		if err == nil || res != (scoring.AnswerResult{}) {
			t.Fatalf("outcome %d: %+v, %v, want an error and the zero result", outcome, res, err)
		}
		if got := f.spy.matchCalls.Load(); got != 0 {
			t.Fatalf("outcome %d: Match ran %d time(s), want 0", outcome, got)
		}
		if f.fs.markSolvedCalls != 0 || f.fa.state("seat-a", oneCID, "who") != (store.AnswerState{}) {
			t.Fatalf("outcome %d: an unknown outcome led to a write", outcome)
		}
	}
}

// A question with no valid budget (a catalog the loader would have refused) is an
// error before anything is spent or compared.
func TestSubmitAnswer_AQuestionWithoutABudgetIsAnErrorAndSpendsNothing(t *testing.T) {
	for _, attempts := range []int{0, -3} {
		fs := newFakeStore()
		events := &eventLog{}
		fa := newFakeAnswers(fs, events)
		spy := &spyJudge{inner: realJudge(t, answerRows()), events: events}
		cat := catalog.Catalog{oneCID: catalog.Challenge{ID: oneCID, Type: catalog.TypeInvestigate, Investigate: &catalog.Investigate{
			Questions: []catalog.Question{{ID: "who", Format: answerformat.Name, Attempts: attempts}},
		}}}
		g := scoring.New(cat, fs, fixedClock(time.Now())).
			WithAnswers(fa, spy, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		res, err := g.SubmitAnswer(context.Background(), "seat-a", oneCID, "who", tableSecret+"-a")
		if err == nil || res != (scoring.AnswerResult{}) {
			t.Fatalf("attempts %d: %+v, %v, want an error and the zero result", attempts, res, err)
		}
		if fs.answerStoreCalls != 0 || spy.matchCalls.Load() != 0 || fs.markSolvedCalls != 0 {
			t.Fatalf("attempts %d: the budget store (%d calls), the judge or MarkSolved was reached", attempts, fs.answerStoreCalls)
		}
	}
}

func TestSubmitAnswer_ACancelledRequestSpendsNothing(t *testing.T) {
	f := newInvFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := f.g.SubmitAnswer(ctx, "seat-a", oneCID, "who", "x")
	if !errors.Is(err, context.Canceled) || res != (scoring.AnswerResult{}) {
		t.Fatalf("%+v, %v, want context.Canceled", res, err)
	}
	if f.fs.answerStoreCalls != 0 {
		t.Fatal("a cancelled request spent an attempt")
	}
}

// ---- V1: no value reaches an error, a log or the store; V5 with a real store ----

func openAnswerStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "scoreboard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, dir
}

func TestSubmitAnswer_NoValueReachesAnErrorALogOrTheStore(t *testing.T) {
	st, dir := openAnswerStore(t)
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	g := scoring.New(invCatalog(), st, fixedClock(time.Now())).WithAnswers(st, realJudge(t, answerRows()), logger)
	ctx := context.Background()

	var seen []string
	note := func(res scoring.AnswerResult, err error) {
		seen = append(seen, fmt.Sprintf("%v|%v|%+v|%#v", err, errors.Unwrap(err), res, res))
	}
	// In order: a wrong value; another seat's value; one that does not fit the
	// format; the last attempt; one after the limit; a seat the table does not name;
	// the right value; the right value again (already answered).
	for _, c := range []struct{ user, cid, qid, in string }{
		{"seat-a", oneCID, "who", typedSecret},
		{"seat-a", oneCID, "who", tableSecret + "-b"},
		{"seat-a", oneCID, "who", tableSecret + " has space"},
		{"seat-a", oneCID, "who", tableSecret + "-nope"},
		{"seat-a", oneCID, "who", typedSecret},
		{"seat-z", twoCID, "who", typedSecret},
		{"seat-a", twoCID, "who", tableSecret + "-a2"},
		{"seat-a", twoCID, "who", tableSecret + "-a2"},
	} {
		note(g.SubmitAnswer(ctx, c.user, c.cid, c.qid, c.in))
	}
	for _, s := range seen {
		for _, secret := range []string{tableSecret, typedSecret} {
			if strings.Contains(s, secret) {
				t.Errorf("a returned value carries %q: %s", secret, s)
			}
		}
	}
	for _, secret := range []string{tableSecret, typedSecret} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the log carries %q: %s", secret, logs.String())
		}
	}
	// The store's files (database and write-ahead log): neither an input nor a
	// table value is in a row.
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("reading the store directory: %v (%d entries)", err, len(ents))
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{tableSecret, typedSecret} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("%s carries %q", e.Name(), secret)
			}
		}
	}
	// What the store does hold of the exercise is counts and flags.
	rows, err := st.AnswerAttempts("seat-a", oneCID)
	if err != nil || rows["who"] != (store.AnswerState{N: 3}) {
		t.Fatalf("stored state = %v, %v, want n=3, not answered", rows, err)
	}
}

// V5: at the last attempt, N callers at once compare at most once and the count
// never passes the limit.
func TestSubmitAnswer_ConcurrentSubmissionsAtTheLastAttemptCompareAtMostOnce(t *testing.T) {
	st, _ := openAnswerStore(t)
	spy := &spyJudge{inner: realJudge(t, answerRows()), events: &eventLog{}}
	g := scoring.New(invCatalog(), st, fixedClock(time.Now())).
		WithAnswers(st, spy, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	ctx := context.Background()
	for i := 0; i < 2; i++ { // 2 of 3 spent
		if _, err := g.SubmitAnswer(ctx, "seat-a", oneCID, "who", fmt.Sprintf("wrong-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	before := spy.matchCalls.Load()

	const callers = 24
	results := make([]scoring.AnswerResult, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = g.SubmitAnswer(ctx, "seat-a", oneCID, "who", fmt.Sprintf("racing-%d", i))
		}()
	}
	wg.Wait()

	incorrect, exhausted := 0, 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		switch results[i].Status {
		case scoring.AnswerIncorrect:
			incorrect++
		case scoring.AnswerExhausted:
			exhausted++
		default:
			t.Fatalf("caller %d: %+v", i, results[i])
		}
	}
	if compared := spy.matchCalls.Load() - before; compared != 1 {
		t.Fatalf("Match ran %d times for the one attempt that was left, want exactly 1", compared)
	}
	if incorrect != 1 || exhausted != callers-1 {
		t.Fatalf("%d incorrect and %d exhausted, want 1 and %d", incorrect, exhausted, callers-1)
	}
	if rows, err := st.AnswerAttempts("seat-a", oneCID); err != nil || rows["who"].N != 3 {
		t.Fatalf("stored n = %v, %v, want 3 (the limit)", rows, err)
	}
}

// N callers all give the right answer at once: the number of comparisons is the
// number of counted attempts, never more than the limit, and the challenge ends
// up solved. A caller that arrives after the budget is spent but before the first
// right answer is recorded gets exhausted (nothing is compared for it), which is
// correct: the budget is for attempts, and the count is what comes first.
func TestSubmitAnswer_ConcurrentCorrectAnswersAreBoundedAndSolveOnce(t *testing.T) {
	st, _ := openAnswerStore(t)
	spy := &spyJudge{inner: realJudge(t, answerRows()), events: &eventLog{}}
	g := scoring.New(invCatalog(), st, fixedClock(time.Now())).
		WithAnswers(st, spy, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	ctx := context.Background()

	const callers = 16
	results := make([]scoring.AnswerResult, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = g.SubmitAnswer(ctx, "seat-a", oneCID, "who", tableSecret+"-a")
		}()
	}
	wg.Wait()

	correct, newly := 0, 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if results[i].Newly {
			newly++
		}
		switch results[i].Status {
		case scoring.AnswerCorrect:
			correct++
			fallthrough
		case scoring.AnswerAlreadyCorrect:
			if !results[i].Correct || !results[i].Solved {
				t.Fatalf("caller %d: %+v, want correct and solved", i, results[i])
			}
		case scoring.AnswerExhausted:
			if results[i].Correct {
				t.Fatalf("caller %d: %+v, an exhausted call is not correct", i, results[i])
			}
		default:
			t.Fatalf("caller %d: %+v", i, results[i])
		}
	}
	compared := int(spy.matchCalls.Load())
	if compared < 1 || compared > 3 {
		t.Fatalf("Match ran %d times, want between 1 and the limit 3", compared)
	}
	if newly != 1 {
		t.Fatalf("%d calls reported the new solve, want exactly 1 (the solve metric counts it once)", newly)
	}
	if correct != compared {
		t.Fatalf("%d calls were graded correct but Match ran %d times (every comparison here is a match)", correct, compared)
	}
	rows, err := st.AnswerAttempts("seat-a", oneCID)
	if err != nil || rows["who"].N != compared || !rows["who"].Correct {
		t.Fatalf("stored state = %v, %v, want n == %d comparisons and answered", rows, err, compared)
	}
	if !st.IsSolved("seat-a", oneCID) {
		t.Fatal("not solved")
	}
}

// POST /api/admin/reset clears the counts: a participant who had spent the budget
// has it back (D7).
func TestSubmitAnswer_AdminResetGivesTheBudgetBack(t *testing.T) {
	st, _ := openAnswerStore(t)
	g := scoring.New(invCatalog(), st, fixedClock(time.Now())).
		WithAnswers(st, realJudge(t, answerRows()), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := g.SubmitAnswer(ctx, "seat-a", oneCID, "who", fmt.Sprintf("wrong-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if res, _ := g.SubmitAnswer(ctx, "seat-a", oneCID, "who", tableSecret+"-a"); res.Status != scoring.AnswerExhausted {
		t.Fatalf("before the reset: %+v, want exhausted", res)
	}
	if _, err := st.Reset(); err != nil {
		t.Fatal(err)
	}
	res, err := g.SubmitAnswer(ctx, "seat-a", oneCID, "who", tableSecret+"-a")
	if err != nil || res != (scoring.AnswerResult{Status: scoring.AnswerCorrect, Correct: true, Solved: true, Newly: true, Remaining: 2}) {
		t.Fatalf("after the reset: %+v, %v, want a fresh budget and a new solve", res, err)
	}
}
