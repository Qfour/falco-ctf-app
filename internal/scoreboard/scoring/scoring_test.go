package scoring_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// fakeStore is an in-memory ScoreStore with a scriptable forbidden-fire and
// exfil surface — no SQLite, no HTTP. It records MarkSolved calls so tests can
// assert the Grader is the single writer.
type fakeStore struct {
	solved map[string]string // "user|challenge" -> at (first-write-wins)
	// forbidden[user] is the set of forbidden rules the store should report as
	// having fired within any window. RecentForbiddenFires intersects it with
	// the challenge's forbidden list, mirroring the real store's filtering.
	forbidden map[string][]string
	// exfil["user|challenge"] is the flag the collector received for that pair.
	exfil map[string]string

	markSolvedErr  error // if set, MarkSolved returns it for every challenge
	recordExfilErr error // if set, RecordExfil returns it

	// markSolvedErrFor[challenge], if set, makes MarkSolved fail only for that
	// challenge (used to prove continue-on-error skips just the failing one).
	markSolvedErrFor map[string]error

	markSolvedCalls int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		solved:    map[string]string{},
		forbidden: map[string][]string{},
		exfil:     map[string]string{},
	}
}

func key(user, challenge string) string { return user + "|" + challenge }

func (f *fakeStore) MarkSolved(user, challenge, at string) (bool, error) {
	f.markSolvedCalls++
	if f.markSolvedErr != nil {
		return false, f.markSolvedErr
	}
	if err := f.markSolvedErrFor[challenge]; err != nil {
		return false, err
	}
	k := key(user, challenge)
	if _, ok := f.solved[k]; ok {
		return false, nil // first solve wins (idempotent, like the real store)
	}
	f.solved[k] = at
	return true, nil
}

func (f *fakeStore) RecentForbiddenFires(user string, forbidden []string, _ float64, _ int) []string {
	want := map[string]struct{}{}
	for _, r := range forbidden {
		want[r] = struct{}{}
	}
	var out []string
	for _, r := range f.forbidden[user] {
		if _, ok := want[r]; ok {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeStore) HasExfil(user, challenge, flag string) bool {
	got, ok := f.exfil[key(user, challenge)]
	return ok && got == flag
}

func (f *fakeStore) RecordExfil(user, challenge, flag, _ string) error {
	if f.recordExfilErr != nil {
		return f.recordExfilErr
	}
	f.exfil[key(user, challenge)] = flag
	return nil
}

// PendingExfilSolves mirrors the real store: every recorded receipt whose
// (user, challenge) pair is not yet in the solved set, sorted by (user,
// challenge) for deterministic assertions.
func (f *fakeStore) PendingExfilSolves() []store.ExfilReceipt {
	var out []store.ExfilReceipt
	for k, flag := range f.exfil {
		if _, solved := f.solved[k]; solved {
			continue
		}
		user, challenge, _ := strings.Cut(k, "|")
		out = append(out, store.ExfilReceipt{User: user, Challenge: challenge, Flag: flag})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		return out[i].Challenge < out[j].Challenge
	})
	return out
}

// testCatalog mirrors the fixture used by the HTTP tests: one trigger, one
// plain evade, one exfil-required evade.
func testCatalog() catalog.Catalog {
	return catalog.Catalog{
		"01-trigger": catalog.Challenge{
			ID:            "01-trigger",
			Type:          "trigger",
			ExpectedRules: []string{"Read sensitive file untrusted"},
			WindowSeconds: 10,
		},
		"02-evade": catalog.Challenge{
			ID:             "02-evade",
			Type:           "evade",
			ForbiddenRules: []string{"Read sensitive file untrusted"},
			ExpectedFlag:   "FALCO{ok}",
			WindowSeconds:  10,
		},
		"03-exfil": catalog.Challenge{
			ID:             "03-exfil",
			Type:           "evade",
			ForbiddenRules: []string{"Read sensitive file untrusted"},
			ExpectedFlag:   "FALCO{boss}",
			WindowSeconds:  10,
			RequireExfil:   true,
		},
	}
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// --- Quadrant 1: trigger fire ------------------------------------------------

func TestEvaluateTrigger_SolvesMatchingChallenge(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Unix(1000, 0).UTC()))

	res, err := g.EvaluateTrigger("alice", "Read sensitive file untrusted")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Challenge != "01-trigger" || !res[0].Newly {
		t.Fatalf("want one newly solve of 01-trigger, got %+v", res)
	}
	if fs.markSolvedCalls != 1 {
		t.Fatalf("Grader must be the single MarkSolved writer; calls=%d", fs.markSolvedCalls)
	}
	// Idempotent: a second identical fire records nothing new.
	res, err = g.EvaluateTrigger("alice", "Read sensitive file untrusted")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Newly {
		t.Fatalf("second fire must not be newly, got %+v", res)
	}
}

func TestEvaluateTrigger_NonMatchingRuleSolvesNothing(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Unix(1000, 0).UTC()))

	res, err := g.EvaluateTrigger("alice", "Unrelated rule")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("non-matching rule must solve nothing, got %+v", res)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatalf("no MarkSolved expected; calls=%d", fs.markSolvedCalls)
	}
}

func TestEvaluateTrigger_EvadeRuleDoesNotAutoSolve(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Unix(1000, 0).UTC()))

	// 02-evade lists this rule as *forbidden*, not expected; a fire must not
	// auto-solve an evade challenge.
	res, err := g.EvaluateTrigger("alice", "Read sensitive file untrusted")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Challenge == "02-evade" {
			t.Fatalf("evade challenge must never auto-solve via trigger path: %+v", res)
		}
	}
}

// --- Quadrant 2: evade clean -------------------------------------------------

func TestSubmitEvade_CleanWindow_Solves(t *testing.T) {
	fs := newFakeStore()
	at := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	g := scoring.New(testCatalog(), fs, fixedClock(at))

	out, err := g.SubmitEvade("alice", "02-evade", "FALCO{ok}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeSolved || !out.Newly {
		t.Fatalf("clean window + correct flag must solve newly, got %+v", out)
	}
	if got := fs.solved[key("alice", "02-evade")]; got != at.Format(time.RFC3339Nano) {
		t.Fatalf("solve timestamp must be the injected clock, got %q", got)
	}
}

func TestSubmitEvade_WrongFlag(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	out, err := g.SubmitEvade("alice", "02-evade", "FALCO{nope}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeWrongFlag {
		t.Fatalf("want EvadeWrongFlag, got %+v", out)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("wrong flag must not reach MarkSolved")
	}
}

func TestSubmitEvade_UnknownAndNonEvade(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	if out, _ := g.SubmitEvade("alice", "nope", "x"); out.Status != scoring.EvadeUnknownChallenge {
		t.Fatalf("unknown challenge: got %+v", out)
	}
	if out, _ := g.SubmitEvade("alice", "01-trigger", "x"); out.Status != scoring.EvadeNotEvadeType {
		t.Fatalf("trigger challenge submitted as evade: got %+v", out)
	}
}

// --- Quadrant 3: evade forbidden fired ---------------------------------------

func TestSubmitEvade_ForbiddenFired_NotSolved(t *testing.T) {
	fs := newFakeStore()
	fs.forbidden["alice"] = []string{"Read sensitive file untrusted"}
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	out, err := g.SubmitEvade("alice", "02-evade", "FALCO{ok}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeForbiddenFired {
		t.Fatalf("forbidden fire must block, got %+v", out)
	}
	if len(out.Offending) != 1 || out.Offending[0] != "Read sensitive file untrusted" {
		t.Fatalf("offending rules not surfaced: %+v", out.Offending)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("forbidden fire must not reach MarkSolved")
	}
}

// --- Quadrant 4: exfil required (unmet then met) -----------------------------

func TestSubmitEvade_ExfilRequired_NotDelivered(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	out, err := g.SubmitEvade("alice", "03-exfil", "FALCO{boss}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeExfilRequired {
		t.Fatalf("missing exfil must block, got %+v", out)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("exfil-required must not solve before delivery")
	}
}

func TestSubmitEvade_ExfilRequired_AfterDelivery_Solves(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	// Record the collector receipt through the Grader, then submit.
	st, err := g.RecordExfil("alice", "03-exfil", "FALCO{boss}")
	if err != nil {
		t.Fatal(err)
	}
	if st != scoring.ExfilRecorded {
		t.Fatalf("want ExfilRecorded, got %v", st)
	}
	out, err := g.SubmitEvade("alice", "03-exfil", "FALCO{boss}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeSolved || !out.Newly {
		t.Fatalf("clean window + delivered exfil must solve, got %+v", out)
	}
}

func TestSubmitEvade_ExfilRequired_WrongExfilValue_StillBlocked(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	// Deliver a value that does not match the real flag.
	if _, err := g.RecordExfil("alice", "03-exfil", "FALCO{wrong}"); err != nil {
		t.Fatal(err)
	}
	out, err := g.SubmitEvade("alice", "03-exfil", "FALCO{boss}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeExfilRequired {
		t.Fatalf("mismatched exfil must not satisfy the gate, got %+v", out)
	}
}

// --- RecordExfil guards ------------------------------------------------------

func TestRecordExfil_Guards(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	if st, _ := g.RecordExfil("alice", "nope", "x"); st != scoring.ExfilUnknownChallenge {
		t.Fatalf("unknown challenge: got %v", st)
	}
	if st, _ := g.RecordExfil("alice", "02-evade", "FALCO{ok}"); st != scoring.ExfilNotRequired {
		t.Fatalf("non-exfil challenge must be ExfilNotRequired, got %v", st)
	}
}

// --- store error propagation -------------------------------------------------

func TestSubmitEvade_StoreErrorPropagates(t *testing.T) {
	fs := newFakeStore()
	fs.markSolvedErr = errors.New("boom")
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	_, err := g.SubmitEvade("alice", "02-evade", "FALCO{ok}")
	if err == nil {
		t.Fatal("MarkSolved error must propagate from SubmitEvade")
	}
}

func TestEvaluateTrigger_StoreErrorPropagates(t *testing.T) {
	fs := newFakeStore()
	fs.markSolvedErr = errors.New("boom")
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	_, err := g.EvaluateTrigger("alice", "Read sensitive file untrusted")
	if err == nil {
		t.Fatal("MarkSolved error must propagate from EvaluateTrigger")
	}
}

// TestEvaluateTrigger_ContinueOnError proves the loop mirrors the old ingest
// behaviour: when two trigger challenges share a rule and the first's
// MarkSolved errors, the failing challenge is skipped (continue-on-error) but
// the second is still solved, and the joined error is returned non-nil. A
// regression to early-return-on-error would drop the second challenge's solve.
func TestEvaluateTrigger_ContinueOnError(t *testing.T) {
	const rule = "Read sensitive file untrusted"
	cat := catalog.Catalog{
		"01a-trigger": catalog.Challenge{
			ID:            "01a-trigger",
			Type:          "trigger",
			ExpectedRules: []string{rule},
		},
		"01b-trigger": catalog.Challenge{
			ID:            "01b-trigger",
			Type:          "trigger",
			ExpectedRules: []string{rule},
		},
	}
	fs := newFakeStore()
	fs.markSolvedErrFor = map[string]error{"01a-trigger": errors.New("boom")}
	g := scoring.New(cat, fs, fixedClock(time.Now()))

	res, err := g.EvaluateTrigger("alice", rule)
	if err == nil {
		t.Fatal("the joined store error must be returned non-nil")
	}
	// The failing challenge must not appear; the second must be solved.
	if len(res) != 1 || res[0].Challenge != "01b-trigger" || !res[0].Newly {
		t.Fatalf("second challenge must still solve despite the first's error, got %+v", res)
	}
	// Both were attempted (proves it did not early-return after the failure).
	if fs.markSolvedCalls != 2 {
		t.Fatalf("both challenges must be attempted (continue-on-error); calls=%d", fs.markSolvedCalls)
	}
	if _, ok := fs.solved[key("alice", "01b-trigger")]; !ok {
		t.Fatal("01b-trigger solve must be persisted")
	}
}

// --- P16 auto-solve sweeper --------------------------------------------------

// TestSweep_ManualAndSweeperShareVerdict proves the two entry points reach the
// identical solve through the shared evaluateClean gate. Given the same store
// state (exfil delivered, clean window), a manual SubmitEvade and a Sweep both
// solve 03-exfil, and the manual path is a no-op newly=false after the sweep
// already solved it (single-writer, first-wins).
func TestSweep_ManualAndSweeperShareVerdict(t *testing.T) {
	// Sweeper solves first.
	fsA := newFakeStore()
	gA := scoring.New(testCatalog(), fsA, fixedClock(time.Now()))
	if _, err := gA.RecordExfil("alice", "03-exfil", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	solved, err := gA.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 1 || solved[0] != (scoring.SweepResult{User: "alice", Challenge: "03-exfil"}) {
		t.Fatalf("sweep must solve exactly (alice,03-exfil), got %+v", solved)
	}
	// A manual submit after the sweep must agree: solved, but not newly.
	out, err := gA.SubmitEvade("alice", "03-exfil", "FALCO{boss}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeSolved || out.Newly {
		t.Fatalf("manual submit after sweep must be EvadeSolved & not newly, got %+v", out)
	}

	// Manual solves first — sweeper must then find nothing pending.
	fsB := newFakeStore()
	gB := scoring.New(testCatalog(), fsB, fixedClock(time.Now()))
	if _, err := gB.RecordExfil("bob", "03-exfil", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	if out, err := gB.SubmitEvade("bob", "03-exfil", "FALCO{boss}"); err != nil || out.Status != scoring.EvadeSolved || !out.Newly {
		t.Fatalf("manual submit must solve newly, got %+v err=%v", out, err)
	}
	solved, err = gB.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 0 {
		t.Fatalf("sweep must find nothing after manual solve, got %+v", solved)
	}
}

// (a) clean window → sweeper solves.
func TestSweep_CleanWindow_Solves(t *testing.T) {
	fs := newFakeStore()
	at := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	g := scoring.New(testCatalog(), fs, fixedClock(at))
	if _, err := g.RecordExfil("alice", "03-exfil", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	solved, err := g.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 1 {
		t.Fatalf("clean window must auto-solve, got %+v", solved)
	}
	if got := fs.solved[key("alice", "03-exfil")]; got != at.Format(time.RFC3339Nano) {
		t.Fatalf("solve timestamp must be the injected clock, got %q", got)
	}
	if fs.markSolvedCalls != 1 {
		t.Fatalf("Grader must be the single MarkSolved writer; calls=%d", fs.markSolvedCalls)
	}
}

// (b) forbidden fired within the window → sweeper must NOT solve (fail-closed).
func TestSweep_ForbiddenFired_NotSolved(t *testing.T) {
	fs := newFakeStore()
	fs.forbidden["alice"] = []string{"Read sensitive file untrusted"}
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	if _, err := g.RecordExfil("alice", "03-exfil", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	solved, err := g.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 0 {
		t.Fatalf("forbidden fire in window must block auto-solve, got %+v", solved)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("forbidden fire must not reach MarkSolved")
	}
	// The pair stays pending so a later clean window still solves it.
	fs.forbidden["alice"] = nil
	solved, err = g.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 1 {
		t.Fatalf("pair must still be pending and solve once clean, got %+v", solved)
	}
}

// (c) exfil not received → nothing pending, sweeper solves nothing.
func TestSweep_NoExfil_SolvesNothing(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	// No RecordExfil call → PendingExfilSolves is empty.
	solved, err := g.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 0 {
		t.Fatalf("no exfil receipt must yield no auto-solve, got %+v", solved)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("no exfil must not reach MarkSolved")
	}
}

// (c') wrong exfil value → never satisfies the exact-flag gate.
func TestSweep_WrongExfilValue_NeverSolves(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	if _, err := g.RecordExfil("alice", "03-exfil", "FALCO{wrong}"); err != nil {
		t.Fatal(err)
	}
	solved, err := g.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 0 {
		t.Fatalf("wrong exfil value must never auto-solve, got %+v", solved)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("wrong exfil value must not reach MarkSolved")
	}
}

// (d) already solved → idempotent; PendingExfilSolves excludes it and no second
// MarkSolved fires.
func TestSweep_AlreadySolved_Idempotent(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	if _, err := g.RecordExfil("alice", "03-exfil", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Sweep(); err != nil { // first sweep solves
		t.Fatal(err)
	}
	callsAfterFirst := fs.markSolvedCalls
	solved, err := g.Sweep() // second sweep must be a no-op
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 0 {
		t.Fatalf("second sweep must report no new solves, got %+v", solved)
	}
	if fs.markSolvedCalls != callsAfterFirst {
		t.Fatalf("solved pair must be excluded from the queue; extra MarkSolved calls: %d", fs.markSolvedCalls-callsAfterFirst)
	}
}

// Non-exfil evade / trigger receipts are never auto-solved even if a receipt
// somehow exists for them (catalog is the RequireExfil authority).
func TestSweep_OnlyExfilRequiredEvade(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	// Inject receipts directly for a plain evade and a trigger challenge.
	fs.exfil[key("alice", "02-evade")] = "FALCO{ok}"
	fs.exfil[key("alice", "01-trigger")] = "whatever"
	solved, err := g.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 0 {
		t.Fatalf("only exfil-required evade challenges auto-solve, got %+v", solved)
	}
}

// Store error on one pair is collected and the pass continues.
func TestSweep_StoreErrorPropagatesAndContinues(t *testing.T) {
	fs := newFakeStore()
	fs.markSolvedErr = errors.New("boom")
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	if _, err := g.RecordExfil("alice", "03-exfil", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	solved, err := g.Sweep()
	if err == nil {
		t.Fatal("a MarkSolved store error must be returned from Sweep")
	}
	if len(solved) != 0 {
		t.Fatalf("a failed MarkSolved must not report a solve, got %+v", solved)
	}
}

// Sweeper lifecycle: Run must return promptly on context cancel (no goroutine
// leak). Uses a fast cadence and a done channel.
func TestSweeper_StopsOnContextCancel(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	sw := scoring.NewSweeper(g, time.Millisecond, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sw.Run(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Sweeper.Run did not return after context cancel (goroutine leak)")
	}
}

// Sweeper metric hook fires once per newly auto-solved pair.
func TestSweeper_OnSolvedHookFiresOncePerSolve(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	if _, err := g.RecordExfil("alice", "03-exfil", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	var hookCalls []scoring.SweepResult
	sw := scoring.NewSweeper(g, time.Hour, nil, func(r scoring.SweepResult) {
		hookCalls = append(hookCalls, r)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	// Run does one immediate sweep on entry; cancel right after so we exercise
	// exactly that first sweep (cadence is 1h so no tick races in).
	go func() { sw.Run(ctx); close(done) }()
	// Give the immediate sweep a moment, then stop.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if len(hookCalls) != 1 || hookCalls[0].Challenge != "03-exfil" {
		t.Fatalf("onSolved hook must fire once for the auto-solve, got %+v", hookCalls)
	}
}
