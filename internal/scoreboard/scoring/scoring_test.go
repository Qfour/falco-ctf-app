package scoring_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
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

	markSolvedErr  error // if set, MarkSolved returns it
	recordExfilErr error // if set, RecordExfil returns it

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
