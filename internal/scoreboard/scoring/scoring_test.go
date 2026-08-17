package scoring_test

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// fakeStore is an in-memory ScoreStore with a scriptable dirty-flag and exfil
// surface — no SQLite, no HTTP. It records MarkSolved calls so tests can
// assert the Grader is the single writer.
type fakeStore struct {
	solved map[string]string // "user|challenge" -> at (first-write-wins)
	// dirty["user|challenge"] is the sorted set of forbidden rules App-H2's
	// persistent taint has recorded for that pair — the fake's mirror of the
	// real store's evade_dirty table. Tests normally seed this indirectly via
	// (*Grader).MarkDirtyOnRuleFire (the real write path); a few whitebox
	// tests poke it directly to simulate "the taint was already there",
	// mirroring what store.ResetDirty's absence would look like.
	dirty map[string][]string
	// exfil["user|challenge"] is the flag the collector received for that pair.
	exfil map[string]string
	// hintViews[user] maps challenge -> revealed 1-based hint indices (#40).
	hintViews map[string]map[string][]int

	markSolvedErr  error // if set, MarkSolved returns it for every challenge
	recordExfilErr error // if set, RecordExfil returns it
	markDirtyErr   error // if set, MarkDirty returns it for every call

	// markSolvedErrFor[challenge], if set, makes MarkSolved fail only for that
	// challenge (used to prove continue-on-error skips just the failing one).
	markSolvedErrFor map[string]error
	// markDirtyErrFor[challenge], if set, makes MarkDirty fail only for that
	// challenge (mirrors markSolvedErrFor for MarkDirtyOnRuleFire's
	// continue-on-error fan-out).
	markDirtyErrFor map[string]error

	markSolvedCalls int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		solved: map[string]string{},
		dirty:  map[string][]string{},
		exfil:  map[string]string{},
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

// DirtyRules mirrors the real store's persistent-taint read: whatever has
// been recorded via MarkDirty (or seeded directly by a whitebox test) for
// (user, challenge), with no time filtering whatsoever — the point of App-H2.
func (f *fakeStore) DirtyRules(user, challenge string) []string {
	got := f.dirty[key(user, challenge)]
	if len(got) == 0 {
		return nil
	}
	out := append([]string(nil), got...)
	sort.Strings(out)
	return out
}

// MarkDirty mirrors the real store's write: additive, idempotent per
// (user, challenge, rule), no expiry.
func (f *fakeStore) MarkDirty(user, challenge, rule, _ string) error {
	if f.markDirtyErr != nil {
		return f.markDirtyErr
	}
	if err := f.markDirtyErrFor[challenge]; err != nil {
		return err
	}
	k := key(user, challenge)
	for _, r := range f.dirty[k] {
		if r == rule {
			return nil // already recorded — idempotent
		}
	}
	f.dirty[k] = append(f.dirty[k], rule)
	return nil
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

// hintViews["user"] maps challenge -> revealed 1-based hint indices. Satisfies
// the ScoreStore.HintViews port so UserScore (#40) can sum the per-user reveal
// count for the penalty. Defaults to empty (no reveals) unless a test seeds it.
func (f *fakeStore) HintViews(user string) map[string][]int {
	if f.hintViews == nil {
		return nil
	}
	return f.hintViews[user]
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
		"04-detect": catalog.Challenge{
			ID:   "04-detect",
			Type: "detect",
			// Detect challenges are not flag/live-Falco based; the Detect block's
			// capture resolution is exercised in catalog_test — here we only need the
			// type + a non-nil Detect so SubmitDetect passes its type guard and
			// delegates to the (fake) DetectRunner.
			Detect: &catalog.Detect{RuleName: "participant_detect"},
		},
	}
}

// fakeDetectRunner is a scriptable scoring.DetectRunner: the test sets the exact
// (evasionFires, benignFires, invalid, err) tuple Grade returns and records how
// many times it was called, so SubmitDetect's interpretation of each runner
// outcome is verified at the value level without any Falco.
type fakeDetectRunner struct {
	evasionFires int
	benignFires  int
	invalid      bool
	err          error
	calls        int
}

func (f *fakeDetectRunner) Grade(_ context.Context, _, _ string) (int, int, bool, error) {
	f.calls++
	return f.evasionFires, f.benignFires, f.invalid, f.err
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
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	// Drive the taint through the real write path (MarkDirtyOnRuleFire), not a
	// direct fake seed — this also exercises the catalog-driven fan-out.
	if err := g.MarkDirtyOnRuleFire("alice", "Read sensitive file untrusted"); err != nil {
		t.Fatal(err)
	}

	out, err := g.SubmitEvade("alice", "02-evade", "FALCO{ok}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeForbiddenFired {
		t.Fatalf("dirty pair must block, got %+v", out)
	}
	if len(out.Offending) != 1 || out.Offending[0] != "Read sensitive file untrusted" {
		t.Fatalf("offending rules not surfaced: %+v", out.Offending)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("dirty pair must not reach MarkSolved")
	}
}

// TestSubmitEvade_DirtyStaysDirtyRegardlessOfClockAdvance is the App-H2
// exploit-#1 regression at the Grader level (the HTTP-level twin lives in
// server_test.go's TestSubmit_CorrectFlag_AfterWaiting_StaysDirty_NotSolved):
// before the fix, evaluateClean re-derived "clean" from a windowSeconds
// lookback against g.now(), so advancing the clock past the window always
// cleared it. The dirty flag involves no clock at all — advancing the
// Grader's injected clock by a full day must not budge the verdict.
func TestSubmitEvade_DirtyStaysDirtyRegardlessOfClockAdvance(t *testing.T) {
	fs := newFakeStore()
	clock := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	g := scoring.New(testCatalog(), fs, func() time.Time { return clock })
	if err := g.MarkDirtyOnRuleFire("alice", "Read sensitive file untrusted"); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(24 * time.Hour)
	out, err := g.SubmitEvade("alice", "02-evade", "FALCO{ok}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeForbiddenFired {
		t.Fatalf("App-H2 regression: waiting must never clear the dirty taint, got %+v", out)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("a still-dirty pair must never reach MarkSolved no matter how long it waited")
	}
}

// --- App-H2: MarkDirtyOnRuleFire ---------------------------------------------

// TestMarkDirtyOnRuleFire_TaintsOnlyMatchingEvadeChallenges proves the
// catalog-driven fan-out mirrors EvaluateTrigger's: only evade-type
// challenges whose forbiddenRules contain the fired rule are tainted. A
// trigger challenge that EXPECTS the same rule name must be unaffected (it
// has no dirty concept at all), and an unrelated rule must taint nothing.
func TestMarkDirtyOnRuleFire_TaintsOnlyMatchingEvadeChallenges(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	if err := g.MarkDirtyOnRuleFire("alice", "Read sensitive file untrusted"); err != nil {
		t.Fatal(err)
	}
	// 02-evade and 03-exfil both forbid this rule (testCatalog).
	if len(fs.DirtyRules("alice", "02-evade")) == 0 {
		t.Fatal("02-evade must be tainted")
	}
	if len(fs.DirtyRules("alice", "03-exfil")) == 0 {
		t.Fatal("03-exfil must be tainted")
	}
	// 01-trigger EXPECTS this rule (not forbidden) — never tainted.
	if got := fs.DirtyRules("alice", "01-trigger"); len(got) != 0 {
		t.Fatalf("trigger challenge must never be tainted, got %v", got)
	}

	// An unrelated rule taints nothing, for anyone.
	if err := g.MarkDirtyOnRuleFire("bob", "Some unrelated rule"); err != nil {
		t.Fatal(err)
	}
	if got := fs.DirtyRules("bob", "02-evade"); len(got) != 0 {
		t.Fatalf("non-matching rule must taint nothing, got %v", got)
	}
}

// TestMarkDirtyOnRuleFire_IsIdempotent proves a repeat fire of the same rule
// against the same (user, challenge) does not error and leaves the offending
// set unchanged (the real store's PRIMARY KEY(user,challenge,rule) enforces
// the same property — see store_test.go's TestMarkDirty_SetsAndAccumulatesRules).
func TestMarkDirtyOnRuleFire_IsIdempotent(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	for i := 0; i < 3; i++ {
		if err := g.MarkDirtyOnRuleFire("alice", "Read sensitive file untrusted"); err != nil {
			t.Fatal(err)
		}
	}
	got := fs.DirtyRules("alice", "02-evade")
	if len(got) != 1 || got[0] != "Read sensitive file untrusted" {
		t.Fatalf("repeat fires of the same rule must not duplicate, got %v", got)
	}
}

// TestMarkDirtyOnRuleFire_ContinueOnError mirrors
// TestEvaluateTrigger_ContinueOnError: two evade challenges share a forbidden
// rule; the first's MarkDirty errors but the second must still be tainted,
// and the joined error must be non-nil (the ingest handler logs it — a
// silently-swallowed error here would leave a false "clean" gap).
func TestMarkDirtyOnRuleFire_ContinueOnError(t *testing.T) {
	const rule = "Read sensitive file untrusted"
	cat := catalog.Catalog{
		"02a-evade": catalog.Challenge{ID: "02a-evade", Type: "evade", ForbiddenRules: []string{rule}, ExpectedFlag: "FALCO{a}"},
		"02b-evade": catalog.Challenge{ID: "02b-evade", Type: "evade", ForbiddenRules: []string{rule}, ExpectedFlag: "FALCO{b}"},
	}
	fs := newFakeStore()
	fs.markDirtyErrFor = map[string]error{"02a-evade": errors.New("boom")}
	g := scoring.New(cat, fs, fixedClock(time.Now()))

	err := g.MarkDirtyOnRuleFire("alice", rule)
	if err == nil {
		t.Fatal("the joined store error must be returned non-nil")
	}
	if got := fs.DirtyRules("alice", "02a-evade"); len(got) != 0 {
		t.Fatalf("the failing challenge must not appear tainted, got %v", got)
	}
	if got := fs.DirtyRules("alice", "02b-evade"); len(got) != 1 {
		t.Fatalf("the second challenge must still be tainted despite the first's error, got %v", got)
	}
}

// TestDirtyFlag_SurvivesStoreRestart is the App-H2 exploit-#2 regression: the
// most important negative test in this PR. It proves the persistent dirty
// flag — unlike the old in-memory ruleFires window — survives a scoreboard
// restart, using a REAL on-disk SQLite store (not fakeStore) rebuilt from
// scratch exactly like store.Open does on every process boot (conventions I1:
// single replica + Recreate strategy means this happens on every image bump /
// node drain / OOM kill).
//
// Before the fix: a forbidden rule fire only lived in the in-memory
// ruleFires map (store.RecentFiresMatching). A restart wiped that map to
// empty, so the Sweeper's very next tick would see "no forbidden fire in the
// window" and auto-solve every exfil-delivered pair — regardless of how noisy
// the original attack was, and with ZERO participant action after the
// restart. This test fails on the pre-fix gate (RecentFiresMatching) and
// passes on the fix (DirtyRules), which is exactly the point.
func TestDirtyFlag_SurvivesStoreRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "scoreboard.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	cat := testCatalog()
	at := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	g := scoring.New(cat, st, fixedClock(at))

	// The forbidden rule fires (dirties 02-evade AND 03-exfil, both of which
	// forbid it in testCatalog), and the collector delivers the boss flag —
	// exactly the state a real attacker-then-caught-then-restarted scoreboard
	// would be in.
	if err := g.MarkDirtyOnRuleFire("alice", "Read sensitive file untrusted"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.RecordExfil("alice", "03-exfil", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}

	// Sanity check while the process is still "up": dirty blocks the sweep.
	if solved, err := g.Sweep(); err != nil || len(solved) != 0 {
		t.Fatalf("dirty pair must not auto-solve pre-restart, got solved=%+v err=%v", solved, err)
	}

	// Simulate a scoreboard restart: close the store, reopen the SAME file
	// (re-running loadFromDB, exactly like cmd/scoreboard/main.go on boot), and
	// build a brand new Grader/clock — nothing carries over from the old
	// process except what is on disk.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	g2 := scoring.New(cat, st2, fixedClock(at.Add(48*time.Hour))) // time also moved on; must not matter

	solved, err := g2.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 0 {
		t.Fatalf("App-H2 regression: the dirty flag did not survive a store restart — "+
			"the sweeper auto-solved a still-tainted receipt: %+v", solved)
	}

	// And the manual submit path agrees (SAME shared evaluateClean gate).
	out, err := g2.SubmitEvade("alice", "03-exfil", "FALCO{boss}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeForbiddenFired {
		t.Fatalf("App-H2 regression: manual submit after restart must also see the pair as dirty, got %+v", out)
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

// (b) dirty pair → sweeper must NOT solve (fail-closed), and — App-H2 — stays
// blocked no matter how long it stays pending; only an explicit reset (never
// the mere passage of time) clears it and lets a later sweep solve.
func TestSweep_ForbiddenFired_NotSolved(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	if err := g.MarkDirtyOnRuleFire("alice", "Read sensitive file untrusted"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.RecordExfil("alice", "03-exfil", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	solved, err := g.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 0 {
		t.Fatalf("dirty pair must block auto-solve, got %+v", solved)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("dirty pair must not reach MarkSolved")
	}
	// Merely re-sweeping (time passing, no reset) must NOT clear it — this is
	// exactly the exploit App-H2 closes.
	solved, err = g.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 0 {
		t.Fatalf("App-H2 regression: re-sweeping without an explicit reset must not solve, got %+v", solved)
	}
	// Only an explicit reset (the store-level operation the participant's
	// reset-dirty endpoint performs) clears the taint; the pair then solves on
	// the next sweep.
	delete(fs.dirty, key("alice", "03-exfil"))
	solved, err = g.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(solved) != 1 {
		t.Fatalf("pair must solve once explicitly reset and swept again, got %+v", solved)
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

// --- detect challenges (SubmitDetect) ---------------------------------------

// TestSubmitDetect_PreGuards covers gates 1-2: an unknown challenge and a
// non-detect challenge are decided by the Grader BEFORE the runner is consulted,
// so the runner must not be called and nothing must be marked solved.
func TestSubmitDetect_PreGuards(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	r := &fakeDetectRunner{}
	if out, err := g.SubmitDetect(context.Background(), r, "alice", "nope", "x"); err != nil || out.Status != scoring.DetectUnknownChallenge {
		t.Fatalf("unknown challenge: got %+v err=%v", out, err)
	}
	if out, err := g.SubmitDetect(context.Background(), r, "alice", "01-trigger", "x"); err != nil || out.Status != scoring.DetectNotDetectType {
		t.Fatalf("non-detect challenge: got %+v err=%v", out, err)
	}
	if r.calls != 0 {
		t.Fatalf("pre-guards must short-circuit before the runner; calls=%d", r.calls)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("pre-guards must not mark solved")
	}
}

// TestSubmitDetect_Invalid: `falco -V` rejected the condition (invalid=true).
// The counts are meaningless (no replay ran) and must be dropped; no solve.
func TestSubmitDetect_Invalid(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	// Even if a buggy runner returned non-zero fires alongside invalid, the Grader
	// must ignore them (fail-closed: invalid wins).
	r := &fakeDetectRunner{invalid: true, evasionFires: 9, benignFires: 9}

	out, err := g.SubmitDetect(context.Background(), r, "alice", "04-detect", "evt.type=open")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.DetectInvalidCondition {
		t.Fatalf("want DetectInvalidCondition, got %+v", out)
	}
	if out.EvasionFires != 0 || out.BenignFires != 0 {
		t.Fatalf("invalid must not surface replay counts, got %+v", out)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("invalid condition must not solve")
	}
}

// TestSubmitDetect_MissedEvasion: compiled but fired 0× on the evasion capture.
func TestSubmitDetect_MissedEvasion(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	r := &fakeDetectRunner{evasionFires: 0, benignFires: 0}

	out, err := g.SubmitDetect(context.Background(), r, "alice", "04-detect", "cond")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.DetectMissedEvasion {
		t.Fatalf("want DetectMissedEvasion, got %+v", out)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("a missed evasion must not solve")
	}
}

// TestSubmitDetect_FalsePositive: fired on the evasion AND on the benign capture
// (too broad). benignFires>0 must lose to no-solve even with evasionFires>0.
func TestSubmitDetect_FalsePositive(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	r := &fakeDetectRunner{evasionFires: 3, benignFires: 2}

	out, err := g.SubmitDetect(context.Background(), r, "alice", "04-detect", "cond")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.DetectFalsePositive {
		t.Fatalf("want DetectFalsePositive, got %+v", out)
	}
	if out.EvasionFires != 3 || out.BenignFires != 2 {
		t.Fatalf("false-positive must surface both counts for feedback, got %+v", out)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("a false-positive must not solve")
	}
}

// TestSubmitDetect_Solved: fired on evasion, silent on benign → solve recorded
// through the SAME MarkSolved single-writer path (I1). Newly is true the first
// time; a second identical submit is idempotent (Newly=false, no extra write).
func TestSubmitDetect_Solved(t *testing.T) {
	fs := newFakeStore()
	at := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	g := scoring.New(testCatalog(), fs, fixedClock(at))
	r := &fakeDetectRunner{evasionFires: 2, benignFires: 0}

	out, err := g.SubmitDetect(context.Background(), r, "alice", "04-detect", "cond")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.DetectSolved || !out.Newly {
		t.Fatalf("evasion-fire + benign-clean must solve newly, got %+v", out)
	}
	if out.EvasionFires != 2 || out.BenignFires != 0 {
		t.Fatalf("solve must surface the counts, got %+v", out)
	}
	if got := fs.solved[key("alice", "04-detect")]; got != at.Format(time.RFC3339Nano) {
		t.Fatalf("solve timestamp must be the injected clock, got %q", got)
	}
	if fs.markSolvedCalls != 1 {
		t.Fatalf("Grader must be the single MarkSolved writer; calls=%d", fs.markSolvedCalls)
	}

	// Idempotent: a second submit re-runs the runner (grade is cheap/deterministic)
	// but MarkSolved is first-wins, so Newly is false and no second write lands.
	out, err = g.SubmitDetect(context.Background(), r, "alice", "04-detect", "cond")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.DetectSolved || out.Newly {
		t.Fatalf("second identical submit must be solved & not newly, got %+v", out)
	}
	if fs.markSolvedCalls != 2 {
		t.Fatalf("second submit must still call MarkSolved (first-wins dedup lives in the store), calls=%d", fs.markSolvedCalls)
	}
}

// TestSubmitDetect_RunnerError: an infra error from Grade is returned unrecorded
// so the handler fails closed (500) and never solves. This is the app-side twin
// of the localexec replay fail-closed regression (localexec_test.go).
func TestSubmitDetect_RunnerError(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	// A runner that "fired on evasion, clean on benign" BUT errored: the counts
	// look like a solve, yet the error must win — no solve is recorded.
	r := &fakeDetectRunner{evasionFires: 5, benignFires: 0, err: errors.New("falco replay exited non-zero")}

	out, err := g.SubmitDetect(context.Background(), r, "alice", "04-detect", "cond")
	if err == nil {
		t.Fatal("a runner infra error must propagate from SubmitDetect")
	}
	if out.Status != scoring.DetectUnknownChallenge { // zero value; handler branches on err first
		t.Fatalf("on error the outcome is the zero value, got %+v", out)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("a runner error must never reach MarkSolved (fail-closed)")
	}
}

// TestSubmitDetect_MarkSolvedError: the grade passed but the store write failed;
// the error must propagate and the outcome must not be a silent solve.
func TestSubmitDetect_MarkSolvedError(t *testing.T) {
	fs := newFakeStore()
	fs.markSolvedErr = errors.New("boom")
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	r := &fakeDetectRunner{evasionFires: 1, benignFires: 0}

	if _, err := g.SubmitDetect(context.Background(), r, "alice", "04-detect", "cond"); err == nil {
		t.Fatal("a MarkSolved store error must propagate from SubmitDetect")
	}
}
