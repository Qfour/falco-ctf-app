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
	// real store's evade_dirty table. Tests that are about the taint's
	// EFFECT (blocks submit, survives clock advance, blocks the sweeper) poke
	// this directly (a few whitebox tests below), mirroring what
	// store.ResetDirty's absence would look like — the mechanics of WHICH
	// challenge gets tainted (ADR-0003 attempt scope) is the concern of the
	// dedicated OnRuleFire attempt-scope tests, which DO drive the real write
	// path ((*Grader).OnRuleFire) instead of seeding this map directly.
	dirty map[string][]string
	// expectedFire["user|challenge"] is the sorted set of expectedRules ADR-0008's
	// positive-proof gate has recorded as fired for that pair — the fake's
	// mirror of the real store's expected_rule_fire table.
	expectedFire map[string][]string
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

	// recordExpectedRuleFireErr, if set, makes RecordExpectedRuleFire return it
	// for every call (ADR-0008's fail-closed error-propagation test).
	recordExpectedRuleFireErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		solved:       map[string]string{},
		dirty:        map[string][]string{},
		expectedFire: map[string][]string{},
		exfil:        map[string]string{},
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

// IsSolved mirrors the real store's per-pair read: scoring.CurrentMission
// (via Grader.currentMission) calls this once per id while walking the
// progression order to resolve "current" (ADR-0003 A1).
func (f *fakeStore) IsSolved(user, challenge string) bool {
	_, ok := f.solved[key(user, challenge)]
	return ok
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

// HasExpectedRuleFire / RecordExpectedRuleFire mirror the real store's
// ADR-0008 positive-proof read/write: additive, idempotent per
// (user, challenge, rule), no expiry — the mirror image of
// DirtyRules/MarkDirty above.
func (f *fakeStore) HasExpectedRuleFire(user, challenge string) bool {
	return len(f.expectedFire[key(user, challenge)]) > 0
}

func (f *fakeStore) RecordExpectedRuleFire(user, challenge, rule, _ string) error {
	if f.recordExpectedRuleFireErr != nil {
		return f.recordExpectedRuleFireErr
	}
	k := key(user, challenge)
	for _, r := range f.expectedFire[k] {
		if r == rule {
			return nil // already recorded — idempotent
		}
	}
	f.expectedFire[k] = append(f.expectedFire[k], rule)
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
// plain evade, one exfil-required evade, one detect, and (ADR-0008) one
// positive-proof-required evade.
func testCatalog() catalog.Catalog {
	return catalog.Catalog{
		"01-trigger": catalog.Challenge{
			ID:            "01-trigger",
			Type:          "trigger",
			ExpectedRules: []string{"Read sensitive file untrusted"},
		},
		"02-evade": catalog.Challenge{
			ID:             "02-evade",
			Type:           "evade",
			ForbiddenRules: []string{"Read sensitive file untrusted"},
			ExpectedFlag:   "FALCO{ok}",
		},
		"03-exfil": catalog.Challenge{
			ID:             "03-exfil",
			Type:           "evade",
			ForbiddenRules: []string{"Read sensitive file untrusted"},
			ExpectedFlag:   "FALCO{boss}",
			RequireExfil:   true,
		},
		// 05-proof (ADR-0008): a positive-proof-required evade mission, sorting
		// AFTER 04-detect in the default (catalog-id) progression order so it
		// never becomes "current" for any existing test that does not solve
		// through 01-04 (none do — see the ADR-0008 test group below for the
		// dedicated coverage that DOES walk it).
		"05-proof": catalog.Challenge{
			ID:                      "05-proof",
			Type:                    "evade",
			ExpectedRules:           []string{"Shell Redirected Private Key Read"},
			RequireExpectedRuleFire: true,
			ExpectedFlag:            "FALCO{proof}",
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

func TestOnRuleFire_SolvesMatchingTriggerChallenge(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Unix(1000, 0).UTC()))

	res := g.OnRuleFire("alice", "Read sensitive file untrusted")
	if res.TaintErr != nil || res.TriggerErr != nil {
		t.Fatalf("taintErr=%v triggerErr=%v", res.TaintErr, res.TriggerErr)
	}
	if len(res.Results) != 1 || res.Results[0].Challenge != "01-trigger" || !res.Results[0].Newly {
		t.Fatalf("want one newly solve of 01-trigger, got %+v", res.Results)
	}
	if fs.markSolvedCalls != 1 {
		t.Fatalf("Grader must be the single MarkSolved writer; calls=%d", fs.markSolvedCalls)
	}
	// Idempotent: a second identical fire records nothing new (01-trigger is
	// solved now, so current has advanced to 02-evade — this second fire
	// taints 02-evade instead, per attempt scope; the TRIGGER side stays
	// idempotent regardless).
	res = g.OnRuleFire("alice", "Read sensitive file untrusted")
	if res.TaintErr != nil {
		t.Fatal(res.TaintErr)
	}
	if len(res.Results) != 1 || res.Results[0].Newly {
		t.Fatalf("second fire must not be newly, got %+v", res.Results)
	}
}

func TestOnRuleFire_NonMatchingRuleSolvesNothing(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Unix(1000, 0).UTC()))

	res := g.OnRuleFire("alice", "Unrelated rule")
	if res.TaintErr != nil || res.TriggerErr != nil {
		t.Fatalf("taintErr=%v triggerErr=%v", res.TaintErr, res.TriggerErr)
	}
	if len(res.Results) != 0 {
		t.Fatalf("non-matching rule must solve nothing, got %+v", res.Results)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatalf("no MarkSolved expected; calls=%d", fs.markSolvedCalls)
	}
}

func TestOnRuleFire_EvadeRuleDoesNotAutoSolve(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Unix(1000, 0).UTC()))

	// 02-evade lists this rule as *forbidden*, not expected; a fire must not
	// auto-solve an evade challenge (it may TAINT it — irrelevant here since
	// current is 01-trigger, not 02-evade, so this fire is exempt either way).
	res := g.OnRuleFire("alice", "Read sensitive file untrusted")
	if res.TaintErr != nil || res.TriggerErr != nil {
		t.Fatalf("taintErr=%v triggerErr=%v", res.TaintErr, res.TriggerErr)
	}
	for _, r := range res.Results {
		if r.Challenge == "02-evade" {
			t.Fatalf("evade challenge must never auto-solve via trigger path: %+v", res.Results)
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
	// Seed the taint directly (this test is about evaluateClean's gate 4
	// GIVEN a dirty pair, not about WHICH challenge gets tainted — that
	// catalog-driven, attempt-scoped fan-out has its own dedicated test suite
	// below, "--- ADR-0003: attempt-scoped taint (OnRuleFire) ---").
	fs.dirty[key("alice", "02-evade")] = []string{"Read sensitive file untrusted"}

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
	// Seed directly — this test is about clock independence GIVEN a dirty
	// pair, not about the attempt-scoped fan-out that decides which
	// challenge gets tainted (see the dedicated OnRuleFire tests below).
	fs.dirty[key("alice", "02-evade")] = []string{"Read sensitive file untrusted"}

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

// --- ADR-0003: attempt-scoped taint (OnRuleFire) -----------------------------
//
// This section REPLACES the pre-ADR-0003 "TestMarkDirtyOnRuleFire_*" suite.
// The old TestMarkDirtyOnRuleFire_TaintsOnlyMatchingEvadeChallenges asserted
// that a SINGLE fire of "Read sensitive file untrusted" tainted BOTH
// 02-evade AND 03-exfil (testCatalog's two evade challenges that forbid it) —
// i.e. it positively asserted the unconditional fan-out that IS PR #124's
// BLOCKING-1 regression (a persistent taint with no attempt scope taints
// every sibling challenge that forbids a rule, the instant it fires for ANY
// reason — including the required fire that clears an earlier, unrelated
// trigger mission). That assertion was wrong as a matter of product
// correctness, not merely as an implementation detail: keeping it "green" by
// construction hides the exact regression this ADR exists to fix. It is
// removed rather than "fixed to pass" — see TestOnRuleFire_AttemptScope_*
// below for what replaces it.

// TestOnRuleFire_AttemptScope_OnlyTaintsCurrentChallenge is the core
// attempt-scope regression test (ADR-0003 §A1) at the Grader level. Walks the
// exact twin-mission shape testCatalog() has always had (01-trigger's
// required rule IS 02-evade's AND 03-exfil's forbidden rule) through a full,
// legitimate progression and proves at each step that ONLY the participant's
// CURRENT mission gets tainted — the fire that clears an earlier mission
// never taints a later sibling that has not been reached yet.
func TestOnRuleFire_AttemptScope_OnlyTaintsCurrentChallenge(t *testing.T) {
	const rule = "Read sensitive file untrusted"
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	// current(alice) = 01-trigger (nothing solved yet). This fire is
	// 01-trigger's REQUIRED expectedRule: it must solve 01-trigger and taint
	// NEITHER 02-evade NOR 03-exfil, even though both forbid this exact rule
	// name — they have not been reached yet.
	res := g.OnRuleFire("alice", rule)
	if res.TaintErr != nil {
		t.Fatal(res.TaintErr)
	}
	if len(res.Results) != 1 || res.Results[0].Challenge != "01-trigger" || !res.Results[0].Newly {
		t.Fatalf("want a newly solve of 01-trigger, got %+v", res.Results)
	}
	if got := fs.DirtyRules("alice", "02-evade"); len(got) != 0 {
		t.Fatalf("ADR-0003 regression: 01-trigger's required fire must not taint 02-evade (not yet current), got %v", got)
	}
	if got := fs.DirtyRules("alice", "03-exfil"); len(got) != 0 {
		t.Fatalf("ADR-0003 regression: 01-trigger's required fire must not taint 03-exfil (not yet current), got %v", got)
	}

	// current(alice) is now 02-evade. The SAME rule fired again now taints
	// it (it IS current, and it forbids this rule) — but NOT its sibling
	// 03-exfil, which is still not current.
	res = g.OnRuleFire("alice", rule)
	if res.TaintErr != nil {
		t.Fatal(res.TaintErr)
	}
	if got := fs.DirtyRules("alice", "02-evade"); len(got) != 1 || got[0] != rule {
		t.Fatalf("02-evade must be tainted now that it is current, got %v", got)
	}
	if got := fs.DirtyRules("alice", "03-exfil"); len(got) != 0 {
		t.Fatalf("03-exfil must still be clean (not yet current), got %v", got)
	}

	// Advance current to 03-exfil by directly marking 02-evade solved (its
	// own dirty taint would otherwise block a real SubmitEvade — irrelevant
	// to what this test is proving, so bypass it at the fake-store level).
	if _, err := fs.MarkSolved("alice", "02-evade", "t"); err != nil {
		t.Fatal(err)
	}

	// current(alice) is now 03-exfil. The same rule fired a third time taints
	// IT — proving the fan-out follows current as it advances, rather than
	// being pinned to whichever challenge happened to be first.
	res = g.OnRuleFire("alice", rule)
	if res.TaintErr != nil {
		t.Fatal(res.TaintErr)
	}
	if got := fs.DirtyRules("alice", "03-exfil"); len(got) != 1 || got[0] != rule {
		t.Fatalf("03-exfil must be tainted now that IT is current, got %v", got)
	}

	// An unrelated rule taints nothing, for anyone, regardless of current.
	res = g.OnRuleFire("bob", "Some unrelated rule")
	if res.TaintErr != nil {
		t.Fatal(res.TaintErr)
	}
	if got := fs.DirtyRules("bob", "01-trigger"); len(got) != 0 {
		t.Fatalf("non-matching rule must taint nothing, got %v", got)
	}
}

// TestOnRuleFire_AttemptScope_IsIdempotent proves a repeat fire of the same
// rule against the same (user, challenge) does not error and leaves the
// offending set unchanged, once that challenge IS current (the real store's
// PRIMARY KEY(user,challenge,rule) enforces the same property — see
// store_test.go's TestMarkDirty_SetsAndAccumulatesRules). The FIRST of the
// three fires below is 01-trigger's required fire (current at that point) —
// exempt by attempt scope — after which 02-evade becomes current for the
// remaining two, which must accumulate to exactly one dirty rule, not two.
func TestOnRuleFire_AttemptScope_IsIdempotent(t *testing.T) {
	const rule = "Read sensitive file untrusted"
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	for i := 0; i < 3; i++ {
		if res := g.OnRuleFire("alice", rule); res.TaintErr != nil {
			t.Fatal(res.TaintErr)
		}
	}
	got := fs.DirtyRules("alice", "02-evade")
	if len(got) != 1 || got[0] != rule {
		t.Fatalf("repeat fires of the same rule against the same current challenge must not duplicate, got %v", got)
	}
}

// TestOnRuleFire_TaintErrorDoesNotBlockTriggerSolve proves ADR-0003 A5's
// cross-stage continue-on-error contract: a failed taint PERSISTENCE write
// for the current evade challenge must not suppress the SAME event's trigger
// solves. Catalog is built so 02-evade is current from the start (sorts
// before both triggers) and its MarkDirty is rigged to fail; both trigger
// challenges sharing the same rule name must still solve.
func TestOnRuleFire_TaintErrorDoesNotBlockTriggerSolve(t *testing.T) {
	const rule = "Read sensitive file untrusted"
	cat := catalog.Catalog{
		"02-evade":    catalog.Challenge{ID: "02-evade", Type: "evade", ForbiddenRules: []string{rule}, ExpectedFlag: "FALCO{a}"},
		"03a-trigger": catalog.Challenge{ID: "03a-trigger", Type: "trigger", ExpectedRules: []string{rule}},
		"03b-trigger": catalog.Challenge{ID: "03b-trigger", Type: "trigger", ExpectedRules: []string{rule}},
	}
	fs := newFakeStore()
	fs.markDirtyErrFor = map[string]error{"02-evade": errors.New("boom")}
	g := scoring.New(cat, fs, fixedClock(time.Now()))

	res := g.OnRuleFire("alice", rule)
	if res.TaintErr == nil {
		t.Fatal("the current evade challenge's MarkDirty error must propagate as TaintErr")
	}
	if got := fs.DirtyRules("alice", "02-evade"); len(got) != 0 {
		t.Fatalf("a failed MarkDirty must not appear tainted in the fake, got %v", got)
	}
	if res.TriggerErr != nil {
		t.Fatalf("the trigger stage must not be affected by the taint stage's error, got %v", res.TriggerErr)
	}
	if len(res.Results) != 2 {
		t.Fatalf("both trigger challenges must still solve despite the taint error, got %+v", res.Results)
	}
	if _, ok := fs.solved[key("alice", "03a-trigger")]; !ok {
		t.Fatal("03a-trigger solve must be persisted")
	}
	if _, ok := fs.solved[key("alice", "03b-trigger")]; !ok {
		t.Fatal("03b-trigger solve must be persisted")
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
	const rule = "Read sensitive file untrusted"

	// Advance alice legitimately to 03-exfil being current (ADR-0003 attempt
	// scope): the first fire of `rule` is 01-trigger's REQUIRED expectedRule
	// and must not taint anything (01-trigger becomes current's predecessor,
	// not yet 02-evade/03-exfil); then a clean submit of 02-evade (still
	// current's predecessor at that point) solves it and advances current to
	// 03-exfil.
	if res := g.OnRuleFire("alice", rule); res.TaintErr != nil {
		t.Fatal(res.TaintErr)
	}
	if out, err := g.SubmitEvade("alice", "02-evade", "FALCO{ok}"); err != nil || out.Status != scoring.EvadeSolved {
		t.Fatalf("02-evade must solve cleanly to advance current to 03-exfil, got %+v err=%v", out, err)
	}

	// NOW 03-exfil is current: the SAME rule fired again taints IT (it is
	// evade-type and forbids this rule), and the collector delivers the boss
	// flag — exactly the state a real attacker-then-caught-then-restarted
	// scoreboard would be in.
	if res := g.OnRuleFire("alice", rule); res.TaintErr != nil {
		t.Fatal(res.TaintErr)
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

// --- ADR-0008: positive-proof gate (requireExpectedRuleFire) ---------------
//
// Note (ADR-0008 Verification (b), non-scope reminder): these tests drive
// SIMULATED rule-fire events through Grader.OnRuleFire — they prove the Go
// wiring only. Whether the underlying Falco condition ("Shell Redirected
// Private Key Read") actually fires for the intended shell-redirection
// technique, or fails to fire for a direct `cat /root/.ssh/id_rsa` argument,
// is NOT something this package can verify; that is the cluster E2E's job
// (ADR-0008 Verification (a)/(a-1)/(a-2), explicitly out of scope here).

// TestSubmitEvade_ExpectedRuleFireRequired_NotDelivered is the ADR-0008
// counterpart of TestSubmitEvade_ExfilRequired_NotDelivered: a correct flag
// on a clean (never-dirtied) pair still does not solve a
// RequireExpectedRuleFire mission until the positive proof has been recorded.
func TestSubmitEvade_ExpectedRuleFireRequired_NotDelivered(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	out, err := g.SubmitEvade("alice", "05-proof", "FALCO{proof}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeExpectedRuleFireRequired {
		t.Fatalf("missing positive proof must block, got %+v", out)
	}
	if fs.markSolvedCalls != 0 {
		t.Fatal("proof-required must not solve before the technique is proven")
	}
}

// TestSubmitEvade_ExpectedRuleFireRequired_AfterFire_Solves proves the
// positive path: once OnRuleFire has recorded a fire of one of the
// challenge's expectedRules for this user, SubmitEvade solves.
func TestSubmitEvade_ExpectedRuleFireRequired_AfterFire_Solves(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	res := g.OnRuleFire("alice", "Shell Redirected Private Key Read")
	if res.TaintErr != nil || res.ExpectedFireErr != nil || res.TriggerErr != nil {
		t.Fatalf("taintErr=%v expectedFireErr=%v triggerErr=%v", res.TaintErr, res.ExpectedFireErr, res.TriggerErr)
	}
	if !fs.HasExpectedRuleFire("alice", "05-proof") {
		t.Fatal("OnRuleFire must record the positive proof for 05-proof")
	}

	out, err := g.SubmitEvade("alice", "05-proof", "FALCO{proof}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeSolved || !out.Newly {
		t.Fatalf("proof recorded + correct flag + clean window must solve, got %+v", out)
	}
}

// TestOnRuleFire_ExpectedRuleFire_TypeGuard proves the `ch.Type == "evade"`
// guard in recordExpectedRuleFire (ADR-0008 Decision (3)): a trigger
// challenge's OWN expectedRules firing must NOT leak into
// expected_rule_fire, even though ExpectedRules is a field shared by both
// types. Dropping this guard would let 01-trigger's rule fire register as
// "proof" for a hypothetical evade mission sharing the same rule name.
func TestOnRuleFire_ExpectedRuleFire_TypeGuard(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	// "Read sensitive file untrusted" is 01-trigger's (type=trigger)
	// expectedRule, not 05-proof's. Firing it must solve 01-trigger but must
	// NOT register as proof for any RequireExpectedRuleFire mission.
	res := g.OnRuleFire("alice", "Read sensitive file untrusted")
	if res.ExpectedFireErr != nil {
		t.Fatal(res.ExpectedFireErr)
	}
	if fs.HasExpectedRuleFire("alice", "05-proof") {
		t.Fatal("a trigger challenge's expectedRules firing must never register as 05-proof's positive proof")
	}
}

// TestOnRuleFire_ExpectedRuleFire_NotAttemptScoped proves ADR-0008 Decision
// (3)'s explicit non-scoping: unlike markDirtyOnRuleFire, recordExpectedRuleFire
// records the proof EVEN WHEN the RequireExpectedRuleFire mission is not yet
// the participant's "current" mission (nothing else has been solved).
func TestOnRuleFire_ExpectedRuleFire_NotAttemptScoped(t *testing.T) {
	fs := newFakeStore()
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))
	// current(alice) is 01-trigger — 05-proof is nowhere close to current.
	res := g.OnRuleFire("alice", "Shell Redirected Private Key Read")
	if res.ExpectedFireErr != nil {
		t.Fatal(res.ExpectedFireErr)
	}
	if !fs.HasExpectedRuleFire("alice", "05-proof") {
		t.Fatal("ADR-0008 Decision (3): the positive-proof write must not be attempt-scoped")
	}
}

// TestOnRuleFire_ExpectedRuleFireErrorPropagates proves a store error from
// RecordExpectedRuleFire surfaces via RuleFireOutcome.ExpectedFireErr (and
// only that field — not TaintErr/TriggerErr), matching the error-isolation
// contract the doc comment on RuleFireOutcome describes.
func TestOnRuleFire_ExpectedRuleFireErrorPropagates(t *testing.T) {
	fs := newFakeStore()
	fs.recordExpectedRuleFireErr = errors.New("boom")
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	res := g.OnRuleFire("alice", "Shell Redirected Private Key Read")
	if res.ExpectedFireErr == nil {
		t.Fatal("expected a non-nil ExpectedFireErr")
	}
	if res.TaintErr != nil || res.TriggerErr != nil {
		t.Fatalf("a RecordExpectedRuleFire failure must not surface as TaintErr/TriggerErr, got taintErr=%v triggerErr=%v", res.TaintErr, res.TriggerErr)
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

func TestOnRuleFire_TriggerStoreErrorPropagates(t *testing.T) {
	fs := newFakeStore()
	fs.markSolvedErr = errors.New("boom")
	g := scoring.New(testCatalog(), fs, fixedClock(time.Now()))

	res := g.OnRuleFire("alice", "Read sensitive file untrusted")
	if res.TriggerErr == nil {
		t.Fatal("MarkSolved error must propagate as TriggerErr from OnRuleFire")
	}
}

// TestOnRuleFire_TriggerContinueOnError proves the trigger stage's loop
// mirrors the old ingest behaviour: when two trigger challenges share a rule
// and the first's MarkSolved errors, the failing challenge is skipped
// (continue-on-error) but the second is still solved, and TriggerErr is
// returned non-nil. A regression to early-return-on-error would drop the
// second challenge's solve. Catalog has no evade challenge at all, so
// current is always a trigger mission and TaintErr stays nil throughout —
// this test is purely about the trigger stage.
func TestOnRuleFire_TriggerContinueOnError(t *testing.T) {
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

	res := g.OnRuleFire("alice", rule)
	if res.TaintErr != nil {
		t.Fatalf("no evade challenge exists; TaintErr must stay nil, got %v", res.TaintErr)
	}
	if res.TriggerErr == nil {
		t.Fatal("the joined trigger store error must be returned non-nil as TriggerErr")
	}
	// The failing challenge must not appear; the second must be solved.
	if len(res.Results) != 1 || res.Results[0].Challenge != "01b-trigger" || !res.Results[0].Newly {
		t.Fatalf("second challenge must still solve despite the first's error, got %+v", res.Results)
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
	// Seed directly — this test is about the sweeper's behaviour GIVEN a
	// dirty pair, not about the attempt-scoped fan-out that decides which
	// challenge gets tainted (see the dedicated OnRuleFire tests above).
	fs.dirty[key("alice", "03-exfil")] = []string{"Read sensitive file untrusted"}
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

// --- ADR-0003 Verification (a): real catalog + real scenario order ----------

// TestOnRuleFire_RealCatalog_AttemptScope_TwinMissionsStayClean is ADR-0003
// Verification (a)'s scoring-side half. It reads the REAL challenges/ tree
// and the REAL nimbusbreach-full scenario order (not testCatalog()'s
// synthetic fixture) and walks a full, legitimate 01→10 progression:
//   - every trigger mission is cleared by firing its own required rule(s);
//   - every evade mission is checked for cleanliness BEFORE being submitted
//     (with a fresh exfil delivery first when RequireExfil), and must solve.
//
// This is deliberately run against the PRODUCTION catalog, not a hand-built
// one: catalog_test.go's TestEvadeForbiddenRules_IntersectPriorTriggerExpectedRules
// already proves the synthetic testCatalog() fixture had the same
// intersecting-rule-names shape BEFORE PR #124 shipped and still missed the
// regression — what was missing was this exact progression-property
// assertion, run against real data, not a better fixture.
func TestOnRuleFire_RealCatalog_AttemptScope_TwinMissionsStayClean(t *testing.T) {
	cat, err := catalog.Load("../../../challenges")
	if err != nil {
		t.Fatalf("load real challenges: %v", err)
	}
	sc, err := catalog.LoadScenario("../../../scenarios/nimbusbreach-full/scenario.yaml")
	if err != nil {
		t.Fatalf("load scenario: %v", err)
	}
	scored, err := cat.Restrict(sc.Challenges)
	if err != nil {
		t.Fatalf("restrict to scored scenario: %v", err)
	}

	fs := newFakeStore()
	g := scoring.New(scored, fs, fixedClock(time.Now())).WithOrder(sc.Challenges)

	for _, cid := range sc.Challenges {
		ch := scored[cid]
		switch ch.Type {
		case "trigger":
			for _, rule := range ch.ExpectedRules {
				res := g.OnRuleFire("alice", rule)
				if res.TaintErr != nil || res.TriggerErr != nil {
					t.Fatalf("%s: fire %q: taintErr=%v triggerErr=%v", cid, rule, res.TaintErr, res.TriggerErr)
				}
			}
			if _, ok := fs.solved[key("alice", cid)]; !ok {
				t.Fatalf("%s must be solved by its own required rule fire(s)", cid)
			}
		case "evade":
			// The core regression check: this mission's forbiddenRules very
			// likely intersect an EARLIER trigger's expectedRules (the "twin"
			// structure pinned by catalog_test.go's
			// TestEvadeForbiddenRules_IntersectPriorTriggerExpectedRules).
			// Every one of those required fires happened above; attempt
			// scope must have exempted all of them.
			if got := fs.DirtyRules("alice", cid); len(got) != 0 {
				t.Fatalf("%s: ADR-0003 regression — dirty from a predecessor's required fire: %v", cid, got)
			}
			// ADR-0008: a RequireExpectedRuleFire mission (05-silent-search)
			// also needs its OWN expectedRules fired at least once — simulating
			// the participant actually demonstrating the evasion technique —
			// before SubmitEvade can reach EvadeSolved. This fire must be a
			// no-op for every OTHER mission's gates (the new rule name is not
			// shared with any forbiddenRules/trigger expectedRules — see
			// catalog_test.go's TestExpectedRuleFire_NewRuleNameUniqueToMission05).
			if ch.RequireExpectedRuleFire {
				for _, rule := range ch.ExpectedRules {
					res := g.OnRuleFire("alice", rule)
					if res.TaintErr != nil || res.ExpectedFireErr != nil || res.TriggerErr != nil {
						t.Fatalf("%s: prove-technique fire %q: taintErr=%v expectedFireErr=%v triggerErr=%v",
							cid, rule, res.TaintErr, res.ExpectedFireErr, res.TriggerErr)
					}
				}
				if !fs.HasExpectedRuleFire("alice", cid) {
					t.Fatalf("%s: expected rule fire must be recorded after firing %v", cid, ch.ExpectedRules)
				}
			}
			if ch.RequireExfil {
				if _, err := g.RecordExfil("alice", cid, ch.ExpectedFlag); err != nil {
					t.Fatalf("%s: RecordExfil: %v", cid, err)
				}
			}
			out, err := g.SubmitEvade("alice", cid, ch.ExpectedFlag)
			if err != nil {
				t.Fatalf("%s: SubmitEvade: %v", cid, err)
			}
			if out.Status != scoring.EvadeSolved || !out.Newly {
				t.Fatalf("%s: must solve on a clean, exfil-satisfied submit, got %+v", cid, out)
			}
		default:
			t.Fatalf("unexpected challenge type %q for %s in the scored scenario", ch.Type, cid)
		}
	}
}

// --- ADR-0003 Verification (c): highest-risk real shape (7 forbiddenRules +
// requireExfil, matching 10-final-exfil) ------------------------------------

// TestSubmitEvade_SevenForbiddenRules_ResetRequiresFreshExfil exercises the
// production capstone's exact shape (7 forbiddenRules + requireExfil is the
// riskiest combination in the real catalog — see catalog_test.go's real-data
// table) and proves the two properties that must hold TOGETHER:
//  1. ANY ONE of the seven forbidden rules firing while the pair is current
//     dirties it (attempt-scoped fan-out still works with >1 forbidden rule);
//  2. a reset does NOT let a stale exfil receipt auto-solve it (ADR-0003
//     A2-2, CEO enforce decision) — the pair needs a BRAND NEW exfil
//     delivery after the reset, not just a clean taint.
func TestSubmitEvade_SevenForbiddenRules_ResetRequiresFreshExfil(t *testing.T) {
	forbidden := []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7"}
	cat := catalog.Catalog{
		"10-boss": catalog.Challenge{
			ID: "10-boss", Type: "evade", ForbiddenRules: forbidden,
			ExpectedFlag: "FALCO{boss}", RequireExfil: true,
		},
	}
	fs := newFakeStore()
	g := scoring.New(cat, fs, fixedClock(time.Now()))

	// 10-boss is the sole (hence always-current) mission: any one of the
	// seven forbidden rules firing must dirty it.
	res := g.OnRuleFire("alice", "r4")
	if res.TaintErr != nil {
		t.Fatal(res.TaintErr)
	}
	if got := fs.DirtyRules("alice", "10-boss"); len(got) != 1 || got[0] != "r4" {
		t.Fatalf("one of seven forbidden rules must dirty the pair, got %v", got)
	}

	// Deliver the exfil receipt anyway (as an unaware participant might) —
	// must not solve while dirty.
	if _, err := g.RecordExfil("alice", "10-boss", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	out, err := g.SubmitEvade("alice", "10-boss", "FALCO{boss}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeForbiddenFired {
		t.Fatalf("dirty pair must block even with exfil delivered, got %+v", out)
	}

	// Reset (mirrors what store.ResetDirty does under the reset-dirty
	// endpoint, ADR-0003 A2-2's enforce contract: the SAME call clears BOTH
	// the taint AND the exfil receipt).
	delete(fs.dirty, key("alice", "10-boss"))
	delete(fs.exfil, key("alice", "10-boss"))

	// Submitting again WITHOUT a fresh exfil delivery must NOT solve — this
	// is A2-2's whole point (closing "fire → reset → auto-solve off the
	// stale receipt").
	out, err = g.SubmitEvade("alice", "10-boss", "FALCO{boss}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeExfilRequired {
		t.Fatalf("A2-2: reset must require a FRESH exfil delivery, not resurrect the stale one, got %+v", out)
	}

	// A fresh delivery after the reset finally solves.
	if _, err := g.RecordExfil("alice", "10-boss", "FALCO{boss}"); err != nil {
		t.Fatal(err)
	}
	out, err = g.SubmitEvade("alice", "10-boss", "FALCO{boss}")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != scoring.EvadeSolved || !out.Newly {
		t.Fatalf("fresh exfil after reset must solve, got %+v", out)
	}
}
