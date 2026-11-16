package ingest_test

// ADR-0056 V39, second half (A3b-5): the CURRENT behaviour of a forbidden-rule fire
// while an investigate challenge is the participant's current mission, fixed in a
// test so that the reason for the placement rule stays written down.
//
// The reason (ADR-0003 W2, which ADR-0056 extends to the investigate type): the
// evade clean gate taints only the participant's CURRENT mission (Grader.taintTarget),
// and an investigate challenge has no forbidden rule of its own. A participant who
// leaves an investigate challenge unsolved (one question left) keeps it current, so
// while it is current a fire of a rule that a LATER evade challenge forbids taints
// nobody: not the investigate challenge, not the evade challenge. That is not a
// defect to fix here (I11, the attempt scope, is not changed); it is why a course
// must not place an evade challenge after an investigate challenge. catalog.LoadScored
// refuses such an order (checkPlacement, V39), so the shape below cannot be started
// with a scenario or without one; it is built here from a literal catalog on purpose.
//
// Both paths are fixed: the normal path (OnRuleFire) and the overflow path (the
// scoring bucket is spent, Grader.TaintOnOverflow, app#359). The overflow path with
// an investigate challenge current was untested before this file (the #622 review's
// LOW). The control in each test is the same fire with the evade challenge current,
// which taints, so the test is not green only because the ingest is not reached.

import (
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
)

const w2Investigate = "01-ir-demo"

// investigateFirstCatalog: the investigate challenge sorts first, so it is every
// participant's current mission until it is solved (the default order is the sorted
// ids). 02-evade comes after it (the shape V39 forbids in a course).
func investigateFirstCatalog() catalog.Catalog {
	c := evadeOnlyCatalog()
	c[w2Investigate] = catalog.Challenge{ID: w2Investigate, Type: catalog.TypeInvestigate}
	return c
}

func requireNoTaint(t *testing.T, when string, dirty func(cid string) []string) {
	t.Helper()
	for _, cid := range []string{w2Investigate, rlEvadeChallenge} {
		if got := dirty(cid); len(got) != 0 {
			t.Fatalf("%s: %s is tainted %v while the investigate challenge is current (ADR-0003 W2)", when, cid, got)
		}
	}
}

func TestW2_ForbiddenFireWhileInvestigateIsCurrent_TaintsNobody(t *testing.T) {
	srv, s := newRateLimitFixture(t, investigateFirstCatalog(), false)
	for i := 0; i < 3; i++ {
		if resp := post(t, srv.URL, "ctf-ir", forbiddenRule, nil); resp.StatusCode != 200 {
			t.Fatalf("forbidden fire %d: status %d, want 200", i, resp.StatusCode)
		}
	}
	requireNoTaint(t, "normal path", func(cid string) []string { return s.DirtyRules("ir", cid) })

	// control: the same fires with the evade challenge current do taint it
	ctl, cs := newRateLimitFixture(t, evadeOnlyCatalog(), false)
	post(t, ctl.URL, "ctf-ir", forbiddenRule, nil)
	if got := cs.DirtyRules("ir", rlEvadeChallenge); !slices.Equal(got, []string{forbiddenRule}) {
		t.Fatalf("control: dirtyRules = %v, want [%q]: the ingest path is not live", got, forbiddenRule)
	}
}

func TestW2_OverflowForbiddenFireWhileInvestigateIsCurrent_TaintsNobody(t *testing.T) {
	srv, s := newRateLimitFixture(t, investigateFirstCatalog(), true)
	tainted := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_tainted"))
	skipped := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_skipped"))
	over := nsCount(t, overflowFamily, "ctf-ir")

	// spend the scoring bucket with proof fires (a scoring rule, not forbidden), then
	// the forbidden fire arrives over the bucket: the overflow path, TaintOnOverflow
	for i := 0; i < tinyBurst; i++ {
		post(t, srv.URL, "ctf-ir", proofRule, nil)
	}
	resp := post(t, srv.URL, "ctf-ir", forbiddenRule, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("over-bucket forbidden fire: status %d, want 200 (never 429)", resp.StatusCode)
	}
	if d := nsCount(t, overflowFamily, "ctf-ir") - over; d != 1 {
		t.Fatalf("scoring_overflow delta = %v, want 1: the fire did not take the overflow path", d)
	}
	requireNoTaint(t, "overflow path", func(cid string) []string { return s.DirtyRules("ir", cid) })
	if d := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_tainted")) - tainted; d != 0 {
		t.Fatalf("overflow_tainted delta = %v, want 0 (nothing was tainted)", d)
	}
	if d := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_skipped")) - skipped; d != 1 {
		t.Fatalf("overflow_skipped delta = %v, want 1 (the outcome is reported as skipped)", d)
	}

	// control: the same sequence with the evade challenge current taints it
	ctl, cs := newRateLimitFixture(t, evadeOnlyCatalog(), true)
	for i := 0; i < tinyBurst; i++ {
		post(t, ctl.URL, "ctf-ir", proofRule, nil)
	}
	post(t, ctl.URL, "ctf-ir", forbiddenRule, nil)
	if got := cs.DirtyRules("ir", rlEvadeChallenge); !slices.Equal(got, []string{forbiddenRule}) {
		t.Fatalf("control: dirtyRules = %v, want [%q]: the overflow path is not live", got, forbiddenRule)
	}
}
