package ingest_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ingest"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// app#359: the /falco/events bucket is the PARTICIPANT, not the (single,
// shared) falcosidekick sender. These tests pin the three properties that
// make a flood by one participant harmless to the others:
//   - a scoring-relevant (forbidden/expected) event is never dropped: over the
//     bucket it taints the participant's current evade mission instead,
//   - an observation-only event over the bucket is 429, counted per ns,
//   - one participant's flood never changes another participant's outcome.

const (
	forbiddenRule    = "Detect Outbound Connection" // forbidden by 02-evade
	observationRule  = "Some Unlisted Noisy Rule"   // in no challenge
	rlNamespacePfx   = "ctf-"
	tinyBurst        = 3
	rlEvadeChallenge = "02-evade"
)

func newRateLimitFixture(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	fixed := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed } // frozen: buckets never refill
	cat := catalog.Catalog{
		rlEvadeChallenge: {ID: rlEvadeChallenge, Type: "evade", ForbiddenRules: []string{forbiddenRule}},
	}
	s, err := store.Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	grader := scoring.New(cat, s, clock)
	h := ingest.New(grader, s, slog.New(slog.NewTextHandler(io.Discard, nil)), clock, "", ingest.SecretModeOff).
		WithLimits(0, tinyBurst, 0, tinyBurst)
	mux, _ := apispec.NewMux(h.Routes())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, s
}

// post sends one event for namespace ns from the (only) test sender.
func post(t *testing.T, url, ns, rule string, extra map[string]any) *http.Response {
	t.Helper()
	fields := map[string]any{
		"k8s.ns.name":                ns,
		"k8s.pod.name":               "workspace",
		"container.image.repository": "falco-ctf/challenge",
	}
	for k, v := range extra {
		fields[k] = v
	}
	buf, err := json.Marshal(map[string]any{"rule": rule, "priority": "Warning", "output_fields": fields})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url+"/falco/events", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestRateLimit_OneParticipantFlood_DoesNotDropAnotherParticipantsForbiddenFire(t *testing.T) {
	srv, s := newRateLimitFixture(t)
	// alice floods well past both buckets (observation and scoring).
	for i := 0; i < 5*tinyBurst; i++ {
		post(t, srv.URL, "ctf-flood-a", observationRule, nil)
		post(t, srv.URL, "ctf-flood-a", forbiddenRule, nil)
	}
	// bob's single forbidden fire, arriving AFTER the flood from the same
	// sender, must still taint bob with the real rule (the pre-#359 shared
	// per-IP bucket answered this 429 and bob read clean).
	resp := post(t, srv.URL, "ctf-flood-b", forbiddenRule, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's forbidden fire: status %d, want 200", resp.StatusCode)
	}
	if got := s.DirtyRules("flood-b", rlEvadeChallenge); !slices.Equal(got, []string{forbiddenRule}) {
		t.Fatalf("bob dirtyRules = %v, want exactly [%q]", got, forbiddenRule)
	}
}

func TestRateLimit_ScoringOverflow_TaintsInsteadOfDropping(t *testing.T) {
	srv, s := newRateLimitFixture(t)
	before := testutil.ToFloat64(metrics.FalcoEventsScoringOverflow.WithLabelValues("ctf-over"))
	beforeRL := testutil.ToFloat64(metrics.FalcoEventsRateLimited.WithLabelValues("ctf-over"))

	// Within the bucket: the real forbidden rule is recorded, no sentinel.
	for i := 0; i < tinyBurst; i++ {
		if resp := post(t, srv.URL, "ctf-over", forbiddenRule, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("in-bucket event %d: status %d", i, resp.StatusCode)
		}
	}
	if got := s.DirtyRules("over", rlEvadeChallenge); !slices.Equal(got, []string{forbiddenRule}) {
		t.Fatalf("in-bucket dirtyRules = %v, want [%q]", got, forbiddenRule)
	}

	// Over the bucket: NOT 429 (never dropped), accepted, and the sentinel
	// taint is recorded alongside the real one; the overflow metric moves, the
	// 429 metric does not.
	resp := post(t, srv.URL, "ctf-over", forbiddenRule, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("over-bucket scoring event: status %d, want 200 (taint, never 429)", resp.StatusCode)
	}
	got := s.DirtyRules("over", rlEvadeChallenge)
	if !slices.Contains(got, scoring.OverflowTaintRule) || !slices.Contains(got, forbiddenRule) {
		t.Fatalf("dirtyRules = %v, want both %q and %q", got, forbiddenRule, scoring.OverflowTaintRule)
	}
	if d := testutil.ToFloat64(metrics.FalcoEventsScoringOverflow.WithLabelValues("ctf-over")) - before; d != 1 {
		t.Fatalf("scoring_overflow delta = %v, want 1", d)
	}
	if d := testutil.ToFloat64(metrics.FalcoEventsRateLimited.WithLabelValues("ctf-over")) - beforeRL; d != 0 {
		t.Fatalf("rate_limited delta = %v, want 0 (scoring events are never 429)", d)
	}
}

func TestRateLimit_ScoringOverflow_TaintsEvenWhenOverflowRuleIsNotForbidden(t *testing.T) {
	srv, s := newRateLimitFixture(t)
	// The flood is of a rule that is forbidden for 02-evade; the point here is
	// the fail-closed direction — a participant who exhausted the scoring
	// bucket has their current evade mission tainted regardless of which
	// event arrived next.
	for i := 0; i < tinyBurst+1; i++ {
		post(t, srv.URL, "ctf-over2", forbiddenRule, nil)
	}
	if !slices.Contains(s.DirtyRules("over2", rlEvadeChallenge), scoring.OverflowTaintRule) {
		t.Fatalf("overflow sentinel missing: %v", s.DirtyRules("over2", rlEvadeChallenge))
	}
}

func TestRateLimit_ObservationOverBucket_429AndCountedPerNamespace(t *testing.T) {
	srv, _ := newRateLimitFixture(t)
	before := testutil.ToFloat64(metrics.FalcoEventsRateLimited.WithLabelValues("ctf-noisy"))
	var statuses []int
	for i := 0; i < tinyBurst+2; i++ {
		statuses = append(statuses, post(t, srv.URL, "ctf-noisy", observationRule, nil).StatusCode)
	}
	want := []int{200, 200, 200, 429, 429}
	if !slices.Equal(statuses, want) {
		t.Fatalf("statuses = %v, want %v", statuses, want)
	}
	if d := testutil.ToFloat64(metrics.FalcoEventsRateLimited.WithLabelValues("ctf-noisy")) - before; d != 2 {
		t.Fatalf("rate_limited delta = %v, want 2", d)
	}
	// Another participant's observation bucket is untouched.
	if resp := post(t, srv.URL, "ctf-quiet", observationRule, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("other participant's observation event: status %d, want 200", resp.StatusCode)
	}
}

func TestRateLimit_ScoringAndObservationBucketsAreIndependent(t *testing.T) {
	srv, s := newRateLimitFixture(t)
	for i := 0; i < 3*tinyBurst; i++ { // drain the observation bucket
		post(t, srv.URL, "ctf-indep", observationRule, nil)
	}
	// A scoring event right after must still be processed normally (real
	// rule recorded, no overflow sentinel).
	if resp := post(t, srv.URL, "ctf-indep", forbiddenRule, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := s.DirtyRules("indep", rlEvadeChallenge); !slices.Equal(got, []string{forbiddenRule}) {
		t.Fatalf("dirtyRules = %v, want [%q] only", got, forbiddenRule)
	}
}

func TestRateLimit_UnattributedEvents_AreNeverRateLimited(t *testing.T) {
	srv, _ := newRateLimitFixture(t)
	// Cluster noise (other namespaces) used to burn the shared sender bucket.
	// It must neither be limited nor consume anyone's bucket.
	for i := 0; i < 10*tinyBurst; i++ {
		if resp := post(t, srv.URL, "kube-system", observationRule, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("non-ctf event %d: status %d, want 200 ignored", i, resp.StatusCode)
		}
	}
	if resp := post(t, srv.URL, "ctf-after-noise", forbiddenRule, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestRateLimit_OverflowTaintPersistFailure_Returns500(t *testing.T) {
	srv, s := newRateLimitFixture(t)
	for i := 0; i < tinyBurst; i++ {
		post(t, srv.URL, "ctf-broken", forbiddenRule, nil)
	}
	if err := s.Close(); err != nil { // break persistence only
		t.Fatalf("close: %v", err)
	}
	// "ctf-broken" is already dirty in memory with the real rule, but the
	// overflow sentinel write must fail loudly (5xx), never 200-as-clean.
	if resp := post(t, srv.URL, "ctf-broken", forbiddenRule, nil); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 on overflow-taint persist failure", resp.StatusCode)
	}
}
