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
	"strings"
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
//   - a scoring-relevant (forbidden/expected) event is never answered 429: over
//     the bucket the NORMAL taint predicate still applies (current evade
//     mission forbids the rule -> tainted with that real rule; nothing wider),
//   - an observation-only event over the bucket is 429, counted per ns,
//   - one participant's flood never changes another participant's outcome.

const (
	forbiddenRule    = "Detect Outbound Connection" // forbidden by 02-evade
	proofRule        = "Proof Technique Rule"       // expected (not forbidden) by 02-evade
	triggerRule      = "Trigger Mission Rule"       // expected by 01-trigger
	observationRule  = "Some Unlisted Noisy Rule"   // in no challenge
	tinyBurst        = 3
	rlEvadeChallenge = "02-evade"
)

// evadeOnlyCatalog: 02-evade is the participant's CURRENT mission from the
// start (nothing else to be current instead).
func evadeOnlyCatalog() catalog.Catalog {
	return catalog.Catalog{
		rlEvadeChallenge: {ID: rlEvadeChallenge, Type: "evade", ForbiddenRules: []string{forbiddenRule}, ExpectedRules: []string{proofRule}},
	}
}

// triggerFirstCatalog: 01-trigger is current until its rule fires.
func triggerFirstCatalog() catalog.Catalog {
	c := evadeOnlyCatalog()
	c["01-trigger"] = catalog.Challenge{ID: "01-trigger", Type: "trigger", ExpectedRules: []string{triggerRule}}
	return c
}

// newRateLimitFixture wires a real ingest handler. tiny=true uses frozen-clock
// buckets of tinyBurst (no refill); tiny=false keeps the production limits.
func newRateLimitFixture(t *testing.T, cat catalog.Catalog, tiny bool) (*httptest.Server, *store.Store) {
	t.Helper()
	return newRateLimitFixtureMode(t, cat, tiny, "", ingest.SecretModeOff)
}

func newRateLimitFixtureMode(t *testing.T, cat catalog.Catalog, tiny bool, secret string, mode ingest.SecretMode) (*httptest.Server, *store.Store) {
	t.Helper()
	fixed := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed } // frozen: buckets never refill
	s, err := store.Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	grader := scoring.New(cat, s, clock)
	h := ingest.New(grader, s, slog.New(slog.NewTextHandler(io.Discard, nil)), clock, secret, mode)
	if tiny {
		h.WithLimits(0, tinyBurst, 0, tinyBurst)
	}
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
	srv, s := newRateLimitFixture(t, evadeOnlyCatalog(), true)
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

// A forbidden rule that overflows the scoring bucket still taints the current
// evade mission — with the REAL rule name — and is never 429.
func TestRateLimit_ForbiddenRuleOverflow_TaintsWithRealRuleNeverDrops(t *testing.T) {
	srv, s := newRateLimitFixture(t, evadeOnlyCatalog(), true)
	over := nsCount(t, overflowFamily, "ctf-over")
	rl := nsCount(t, rateLimitedFamily, "ctf-over")
	overTotal, rlTotal := nsTotal(t, overflowFamily), nsTotal(t, rateLimitedFamily)
	tainted := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_tainted"))

	// Exhaust the scoring bucket with proof fires (current evade does not
	// forbid them), then a forbidden fire arrives over the bucket.
	for i := 0; i < tinyBurst; i++ {
		post(t, srv.URL, "ctf-over", proofRule, nil)
	}
	if got := s.DirtyRules("over", rlEvadeChallenge); len(got) != 0 {
		t.Fatalf("in-bucket proof fires must not taint: %v", got)
	}
	resp := post(t, srv.URL, "ctf-over", forbiddenRule, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("over-bucket forbidden event: status %d, want 200 (taint, never 429)", resp.StatusCode)
	}
	if got := s.DirtyRules("over", rlEvadeChallenge); !slices.Equal(got, []string{forbiddenRule}) {
		t.Fatalf("dirtyRules = %v, want exactly [%q] (real rule, no synthetic name)", got, forbiddenRule)
	}
	if d := nsCount(t, overflowFamily, "ctf-over") - over; d != 1 {
		t.Fatalf("scoring_overflow delta = %v, want 1", d)
	}
	if !nsExists(t, overflowFamily, "ctf-over") {
		t.Fatal("the overflow was counted, but not under its own ns series")
	}
	if d := nsTotal(t, overflowFamily) - overTotal; d != 1 {
		t.Fatalf("scoring_overflow family total delta = %v, want 1 (the per-ns series and _other together)", d)
	}
	if d := nsCount(t, rateLimitedFamily, "ctf-over") - rl; d != 0 {
		t.Fatalf("rate_limited delta = %v, want 0 (scoring events are never 429)", d)
	}
	if d := nsTotal(t, rateLimitedFamily) - rlTotal; d != 0 {
		t.Fatalf("rate_limited family total delta = %v, want 0 (a count folded into _other would show here)", d)
	}
	if d := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_tainted")) - tainted; d != 1 {
		t.Fatalf("overflow_tainted outcome delta = %v, want 1", d)
	}
}

// M1: a burst of a rule the current evade mission does NOT forbid (the proof
// rule of 05/10 is fired repeatedly by the correct run) must never taint it,
// however far over the bucket it goes.
func TestRateLimit_ProofRuleFlood_DoesNotTaintCorrectRun(t *testing.T) {
	srv, s := newRateLimitFixture(t, evadeOnlyCatalog(), true)
	skipped := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_skipped"))
	for i := 0; i < 5*tinyBurst; i++ {
		if resp := post(t, srv.URL, "ctf-proof", proofRule, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("proof event %d: status %d, want 200", i, resp.StatusCode)
		}
	}
	if got := s.DirtyRules("proof", rlEvadeChallenge); len(got) != 0 {
		t.Fatalf("a proof-rule flood tainted a correct run: %v", got)
	}
	if d := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_skipped")) - skipped; d != float64(4*tinyBurst) {
		t.Fatalf("overflow_skipped delta = %v, want %d", d, 4*tinyBurst)
	}
}

// Current mission is a trigger mission: overflow of a scoring rule is 200,
// taints nothing and does NOT solve the trigger (the event is skipped).
func TestRateLimit_OverflowWhileTriggerCurrent_NoTaintNoSolve(t *testing.T) {
	srv, s := newRateLimitFixture(t, triggerFirstCatalog(), true)
	tainted := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_tainted"))
	for i := 0; i < tinyBurst; i++ {
		post(t, srv.URL, "ctf-trig", forbiddenRule, nil) // current is 01-trigger: no taint, no solve
	}
	resp := post(t, srv.URL, "ctf-trig", triggerRule, nil) // over the bucket
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if s.IsSolved("trig", "01-trigger") {
		t.Fatal("an over-bucket (skipped) trigger fire must not solve")
	}
	if got := s.DirtyRules("trig", rlEvadeChallenge); len(got) != 0 {
		t.Fatalf("nothing may be tainted while a trigger mission is current: %v", got)
	}
	if d := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("overflow_tainted")) - tainted; d != 0 {
		t.Fatalf("overflow_tainted delta = %v, want 0 (nothing was tainted)", d)
	}
}

func TestRateLimit_ObservationOverBucket_429AndCountedPerNamespace(t *testing.T) {
	srv, _ := newRateLimitFixture(t, evadeOnlyCatalog(), true)
	before := nsCount(t, rateLimitedFamily, "ctf-noisy")
	beforeTotal := nsTotal(t, rateLimitedFamily)
	var statuses []int
	for i := 0; i < tinyBurst+2; i++ {
		statuses = append(statuses, post(t, srv.URL, "ctf-noisy", observationRule, nil).StatusCode)
	}
	want := []int{200, 200, 200, 429, 429}
	if !slices.Equal(statuses, want) {
		t.Fatalf("statuses = %v, want %v", statuses, want)
	}
	if d := nsCount(t, rateLimitedFamily, "ctf-noisy") - before; d != 2 {
		t.Fatalf("rate_limited delta = %v, want 2", d)
	}
	if !nsExists(t, rateLimitedFamily, "ctf-noisy") {
		t.Fatal("the 429s were counted, but not under their own ns series")
	}
	if d := nsTotal(t, rateLimitedFamily) - beforeTotal; d != 2 {
		t.Fatalf("rate_limited family total delta = %v, want 2", d)
	}
	if resp := post(t, srv.URL, "ctf-quiet", observationRule, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("other participant's observation event: status %d, want 200", resp.StatusCode)
	}
}

func TestRateLimit_ScoringAndObservationBucketsAreIndependent(t *testing.T) {
	srv, s := newRateLimitFixture(t, evadeOnlyCatalog(), true)
	for i := 0; i < 3*tinyBurst; i++ { // drain the observation bucket
		post(t, srv.URL, "ctf-indep", observationRule, nil)
	}
	if resp := post(t, srv.URL, "ctf-indep", forbiddenRule, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := s.DirtyRules("indep", rlEvadeChallenge); !slices.Equal(got, []string{forbiddenRule}) {
		t.Fatalf("dirtyRules = %v, want [%q] only", got, forbiddenRule)
	}
}

// Cluster noise (other namespaces) used to burn the shared sender bucket. It
// must neither be limited nor consume anyone's bucket. Runs at the PRODUCTION
// limits and past the old per-IP burst (200), so it also catches a regression
// to the shared bucket.
func TestRateLimit_UnattributedEvents_AreNeverRateLimited(t *testing.T) {
	srv, _ := newRateLimitFixture(t, evadeOnlyCatalog(), false)
	for i := 0; i < 450; i++ {
		if resp := post(t, srv.URL, "kube-system", observationRule, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("non-ctf event %d: status %d, want 200 ignored", i, resp.StatusCode)
		}
	}
	if resp := post(t, srv.URL, "ctf-after-noise", forbiddenRule, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// M2: the ns is sender-supplied JSON that becomes a limiter key, a store key
// and a metric label. One that is not a username slug is "ignored" like any
// non-workspace event and reaches none of them.
func TestRateLimit_InvalidNamespace_IsIgnored(t *testing.T) {
	srv, s := newRateLimitFixture(t, evadeOnlyCatalog(), true)
	long := "ctf-" + strings.Repeat("a", 64)
	for _, ns := range []string{"ctf-", "ctf-Alice", "ctf-a_b", "ctf--x", "ctf-x-", "ctf-a b", "ctf-a/b", "ctf-" + strings.Repeat("a", 54), long} {
		resp := post(t, srv.URL, ns, forbiddenRule, nil)
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("ns %q: decode: %v", ns, err)
		}
		if resp.StatusCode != http.StatusOK || body["ignored"] != true {
			t.Fatalf("ns %q: status %d body %v, want 200 ignored", ns, resp.StatusCode, body)
		}
	}
	// Look under the seat part of each ns that was tried (what a gate-less
	// ingest would have used as the user), not under "" (app#479).
	for _, ns := range []string{"ctf-", "ctf-Alice", "ctf-a_b", "ctf--x", "ctf-a b", "ctf-a/b", long} {
		if got := s.DirtyRules(strings.TrimPrefix(ns, "ctf-"), rlEvadeChallenge); len(got) != 0 {
			t.Fatalf("ns %q reached the store: %v", ns, got)
		}
	}
}

func TestRateLimit_OverflowTaintPersistFailure_Returns500(t *testing.T) {
	srv, s := newRateLimitFixture(t, evadeOnlyCatalog(), true)
	for i := 0; i < tinyBurst; i++ {
		post(t, srv.URL, "ctf-broken", proofRule, nil)
	}
	if err := s.Close(); err != nil { // break persistence only
		t.Fatalf("close: %v", err)
	}
	if resp := post(t, srv.URL, "ctf-broken", forbiddenRule, nil); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 on overflow-taint persist failure", resp.StatusCode)
	}
}

// Merge-order pin (#334 x #359): the decode-free gates — browser/proxy identity
// header (403), non-JSON Content-Type (415), shared-secret mismatch in enforce
// mode (401) — return BEFORE the per-participant limiter. A rejected request
// must never spend the participant's bucket, so a flood of them cannot push the
// same ns's genuine event into overflow. Each rejected body is a valid scoring
// event for the pinned ns, so a gate that slipped behind the limiter would
// drain the tiny bucket and bump the overflow metrics.
func TestRateLimit_PreDecodeGatesReturnBeforeTheLimiter(t *testing.T) {
	const secret = "dev-not-a-secret"
	srv, s := newRateLimitFixtureMode(t, evadeOnlyCatalog(), true, secret, ingest.SecretModeEnforce)
	body, _ := json.Marshal(map[string]any{"rule": forbiddenRule, "priority": "Warning", "output_fields": map[string]any{
		"k8s.ns.name": "ctf-pin", "k8s.pod.name": "workspace", "container.image.repository": "falco-ctf/challenge"}})
	send := func(contentType string, hdr map[string]string) int {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/falco/events", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	over := nsCount(t, overflowFamily, "ctf-pin")
	overTotal := nsTotal(t, overflowFamily)
	ok := map[string]string{ingest.SharedSecretHeader: secret}
	for i := 0; i < 5*tinyBurst; i++ {
		if got := send("application/json", map[string]string{ingest.SharedSecretHeader: secret, "X-Auth-Request-Email": "u@ctf.local"}); got != http.StatusForbidden {
			t.Fatalf("proxy-identity header: status %d, want 403", got)
		}
		if got := send("text/plain", ok); got != http.StatusUnsupportedMediaType {
			t.Fatalf("text/plain: status %d, want 415", got)
		}
		if got := send("application/json", map[string]string{ingest.SharedSecretHeader: "wrong"}); got != http.StatusUnauthorized {
			t.Fatalf("secret mismatch: status %d, want 401", got)
		}
	}
	if got := send("application/json", ok); got != http.StatusOK {
		t.Fatalf("genuine event: status %d, want 200", got)
	}
	if d := nsCount(t, overflowFamily, "ctf-pin") - over; d != 0 {
		t.Fatalf("scoring_overflow delta = %v, want 0: a pre-decode gate spent the participant's bucket", d)
	}
	if d := nsTotal(t, overflowFamily) - overTotal; d != 0 {
		t.Fatalf("scoring_overflow family total delta = %v, want 0 (a count folded into _other would show here)", d)
	}
	if got := s.DirtyRules("pin", rlEvadeChallenge); !slices.Equal(got, []string{forbiddenRule}) {
		t.Fatalf("dirtyRules = %v, want exactly [%q]", got, forbiddenRule)
	}
}
