package ingest_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// fixture wires a real ingest.Handler behind a real store.Store and
// scoring.Grader — no fakes/mocks — so these tests exercise the actual HTTP
// status + metrics WIRING (app#124 5x review, R1 + R2 converged on this gap:
// internal/scoreboard/ingest had zero test files before this, so nothing
// caught the response-body error leak or the metric double/under-count this
// package fixes).
func newFixture(t *testing.T, clock func() time.Time) (*httptest.Server, *store.Store) {
	t.Helper()
	return newFixtureWithSecret(t, clock, "", ingest.SecretModeOff)
}

// newFixtureWithSecret is newFixture plus explicit ADR-WS-0006 shared-secret
// wiring, for tests that exercise warn/enforce mode.
func newFixtureWithSecret(t *testing.T, clock func() time.Time, secret string, mode ingest.SecretMode) (*httptest.Server, *store.Store) {
	t.Helper()

	// A single evade challenge, forbidding the same rule the test fires, so
	// it is trivially the participant's CURRENT mission (nothing else in the
	// catalog to be current instead) and markDirtyOnRuleFire's evade branch
	// is guaranteed to run.
	cat := catalog.Catalog{
		"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"Detect Outbound Connection"}},
	}

	s, err := store.Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	grader := scoring.New(cat, s, clock)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := ingest.New(grader, s, logger, clock, secret, mode)

	// ADR-0005 V2 / Requirement 6.1 (final review round): ingest no longer
	// carries its own Register(mux) method (LOW, 5x review — it was dead
	// code, called only from here in production terms; scoreboard.Handler's
	// NewHandler collects every sub-package's Routes() and calls
	// apispec.NewMux exactly once). This test now goes through the SAME
	// call every other package's test/production wiring uses, so a mutation
	// to apispec.NewMux itself is exercised here too, not bypassed by a
	// package-local shortcut.
	mux, _ := apispec.NewMux(h.Routes())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, s
}

func postFalcoEvent(t *testing.T, url, rule string) *http.Response {
	t.Helper()
	return postFalcoEventWithHeader(t, url, rule, "")
}

// postFalcoEventWithHeader is postFalcoEvent plus an optional
// X-Falco-Shared-Secret header value ("" = header omitted entirely, not
// "sent empty" — Header.Set is skipped so http.Header never carries the key).
func postFalcoEventWithHeader(t *testing.T, url, rule, sharedSecretHeader string) *http.Response {
	t.Helper()
	body := map[string]any{
		"rule":     rule,
		"priority": "Warning",
		"output_fields": map[string]any{
			"k8s.ns.name":                 "ctf-alice",
			"k8s.pod.name":                "workspace",
			"container.image.repository": "falco-ctf/challenge",
		},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url+"/falco/events", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sharedSecretHeader != "" {
		req.Header.Set(ingest.SharedSecretHeader, sharedSecretHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /falco/events: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestReceive_TaintPersistFailure_Returns500AndBumpsTaintErrorMetric is the
// wiring proof app#124 5x review finding #4 asked for: break ONLY the taint
// persistence write (by closing the store's DB before the request, exactly
// like store_test.go's TestMarkDirty_FailClosed_... does) and assert the
// HTTP layer surfaces it as a 500 with the taint_error outcome metric
// bumped — not logic (that is scoring_test.go's job), the ingest handler's
// OWN translation of a Grader outcome into a status code + metric label.
func TestReceive_TaintPersistFailure_Returns500AndBumpsTaintErrorMetric(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }
	srv, s := newFixture(t, clock)

	before := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("taint_error"))
	acceptedBefore := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted"))

	// Close the store's DB so the taint's persistence Exec fails, while
	// RecordRuleFire (in-memory only, see store.go) keeps succeeding — this
	// isolates the failure to exactly the taint write, mirroring
	// store_test.go's TestMarkDirty_FailClosed_InMemoryTaintSurvivesPersistenceFailure.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	resp := postFalcoEvent(t, srv.URL, "Detect Outbound Connection")

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}

	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	// app#124 5x review R1 finding: the response body must be a stable,
	// generic message, never the raw store/driver error text (the
	// err.Error()-leak pattern app#113 catalogued elsewhere).
	if errMsg, _ := got["error"].(string); errMsg != "could not persist taint" {
		t.Fatalf(`response body error = %q, want the stable "could not persist taint" message (not a raw driver error)`, errMsg)
	}

	if after := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("taint_error")); after != before+1 {
		t.Fatalf("taint_error metric = %v, want %v", after, before+1)
	}
	// app#124 5x review R4 finding F4: "accepted" must NOT also be bumped on
	// a taint_error request — the two outcomes are mutually exclusive for a
	// single request, or the label total silently exceeds the request count.
	if after := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted")); after != acceptedBefore {
		t.Fatalf(`"accepted" metric = %v, want unchanged at %v (taint_error and accepted must be mutually exclusive per request)`, after, acceptedBefore)
	}
}

// ADR-WS-0006 (webhook shared-secret, Layer 2 defense-in-depth): the tests
// below cover the 3 SecretMode states plus the ParseSecretMode boot-time
// validation the brief's acceptance criteria call out explicitly.

// TestReceive_SecretMode_Off_RegressionUnaffected pins that the off mode
// (the wire default, cmd/scoreboard/main.go) reproduces EXACTLY today's
// behaviour: no header sent, request still accepted and scored normally.
// This is the "off 既定で既存挙動が不変" acceptance criterion — it must keep
// passing with zero changes even as warn/enforce evolve.
func TestReceive_SecretMode_Off_RegressionUnaffected(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }
	srv, s := newFixtureWithSecret(t, clock, "", ingest.SecretModeOff)

	acceptedBefore := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted"))
	mismatchBefore := testutil.ToFloat64(metrics.FalcoEventsSecretMismatch.WithLabelValues("off"))

	// No X-Falco-Shared-Secret header at all — off mode must not care.
	resp := postFalcoEvent(t, srv.URL, "Detect Outbound Connection")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (off mode must not gate on the header)", resp.StatusCode)
	}

	now := clock().UnixNano()
	nowUnix := float64(now) / 1e9
	if fires := s.RecentRuleFires("alice", nowUnix, 3600); len(fires) != 1 {
		t.Fatalf("RecentRuleFires = %v, want exactly 1 (off mode must process the event as before)", fires)
	}

	if after := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted")); after != acceptedBefore+1 {
		t.Fatalf(`"accepted" metric = %v, want %v`, after, acceptedBefore+1)
	}
	// off mode never touches FalcoEventsSecretMismatch, under any label —
	// ParseSecretMode only ever produces warn/enforce as the mismatch
	// counter's label values, so an "off" label is always 0.
	if after := testutil.ToFloat64(metrics.FalcoEventsSecretMismatch.WithLabelValues("off")); after != mismatchBefore {
		t.Fatalf(`FalcoEventsSecretMismatch{mode="off"} = %v, want unchanged at %v`, after, mismatchBefore)
	}
}

// TestReceive_SecretMode_Enforce_Mismatch_Returns401AndStoreUntouched is the
// brief's headline negative test: enforce mode, wrong (and separately,
// entirely missing) header, must return 401 and never reach
// store.RecordRuleFire / scoring.Grader.OnRuleFire — proven here by reading
// the store back rather than trusting the status code alone.
func TestReceive_SecretMode_Enforce_Mismatch_Returns401AndStoreUntouched(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }
	nowUnix := float64(clock().UnixNano()) / 1e9

	cases := []struct {
		name   string
		header string // "" = header omitted
	}{
		{"wrong secret", "not-the-real-secret"},
		{"missing header", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, s := newFixtureWithSecret(t, clock, "correct-horse-battery-staple", ingest.SecretModeEnforce)

			acceptedBefore := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted"))
			mismatchBefore := testutil.ToFloat64(metrics.FalcoEventsSecretMismatch.WithLabelValues("enforce"))

			resp := postFalcoEventWithHeader(t, srv.URL, "Detect Outbound Connection", tc.header)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}

			var got map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if _, ok := got["error"]; !ok {
				t.Fatalf("response body = %v, want an \"error\" key (contract: non-2xx is always {\"error\": string})", got)
			}
			if _, ok := got["accepted"]; ok {
				t.Fatalf("response body = %v, want no \"accepted\" key on a rejected request", got)
			}

			// The load-bearing assertion: the request never reached
			// store.RecordRuleFire (no rule fire recorded) or
			// scoring.Grader.OnRuleFire (no dirty taint recorded) — a 401
			// alone would not prove the store was never touched.
			if fires := s.RecentRuleFires("alice", nowUnix, 3600); len(fires) != 0 {
				t.Fatalf("RecentRuleFires = %v, want empty (store must be untouched on a rejected request)", fires)
			}
			if dirty := s.DirtyRules("alice", "02-evade"); len(dirty) != 0 {
				t.Fatalf("DirtyRules = %v, want empty (grader must never run on a rejected request)", dirty)
			}

			if after := testutil.ToFloat64(metrics.FalcoEventsSecretMismatch.WithLabelValues("enforce")); after != mismatchBefore+1 {
				t.Fatalf("FalcoEventsSecretMismatch{mode=\"enforce\"} = %v, want %v", after, mismatchBefore+1)
			}
			// A rejected request contributes to NEITHER FalcoEventsReceived
			// outcome label — it never reaches that metric's call sites at
			// all (the ADR-WS-0006 handoff's "separate counter" requirement).
			if after := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted")); after != acceptedBefore {
				t.Fatalf(`"accepted" metric = %v, want unchanged at %v (a 401 must not also count as accepted)`, after, acceptedBefore)
			}
		})
	}
}

// TestReceive_SecretMode_Enforce_Match_ProcessesNormally proves enforce mode
// is not simply "always reject" — a correct header still gets through to
// scoring, unchanged from off mode's behaviour.
func TestReceive_SecretMode_Enforce_Match_ProcessesNormally(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }
	srv, s := newFixtureWithSecret(t, clock, "correct-horse-battery-staple", ingest.SecretModeEnforce)

	resp := postFalcoEventWithHeader(t, srv.URL, "Detect Outbound Connection", "correct-horse-battery-staple")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	nowUnix := float64(clock().UnixNano()) / 1e9
	if fires := s.RecentRuleFires("alice", nowUnix, 3600); len(fires) != 1 {
		t.Fatalf("RecentRuleFires = %v, want exactly 1 (a matching secret must still be processed)", fires)
	}
}

// TestReceive_SecretMode_Warn_Mismatch_ProcessesAndCounts covers warn mode's
// fail-open contract: a mismatch is counted on the dedicated metric but the
// request still flows through to scoring exactly as in off mode — this is
// what makes warn safe to run against genuine production traffic to measure
// mismatches before flipping to enforce (ADR-WS-0006 rollout step 4).
func TestReceive_SecretMode_Warn_Mismatch_ProcessesAndCounts(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }
	srv, s := newFixtureWithSecret(t, clock, "correct-horse-battery-staple", ingest.SecretModeWarn)

	acceptedBefore := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted"))
	mismatchBefore := testutil.ToFloat64(metrics.FalcoEventsSecretMismatch.WithLabelValues("warn"))

	resp := postFalcoEventWithHeader(t, srv.URL, "Detect Outbound Connection", "wrong-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (warn mode must not reject)", resp.StatusCode)
	}

	nowUnix := float64(clock().UnixNano()) / 1e9
	if fires := s.RecentRuleFires("alice", nowUnix, 3600); len(fires) != 1 {
		t.Fatalf("RecentRuleFires = %v, want exactly 1 (warn mode must still process the event)", fires)
	}
	if after := testutil.ToFloat64(metrics.FalcoEventsSecretMismatch.WithLabelValues("warn")); after != mismatchBefore+1 {
		t.Fatalf("FalcoEventsSecretMismatch{mode=\"warn\"} = %v, want %v", after, mismatchBefore+1)
	}
	// Unlike enforce, warn's mismatch ALSO bumps the normal outcome label —
	// the two metrics deliberately do not sum to the same total across modes.
	if after := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted")); after != acceptedBefore+1 {
		t.Fatalf(`"accepted" metric = %v, want %v (warn mode still counts the normal outcome)`, after, acceptedBefore+1)
	}
}

// TestParseSecretMode is the boot-time-fatal acceptance criterion's unit
// coverage: cmd/scoreboard/main.go calls this and os.Exit(1)s on a non-nil
// error, so the validation itself (which values are/aren't accepted) is
// tested here rather than by spawning a subprocess to observe os.Exit.
func TestParseSecretMode(t *testing.T) {
	cases := []struct {
		raw     string
		want    ingest.SecretMode
		wantErr bool
	}{
		{"off", ingest.SecretModeOff, false},
		{"warn", ingest.SecretModeWarn, false},
		{"enforce", ingest.SecretModeEnforce, false},
		{"", "", true},
		{"OFF", "", true}, // case-sensitive: no silent normalisation
		{"disabled", "", true},
		{"enforced", "", true}, // near-miss typo must still fail loud
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := ingest.ParseSecretMode(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSecretMode(%q) = %q, nil; want an error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSecretMode(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("ParseSecretMode(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
