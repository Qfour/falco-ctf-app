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
	h := ingest.New(grader, s, logger, clock)

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, s
}

func postFalcoEvent(t *testing.T, url, rule string) *http.Response {
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
	resp, err := http.Post(url+"/falco/events", "application/json", bytes.NewReader(buf))
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
