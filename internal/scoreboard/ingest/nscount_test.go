package ingest_test

// A reader for the two ns-labelled counters. They are metrics.NSCounter: the
// vec is unexported (app#463), so a test reads the exposed value the way
// Prometheus does, from the default gatherer.

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	rateLimitedFamily = "scoreboard_ingest_falco_events_rate_limited_total"
	overflowFamily    = "scoreboard_ingest_falco_events_scoring_overflow_total"
)

// nsCount is the value of family{ns="<ns>"}, 0 when that series does not exist.
func nsCount(t *testing.T, family, ns string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != family {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "ns" && lp.GetValue() == ns {
					return m.GetCounter().GetValue()
				}
			}
		}
		return 0
	}
	t.Fatalf("family %s is not exposed", family)
	return 0
}
