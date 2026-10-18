package ingest_test

// A reader for the two ns-labelled counters. They are metrics.NSCounter: the
// vec is unexported (app#463), so a test reads the exposed value the way
// Prometheus does, from the default gatherer.
//
// Do NOT push 1024 or more distinct ns values through the REAL counters from a
// test in this package: the cap is per process, so that would fold every later
// test's ns into "_other" (and make a "delta == 0" assert below blind). A test
// that needs the cap uses a fresh-registry NSCounter in package metrics.

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

// nsExists reports whether family has a series labelled exactly ns.
func nsExists(t *testing.T, family, ns string) bool {
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
					return true
				}
			}
		}
	}
	return false
}

// nsTotal is the sum of every series of family, `_other` included: a count that
// the process-wide cap folded into `_other` still moves it.
func nsTotal(t *testing.T, family string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, mf := range mfs {
		if mf.GetName() == family {
			for _, m := range mf.GetMetric() {
				sum += m.GetCounter().GetValue()
			}
		}
	}
	return sum
}

// Both families carry an ns="_other" series from process start (app#412): a
// reader that sums the family can tell "nothing counted" (0) from "no such
// metric". Existence only: other tests in this process may have counted into it.
func TestNSFamilies_HaveTheOtherSeriesFromStart(t *testing.T) {
	for _, family := range []string{rateLimitedFamily, overflowFamily} {
		if !nsExists(t, family, "_other") {
			t.Errorf("%s has no ns=\"_other\" series: it must exist from start", family)
		}
	}
}
