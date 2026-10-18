package metrics

// The pre-generation is checked on a FRESH registry, right after registration,
// so what it sees cannot depend on which tests ran before in the process.

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNewNSCounterVecCreatesTheOtherSeriesAtZero(t *testing.T) {
	reg := prometheus.NewRegistry()
	newNSCounterVec(reg, prometheus.CounterOpts{Namespace: "t", Name: "x_total", Help: "h"})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(mfs) != 1 || mfs[0].GetName() != "t_x_total" {
		t.Fatalf("families = %v, want exactly t_x_total (the family must exist before any increment)", mfs)
	}
	ms := mfs[0].GetMetric()
	if len(ms) != 1 {
		t.Fatalf("series = %d, want 1", len(ms))
	}
	if ms[0].GetCounter().GetValue() != 0 {
		t.Fatalf("starts at %v, want 0", ms[0].GetCounter().GetValue())
	}
	lp := ms[0].GetLabel()
	if len(lp) != 1 || lp[0].GetName() != "ns" || lp[0].GetValue() != OtherNS {
		t.Fatalf("labels = %v, want ns=%q", lp, OtherNS)
	}
}
