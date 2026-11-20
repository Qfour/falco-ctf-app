package metrics

// ADR-0056 A4f / V105: scoreboard_edition_loaded_info has exactly one series, at 1,
// after any number of sets. Checked on a FRESH registry, so what it sees does not
// depend on which tests ran before in the process (the default registry's series is
// internal/contractmetrics' and cmd/scoreboard's to check).

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	edRunA = "0123456789abcdef0123456789abcdef"
	edRunB = "fedcba9876543210fedcba9876543210"
)

// editionSeriesProblems is how the registry departs from "the family
// scoreboard_edition_loaded_info is a gauge with exactly one series, run_id=want, at 1".
func editionSeriesProblems(t *testing.T, g prometheus.Gatherer, want string) []string {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "scoreboard_edition_loaded_info" {
			continue
		}
		var out []string
		if mf.GetType().String() != "GAUGE" {
			out = append(out, "the family is a "+mf.GetType().String()+", want a GAUGE")
		}
		ms := mf.GetMetric()
		if len(ms) != 1 {
			return append(out, fmt.Sprintf("%d series, want exactly 1", len(ms)))
		}
		lp := ms[0].GetLabel()
		if len(lp) != 1 || lp[0].GetName() != "run_id" || lp[0].GetValue() != want {
			out = append(out, fmt.Sprintf("labels %v, want exactly run_id=%q", lp, want))
		}
		if v := ms[0].GetGauge().GetValue(); v != 1 {
			out = append(out, fmt.Sprintf("value %v, want 1", v))
		}
		return out
	}
	return []string{"the family is not exposed"}
}

func TestEditionLoaded_NoSeriesBeforeTheFirstSet(t *testing.T) {
	reg := prometheus.NewRegistry()
	newEditionLoadedGauge(reg)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(mfs) != 0 {
		t.Fatalf("families before any set = %v, want none (ADR-0040's info kind (3): absent before the assembly)", mfs)
	}
}

func TestEditionLoaded_ExactlyOneSeriesAfterEverySet(t *testing.T) {
	reg := prometheus.NewRegistry()
	g := newEditionLoadedGauge(reg)
	for i, run := range []string{edRunA, EditionNone, edRunB, edRunB} {
		g.set(run)
		if p := editionSeriesProblems(t, reg, run); len(p) != 0 {
			t.Fatalf("after set #%d (%q): %v", i+1, run, p)
		}
	}
}

// The check above is not vacuous: what a set without the Reset would leave (two
// series), a series at 0, another label value and a family that is absent are each
// flagged.
func TestEditionLoaded_TheCheckCatchesDrift(t *testing.T) {
	vec := func(reg *prometheus.Registry) *prometheus.GaugeVec {
		v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "scoreboard_edition_loaded_info", Help: "synthetic"}, []string{"run_id"})
		reg.MustRegister(v)
		return v
	}
	t.Run("a second set without the Reset (two series)", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		v := vec(reg)
		v.WithLabelValues(edRunA).Set(1)
		v.WithLabelValues(edRunB).Set(1)
		if p := editionSeriesProblems(t, reg, edRunB); len(p) == 0 {
			t.Fatal("two series were not flagged")
		}
	})
	t.Run("the series at 0", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		vec(reg).WithLabelValues(edRunA).Set(0)
		if p := editionSeriesProblems(t, reg, edRunA); len(p) == 0 {
			t.Fatal("a series at 0 was not flagged")
		}
	})
	t.Run("another run id", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		vec(reg).WithLabelValues(edRunA).Set(1)
		if p := editionSeriesProblems(t, reg, edRunB); len(p) == 0 {
			t.Fatal("another run id was not flagged")
		}
	})
	t.Run("the family absent", func(t *testing.T) {
		if p := editionSeriesProblems(t, prometheus.NewRegistry(), edRunA); len(p) == 0 {
			t.Fatal("an absent family was not flagged")
		}
	})
}
