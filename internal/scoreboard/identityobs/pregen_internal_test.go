package identityobs

// ADR-0038 V3 / V8: the pre-generation is checked on a FRESH registry, right
// after registration, so what it sees cannot depend on which tests ran before
// in the process. (The default registry's own state is checked in
// internal/scoreboard/identity_denials_test.go.)

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// seriesOn is the (gate, reason) set reg holds for the metric.
func seriesOn(t *testing.T, reg *prometheus.Registry) map[Pair]bool {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[Pair]bool{}
	for _, mf := range mfs {
		if mf.GetName() != "scoreboard_identity_denials_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var p Pair
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "gate":
					p.Gate = Gate(lp.GetValue())
				case "reason":
					p.Reason = Reason(lp.GetValue())
				}
			}
			if m.GetCounter().GetValue() != 0 {
				t.Errorf("series %v starts at %v, want 0", p, m.GetCounter().GetValue())
			}
			out[p] = true
		}
	}
	return out
}

func sameSet(got map[Pair]bool, want []Pair) bool {
	if len(got) != len(want) {
		return false
	}
	for _, p := range want {
		if !got[p] {
			return false
		}
	}
	return true
}

func TestNewDenialsVecPregeneratesTheDeclaredEight(t *testing.T) {
	reg := prometheus.NewRegistry()
	newDenialsVec(reg)
	got := seriesOn(t, reg)
	if len(declared) != 8 || !sameSet(got, declared) {
		t.Fatalf("series on a fresh registry = %v, want exactly the 8 declared %v", got, declared)
	}
	for _, g := range []Gate{GateStrict, GateSelfOrAdmin, GateAuthenticated, GatePortal} {
		if !got[Pair{g, ReasonNoIdentity}] {
			t.Errorf("gate %q has no no_identity series", g)
		}
	}
}

// The check is not vacuous: the same metric registered without the loop that
// creates the children exposes nothing, and seriesOn / sameSet say so.
func TestPregenerationCheckCatchesAMissingLoop(t *testing.T) {
	reg := prometheus.NewRegistry()
	promauto.With(reg).NewCounterVec(denialsOpts(), []string{"gate", "reason"}) // no WithLabelValues
	if got := seriesOn(t, reg); sameSet(got, declared) {
		t.Fatalf("a metric with no pre-created children passed the check: %v", got)
	}
	// One pair short is flagged too.
	reg = prometheus.NewRegistry()
	v := promauto.With(reg).NewCounterVec(denialsOpts(), []string{"gate", "reason"})
	for _, p := range declared[1:] {
		v.WithLabelValues(string(p.Gate), string(p.Reason))
	}
	if got := seriesOn(t, reg); sameSet(got, declared) {
		t.Fatalf("7 of 8 series passed the check: %v", got)
	}
}
