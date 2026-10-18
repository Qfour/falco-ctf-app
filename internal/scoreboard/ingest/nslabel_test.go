package ingest

// The ns label of the two per-participant ingest counters is capped (app#448,
// app#412): at most maxNSLabels distinct values, then metrics.OtherNS, and a
// value longer than 63 bytes is never a label. This pins that cap, because the
// claim "a forged ns cannot grow the series set" rests on it.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
)

func newNSHandler() *Handler { return &Handler{nsSeen: make(map[string]struct{})} }

func nsN(i int) string { return fmt.Sprintf("ctf-user%d", i) }

func TestNSLabel_Cap(t *testing.T) {
	long63 := "ctf-" + strings.Repeat("a", 59) // 63 bytes: still a label
	long64 := "ctf-" + strings.Repeat("a", 60) // 64 bytes: never a label
	cases := []struct {
		name string
		run  func(t *testing.T, h *Handler)
	}{
		{"a new ns after maxNSLabels distinct ones is OtherNS", func(t *testing.T, h *Handler) {
			for i := 0; i < maxNSLabels; i++ {
				if got := h.nsLabel(nsN(i)); got != nsN(i) {
					t.Fatalf("ns #%d (within the cap) = %q, want itself", i, got)
				}
			}
			if got := h.nsLabel(nsN(maxNSLabels)); got != metrics.OtherNS {
				t.Fatalf("ns #%d (past the cap) = %q, want %q", maxNSLabels, got, metrics.OtherNS)
			}
			if got := h.nsLabel(nsN(maxNSLabels + 1)); got != metrics.OtherNS {
				t.Fatalf("ns #%d (past the cap) = %q, want %q", maxNSLabels+1, got, metrics.OtherNS)
			}
		}},
		{"an ns already used keeps its own label after the cap is reached", func(t *testing.T, h *Handler) {
			for i := 0; i < maxNSLabels; i++ {
				h.nsLabel(nsN(i))
			}
			h.nsLabel(nsN(maxNSLabels)) // folded
			for _, i := range []int{0, 1, maxNSLabels / 2, maxNSLabels - 1} {
				if got := h.nsLabel(nsN(i)); got != nsN(i) {
					t.Fatalf("seen ns #%d = %q after the cap, want itself", i, got)
				}
			}
			// A folded ns is not remembered: it does not take a slot later.
			if got := h.nsLabel(nsN(maxNSLabels)); got != metrics.OtherNS {
				t.Fatalf("a folded ns came back as %q, want %q", got, metrics.OtherNS)
			}
		}},
		{"a value over 63 bytes is OtherNS even when there is room", func(t *testing.T, h *Handler) {
			if got := h.nsLabel(long63); got != long63 {
				t.Fatalf("63-byte ns = %q, want itself (the limit is > 63)", got)
			}
			if got := h.nsLabel(long64); got != metrics.OtherNS {
				t.Fatalf("64-byte ns = %q, want %q", got, metrics.OtherNS)
			}
			if got := h.nsLabel(long64); got != metrics.OtherNS {
				t.Fatalf("64-byte ns again = %q, want %q (never remembered)", got, metrics.OtherNS)
			}
			if _, seen := h.nsSeen[long64]; seen {
				t.Fatal("an over-long ns was added to the seen set")
			}
		}},
		{"an over-long value does not use up a slot", func(t *testing.T, h *Handler) {
			for i := 0; i < 5000; i++ {
				h.nsLabel("ctf-" + strings.Repeat("b", 60) + fmt.Sprint(i))
			}
			for i := 0; i < maxNSLabels; i++ {
				if got := h.nsLabel(nsN(i)); got != nsN(i) {
					t.Fatalf("ns #%d = %q, want itself: over-long values used up the slots", i, got)
				}
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.run(t, newNSHandler()) })
	}
}

// seriesWithNS returns, per family name, the ns label values currently exposed.
func seriesWithNS(t *testing.T) map[string]map[string]bool {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]bool{}
	for _, mf := range mfs {
		n := mf.GetName()
		if !strings.HasSuffix(n, "falco_events_rate_limited_total") && !strings.HasSuffix(n, "falco_events_scoring_overflow_total") {
			continue
		}
		out[n] = map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "ns" {
					out[n][lp.GetValue()] = true
				}
			}
		}
	}
	return out
}

// Counting through the two real counters, with the same call the handler makes
// (WithLabelValues(h.nsLabel(ns))): however many distinct ns values arrive, the
// series this adds are at most maxNSLabels + 1 per counter.
func TestNSLabel_CountersGrowByAtMostTheCapPlusOne(t *testing.T) {
	before := seriesWithNS(t)
	h := newNSHandler()
	forged := []string{strings.Repeat("x", 4096), "ctf-" + strings.Repeat("y", 100)}
	for i := 0; i < 3*maxNSLabels; i++ {
		ns := fmt.Sprintf("ctf-forged%d", i)
		if i%7 == 0 {
			ns = forged[i%2] + fmt.Sprint(i)
		}
		metrics.FalcoEventsRateLimited.WithLabelValues(h.nsLabel(ns)).Inc()
		metrics.FalcoEventsScoringOverflow.WithLabelValues(h.nsLabel(ns)).Inc()
	}
	after := seriesWithNS(t)
	if len(after) != 2 {
		t.Fatalf("found %d of the 2 counters", len(after))
	}
	for name, vals := range after {
		added := 0
		for v := range vals {
			if !before[name][v] {
				added++
			}
		}
		if added > maxNSLabels+1 {
			t.Errorf("%s gained %d series, want at most %d", name, added, maxNSLabels+1)
		}
		if added < maxNSLabels {
			t.Errorf("%s gained only %d series: the test did not reach the cap", name, added)
		}
		for v := range vals {
			if len(v) > 63 {
				t.Errorf("%s has an over-long ns label of %d bytes", name, len(v))
			}
		}
		if !vals[metrics.OtherNS] {
			t.Errorf("%s has no %q series", name, metrics.OtherNS)
		}
	}
}

// Every increment of the two counters in ingest.go takes its ns label from
// h.nsLabel, never from the raw value (so the cap above is the one that applies).
func TestNSLabel_EveryCounterIncrementGoesThroughIt(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "ingest.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithLabelValues" {
			return true
		}
		recv, ok := sel.X.(*ast.SelectorExpr)
		if !ok || (recv.Sel.Name != "FalcoEventsRateLimited" && recv.Sel.Name != "FalcoEventsScoringOverflow") {
			return true
		}
		found++
		ok = false
		if len(call.Args) == 1 {
			if inner, isCall := call.Args[0].(*ast.CallExpr); isCall {
				if s, isSel := inner.Fun.(*ast.SelectorExpr); isSel && s.Sel.Name == "nsLabel" {
					ok = true
				}
			}
		}
		if !ok {
			t.Errorf("%s: %s.WithLabelValues must take h.nsLabel(...) as its only argument", fset.Position(call.Pos()), recv.Sel.Name)
		}
		return true
	})
	if found < 2 {
		t.Fatalf("found %d increments of the two counters in ingest.go; the scan is not seeing them", found)
	}
}
