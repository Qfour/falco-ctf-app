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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
)

// nsRun makes the ns values of one test run unique in the process-wide
// DefaultRegisterer, so the test also passes under -count > 1.
var nsRun atomic.Int64

func newNSHandler() *Handler { return &Handler{nsSeen: make(map[string]struct{})} }

func nsN(i int) string { return fmt.Sprintf("ctf-user%d", i) }

func TestNSLabel_Cap(t *testing.T) {
	// The cases below are written for this cap; change maxNSLabels only together
	// with this test (and the contract row / docs that quote it).
	if maxNSLabels != 1024 {
		t.Fatalf("maxNSLabels = %d, want 1024: update this test with it", maxNSLabels)
	}
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
	for name, vals := range before {
		if !vals[metrics.OtherNS] {
			t.Fatalf("%s has no %q series before any event: it must exist from start (app#412)", name, metrics.OtherNS)
		}
	}
	run := nsRun.Add(1)
	h := newNSHandler()
	forged := []string{strings.Repeat("x", 4096), "ctf-" + strings.Repeat("y", 100)}
	for i := 0; i < 3*maxNSLabels; i++ {
		ns := fmt.Sprintf("ctf-f%d-%d", run, i)
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
		// OtherNS already existed, so exactly maxNSLabels new ns series appear: the
		// cap was reached and not passed (maxNSLabels + OtherNS in total).
		if added != maxNSLabels {
			t.Errorf("%s gained %d series, want exactly %d (the cap, with %q already present)", name, added, maxNSLabels, metrics.OtherNS)
		}
		for v := range vals {
			if len(v) > 63 {
				t.Errorf("%s has an over-long ns label of %d bytes", name, len(v))
			}
		}
	}
}

// guardedCounters are the two per-participant counters whose ns label must go
// through ingest's nsLabel (its cap). Anything but the declaration in package
// metrics and a direct WithLabelValues(h.nsLabel(...)) call in package ingest is
// a violation: a different method (With, GetMetricWith*, CurryWith,
// MustCurryWith), a raw argument, a use from another package, or the counter
// taken as a value (an alias would escape this check).
var guardedCounters = map[string]bool{"FalcoEventsRateLimited": true, "FalcoEventsScoringOverflow": true}

// counterViolations parses the given sources (file name -> source, non-test
// files only) and lists every use of a guarded counter that is not allowed. It
// also returns how many allowed increments it saw, so a caller can tell a scan
// that saw nothing from a clean one.
func counterViolations(srcs map[string]string) (violations []string, allowedUses int) {
	fset := token.NewFileSet()
	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, srcs[name], 0)
		if err != nil {
			return []string{name + ": " + err.Error()}, 0
		}
		allowed := map[*ast.Ident]bool{}
		// The declaration in package metrics.
		if f.Name.Name == "metrics" {
			ast.Inspect(f, func(n ast.Node) bool {
				if vs, ok := n.(*ast.ValueSpec); ok {
					for _, id := range vs.Names {
						if guardedCounters[id.Name] {
							allowed[id] = true
						}
					}
				}
				return true
			})
		}
		// <pkg>.<Counter>.WithLabelValues(h.nsLabel(...)) in package ingest.
		if f.Name.Name == "ingest" {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "WithLabelValues" {
					return true
				}
				recv, ok := sel.X.(*ast.SelectorExpr)
				if !ok || !guardedCounters[recv.Sel.Name] {
					return true
				}
				arg, ok := call.Args[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				if s, ok := arg.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "nsLabel" {
					allowed[recv.Sel] = true
					allowedUses++
				}
				return true
			})
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && guardedCounters[id.Name] && !allowed[id] {
				violations = append(violations, fmt.Sprintf("%s: %s is used other than as WithLabelValues(h.nsLabel(...)) in package ingest", fset.Position(id.Pos()), id.Name))
			}
			return true
		})
	}
	return violations, allowedUses
}

// Every use of the two counters in the program takes its ns label from
// h.nsLabel (so the cap above is the one that applies).
func TestNSLabel_EveryCounterUseGoesThroughIt(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	srcs := map[string]string{}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			srcs[path] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(srcs) < 20 {
		t.Fatalf("scanned only %d non-test files: the walk is not seeing the tree", len(srcs))
	}
	v, allowed := counterViolations(srcs)
	if len(v) > 0 {
		t.Fatalf("a guarded counter is used outside the nsLabel path:\n  %s", strings.Join(v, "\n  "))
	}
	if allowed != 2 {
		t.Fatalf("saw %d allowed increments, want 2 (rate_limited and scoring_overflow in ingest.go): the scan is not seeing them", allowed)
	}
}

// The check is not vacuous: each of these synthetic sources is a violation, and
// the two allowed shapes are not.
func TestNSLabel_CounterGuardCatchesViolations(t *testing.T) {
	ok := map[string]string{
		"metrics/m.go": "package metrics\nvar FalcoEventsRateLimited = 1\nvar FalcoEventsScoringOverflow = 2\n",
		"ingest/i.go": "package ingest\nfunc f(h *H){ metrics.FalcoEventsRateLimited.WithLabelValues(h.nsLabel(ns)).Inc()\n" +
			"metrics.FalcoEventsScoringOverflow.WithLabelValues(h.nsLabel(ns)).Inc() }\n",
	}
	if v, n := counterViolations(ok); len(v) != 0 || n != 2 {
		t.Fatalf("the allowed shapes were flagged or not counted: %v (%d)", v, n)
	}
	bad := map[string]string{
		"With via Labels, another package": "package other\nfunc f(){ metrics.FalcoEventsRateLimited.With(prometheus.Labels{\"ns\": ns}).Inc() }\n",
		"GetMetricWithLabelValues":         "package ingest\nfunc f(){ metrics.FalcoEventsRateLimited.GetMetricWithLabelValues(h.nsLabel(ns)) }\n",
		"CurryWith":                        "package ingest\nfunc f(){ metrics.FalcoEventsScoringOverflow.CurryWith(nil) }\n",
		"MustCurryWith":                    "package ingest\nfunc f(){ metrics.FalcoEventsScoringOverflow.MustCurryWith(nil) }\n",
		"alias":                            "package ingest\nfunc f(){ c := metrics.FalcoEventsScoringOverflow; c.WithLabelValues(h.nsLabel(ns)) }\n",
		"raw ns argument":                  "package ingest\nfunc f(){ metrics.FalcoEventsRateLimited.WithLabelValues(ns).Inc() }\n",
		"nsLabel but another package":      "package other\nfunc f(){ metrics.FalcoEventsRateLimited.WithLabelValues(h.nsLabel(ns)).Inc() }\n",
		"a use in package metrics":         "package metrics\nfunc g(){ FalcoEventsRateLimited.WithLabelValues(\"x\") }\n",
	}
	for name, src := range bad {
		if v, _ := counterViolations(map[string]string{"x.go": src}); len(v) == 0 {
			t.Errorf("%s: a violation was not flagged", name)
		}
	}
}
