package metrics

// The ns label of the two per-participant ingest counters is capped inside the
// type that owns the counter (app#463; it was ingest.Handler's nsLabel before,
// which held only while there was one Handler per process): at most maxNSLabels
// distinct values, then OtherNS, and a value longer than 63 bytes is never a
// label. The claim "a forged ns cannot grow the series set" rests on this file.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func nsOpts() prometheus.CounterOpts {
	return prometheus.CounterOpts{Namespace: "t", Name: "x_total", Help: "h"}
}

// series returns ns label value -> counter value for the one family on reg.
func series(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(mfs) != 1 {
		t.Fatalf("families = %d, want 1", len(mfs))
	}
	out := map[string]float64{}
	for _, m := range mfs[0].GetMetric() {
		lps := m.GetLabel()
		if len(lps) != 1 || lps[0].GetName() != "ns" {
			t.Fatalf("labels = %v, want only ns", lps)
		}
		out[lps[0].GetValue()] = m.GetCounter().GetValue()
	}
	return out
}

func nsN(i int) string { return fmt.Sprintf("ctf-user%d", i) }

func TestNSCounter_Cap(t *testing.T) {
	// The cases are written for this cap; change maxNSLabels only together with
	// this test (and the contract row / docs that quote it).
	if maxNSLabels != 1024 {
		t.Fatalf("maxNSLabels = %d, want 1024: update this test with it", maxNSLabels)
	}
	long63 := "ctf-" + strings.Repeat("a", 59) // 63 bytes: still a label
	long64 := "ctf-" + strings.Repeat("a", 60) // 64 bytes: never a label
	cases := []struct {
		name string
		run  func(t *testing.T, c *NSCounter, reg *prometheus.Registry)
	}{
		{"a new ns after maxNSLabels distinct ones is counted under OtherNS", func(t *testing.T, c *NSCounter, reg *prometheus.Registry) {
			for i := 0; i < maxNSLabels; i++ {
				c.Inc(nsN(i))
			}
			c.Inc(nsN(maxNSLabels))
			c.Inc(nsN(maxNSLabels + 1))
			got := series(t, reg)
			if len(got) != maxNSLabels+1 {
				t.Fatalf("series = %d, want %d (the cap and OtherNS)", len(got), maxNSLabels+1)
			}
			if got[OtherNS] != 2 {
				t.Fatalf("OtherNS = %v, want 2 (the two past the cap)", got[OtherNS])
			}
			if _, ok := got[nsN(maxNSLabels)]; ok {
				t.Fatal("an ns past the cap got its own series")
			}
		}},
		{"an ns already used keeps its own series after the cap is reached", func(t *testing.T, c *NSCounter, reg *prometheus.Registry) {
			for i := 0; i < maxNSLabels; i++ {
				c.Inc(nsN(i))
			}
			c.Inc(nsN(maxNSLabels)) // folded
			for _, i := range []int{0, 1, maxNSLabels / 2, maxNSLabels - 1} {
				c.Inc(nsN(i))
			}
			got := series(t, reg)
			for _, i := range []int{0, 1, maxNSLabels / 2, maxNSLabels - 1} {
				if got[nsN(i)] != 2 {
					t.Fatalf("seen ns #%d = %v after the cap, want 2", i, got[nsN(i)])
				}
			}
			// A folded ns is not remembered: it does not take a slot later.
			c.Inc(nsN(maxNSLabels))
			if got := series(t, reg); got[OtherNS] != 2 || len(got) != maxNSLabels+1 {
				t.Fatalf("a folded ns changed the series set: other=%v series=%d", got[OtherNS], len(got))
			}
		}},
		{"a value over 63 bytes is OtherNS even when there is room, and never remembered", func(t *testing.T, c *NSCounter, reg *prometheus.Registry) {
			c.Inc(long63)
			c.Inc(long64)
			c.Inc(long64)
			got := series(t, reg)
			if got[long63] != 1 || got[OtherNS] != 2 || len(got) != 2 {
				t.Fatalf("series = %v, want the 63-byte ns once and OtherNS twice", got)
			}
			if _, seen := c.seen[long64]; seen {
				t.Fatal("an over-long ns was added to the seen set")
			}
		}},
		{"the reserved OtherNS value takes no slot", func(t *testing.T, c *NSCounter, reg *prometheus.Registry) {
			for i := 0; i < 5; i++ {
				c.Inc(OtherNS)
			}
			if len(c.seen) != 0 {
				t.Fatalf("seen = %d entries, want 0: %q must not take a slot", len(c.seen), OtherNS)
			}
			if got := series(t, reg); len(got) != 1 || got[OtherNS] != 5 {
				t.Fatalf("series = %v, want only OtherNS = 5", got)
			}
		}},
		{"over-long values do not use up slots", func(t *testing.T, c *NSCounter, reg *prometheus.Registry) {
			for i := 0; i < 5000; i++ {
				c.Inc("ctf-" + strings.Repeat("b", 60) + fmt.Sprint(i))
			}
			for i := 0; i < maxNSLabels; i++ {
				c.Inc(nsN(i))
			}
			if got := series(t, reg); len(got) != maxNSLabels+1 {
				t.Fatalf("series = %d, want %d: over-long values used up the slots", len(got), maxNSLabels+1)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			tc.run(t, newNSCounter(reg, nsOpts()), reg)
		})
	}
}

// 3 x maxNSLabels distinct ns arrive from many goroutines at once: the cap
// holds under concurrency (exactly maxNSLabels labels plus OtherNS, the seen
// set has exactly maxNSLabels entries) and no increment is lost.
func TestNSCounter_CapHoldsUnderConcurrency(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := newNSCounter(reg, nsOpts())
	const goroutines = 32
	total := 3 * maxNSLabels
	per := total / goroutines
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				c.Inc(fmt.Sprintf("ctf-g%d-%d", g, i)) // every ns distinct across all goroutines
			}
		}(g)
	}
	wg.Wait()
	got := series(t, reg)
	if len(got) != maxNSLabels+1 {
		t.Fatalf("series = %d, want %d", len(got), maxNSLabels+1)
	}
	if len(c.seen) != maxNSLabels {
		t.Fatalf("len(seen) = %d, want %d", len(c.seen), maxNSLabels)
	}
	var sum float64
	for _, v := range got {
		sum += v
	}
	if int(sum) != per*goroutines {
		t.Fatalf("counted %v increments, want %d: increments were lost", sum, per*goroutines)
	}
	var labels int
	for ns := range got {
		if ns != OtherNS {
			labels++
		}
	}
	if labels != maxNSLabels {
		t.Fatalf("non-%s labels = %d, want exactly %d", OtherNS, labels, maxNSLabels)
	}
}

// The two real counters are NSCounters, and each applies its own cap.
func TestNSCounter_TheRealCountersAreCapped(t *testing.T) {
	var _ *NSCounter = FalcoEventsRateLimited
	var _ *NSCounter = FalcoEventsScoringOverflow
	if FalcoEventsRateLimited.max != maxNSLabels || FalcoEventsScoringOverflow.max != maxNSLabels {
		t.Fatalf("caps = %d / %d, want %d", FalcoEventsRateLimited.max, FalcoEventsScoringOverflow.max, maxNSLabels)
	}
	if FalcoEventsRateLimited == FalcoEventsScoringOverflow {
		t.Fatal("the two counters share one NSCounter")
	}
}

// nsCounterViolations is the structural guard over package metrics' sources
// (file name -> source, non-test files only): the compiler already stops
// another package from reaching the unexported vec, so this keeps the package
// itself from growing a way around the type.
//
//   - NSCounter has no exported field, embeds nothing, and has no exported
//     method other than Inc;
//   - the fields vec, seen and max are touched only by NSCounter.Inc (vec) and
//     NSCounter.label (seen, max); every other function, including a
//     package-level one, may not select them (the constructor builds the
//     struct with a composite literal, which selects nothing);
//   - the only function that may call newNSCounterVec is newNSCounterMax (an
//     exact name, not a prefix, so a new newNSCounterXxx is not trusted);
//   - no function other than newNSCounterVec returns a *prometheus.CounterVec;
//   - the string "ns" (the label name) appears nowhere outside newNSCounterVec,
//     so no other counter is labelled by ns without being an NSCounter.
//
// declared is how many package-level vars were declared with newNSCounter, so a
// caller can tell a scan that saw nothing from a clean one.
func nsCounterViolations(srcs map[string]string) (violations []string, declared int) {
	fset := token.NewFileSet()
	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}
	sort.Strings(names)
	// which functions may select which NSCounter field
	fieldOwners := map[string]map[string]bool{
		"vec":  {"NSCounter.Inc": true},
		"seen": {"NSCounter.label": true},
		"max":  {"NSCounter.label": true},
	}
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, srcs[name], 0)
		if err != nil {
			return []string{name + ": " + err.Error()}, 0
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					switch sp := sp.(type) {
					case *ast.TypeSpec:
						if sp.Name.Name == "NSCounter" {
							if st, ok := sp.Type.(*ast.StructType); ok {
								for _, fl := range st.Fields.List {
									for _, id := range fl.Names {
										if id.IsExported() {
											violations = append(violations, fmt.Sprintf("%s: NSCounter has the exported field %s", fset.Position(id.Pos()), id.Name))
										}
									}
									if len(fl.Names) == 0 {
										violations = append(violations, fmt.Sprintf("%s: NSCounter embeds a type (its exported methods would be promoted)", fset.Position(fl.Pos())))
									}
								}
							}
						}
					case *ast.ValueSpec:
						for _, v := range sp.Values {
							if call, ok := v.(*ast.CallExpr); ok {
								if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "newNSCounter" {
									declared++
								}
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil && len(d.Recv.List) == 1 && d.Name.IsExported() {
					if recvTypeName(d.Recv.List[0].Type) == "NSCounter" && d.Name.Name != "Inc" {
						violations = append(violations, fmt.Sprintf("%s: NSCounter has the exported method %s (Inc is the only way to count)", fset.Position(d.Pos()), d.Name.Name))
					}
				}
				if d.Type.Results != nil && d.Name.Name != "newNSCounterVec" {
					for _, r := range d.Type.Results.List {
						if mentionsCounterVec(r.Type) {
							violations = append(violations, fmt.Sprintf("%s: %s returns a CounterVec (only newNSCounterVec may; the raw vec must not leave the package's constructors)", fset.Position(r.Pos()), d.Name.Name))
						}
					}
				}
			}
		}
		// Selections of the guarded fields, calls to newNSCounterVec and the label
		// name "ns", each by enclosing function.
		for _, d := range f.Decls {
			owner := ""
			if fd, isFunc := d.(*ast.FuncDecl); isFunc {
				owner = fd.Name.Name
				if fd.Recv != nil && len(fd.Recv.List) == 1 {
					if rt := recvTypeName(fd.Recv.List[0].Type); rt != "" {
						owner = rt + "." + fd.Name.Name
					}
				}
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					if owners, guarded := fieldOwners[n.Sel.Name]; guarded && !owners[owner] {
						violations = append(violations, fmt.Sprintf("%s: .%s selected in %q (only %s may touch it: the vec and its cap state are reached through Inc)", fset.Position(n.Pos()), n.Sel.Name, owner, strings.Join(ownerList(owners), ", ")))
					}
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "newNSCounterVec" && owner != "newNSCounterMax" {
						violations = append(violations, fmt.Sprintf("%s: newNSCounterVec called in %q; only newNSCounterMax may (it returns the raw vec)", fset.Position(n.Pos()), owner))
					}
				case *ast.BasicLit:
					if n.Kind == token.STRING && n.Value == `"ns"` && owner != "newNSCounterVec" {
						violations = append(violations, fmt.Sprintf("%s: the label name \"ns\" outside newNSCounterVec: a counter labelled by ns must be an NSCounter", fset.Position(n.Pos())))
					}
				}
				return true
			})
		}
	}
	return violations, declared
}

func ownerList(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// mentionsCounterVec reports whether a type expression names CounterVec
// (prometheus.CounterVec, *prometheus.CounterVec, a bare CounterVec).
func mentionsCounterVec(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			if n.Name == "CounterVec" {
				found = true
			}
		case *ast.SelectorExpr:
			if n.Sel.Name == "CounterVec" {
				found = true
			}
		}
		return true
	})
	return found
}

func recvTypeName(e ast.Expr) string {
	if s, ok := e.(*ast.StarExpr); ok {
		e = s.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func TestNSCounter_PackageHasNoWayAroundTheType(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string]string{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", n))
		if err != nil {
			t.Fatal(err)
		}
		srcs[n] = string(b)
	}
	if len(srcs) == 0 {
		t.Fatal("no source file read: the scan is not seeing the package")
	}
	v, declared := nsCounterViolations(srcs)
	if len(v) > 0 {
		t.Fatalf("package metrics has a way around NSCounter:\n  %s", strings.Join(v, "\n  "))
	}
	if declared != 2 {
		t.Fatalf("saw %d vars declared with newNSCounter, want 2 (rate_limited and scoring_overflow): the scan is not seeing them", declared)
	}
}

// The guard is not vacuous: each synthetic source is a violation, the allowed
// shape is not.
func TestNSCounter_GuardCatchesViolations(t *testing.T) {
	ok := map[string]string{"m.go": `package metrics
type NSCounter struct{ vec int; seen int; max int }
func (c *NSCounter) Inc(ns string) { use(c.vec) }
func (c *NSCounter) label(ns string) string { use(c.seen, c.max); return ns }
func newNSCounterVec() int { return f("ns") }
func newNSCounterMax() *NSCounter { newNSCounterVec(); return &NSCounter{vec: 1, max: 2} }
func newNSCounter() *NSCounter { return newNSCounterMax() }
var A = newNSCounter()
var B = newNSCounter()
`}
	if v, n := nsCounterViolations(ok); len(v) != 0 || n != 2 {
		t.Fatalf("the allowed shape was flagged or not counted: %v (%d)", v, n)
	}
	const head = "package metrics\ntype NSCounter struct{ vec int; seen int; max int }\n"
	bad := map[string]string{
		"an exported field":                               "package metrics\ntype NSCounter struct{ Vec int }\n",
		"an embedded type":                                "package metrics\ntype NSCounter struct{ *X }\n",
		"an exported accessor to the vec":                 head + "func (c *NSCounter) Vec() int { return c.vec }\n",
		"an exported WithLabelValues":                     head + "func (c NSCounter) WithLabelValues(s string) {}\n",
		"the raw vec exported":                            "package metrics\nvar C = newNSCounterVec()\n",
		"the raw vec from another function":               "package metrics\nfunc Make() int { return newNSCounterVec() }\n",
		"another counter labelled ns":                     "package metrics\nvar C = promauto.NewCounterVec(o, []string{\"ns\"})\n",
		".vec from a package-level function":              head + "func peek(c *NSCounter) int { return c.vec }\n",
		".vec.WithLabelValues called directly":            head + "func (c *NSCounter) Direct(ns string) { c.vec.WithLabelValues(ns) }\n",
		".seen read by another method":                    head + "func (c *NSCounter) size() int { return c.seen }\n",
		".max read by Inc":                                head + "func (c *NSCounter) Inc(ns string) { use(c.vec, c.max) }\n",
		"a raw vec returned by a newNSCounterXxx":         "package metrics\nfunc newNSCounterRaw(reg R) *prometheus.CounterVec { return newNSCounterVec(reg) }\n",
		"newNSCounterVec called by a prefix-named helper": "package metrics\nfunc newNSCounterHelper() { newNSCounterVec() }\n",
	}
	for name, src := range bad {
		if v, _ := nsCounterViolations(map[string]string{"x.go": src}); len(v) == 0 {
			t.Errorf("%s: a violation was not flagged", name)
		}
	}
}

// newNSCounterMax with a small cap: the boundary is exact (cap-1, cap, cap+1,
// and cap 0 where nothing gets its own series).
func TestNSCounter_SmallCapBoundary(t *testing.T) {
	for _, limit := range []int{0, 1, 4} {
		for _, distinct := range []int{limit - 1, limit, limit + 1, limit + 3} {
			if distinct < 0 {
				continue
			}
			t.Run(fmt.Sprintf("cap %d with %d distinct ns", limit, distinct), func(t *testing.T) {
				reg := prometheus.NewRegistry()
				c := newNSCounterMax(reg, nsOpts(), limit)
				for i := 0; i < distinct; i++ {
					c.Inc(nsN(i))
				}
				got := series(t, reg)
				own := distinct
				if own > limit {
					own = limit
				}
				if len(got) != own+1 { // the own series and OtherNS
					t.Fatalf("series = %d, want %d (%d own + OtherNS)", len(got), own+1, own)
				}
				if want := float64(distinct - own); got[OtherNS] != want {
					t.Fatalf("OtherNS = %v, want %v (the ns past the cap)", got[OtherNS], want)
				}
				if len(c.seen) != own {
					t.Fatalf("len(seen) = %d, want %d", len(c.seen), own)
				}
			})
		}
	}
}
