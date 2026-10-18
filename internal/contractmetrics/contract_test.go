package contractmetrics_test

// ADR-0040 D4: the cross-repo contract table (conventions, "Cross-repo 契約") names
// metric families as `family{labels}`; each one must exist from the start of the
// binary that owns it, with every declared child at 0. This ONE test replaces the two
// per-row tests (identityobs and scoreboard/metrics contract_test.go):
//
//  1. the `family{labels}` code spans of the table are extracted (none = red);
//  2. they are compared both ways with `owned` below, the owning table (a family in the
//     table but not in `owned`, or the reverse, or a different label set, is red);
//  3. before the owner is assembled, a family whose placement is "assembly" has no
//     child (it is created by the owner's wiring, not by a package init that a binary
//     which never counts it would also run);
//  4. the owner is assembled as production does, up to the first request
//     (scoreboard.NewHandler), and the default registry is gathered: each family is
//     there, with exactly the labels of the span and exactly the declared children, all
//     at 0.
//
// The file is in the Docker test context only because .dockerignore re-includes the
// conventions file (`.claude` is otherwise excluded): a missing file FAILS, never skips.

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

const conventionsPath = ".claude/rules/falco-ctf-app-conventions.md"

const (
	placeInit     = "init"     // created by the package's initialisation (one binary links it)
	placeAssembly = "assembly" // created when the owner wires the part that counts (several binaries link the package)
)

// owned is the table of the contract families: label names, the owning binary, where
// the children are created, and the children (label values, in the order of labels)
// that must exist at start. The label VALUES of a child are not the table's contract
// except where listed here (ADR-0040 D5 (c): `caller` and `gate` are for display).
type owned struct {
	name      string
	labels    []string // sorted
	binary    string
	placement string
	children  [][]string // label values, in the order of labels; all at 0 at start
	// rowTokens are values the family's row of the contract table must name as code
	// spans because platform reads them (the identity reasons).
	rowTokens []string
}

func ownedTable() []owned {
	var identity [][]string
	for _, p := range identityobs.Declared() {
		identity = append(identity, []string{string(p.Gate), string(p.Reason)})
	}
	var clientIP [][]string
	for _, caller := range []string{"submit", "csp_report"} {
		for _, src := range []string{"cf_connecting_ip", "x_forwarded_for", "remote_addr"} {
			clientIP = append(clientIP, []string{caller, src})
		}
	}
	return []owned{
		{"scoreboard_identity_denials_total", []string{"gate", "reason"}, "scoreboard", placeInit, identity, []string{"no_identity", "non_canonical", "mismatch"}},
		{"scoreboard_ingest_falco_events_scoring_overflow_total", []string{"ns"}, "scoreboard", placeInit, [][]string{{metrics.OtherNS}}, nil},
		{"scoreboard_ingest_falco_events_rate_limited_total", []string{"ns"}, "scoreboard", placeInit, [][]string{{metrics.OtherNS}}, nil},
		{"ratelimit_client_ip_source_total", []string{"caller", "source"}, "scoreboard", placeAssembly, clientIP, []string{"cf_connecting_ip", "x_forwarded_for", "remote_addr"}},
	}
}

// --- the contract table ----------------------------------------------------

// span is one `family{labels}` code span of the contract table.
type span struct {
	name   string
	labels []string // sorted
}

var spanRe = regexp.MustCompile("`([a-z][a-z0-9_]*)\\{([a-z_, ]*)\\}`")

// contractSpans returns the `family{labels}` code spans of the table rows under the
// "Cross-repo 契約" heading of doc, de-duplicated.
func contractSpans(doc string) []span {
	_, after, ok := strings.Cut(doc, "\n## Cross-repo 契約")
	if !ok {
		return nil
	}
	section, _, _ := strings.Cut(after, "\n## ")
	seen := map[string]bool{}
	var out []span
	for _, ln := range strings.Split(section, "\n") {
		if !strings.HasPrefix(ln, "|") {
			continue
		}
		for _, m := range spanRe.FindAllStringSubmatch(ln, -1) {
			var labels []string
			for _, l := range strings.Split(m[2], ",") {
				if l = strings.TrimSpace(l); l != "" {
					labels = append(labels, l)
				}
			}
			sort.Strings(labels)
			key := m[1] + "{" + strings.Join(labels, ",") + "}"
			if !seen[key] {
				seen[key] = true
				out = append(out, span{m[1], labels})
			}
		}
	}
	return out
}

// rowOf returns the table row of doc that names the family (the first row holding
// `name{`), or "".
func rowOf(doc, name string) string {
	_, after, ok := strings.Cut(doc, "\n## Cross-repo 契約")
	if !ok {
		return ""
	}
	section, _, _ := strings.Cut(after, "\n## ")
	for _, ln := range strings.Split(section, "\n") {
		if strings.HasPrefix(ln, "|") && strings.Contains(ln, "`"+name+"{") {
			return ln
		}
	}
	return ""
}

// rowTokenProblems: each value the owning table says platform reads must be a code
// span of the family's row.
func rowTokenProblems(doc string, table []owned) []string {
	var out []string
	for _, o := range table {
		row := rowOf(doc, o.name)
		for _, tok := range o.rowTokens {
			if row == "" || !strings.Contains(row, "`"+tok+"`") {
				out = append(out, fmt.Sprintf("%s: the row of the contract table does not name `%s` as a code span", o.name, tok))
			}
		}
	}
	return out
}

// tableProblems is how the spans and the owning table disagree, both ways.
func tableProblems(spans []span, table []owned) []string {
	if len(spans) == 0 {
		return []string{"the contract table has no `family{labels}` code span: the extraction found nothing (renamed heading, or the spans lost their {labels})"}
	}
	var out []string
	inDoc := map[string]span{}
	for _, s := range spans {
		inDoc[s.name] = s
	}
	byName := map[string]owned{}
	for _, o := range table {
		byName[o.name] = o
	}
	for _, s := range spans {
		o, ok := byName[s.name]
		if !ok {
			out = append(out, fmt.Sprintf("the contract table names %s{%s}, which the owning table has no row for", s.name, strings.Join(s.labels, ", ")))
			continue
		}
		if strings.Join(o.labels, ",") != strings.Join(s.labels, ",") {
			out = append(out, fmt.Sprintf("%s: the contract table says labels {%s}, the owning table says {%s}", s.name, strings.Join(s.labels, ", "), strings.Join(o.labels, ", ")))
		}
	}
	for _, o := range table {
		if _, ok := inDoc[o.name]; !ok {
			out = append(out, fmt.Sprintf("the owning table has %s, which the contract table does not name as `%s{...}`", o.name, o.name))
		}
	}
	return out
}

// --- the registry ----------------------------------------------------------

// children gathers g and returns, for the family name, its label names (sorted) and
// its children as "v1\x00v2" keys (values in label-name order of `labels`) with their
// values. found=false when the family is not exposed.
func children(t *testing.T, g prometheus.Gatherer, name string, labels []string) (found bool, gotLabels []string, vals map[string]float64) {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		found = true
		vals = map[string]float64{}
		lset := map[string]bool{}
		for _, m := range mf.GetMetric() {
			byName := map[string]string{}
			for _, lp := range m.GetLabel() {
				lset[lp.GetName()] = true
				byName[lp.GetName()] = lp.GetValue()
			}
			var key []string
			for _, l := range labels {
				key = append(key, byName[l])
			}
			vals[strings.Join(key, "\x00")] = m.GetCounter().GetValue()
		}
		for l := range lset {
			gotLabels = append(gotLabels, l)
		}
		sort.Strings(gotLabels)
	}
	return found, gotLabels, vals
}

// startProblems is how the family o departs from "exposed, with the span's labels and
// exactly the declared children, every one at 0".
func startProblems(t *testing.T, g prometheus.Gatherer, o owned) []string {
	t.Helper()
	found, labels, vals := children(t, g, o.name, o.labels)
	if !found {
		return []string{o.name + " is not exposed: a family that is absent at start reads as renamed or an older image (ADR-0040 D1)"}
	}
	var out []string
	if strings.Join(labels, ",") != strings.Join(o.labels, ",") {
		out = append(out, fmt.Sprintf("%s has labels {%s}, want {%s}", o.name, strings.Join(labels, ", "), strings.Join(o.labels, ", ")))
	}
	want := map[string]bool{}
	for _, c := range o.children {
		k := strings.Join(c, "\x00")
		want[k] = true
		v, ok := vals[k]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: the child %q is not pre-created", o.name, c))
		case v != 0:
			out = append(out, fmt.Sprintf("%s: the child %q starts at %v, want 0", o.name, c, v))
		}
	}
	for k, v := range vals {
		if !want[k] {
			out = append(out, fmt.Sprintf("%s: an undeclared child %q exists at start (value %v)", o.name, strings.Split(k, "\x00"), v))
		}
	}
	sort.Strings(out)
	return out
}

// beforeProblems: a family created at assembly has no child before the owner is
// assembled (it is not made by a package init that every binary linking it would run).
func beforeProblems(t *testing.T, g prometheus.Gatherer, table []owned) []string {
	t.Helper()
	var out []string
	for _, o := range table {
		if o.placement != placeAssembly {
			continue
		}
		if found, _, vals := children(t, g, o.name, o.labels); found && len(vals) > 0 {
			out = append(out, fmt.Sprintf("%s has %d child(ren) before %s is assembled, but its placement is %q: a package init created them (ADR-0040 D2, C4)", o.name, len(vals), o.binary, o.placement))
		}
	}
	return out
}

// --- the real check --------------------------------------------------------

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func readConventions(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), conventionsPath))
	if err != nil {
		t.Fatalf("%v (is %s re-included in .dockerignore?)", err, conventionsPath)
	}
	return string(b)
}

// assembleScoreboard builds the scoreboard as cmd/scoreboard does, up to the first
// request (no request is made, so no counter moves).
func assembleScoreboard(t *testing.T) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	scoreboard.NewHandler(catalog.Catalog{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)),
		scoreboard.WithAdminEmails([]string{"admin@ctf.local"}),
		scoreboard.WithExpectedEmailDomain("ctf.local"),
		scoreboard.WithAllowedOrigins([]string{"https://scoreboard.ctf.local"}))
}

// TestContractMetricFamiliesExistFromStart is the one real check. It must stay the only
// test in this package that touches the default registry.
func TestContractMetricFamiliesExistFromStart(t *testing.T) {
	table := ownedTable()
	doc := readConventions(t)
	p := append(tableProblems(contractSpans(doc), table), rowTokenProblems(doc, table)...)
	if len(p) != 0 {
		t.Fatalf("the contract table and the owning table disagree:\n  %s", strings.Join(p, "\n  "))
	}
	if p := beforeProblems(t, prometheus.DefaultGatherer, table); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
	assembleScoreboard(t)
	for _, o := range table {
		if o.binary != "scoreboard" {
			t.Fatalf("%s is owned by %q: this test assembles only the scoreboard", o.name, o.binary)
		}
		if p := startProblems(t, prometheus.DefaultGatherer, o); len(p) != 0 {
			t.Errorf("after assembling the scoreboard:\n  %s", strings.Join(p, "\n  "))
		}
	}
}

// --- the check is not vacuous (ADR-0040 V3) --------------------------------

// synthetic builds a fresh registry holding o with the given children, each at the
// given value (the family is registered even with no child).
func synthetic(t *testing.T, o owned, create [][]string, value float64) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: o.name, Help: "synthetic"}, o.labels)
	reg.MustRegister(v)
	for _, c := range create {
		ctr := v.WithLabelValues(c...)
		ctr.Add(value)
	}
	return reg
}

func TestContractCheck_CatchesDriftInTheTable(t *testing.T) {
	doc := readConventions(t)
	table := ownedTable()
	spans := contractSpans(doc)
	if p := append(tableProblems(spans, table), rowTokenProblems(doc, table)...); len(p) != 0 {
		t.Fatalf("the real table is already flagged: %v", p)
	}
	t.Run("a reason dropped from the identity row", func(t *testing.T) {
		mutated := strings.ReplaceAll(doc, "`mismatch`", "`mismatched`")
		if mutated == doc {
			t.Fatal("the mutation changed nothing")
		}
		if p := rowTokenProblems(mutated, table); len(p) == 0 {
			t.Fatal("a row without the reason `mismatch` was not flagged")
		}
	})
	if len(spans) != len(table) {
		t.Fatalf("%d spans for %d owned families", len(spans), len(table))
	}
	for _, tc := range []struct{ name, old, new string }{
		{"a family renamed in the table", "scoreboard_identity_denials_total{gate, reason}", "scoreboard_identity_denied_total{gate, reason}"},
		{"the {labels} dropped from a span", "`scoreboard_ingest_falco_events_rate_limited_total{ns}`", "`scoreboard_ingest_falco_events_rate_limited_total`"},
		{"a label added", "`ratelimit_client_ip_source_total{caller, source}`", "`ratelimit_client_ip_source_total{caller, source, route}`"},
		{"a label renamed", "`scoreboard_ingest_falco_events_scoring_overflow_total{ns}`", "`scoreboard_ingest_falco_events_scoring_overflow_total{namespace}`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.ReplaceAll(doc, tc.old, tc.new)
			if mutated == doc {
				t.Fatalf("the mutation %q -> %q changed nothing", tc.old, tc.new)
			}
			if p := tableProblems(contractSpans(mutated), table); len(p) == 0 {
				t.Fatal("the drifted table was not flagged")
			}
		})
	}
	t.Run("the owning table has a family the contract table does not name", func(t *testing.T) {
		extra := append(append([]owned(nil), table...), owned{"scoreboard_new_total", []string{"x"}, "scoreboard", placeInit, nil, nil})
		if p := tableProblems(spans, extra); len(p) == 0 {
			t.Fatal("an extra owned family was not flagged")
		}
	})
	t.Run("the extraction finds nothing", func(t *testing.T) {
		if p := tableProblems(contractSpans("no heading here"), table); len(p) == 0 {
			t.Fatal("an empty extraction was not flagged")
		}
		if p := tableProblems(contractSpans("\n## Cross-repo 契約\n| a | b |\n"), table); len(p) == 0 {
			t.Fatal("a section without spans was not flagged")
		}
	})
}

func TestContractCheck_CatchesDriftInTheRegistry(t *testing.T) {
	o := owned{"x_total", []string{"a", "b"}, "scoreboard", placeInit, [][]string{{"p", "q"}, {"r", "s"}}, nil}
	if p := startProblems(t, synthetic(t, o, o.children, 0), o); len(p) != 0 {
		t.Fatalf("a correct family is flagged: %v", p)
	}
	for _, tc := range []struct {
		name   string
		create [][]string
		value  float64
	}{
		{"pre-generation removed (no child)", nil, 0},
		{"a declared child missing", o.children[:1], 0},
		{"a child created at 1", o.children, 1},
		{"an undeclared child exists", append(append([][]string(nil), o.children...), []string{"x", "y"}), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p := startProblems(t, synthetic(t, o, tc.create, tc.value), o); len(p) == 0 {
				t.Fatal("not flagged")
			}
		})
	}
	t.Run("a label renamed in code", func(t *testing.T) {
		wrong := o
		wrong.labels = []string{"a", "c"}
		if p := startProblems(t, synthetic(t, wrong, wrong.children, 0), o); len(p) == 0 {
			t.Fatal("not flagged")
		}
	})
	t.Run("the family is not exposed at all", func(t *testing.T) {
		if p := startProblems(t, prometheus.NewRegistry(), o); len(p) == 0 {
			t.Fatal("not flagged")
		}
	})
}

func TestContractCheck_CatchesAnAssemblyFamilyCreatedAtInit(t *testing.T) {
	o := owned{"x_total", []string{"a"}, "scoreboard", placeAssembly, [][]string{{"p"}}, nil}
	if p := beforeProblems(t, synthetic(t, o, nil, 0), []owned{o}); len(p) != 0 {
		t.Fatalf("a family with no child before assembly is flagged: %v", p)
	}
	if p := beforeProblems(t, synthetic(t, o, o.children, 0), []owned{o}); len(p) == 0 {
		t.Fatal("a child created before the owner was assembled (a package init) was not flagged")
	}
	// An init-placed family is allowed to have children before assembly.
	o.placement = placeInit
	if p := beforeProblems(t, synthetic(t, o, o.children, 0), []owned{o}); len(p) != 0 {
		t.Fatalf("an init family is flagged: %v", p)
	}
}
