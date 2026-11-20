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
//     there, with exactly the labels of the span, and then by the kind column of the
//     owning table: a counter has exactly the declared children, all at 0; an info
//     gauge (ADR-0040's limited extension, ADR-0056 A4f) has exactly one child, at 1,
//     whose label values are the owning table's expectation (what the assembly's input
//     gives: assembleScoreboard wires no answers table, so `none`).
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
	"github.com/Qfour/falco-ctf-app/internal/contractmetrics"
	"github.com/Qfour/falco-ctf-app/internal/contracttable"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

const conventionsPath = contracttable.Path

const (
	placeInit     = "init"     // created by the package's initialisation (one binary links it)
	placeAssembly = "assembly" // created when the owner wires the part that counts (several binaries link the package)
)

// The kind column (ADR-0040's limited extension, 2026-11-20): what "exists from the
// start" means for the family.
const (
	kindCounter = "counter" // the declared children exist, every one at 0 (ADR-0040 D1)
	kindInfo    = "info"    // exactly one child, at 1, label values set by the assembly
)

// assembledEdition is the run_id the scoreboard's info gauge carries after
// assembleScoreboard: it wires no answers table (no WithEditionJudge), so none is
// needed.
const assembledEdition = metrics.EditionNone

// owned is the table of the contract families: label names, the owning binary, the
// kind, where the children are created, and the children (label values, in the order
// of labels) that must exist at start. The label VALUES of a child are not the table's
// contract except where listed here (ADR-0040 D5 (c): `caller` and `gate` are for
// display). For an info family, children is the ONE child the assembly must leave,
// with the label values the assembly's input gives.
type owned struct {
	name      string
	labels    []string // sorted
	binary    string
	kind      string // kindCounter or kindInfo
	placement string
	children  [][]string // label values, in the order of labels; all at 0 at start (counter), or the one child at 1 (info)
	// rowTokens are values the family's row of the contract table must name as code
	// spans because platform reads them (the identity reasons).
	rowTokens []string
	// pkg is the module-relative package whose initialisation creates the children
	// (placement "init"); assembledBy is the function whose call creates them
	// (placement "assembly"). They are what the placement check (V2) derives from.
	pkg, assembledBy string
}

func ownedTable() []owned { return ownedTableFor(identityobs.Declared()) }

// ownedTableFor builds the table with the identity family's children and reason tokens
// taken from declared (identityobs.Declared() in production): the reasons platform
// reads are the reasons the code declares, not a second list (ADR-0038 V9 (b)).
func ownedTableFor(declared []identityobs.Pair) []owned {
	var identity [][]string
	reasons := map[string]bool{}
	for _, p := range declared {
		identity = append(identity, []string{string(p.Gate), string(p.Reason)})
		reasons[string(p.Reason)] = true
	}
	var reasonTokens []string
	for r := range reasons {
		reasonTokens = append(reasonTokens, r)
	}
	sort.Strings(reasonTokens)
	var clientIP [][]string
	for _, caller := range []string{"submit", "csp_report"} {
		for _, src := range []string{"cf_connecting_ip", "x_forwarded_for", "remote_addr"} {
			clientIP = append(clientIP, []string{caller, src})
		}
	}
	const metricsPkg = "internal/scoreboard/metrics"
	return []owned{
		{"scoreboard_identity_denials_total", []string{"gate", "reason"}, "scoreboard", kindCounter, placeInit, identity, reasonTokens, "internal/scoreboard/identityobs", ""},
		{"scoreboard_ingest_falco_events_scoring_overflow_total", []string{"ns"}, "scoreboard", kindCounter, placeInit, [][]string{{metrics.OtherNS}}, nil, metricsPkg, ""},
		{"scoreboard_ingest_falco_events_rate_limited_total", []string{"ns"}, "scoreboard", kindCounter, placeInit, [][]string{{metrics.OtherNS}}, nil, metricsPkg, ""},
		{"ratelimit_client_ip_source_total", []string{"caller", "source"}, "scoreboard", kindCounter, placeAssembly, clientIP, []string{"cf_connecting_ip", "x_forwarded_for", "remote_addr"}, "", "ClientIPKeyed"},
		// ADR-0056 A4f: the generation of the answers table, set in scoreboard.NewHandler
		// (metrics.SetEditionLoaded): no series before the assembly, one after it. The
		// row names `none` because platform's reader tells it apart (P1b-3f: FAIL in an
		// event with an answers table).
		{"scoreboard_edition_loaded_info", []string{"run_id"}, "scoreboard", kindInfo, placeAssembly, [][]string{{assembledEdition}}, []string{metrics.EditionNone}, "", "SetEditionLoaded"},
	}
}

// --- the contract table ----------------------------------------------------

// span is one `family{labels}` code span of the contract table.
type span struct {
	name   string
	labels []string // sorted
}

// A family and label name as Prometheus allows them (family `[a-zA-Z_:][a-zA-Z0-9_:]*`,
// label `[a-zA-Z_][a-zA-Z0-9_]*`), so a span with an upper-case letter or a colon is not
// skipped silently.
var spanRe = regexp.MustCompile("`([a-zA-Z_:][a-zA-Z0-9_:]*)\\{([a-zA-Z0-9_, ]*)\\}`")

// contractSpans returns the `family{labels}` code spans of the table rows under the
// "Cross-repo 契約" heading of doc, de-duplicated.
func contractSpans(doc string) []span {
	rows := contracttable.Rows(doc)
	if rows == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []span
	for _, ln := range rows {
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
	return contracttable.RowWhere(doc, func(row string) bool { return strings.Contains(row, "`"+name+"{") })
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
// values (a gauge's value for a GAUGE family, else the counter's), and its metric
// type. found=false when the family is not exposed.
func children(t *testing.T, g prometheus.Gatherer, name string, labels []string) (found bool, typ string, gotLabels []string, vals map[string]float64) {
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
		typ = mf.GetType().String()
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
			v := m.GetCounter().GetValue()
			if typ == "GAUGE" {
				v = m.GetGauge().GetValue()
			}
			vals[strings.Join(key, "\x00")] = v
		}
		for l := range lset {
			gotLabels = append(gotLabels, l)
		}
		sort.Strings(gotLabels)
	}
	return found, typ, gotLabels, vals
}

// startProblems is how the family o departs from "exposed, with the span's labels and
// exactly the declared children, every one at 0".
func startProblems(t *testing.T, g prometheus.Gatherer, o owned) []string {
	t.Helper()
	found, typ, labels, vals := children(t, g, o.name, o.labels)
	if !found {
		return []string{o.name + " is not exposed: a family that is absent at start reads as renamed or an older image (ADR-0040 D1)"}
	}
	var out []string
	if typ != "COUNTER" {
		out = append(out, fmt.Sprintf("%s is a %s, want a COUNTER (the contract's families are counters; children are read as counters)", o.name, typ))
	}
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

// infoProblems is how the info family o departs from "exposed, a gauge, with the span's
// labels and exactly one child, at 1, whose label values are the owning table's
// expectation" (ADR-0040's info kind (1)(3)(5)). The counter's "every child at 0" is
// not applied.
func infoProblems(t *testing.T, g prometheus.Gatherer, o owned) []string {
	t.Helper()
	if len(o.children) != 1 {
		return []string{fmt.Sprintf("%s: the owning table declares %d expected children for an info family, want exactly 1", o.name, len(o.children))}
	}
	found, typ, labels, vals := children(t, g, o.name, o.labels)
	if !found {
		return []string{o.name + " is not exposed after the assembly: an info family is present from the assembly on (ADR-0040's info kind (3)); absent reads as renamed or an older image"}
	}
	var out []string
	if typ != "GAUGE" {
		out = append(out, fmt.Sprintf("%s is a %s, want a GAUGE (an info family)", o.name, typ))
	}
	if strings.Join(labels, ",") != strings.Join(o.labels, ",") {
		out = append(out, fmt.Sprintf("%s has labels {%s}, want {%s}", o.name, strings.Join(labels, ", "), strings.Join(o.labels, ", ")))
	}
	if len(vals) != 1 {
		out = append(out, fmt.Sprintf("%s has %d children, want exactly 1 (an info family has one series)", o.name, len(vals)))
	}
	k := strings.Join(o.children[0], "\x00")
	v, ok := vals[k]
	switch {
	case !ok:
		out = append(out, fmt.Sprintf("%s: no child %q (the label values the assembly's input gives)", o.name, o.children[0]))
	case v != 1:
		out = append(out, fmt.Sprintf("%s: the child %q is %v, want 1", o.name, o.children[0], v))
	}
	sort.Strings(out)
	return out
}

// familyProblems checks o by its kind column: a counter by startProblems, an info gauge
// by infoProblems. A row with no kind, or another one, is a problem itself: the kind
// decides what "exists from the start" means, so it is not defaulted.
func familyProblems(t *testing.T, g prometheus.Gatherer, o owned) []string {
	t.Helper()
	switch o.kind {
	case kindCounter:
		return startProblems(t, g, o)
	case kindInfo:
		return infoProblems(t, g, o)
	default:
		return []string{fmt.Sprintf("%s: the owning table's kind is %q, want %q or %q", o.name, o.kind, kindCounter, kindInfo)}
	}
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
		if found, _, _, vals := children(t, g, o.name, o.labels); found && len(vals) > 0 {
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
// request (no request is made, so no counter moves). It wires no answers table (no
// WithEditionJudge / WithEditionRunID): the info gauge's expected run_id is therefore
// assembledEdition (`none`).
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

// --- placement (ADR-0040 D2, V2) -------------------------------------------

// placementProblems derives the V2 check from the owning table, not from a hand-written
// list of binaries or packages (D4 step 5):
//   - an "init" family's package must be in the owner's closure and in NO other
//     binary's closure (every cmd/* directory, the gen-* ones included): its init would
//     otherwise create children, as 0, in a binary that never counts them;
//   - an "assembly" family's constructor must be called somewhere in the owner's
//     closure and nowhere in another binary's closure: that is what backs the contract
//     row's "the collector does not expose this family".
//
// The walk is contractmetrics.Closure / CallsIn, which read source text with the
// standard library only (this package is where it lives so this test can call it).
func placementProblems(root string, table []owned) []string {
	bins, err := contractmetrics.Binaries(root)
	if err != nil || len(bins) == 0 {
		return []string{fmt.Sprintf("no binary found under %s/cmd (%v): the derivation would check nothing", root, err)}
	}
	closures := map[string]map[string]bool{}
	for _, b := range bins {
		c, err := contractmetrics.Closure(root, b)
		if err != nil {
			return []string{err.Error()}
		}
		closures[b] = c
	}
	var out []string
	for _, o := range table {
		owner := "cmd/" + o.binary
		oc, ok := closures[owner]
		if !ok {
			out = append(out, fmt.Sprintf("%s: the owner %s is not a binary under cmd/", o.name, owner))
			continue
		}
		switch o.placement {
		case placeInit:
			if !oc[o.pkg] {
				out = append(out, fmt.Sprintf("%s: %s does not link %s (the family's init package): the check would pass on nothing", o.name, owner, o.pkg))
			}
			for _, b := range bins {
				if b != owner && closures[b][o.pkg] {
					out = append(out, fmt.Sprintf("%s: %s links %s, whose init pre-creates the children: that binary would expose them as 0 without counting (ADR-0040 D2)", o.name, b, o.pkg))
				}
			}
		case placeAssembly:
			called, err := contractmetrics.CallsIn(root, oc, o.assembledBy)
			if err != nil {
				out = append(out, err.Error())
			} else if !called {
				out = append(out, fmt.Sprintf("%s: %s never calls %s: nothing creates the children", o.name, owner, o.assembledBy))
			}
			for _, b := range bins {
				if b == owner {
					continue
				}
				if called, err := contractmetrics.CallsIn(root, closures[b], o.assembledBy); err != nil {
					out = append(out, err.Error())
				} else if called {
					out = append(out, fmt.Sprintf("%s: %s calls %s: it would expose a family the contract says only %s owns", o.name, b, o.assembledBy, o.binary))
				}
			}
		default:
			out = append(out, fmt.Sprintf("%s: unknown placement %q", o.name, o.placement))
		}
	}
	return out
}

// assembled is set by the first run of the real check: beforeProblems needs a process
// in which no scoreboard has been assembled yet.
var assembled bool

// TestContractMetricFamiliesExistFromStart is the one real check. It must stay the only
// test in this package that touches the default registry.
func TestContractMetricFamiliesExistFromStart(t *testing.T) {
	if assembled {
		t.Skip("a scoreboard was already assembled in this process (go test -count>1): the before-assembly check needs a fresh process; the first run did the check")
	}
	table := ownedTable()
	doc := readConventions(t)
	p := append(tableProblems(contractSpans(doc), table), rowTokenProblems(doc, table)...)
	if len(p) != 0 {
		t.Fatalf("the contract table and the owning table disagree:\n  %s", strings.Join(p, "\n  "))
	}
	if p := placementProblems(moduleRoot(t), table); len(p) != 0 {
		t.Fatalf("a family is in the wrong place (ADR-0040 D2):\n  %s", strings.Join(p, "\n  "))
	}
	if p := beforeProblems(t, prometheus.DefaultGatherer, table); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
	assembled = true
	assembleScoreboard(t)
	for _, o := range table {
		if o.binary != "scoreboard" {
			t.Fatalf("%s is owned by %q: this test assembles only the scoreboard", o.name, o.binary)
		}
		if p := familyProblems(t, prometheus.DefaultGatherer, o); len(p) != 0 {
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
	t.Run("`none` dropped from the edition row", func(t *testing.T) {
		row := rowOf(doc, "scoreboard_edition_loaded_info")
		if row == "" || !strings.Contains(row, "`none`") {
			t.Fatal("the edition row, or its `none`, is not in the table: the case would test nothing")
		}
		mutated := strings.Replace(doc, row, strings.ReplaceAll(row, "`none`", "none"), 1)
		if p := rowTokenProblems(mutated, table); len(p) == 0 {
			t.Fatal("an edition row without the code span `none` was not flagged")
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
		{"the info family's label renamed", "`scoreboard_edition_loaded_info{run_id}`", "`scoreboard_edition_loaded_info{run}`"},
		{"the info family's span dropped to prose", "`scoreboard_edition_loaded_info{run_id}`", "scoreboard_edition_loaded_info{run_id}"},
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
		extra := append(append([]owned(nil), table...), owned{name: "scoreboard_new_total", labels: []string{"x"}, binary: "scoreboard", placement: placeInit})
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
	o := owned{name: "x_total", labels: []string{"a", "b"}, binary: "scoreboard", placement: placeInit, children: [][]string{{"p", "q"}, {"r", "s"}}}
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
	o := owned{name: "x_total", labels: []string{"a"}, binary: "scoreboard", placement: placeAssembly, children: [][]string{{"p"}}}
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

func TestContractCheck_CatchesAReasonTheRowDoesNotName(t *testing.T) {
	doc := readConventions(t)
	real := identityobs.Declared()
	if p := rowTokenProblems(doc, ownedTableFor(real)); len(p) != 0 {
		t.Fatalf("the real row is already flagged: %v", p)
	}
	// The code declares one more reason than the row names: platform would not be told.
	plus := append(append([]identityobs.Pair(nil), real...), identityobs.Pair{Gate: real[0].Gate, Reason: "new_reason"})
	if p := rowTokenProblems(doc, ownedTableFor(plus)); len(p) == 0 {
		t.Fatal("a reason declared in code but absent from the row was not flagged")
	}
	// The code renames a reason: the row still names the old one.
	renamed := append([]identityobs.Pair(nil), real...)
	renamed[0].Reason = "renamed_reason"
	if p := rowTokenProblems(doc, ownedTableFor(renamed)); len(p) == 0 {
		t.Fatal("a reason renamed in code was not flagged")
	}
}

func TestContractCheck_CatchesAFamilyThatIsNotACounter(t *testing.T) {
	o := owned{name: "x_total", labels: []string{"a"}, binary: "scoreboard", placement: placeInit, children: [][]string{{"p"}}}
	reg := prometheus.NewRegistry()
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: o.name, Help: "synthetic"}, o.labels)
	reg.MustRegister(g)
	g.WithLabelValues("p")
	if p := startProblems(t, reg, o); len(p) == 0 {
		t.Fatal("a gauge in place of the counter was not flagged")
	}
}

// --- the info kind is not vacuous (ADR-0040's limited extension, ADR-0056 V105) ---

// syntheticInfo builds a fresh registry holding o as a gauge with the given labels and
// children, each at the given value (the family is registered even with no child).
func syntheticInfo(t *testing.T, o owned, labels []string, create [][]string, value float64) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: o.name, Help: "synthetic"}, labels)
	reg.MustRegister(v)
	for _, c := range create {
		v.WithLabelValues(c...).Set(value)
	}
	return reg
}

func TestContractCheck_InfoKindCatchesDrift(t *testing.T) {
	var info owned
	for _, o := range ownedTable() {
		if o.kind == kindInfo {
			info = o
		}
	}
	if info.name != "scoreboard_edition_loaded_info" || len(info.children) != 1 {
		t.Fatalf("the owning table's info family is %+v, want scoreboard_edition_loaded_info with one expected child: the cases below would test nothing", info)
	}
	good := syntheticInfo(t, info, info.labels, info.children, 1)
	if p := familyProblems(t, good, info); len(p) != 0 {
		t.Fatalf("a correct info family is flagged: %v", p)
	}

	// Copies of the owning table's row, against the correct registry.
	for _, tc := range []struct {
		name   string
		change func(o *owned)
	}{
		{"the kind column removed", func(o *owned) { o.kind = "" }},
		{"the info family expected as a counter (every child at 0)", func(o *owned) { o.kind = kindCounter }},
		{"another expected label value", func(o *owned) { o.children = [][]string{{"0123456789abcdef0123456789abcdef"}} }},
		{"two expected children", func(o *owned) { o.children = append(append([][]string(nil), o.children...), []string{"other"}) }},
		{"no expected child", func(o *owned) { o.children = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := info
			tc.change(&o)
			if p := familyProblems(t, good, o); len(p) == 0 {
				t.Fatal("not flagged")
			}
		})
	}

	// The registry drifted, the row real.
	for _, tc := range []struct {
		name string
		reg  *prometheus.Registry
	}{
		{"two children (a second set without the Reset)", syntheticInfo(t, info, info.labels, append(append([][]string(nil), info.children...), []string{"0123456789abcdef0123456789abcdef"}), 1)},
		{"the one child at 0", syntheticInfo(t, info, info.labels, info.children, 0)},
		{"another label value only", syntheticInfo(t, info, info.labels, [][]string{{"0123456789abcdef0123456789abcdef"}}, 1)},
		{"no child (the family absent)", syntheticInfo(t, info, info.labels, nil, 1)},
		{"a label added", syntheticInfo(t, info, []string{"run_id", "seat"}, [][]string{{info.children[0][0], "x"}}, 1)},
		{"a counter in place of the gauge", synthetic(t, info, info.children, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p := familyProblems(t, tc.reg, info); len(p) == 0 {
				t.Fatal("not flagged")
			}
		})
	}

	// Its placement is the assembly: a child before the assembly is flagged.
	if p := beforeProblems(t, good, []owned{info}); len(p) == 0 {
		t.Fatal("an info child before the assembly was not flagged")
	}
	if p := beforeProblems(t, syntheticInfo(t, info, info.labels, nil, 1), []owned{info}); len(p) != 0 {
		t.Fatalf("an info family with no child before the assembly is flagged: %v", p)
	}
}

// writeModule makes a throwaway module with cmd/scoreboard and cmd/fakebin for the
// placement mutations.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files["go.mod"] = "module example.test/m\n\ngo 1.26\n"
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestContractCheck_PlacementIsDerivedAndCatchesDrift(t *testing.T) {
	initFam := owned{name: "x_total", labels: []string{"a"}, binary: "scoreboard", placement: placeInit, pkg: "internal/own"}
	asmFam := owned{name: "y_total", labels: []string{"a"}, binary: "scoreboard", placement: placeAssembly, assembledBy: "Build"}
	base := map[string]string{
		"cmd/scoreboard/main.go": "package main\nimport (\n _ \"example.test/m/internal/own\"\n \"example.test/m/internal/shared\"\n)\nfunc main() { shared.Build() }\n",
		"cmd/fakebin/main.go":    "package main\nimport _ \"example.test/m/internal/shared\"\nfunc main() {}\n",
		"internal/own/o.go":      "package own\n",
		"internal/shared/s.go":   "package shared\nfunc Build() {}\n",
	}
	// The reference layout: the owner links the init package and calls the constructor,
	// the other binary links the shared package but calls neither.
	base["internal/shared/s.go"] = "package shared\nfunc Build() {}\n"
	good := writeModule(t, copyMap(base))
	if p := placementProblems(good, []owned{initFam, asmFam}); len(p) != 0 {
		t.Fatalf("the reference layout is flagged: %v", p)
	}
	t.Run("a second binary links the init package", func(t *testing.T) {
		m := copyMap(base)
		m["cmd/fakebin/main.go"] = "package main\nimport _ \"example.test/m/internal/own\"\nfunc main() {}\n"
		if p := placementProblems(writeModule(t, m), []owned{initFam}); len(p) == 0 {
			t.Fatal("not flagged")
		}
	})
	t.Run("a second binary calls the assembly constructor", func(t *testing.T) {
		m := copyMap(base)
		m["cmd/fakebin/main.go"] = "package main\nimport \"example.test/m/internal/shared\"\nfunc main() { shared.Build() }\n"
		if p := placementProblems(writeModule(t, m), []owned{asmFam}); len(p) == 0 {
			t.Fatal("not flagged")
		}
	})
	t.Run("the owner no longer links the init package", func(t *testing.T) {
		m := copyMap(base)
		m["cmd/scoreboard/main.go"] = "package main\nfunc main() {}\n"
		if p := placementProblems(writeModule(t, m), []owned{initFam}); len(p) == 0 {
			t.Fatal("not flagged")
		}
	})
	t.Run("the owner no longer calls the constructor", func(t *testing.T) {
		m := copyMap(base)
		m["cmd/scoreboard/main.go"] = "package main\nfunc main() {}\n"
		if p := placementProblems(writeModule(t, m), []owned{asmFam}); len(p) == 0 {
			t.Fatal("not flagged")
		}
	})
	t.Run("no binary at all", func(t *testing.T) {
		if p := placementProblems(writeModule(t, map[string]string{}), []owned{initFam}); len(p) == 0 {
			t.Fatal("an empty cmd/ was not flagged")
		}
	})
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
