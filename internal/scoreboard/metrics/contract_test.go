package metrics_test

// The cross-repo contract row "Webhook 流量制限 (app#359)" in
// .claude/rules/falco-ctf-app-conventions.md is what platform's verify / teardown
// gate reads: the two ingest metric names, the label name `ns`, and that both
// families exist from process start (so a missing family reads as "renamed or an
// older image", not as 0). This compares the row with what the process exposes,
// so renaming a metric or its label in code without the row (and so without
// platform) fails `make test`.
//
// The file is in the Docker test context only because .dockerignore re-includes
// it (`.claude` is otherwise excluded): a missing file FAILS, never skips.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
)

const (
	conventionsPath = ".claude/rules/falco-ctf-app-conventions.md"
	contractRowKey  = "| Webhook 流量制限 (app#359) |"
	existsFromStart = "起動直後から存在する"
)

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

func contractRow(t *testing.T, doc string) string {
	t.Helper()
	var rows []string
	for _, ln := range strings.Split(doc, "\n") {
		if strings.HasPrefix(ln, contractRowKey) {
			rows = append(rows, ln)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("%s has %d rows starting with %q, want exactly 1", conventionsPath, len(rows), contractRowKey)
	}
	return rows[0]
}

// family is one exposed metric family as the default registry gathers it.
type family struct {
	name   string
	labels []string
	zero   bool // has an ns="_other" series at 0
}

// exposed returns the families whose name ends in suffix, gathered (not read
// from the code's own constants).
func exposed(t *testing.T, suffixes ...string) map[string]family {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]family{}
	for _, mf := range mfs {
		for _, suf := range suffixes {
			if !strings.HasSuffix(mf.GetName(), suf) {
				continue
			}
			f := family{name: mf.GetName()}
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					f.labels = append(f.labels, lp.GetName())
					if lp.GetName() == "ns" && lp.GetValue() == metrics.OtherNS && m.GetCounter().GetValue() == 0 {
						f.zero = true
					}
				}
			}
			out[suf] = f
		}
	}
	return out
}

func contractViolations(row string, fams map[string]family, suffixes []string) []string {
	var out []string
	for _, suf := range suffixes {
		f, ok := fams[suf]
		if !ok {
			out = append(out, "the family ending "+suf+" is not exposed at start")
			continue
		}
		if len(f.labels) != 1 || f.labels[0] != "ns" {
			out = append(out, f.name+" labels are "+strings.Join(f.labels, ",")+", want only ns")
		}
		if !f.zero {
			out = append(out, f.name+" has no ns=\"_other\" series at 0 at start")
		}
		if !strings.Contains(row, "`"+f.name+"{ns}`") {
			out = append(out, "the row does not name `"+f.name+"{ns}`")
		}
	}
	if !strings.Contains(row, existsFromStart) {
		out = append(out, "the row does not say the families exist from start ("+existsFromStart+")")
	}
	return out
}

var suffixes = []string{"falco_events_scoring_overflow_total", "falco_events_rate_limited_total"}

func TestContractRowMatchesTheExposedMetrics(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), conventionsPath))
	if err != nil {
		t.Fatalf("%v (is .claude/rules/falco-ctf-app-conventions.md re-included in .dockerignore?)", err)
	}
	row := contractRow(t, string(b))
	fams := exposed(t, suffixes...)
	if len(fams) != 2 {
		t.Fatalf("exposed %d of the 2 ingest families at start", len(fams))
	}
	for _, f := range fams {
		if !strings.HasPrefix(f.name, "scoreboard_ingest_") {
			t.Fatalf("family %q is not under scoreboard_ingest_", f.name)
		}
	}
	if v := contractViolations(row, fams, suffixes); len(v) > 0 {
		t.Fatalf("the contract row and the exposed metrics disagree:\n  %s", strings.Join(v, "\n  "))
	}
}

// The comparison is not vacuous: a row with a metric renamed, the label
// renamed, or the exists-from-start sentence dropped is flagged, and so is a
// metric that is not exposed at start.
func TestContractCheckCatchesDrift(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), conventionsPath))
	if err != nil {
		t.Fatal(err)
	}
	row := contractRow(t, string(b))
	fams := exposed(t, suffixes...)
	if v := contractViolations(row, fams, suffixes); len(v) != 0 {
		t.Fatalf("the real row is already flagged: %v", v)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"overflow metric renamed", "scoreboard_ingest_falco_events_scoring_overflow_total", "scoreboard_ingest_falco_events_scoring_overflowed_total"},
		{"rate-limited metric renamed", "scoreboard_ingest_falco_events_rate_limited_total", "scoreboard_ingest_falco_events_limited_total"},
		{"label renamed", "_total{ns}`", "_total{namespace}`"},
		{"exists-from-start dropped", existsFromStart, "最初の event の後に存在する"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.ReplaceAll(row, tc.old, tc.new)
			if mutated == row {
				t.Fatalf("the mutation %q -> %q changed nothing: the row does not contain it", tc.old, tc.new)
			}
			if v := contractViolations(mutated, fams, suffixes); len(v) == 0 {
				t.Fatalf("a drifted row (%s) was not flagged", tc.name)
			}
		})
	}
	if v := contractViolations(row, map[string]family{}, suffixes); len(v) == 0 {
		t.Fatal("families that are not exposed at start were not flagged")
	}
}
