package identityobs_test

// The cross-repo contract row "identity 拒否の観測 (app#404、ADR-0038)" in
// .claude/rules/falco-ctf-app-conventions.md is what platform reads: the metric
// name, the label name `reason`, the meaning of `no_identity` / `non_canonical`,
// and that every gate's series exists from start. This compares the row with
// what the process exposes, so renaming the metric, a label or a reason in code
// without the row (and so without platform) fails `make test`.
//
// The file is in the Docker test context only because .dockerignore re-includes
// it (`.claude` is otherwise excluded): a missing file FAILS, never skips.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	conventionsPath = ".claude/rules/falco-ctf-app-conventions.md"
	contractRowKey  = "| identity 拒否の観測 (app#404、ADR-0038) |"
)

// contractRow returns the one table row whose first cell is contractRowKey.
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

// exposed returns the metric's family name, its label names and the distinct
// reason values, as the default registry exposes them (gathered, not read from
// the code's own constants).
func exposed(t *testing.T) (name string, labels, reasons []string) {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	lset, rset := map[string]bool{}, map[string]bool{}
	for _, mf := range mfs {
		if !strings.HasSuffix(mf.GetName(), "identity_denials_total") {
			continue
		}
		name = mf.GetName()
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				lset[lp.GetName()] = true
				if lp.GetName() == "reason" {
					rset[lp.GetValue()] = true
				}
			}
		}
	}
	for k := range lset {
		labels = append(labels, k)
	}
	for k := range rset {
		reasons = append(reasons, k)
	}
	sort.Strings(labels)
	sort.Strings(reasons)
	return name, labels, reasons
}

// contractViolations lists how row disagrees with the exposed metric.
func contractViolations(row, name string, labels, reasons []string) []string {
	var out []string
	if name == "" {
		return []string{"the metric is not exposed at all: nothing to compare the row with"}
	}
	need := func(what, token string) {
		if !strings.Contains(row, "`"+token+"`") {
			out = append(out, what+" "+token+" is not in the row (as a code span)")
		}
	}
	if !strings.Contains(row, "`"+name+"{") {
		out = append(out, "the metric name "+name+" is not in the row followed by its labels (`"+name+"{gate, reason}`)")
	}
	for _, l := range labels {
		need("label", l)
	}
	for _, r := range reasons {
		need("reason", r)
	}
	if strings.Contains(row, "ratelimit_identity_requests_total") {
		out = append(out, "the row names the old metric ratelimit_identity_requests_total: the old name and its no_identity outcome are not part of the contract (ADR-0038 D1)")
	}
	return out
}

func TestContractRowMatchesTheExposedMetric(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), conventionsPath))
	if err != nil {
		t.Fatalf("%v (is .claude/rules/falco-ctf-app-conventions.md re-included in .dockerignore?)", err)
	}
	row := contractRow(t, string(b))
	name, labels, reasons := exposed(t)
	if name != "scoreboard_identity_denials_total" {
		t.Fatalf("exposed metric name = %q, want scoreboard_identity_denials_total", name)
	}
	if len(labels) != 2 || len(reasons) != 3 {
		t.Fatalf("exposed labels %v, reasons %v: want 2 labels (gate, reason) and 3 reasons", labels, reasons)
	}
	if v := contractViolations(row, name, labels, reasons); len(v) > 0 {
		t.Fatalf("the contract row and the exposed metric disagree:\n  %s", strings.Join(v, "\n  "))
	}
}

// The comparison is not vacuous: a row with the metric renamed, a reason
// dropped, the label renamed, or the old metric named is flagged.
func TestContractCheckCatchesDrift(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), conventionsPath))
	if err != nil {
		t.Fatal(err)
	}
	row := contractRow(t, string(b))
	name, labels, reasons := exposed(t)
	if v := contractViolations(row, name, labels, reasons); len(v) != 0 {
		t.Fatalf("the real row is already flagged: %v", v)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"metric renamed", "scoreboard_identity_denials_total", "scoreboard_identity_denied_total"},
		{"reason renamed", "non_canonical", "noncanonical"},
		{"reason dropped", "mismatch", "other"},
		{"label renamed", "`reason`", "`cause`"},
		{"old metric named", "metric `scoreboard_identity_denials_total{gate, reason}`", "metric `scoreboard_identity_denials_total{gate, reason}` (旧 ratelimit_identity_requests_total)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.ReplaceAll(row, tc.old, tc.new)
			if mutated == row {
				t.Fatalf("the mutation %q -> %q changed nothing: the row does not contain it", tc.old, tc.new)
			}
			if v := contractViolations(mutated, name, labels, reasons); len(v) == 0 {
				t.Fatalf("a drifted row (%s) was not flagged", tc.name)
			}
		})
	}
	if v := contractViolations(row, "", nil, nil); len(v) == 0 {
		t.Fatal("an unexposed metric was not flagged")
	}
}
