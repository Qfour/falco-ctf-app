package apispec

// task #148 (5x R3 M-new-2): TestSpecExistsForEveryMuxOwningBinary
// (mux_ownership_test.go, ADR-0005 V6) mechanically guarantees that every
// mux-owning cmd/* binary has a docs/openapi-*.yaml. It does NOT guarantee
// that a corresponding parity test (apispec_parity_test.go, hand-written
// today: internal/{scoreboard,collector,authpolicy}) exists to keep that
// spec honest — a future service could add a spec, satisfy V6, and be
// silently exempt from V1/V3b coverage forever, which is precisely the kind
// of hidden allowlist I14 forbids ("no exception/exclusion list"). This
// file closes that gap the same way V6 closes its own: mechanically, not by
// hand-maintaining a second cmd->package map.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// requiredParityTestFuncs is the set of parity test functions ADR-0005
// treats as universal across EVERY mux-owning binary — i.e. present,
// verbatim, in all three of internal/scoreboard/apispec_parity_test.go,
// internal/collector/apispec_parity_test.go and
// internal/authpolicy/apispec_parity_test.go today:
//
//   - TestAPISpec_V1_RouteSetMatchesSpec — bidirectional route-set match
//     (mux Routes() <-> spec operations). The core "spec isn't lying about
//     what exists" check.
//   - TestAPISpec_V3b_StringExtParity — x-ctf-audience / x-ctf-authz /
//     x-ctf-rate-limit string parity. The core "spec isn't lying about who
//     can call this" check.
//
// Deliberately NOT included, with reasons that must hold for as long as
// they're excluded (re-evaluate if either premise changes):
//
//   - V4 (collector-forward parity, e.g. TestAPISpec_V4_CollectorForwardBijection
//     / TestAPISpec_V4_ResetDirtyNeverForwarded) is NOT universal — it only
//     applies to services that participate in the collector forward
//     allowlist. auth-policy has no V4 test at all because it is neither a
//     forward source nor target, and that absence is correct, not a gap.
//     Folding V4 into this required set would force an inapplicable test
//     onto auth-policy and any future non-collector-adjacent service.
//   - V5 (response field parity, e.g. TestAPISpec_V5_JourneyFieldsMatchSpec)
//     is not yet machine-enumerable: ADR-0009 Decision A plans a generic
//     per-response-schema mechanism (tracked in #258, pending). Until that
//     lands, V5 test names vary per response shape and there is no single
//     canonical function name to require here. Add V5 to this set once #258
//     lands and a canonical entry point exists — do not hand-roll a
//     per-service V5 name list in the meantime, that reintroduces the exact
//     hand-written-allowlist problem this file exists to avoid.
var requiredParityTestFuncs = []string{
	"TestAPISpec_V1_RouteSetMatchesSpec",
	"TestAPISpec_V3b_StringExtParity",
}

// testFuncNames returns the set of top-level (non-method) function names
// declared across dir's *_test.go files, regardless of which package name
// (foo or foo_test) those files declare — only the function identifier
// matters for this check.
func testFuncNames(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	out := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil { // skip methods, keep top-level funcs only
				continue
			}
			out[fn.Name.Name] = true
		}
	}
	return out
}

// TestParityTestsExistForEverySpec is the machine guarantee task #148
// closes: for every cmd/<name> entry in specNameForCmd (every binary V6 has
// already determined owns a ServeMux and therefore must have a
// docs/openapi-*.yaml), the mux-owning internal package — mechanically
// located via muxOwningDir, the SAME BFS/import-graph walk
// TestSpecExistsForEveryMuxOwningBinary uses, not a second hand-authored
// cmd->package map — must also declare every function in
// requiredParityTestFuncs in one of its *_test.go files.
//
// "Spec exists" (V6) without "the tests that keep it honest exist" is
// exactly the drift I14 forbids: a reader sees docs/openapi-<x>.yaml,
// concludes V1/V3b coverage exists, and is wrong. No exclusion list is
// used — specNameForCmd is the same enumeration V6 already trusts as
// complete, and every entry in it is checked here without exception.
func TestParityTestsExistForEverySpec(t *testing.T) {
	root := repoRoot(t)

	cmds := make([]string, 0, len(specNameForCmd))
	for cmdName := range specNameForCmd {
		cmds = append(cmds, cmdName)
	}
	sort.Strings(cmds) // deterministic subtest order

	sawAny := false
	for _, cmdName := range cmds {
		specFile := specNameForCmd[cmdName]
		t.Run(cmdName, func(t *testing.T) {
			dir, found := muxOwningDir(t, root, cmdName)
			if !found {
				t.Fatalf("cmd/%s has a specNameForCmd entry (docs/%s) but the mechanical ServeMux walk (muxOwningDir) found no mux-owning package for it — specNameForCmd and the ownership walk have diverged", cmdName, specFile)
			}
			sawAny = true
			relDir := strings.TrimPrefix(dir, root+string(filepath.Separator))
			have := testFuncNames(t, dir)
			for _, fn := range requiredParityTestFuncs {
				if !have[fn] {
					t.Fatalf("cmd/%s has a spec (docs/%s) but internal package %s has no %s in any *_test.go — a spec was added without the parity test that keeps it honest (ADR-0005 I14): spec existence alone does not guarantee V1/V3b coverage", cmdName, specFile, relDir, fn)
				}
			}
		})
	}
	// Non-empty-result guard (ADR-0005 V8-2 pattern, same rationale as
	// TestSpecExistsForEveryMuxOwningBinary): if specNameForCmd were ever
	// empty or the ownership walk silently matched nothing, this test would
	// be a permanent no-op. Fail loudly instead.
	if !sawAny {
		t.Fatal("no specNameForCmd entries were checked at all — the enumeration or ownership walk is broken (this check must never be a silent no-op)")
	}
}
