package apispec

// Requirement 5 (R1#3a / R4 F2 / R3 M-new-3, final review round): route.go's
// package doc claims two dependency-boundary invariants ("this package holds
// ONLY Route/Register + the stdlib net/http import"; specparity is "imported
// ONLY from *_test.go files"), but before this file existed the ONLY thing
// enforcing either claim was a Dockerfile COPY line (auth-policy/Dockerfile,
// collector/Dockerfile) plus a comment — and:
//
//  1. scoreboard/Dockerfile COPYs the whole `internal/` tree, so it has no
//     equivalent tripwire at all;
//  2. even where the narrow COPY exists, widening it to fix a build error
//     is the single most natural "fix" a developer under time pressure would
//     make — R1 measured the actual errors that provoke that fix: `go build
//     ./cmd/auth-policy` from a context missing internal/apispec/specparity
//     fails with "no required module provides package
//     github.com/Qfour/falco-ctf-app/internal/apispec/specparity; to add it:
//     go get github.com/Qfour/falco-ctf-app/internal/apispec/specparity" — a
//     nonsensical suggestion for a package that already lives in this same
//     module — and a route.go split that references a helper defined only in
//     a file NOT copied into the build context fails as a phantom
//     `undefined: apispec.<Name>` compile error that is green on the host
//     (where the whole directory exists) and red ONLY inside the image
//     build;
//  3. nothing in `make test` / scripts/ / .github/ ran `go list -deps` (or
//     equivalent) to catch either direction before this file existed, and
//     neither `gen-diff-check` nor `build (collector) / scan` are required
//     checks (falco-api skill, branch protection).
//
// This closes the gap at the ONE gate that's actually required: `make test`.
// It reimplements go list -deps' relevant subset (an import-graph BFS) using
// the exact same textual, no-real-build-needed mechanism
// mux_ownership_test.go / staticreg_test.go already use — so it needs no new
// dependency and, unlike a Dockerfile COPY line, cannot be "fixed" by
// widening a copy path.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// specparityImportPath is internal/apispec/specparity's own module-qualified
// import path — the package route.go's doc says a production binary must
// never pull in.
const specparityImportPath = modulePrefix + "internal/apispec/specparity"

// ingressparityImportPath is internal/apispec/ingressparity's own
// module-qualified import path (ADR-0021 / Issue #238, Hard Invariant
// I15) — that package's own doc says a production binary must never pull
// it in, mirroring specparity's rationale (a gopkg.in/yaml.v3 + os/exec
// dependency has no business in a distroless service's SBOM for zero
// runtime benefit).
const ingressparityImportPath = modulePrefix + "internal/apispec/ingressparity"

// transitiveModuleImports breadth-first walks the module-internal import
// graph starting at start (a module-qualified package path, e.g.
// modulePrefix+"cmd/auth-policy"), following importsOf's module-internal
// extraction (mux_ownership_test.go) at each hop, and returns every
// module-qualified package path reached (including start itself).
//
// A visited package whose on-disk directory does not exist under root is
// treated as a LEAF rather than a fatal error — deliberately, so a
// synthetic mutation-proof target (see
// TestNoProductionBinaryImportsSpecparity_CatchesTransitiveImport below) can
// name a package that has no real directory without this function needing
// two code paths for "real repo" vs. "synthetic fixture" callers.
func transitiveModuleImports(t *testing.T, root, start string) map[string]bool {
	t.Helper()
	visited := map[string]bool{}
	queue := []string{start}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if visited[pkg] {
			continue
		}
		visited[pkg] = true
		dir := filepath.Join(root, strings.TrimPrefix(pkg, modulePrefix))
		if _, err := os.Stat(dir); err != nil {
			continue // leaf: nothing on disk to expand further.
		}
		queue = append(queue, importsOf(t, dir)...)
	}
	return visited
}

// TestNoProductionBinaryImportsSpecparity is Requirement 5(a)'s first half:
// cmd/auth-policy's and cmd/collector's module-internal import closure must
// never include internal/apispec/specparity. cmd/scoreboard is not checked
// here — nothing in this Requirement asked for it, and importsOf only ever
// scans NON-TEST files by construction (mux_ownership_test.go's
// nonTestGoFiles), so a *_test.go-only import of specparity anywhere
// (including in cmd/scoreboard's own package) is correctly invisible to this
// walk regardless.
func TestNoProductionBinaryImportsSpecparity(t *testing.T) {
	root := repoRoot(t)
	for _, cmd := range []string{"auth-policy", "collector"} {
		t.Run(cmd, func(t *testing.T) {
			closure := transitiveModuleImports(t, root, modulePrefix+"cmd/"+cmd)
			if closure[specparityImportPath] {
				t.Fatalf("cmd/%s's module-internal import closure includes %s — a production binary must never import the test-only spec-comparison package (route.go's own package doc; 5x review BLOCKING 1: this previously widened both distroless services' SBOM/CVE surface — a yaml.v3 dependency — for zero runtime benefit)", cmd, specparityImportPath)
			}
		})
	}
}

// TestNoProductionBinaryImportsIngressParity is ADR-0021's (Issue #238)
// counterpart to TestNoProductionBinaryImportsSpecparity, checking ALL
// THREE http.ServeMux-owning binaries — including cmd/scoreboard, which
// TestNoProductionBinaryImportsSpecparity above deliberately skips (its own
// comment: "nothing in this Requirement asked for it"). ingressparity's own
// package doc states the stronger claim "本番コードから import されない
// こと" (no production binary, not just auth-policy/collector), so this
// test checks scoreboard too — the one binary that actually imports
// ingressparity from its OWN test files
// (internal/scoreboard/ingress_journey_parity_test.go), making it the most
// likely of the three to accidentally gain a non-test import if someone
// ever "simplified" that test file's helpers into a production-reachable
// spot.
func TestNoProductionBinaryImportsIngressParity(t *testing.T) {
	root := repoRoot(t)
	for _, cmd := range []string{"auth-policy", "collector", "scoreboard"} {
		t.Run(cmd, func(t *testing.T) {
			closure := transitiveModuleImports(t, root, modulePrefix+"cmd/"+cmd)
			if closure[ingressparityImportPath] {
				t.Fatalf("cmd/%s's module-internal import closure includes %s — a production binary must never import the test-only ingress-coverage package (ADR-0021 / internal/apispec/ingressparity's own package doc: a yaml.v3 + os/exec dependency has no business in a distroless service's SBOM for zero runtime benefit)", cmd, ingressparityImportPath)
			}
		})
	}
}

// mustWriteGoFile creates dir (and parents) and writes a .go file named name
// with the given content — a minimal synthetic-package builder for the
// mutation-proof tests below. The written file is never actually built by
// `go build`; only importsOf's parser.ImportsOnly pass ever reads it.
func mustWriteGoFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s/%s: %v", dir, name, err)
	}
}

// TestNoProductionBinaryImportsSpecparity_CatchesTransitiveImport is
// Requirement 5's own V8 proof (final review round): it builds a synthetic,
// two-hop chain — cmd/fakebin imports internal/fixture-a, which imports
// internal/apispec/specparity — entirely under a t.TempDir(), and asserts
// transitiveModuleImports follows BOTH hops and reports specparity in the
// closure. This is deliberately multi-hop (not a direct
// cmd/fakebin -> specparity import) because the real risk this Requirement
// closes is exactly a TRANSITIVE pull-in (a helper package cmd/auth-policy
// already depends on later growing a specparity import), not cmd/*
// importing it directly (which R1's repro used route.go itself for, a
// single-hop case TestNoProductionBinaryImportsSpecparity's real-repo run
// already covers as "currently absent").
func TestNoProductionBinaryImportsSpecparity_CatchesTransitiveImport(t *testing.T) {
	root := t.TempDir()
	mustWriteGoFile(t, filepath.Join(root, "cmd", "fakebin"), "main.go",
		`package main

import _ "`+modulePrefix+`internal/fixture-a"

func main() {}
`)
	mustWriteGoFile(t, filepath.Join(root, "internal", "fixture-a"), "a.go",
		`package fixturea

import _ "`+specparityImportPath+`"
`)
	closure := transitiveModuleImports(t, root, modulePrefix+"cmd/fakebin")
	if !closure[specparityImportPath] {
		t.Fatalf("expected the synthetic cmd/fakebin -> internal/fixture-a -> %s chain to be found in the closure, got %v", specparityImportPath, closure)
	}
}

// allImportsOf is importsOf's (mux_ownership_test.go) unfiltered sibling: it
// returns EVERY import path (stdlib, third-party, and module-internal alike)
// referenced anywhere in dir's non-test .go files, because
// TestInternalApispecIsStdlibOnly below needs to see third-party imports
// too — importsOf deliberately filters those out (it only cares about the
// module-internal import graph for V6/V2's BFS purposes).
func allImportsOf(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var out []string
	for _, path := range nonTestGoFiles(t, dir) {
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse imports of %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			out = append(out, strings.Trim(imp.Path.Value, `"`))
		}
	}
	return out
}

// isStdlibImportPath reports whether path looks like a standard-library
// import: every third-party or module-internal Go import path names a host
// in its first path segment, which — by convention every registry (pkg.go.dev,
// GOPROXY, module paths) relies on — always contains a '.' (a domain name:
// "github.com", "gopkg.in", "golang.org", this module's own
// "github.com/Qfour/falco-ctf-app"). No standard-library import path's first
// segment ever contains a '.' ("net/http", "encoding/json", "os", ...). This
// is the same rule `go list -deps` effectively relies on via module
// resolution, applied here as plain string inspection so no `go` toolchain
// invocation (and no network) is needed inside `make test`'s container.
func isStdlibImportPath(path string) bool {
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return !strings.Contains(first, ".")
}

// TestIsStdlibImportPath_MechanicalDetermination pins isStdlibImportPath
// against known-good/known-bad cases (ADR-0005 V8's "prove the detector
// isn't vacuous" discipline applied to this new primitive).
func TestIsStdlibImportPath_MechanicalDetermination(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"net/http", true},
		{"encoding/json", true},
		{"os", true},
		{"path/filepath", true},
		{"gopkg.in/yaml.v3", false},
		{"github.com/prometheus/client_golang/prometheus", false},
		{specparityImportPath, false},
	}
	for _, c := range cases {
		if got := isStdlibImportPath(c.path); got != c.want {
			t.Errorf("isStdlibImportPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestInternalApispecIsStdlibOnly is Requirement 5(a)'s second half:
// internal/apispec's own NON-TEST files (route.go today; *_test.go files are
// exempt by construction, matching specparity's real callers) must import
// nothing but the standard library — route.go's own package doc names this
// as the reason the specparity split exists at all (BLOCKING 1, 5x review:
// a yaml.v3 import anywhere in this directory widens both distroless
// services' build, because Go compiles every non-test .go file in a
// directory as one unit).
func TestInternalApispecIsStdlibOnly(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "apispec")
	imports := allImportsOf(t, dir)
	if len(imports) == 0 {
		t.Fatal("internal/apispec's non-test files import nothing at all — extraction is broken (route.go imports net/http), not clean")
	}
	var bad []string
	for _, imp := range imports {
		if !isStdlibImportPath(imp) {
			bad = append(bad, imp)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("internal/apispec's non-test files import non-stdlib packages: %v — this package must stay buildable with nothing but the stdlib (route.go's own package doc); move YAML/spec-comparison logic into the sibling specparity package instead, imported only from *_test.go files", bad)
	}
}

// TestInternalApispecIsStdlibOnly_CatchesNonStdlibImport is this check's own
// V8 proof: a synthetic internal/apispec-shaped directory with a non-test
// file importing gopkg.in/yaml.v3 must be flagged by allImportsOf +
// isStdlibImportPath together.
func TestInternalApispecIsStdlibOnly_CatchesNonStdlibImport(t *testing.T) {
	dir := t.TempDir()
	mustWriteGoFile(t, dir, "leaky.go", `package apispec

import "gopkg.in/yaml.v3"

var _ = yaml.Marshal
`)
	imports := allImportsOf(t, dir)
	var bad []string
	for _, imp := range imports {
		if !isStdlibImportPath(imp) {
			bad = append(bad, imp)
		}
	}
	if len(bad) != 1 || bad[0] != "gopkg.in/yaml.v3" {
		t.Fatalf("expected exactly one flagged import [gopkg.in/yaml.v3], got %v", bad)
	}
}
