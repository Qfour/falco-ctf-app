package apispec

// ADR-0005 V6: every http.ServeMux-owning binary must have a
// docs/openapi-*.yaml. "Owns a ServeMux" is determined MECHANICALLY here
// (a source-level BFS for http.NewServeMux(), starting at cmd/<name> and
// following this module's own import graph) rather than by a hand-authored
// allow/deny list — ttyd-proxy's exclusion is a computed fact, not a
// judgment call baked into the test (ADR-0005 Decision 2).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const modulePrefix = "github.com/Qfour/falco-ctf-app/"

// repoRoot locates the module root by walking up from this test file's own
// directory until a go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — cannot locate this test file")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod walking up from %s", thisFile)
		}
		dir = parent
	}
}

// nonTestGoFiles lists the non-test .go files directly inside dir (no
// recursion into subdirectories — Go packages are per-directory).
func nonTestGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out
}

// importsOf returns the module-internal import paths (starting with
// modulePrefix) referenced anywhere in dir's non-test .go files.
func importsOf(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var out []string
	for _, path := range nonTestGoFiles(t, dir) {
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse imports of %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(p, modulePrefix) {
				out = append(out, p)
			}
		}
	}
	return out
}

// declaresServeMux reports whether dir's non-test .go files contain a
// direct http.NewServeMux() call expression.
func declaresServeMux(t *testing.T, dir string) bool {
	t.Helper()
	fset := token.NewFileSet()
	for _, path := range nonTestGoFiles(t, dir) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "http" && sel.Sel.Name == "NewServeMux" {
				found = true
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// cmdOwnsServeMux answers ADR-0005 Decision 2's rule by breadth-first
// walking the module-internal import graph starting at cmd/<name>, checking
// every visited package directory for a direct http.NewServeMux() call.
func cmdOwnsServeMux(t *testing.T, root, cmdName string) bool {
	t.Helper()
	start := modulePrefix + "cmd/" + cmdName
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
		if declaresServeMux(t, dir) {
			return true
		}
		queue = append(queue, importsOf(t, dir)...)
	}
	return false
}

// TestCmdOwnsServeMux_MechanicalDetermination pins the mechanism itself
// against known-good/known-bad cases (ADR-0005 V8's "prove the detector
// isn't vacuous", applied to V6's ownership rule): the three real HTTP
// services must be detected as mux-owning, and ttyd-proxy (a catch-all
// reverse proxy with no mux, internal/ttydproxy/ttydproxy.go:151) and
// gen-home-fragments (an offline codegen tool, no net/http at all) must be
// detected as NOT mux-owning.
func TestCmdOwnsServeMux_MechanicalDetermination(t *testing.T) {
	root := repoRoot(t)
	cases := []struct {
		cmd  string
		want bool
	}{
		{"scoreboard", true},
		{"collector", true},
		{"auth-policy", true},
		{"ttyd-proxy", false},
		{"gen-home-fragments", false},
	}
	for _, c := range cases {
		t.Run(c.cmd, func(t *testing.T) {
			if got := cmdOwnsServeMux(t, root, c.cmd); got != c.want {
				t.Fatalf("cmdOwnsServeMux(%s) = %v, want %v", c.cmd, got, c.want)
			}
		})
	}
}

// specNameForCmd maps a mux-owning cmd/<name> to its docs/openapi-<x>.yaml
// file name. This is NOT an exclusion list of binaries (ownership itself
// stays mechanical, above) — it only covers the case where a future
// binary's directory name and spec file name diverge; a binary with no
// entry here still fails loudly (see the test below), it does not silently
// pass.
var specNameForCmd = map[string]string{
	"scoreboard":  "openapi-scoreboard.yaml",
	"collector":   "openapi-collector.yaml",
	"auth-policy": "openapi-auth-policy.yaml",
}

// TestSpecExistsForEveryMuxOwningBinary is ADR-0005 V6: it enumerates
// cmd/*, mechanically determines (via cmdOwnsServeMux) which ones own an
// http.ServeMux, and fails if any such binary has no corresponding
// docs/openapi-*.yaml. A non-mux-owning binary (ttyd-proxy,
// gen-home-fragments today) is skipped, not excluded by name — a future
// binary added under cmd/ automatically gets this check for free.
func TestSpecExistsForEveryMuxOwningBinary(t *testing.T) {
	root := repoRoot(t)
	cmdDir := filepath.Join(root, "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read cmd dir: %v", err)
	}
	sawAny := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			if !cmdOwnsServeMux(t, root, name) {
				t.Skipf("cmd/%s does not build an http.ServeMux (mechanically determined) — no spec required", name)
			}
			sawAny = true
			specFile, known := specNameForCmd[name]
			if !known {
				t.Fatalf("cmd/%s owns a ServeMux but has no entry in specNameForCmd — add docs/openapi-%s.yaml and map it there", name, name)
			}
			path := filepath.Join(root, "docs", specFile)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("cmd/%s owns a ServeMux but %s does not exist: %v", name, path, err)
			}
		})
	}
	// Non-empty-result guard (ADR-0005 V8-2): if cmd/ enumeration or the
	// ownership walk silently returned nothing, this test would be a
	// permanent no-op. Fail loudly instead.
	if !sawAny {
		t.Fatal("no mux-owning cmd/* binary was found at all — the enumeration or ownership walk is broken (this check must never be a silent no-op)")
	}
}
