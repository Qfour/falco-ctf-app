package apispec

// ADR-0035 D4 (a) / V2: no test-only module (chromedp, goja and its transitive
// dependencies, internal/e2e, ...) may be in a production binary's dependency
// graph. e2e_boundary_test.go checks the static import closure of cmd/* with
// go/parser; this file asks the toolchain: `go list -deps ./cmd/...` is the graph
// `go build` links, and none of the entries of testdata/test-only-deps.txt (the
// ONE list, read by both) may be in it. The list is checked both ways: an entry
// that names nothing in go.mod or in the module is red (stale), and a module that
// only tests reach and no entry names (the module itself, or a path under it; an
// org prefix is not enough) is red (complete). Each check also runs on a planted
// violation through the real toolchain: a synthetic module with this go.mod and
// go.sum, so `go list` resolves the real modules from the cache.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

const testOnlyDepsFile = "internal/apispec/testdata/test-only-deps.txt"

// parseTestOnlyDeps returns the import-path prefixes in the list's text: one per
// line, `#` starts a comment, a trailing `/` is dropped.
func parseTestOnlyDeps(text string) []string {
	var deps []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSuffix(strings.TrimSpace(line), "/")
		if line != "" {
			deps = append(deps, line)
		}
	}
	return deps
}

// loadTestOnlyDeps reads the single list. An empty list is an error: it would
// make every check below pass on nothing.
func loadTestOnlyDeps(t *testing.T, root string) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, testOnlyDepsFile))
	if err != nil {
		t.Fatalf("the test-only dependency list is unreadable: %v", err)
	}
	deps := parseTestOnlyDeps(string(src))
	if len(deps) == 0 {
		t.Fatalf("%s has no entry — the list is the single source of ADR-0035 D4 (a); an empty list checks nothing", testOnlyDepsFile)
	}
	return deps
}

func hasPathPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// testOnlyHits returns, sorted and without duplicates, the paths that a prefix in
// deps matches.
func testOnlyHits(paths, deps []string) []string {
	seen := map[string]bool{}
	for _, p := range paths {
		for _, d := range deps {
			if hasPathPrefix(p, d) {
				seen[p] = true
				break
			}
		}
	}
	hits := make([]string, 0, len(seen))
	for p := range seen {
		hits = append(hits, p)
	}
	sort.Strings(hits)
	return hits
}

// goModRequires returns the module paths go.mod requires (direct and indirect).
func goModRequires(t *testing.T, root string) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var reqs []string
	inBlock := false
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case line == "require (":
			inBlock = true
			continue
		case line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimPrefix(line, "require ")
		case !inBlock:
			continue
		}
		if f := strings.Fields(line); len(f) == 2 && strings.HasPrefix(f[1], "v") {
			reqs = append(reqs, f[0])
		}
	}
	if len(reqs) == 0 {
		t.Fatal("go.mod has no require — the parse is broken, and an empty set would call every list entry stale")
	}
	return reqs
}

// staleTestOnlyEntries returns the list entries that name nothing: a module-
// internal entry whose directory does not exist, or an external one that no
// require of go.mod is at or under.
func staleTestOnlyEntries(deps, requires []string, dirExists func(rel string) bool) []string {
	local := strings.TrimSuffix(modulePrefix, "/")
	var stale []string
	for _, d := range deps {
		if hasPathPrefix(d, local) {
			if !dirExists(strings.TrimPrefix(strings.TrimPrefix(d, local), "/")) {
				stale = append(stale, d)
			}
			continue
		}
		found := false
		for _, r := range requires {
			if hasPathPrefix(r, d) {
				found = true
				break
			}
		}
		if !found {
			stale = append(stale, d)
		}
	}
	return stale
}

func TestTestOnlyDepsList_HasNoStaleEntry(t *testing.T) {
	root := repoRoot(t)
	deps := loadTestOnlyDeps(t, root)
	isDir := func(rel string) bool {
		fi, err := os.Stat(filepath.Join(root, rel))
		return err == nil && fi.IsDir()
	}
	if stale := staleTestOnlyEntries(deps, goModRequires(t, root), isDir); len(stale) > 0 {
		t.Fatalf("%s entries that name nothing in go.mod or in this module: %v — delete them (an old entry keeps looking like protection; ADR-0035 D4 (a))", testOnlyDepsFile, stale)
	}
}

func TestStaleTestOnlyEntryDetector_CatchesPlantedEntries(t *testing.T) {
	requires := []string{"github.com/dop251/goja", "github.com/dlclark/regexp2/v2"}
	exists := func(rel string) bool { return rel == "internal/e2e" }
	local := strings.TrimSuffix(modulePrefix, "/")
	cases := []struct {
		name string
		deps []string
		want []string
	}{
		{"every entry resolves", []string{"github.com/dop251", "github.com/dlclark/regexp2", local + "/internal/e2e"}, nil},
		{"a module removed from go.mod", []string{"github.com/dop251", "github.com/gone/module"}, []string{"github.com/gone/module"}},
		{"a directory removed from the module", []string{local + "/internal/e2e", local + "/internal/removed"}, []string{local + "/internal/removed"}},
		{"a sibling name is not a match", []string{"github.com/dop25"}, []string{"github.com/dop25"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := staleTestOnlyEntries(c.deps, requires, exists)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("stale = %v, want %v", got, c.want)
			}
		})
	}
}

// goList runs `go list args...` in dir and returns the non-empty output lines.
// A missing toolchain or a failing list is a test failure, never an empty graph:
// an empty graph has no test-only module in it.
func goList(t *testing.T, dir string, args ...string) []string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("go is not on PATH, so the real dependency graph cannot be read (ADR-0035 D4 (a)): %v", err)
	}
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Dir = dir
	// The production images build with CGO_ENABLED=0; GOTOOLCHAIN=local keeps the
	// check from downloading a toolchain; GOWORK=off keeps a stray go.work out.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s (in %s): %v\n%s", strings.Join(args, " "), dir, err, stderr.String())
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// productionGraph is the import path of every package `go build ./cmd/...` links
// (and of the standard library below them), for the given extra go list flags
// (e.g. -tags e2e).
func productionGraph(t *testing.T, dir string, flags ...string) []string {
	t.Helper()
	args := append(append([]string{}, flags...), "-deps", "-f", "{{.ImportPath}}", "./cmd/...")
	return goList(t, dir, args...)
}

func TestProductionBinaryGraphHasNoTestOnlyDependency(t *testing.T) {
	root := repoRoot(t)
	deps := loadTestOnlyDeps(t, root)
	names := cmdNames(t, root)
	if len(names) == 0 {
		t.Fatal("cmd/ has no binary directory — the enumeration is broken, and checking nothing proves nothing")
	}
	// Plain, and with the e2e tag: a tagged file in a cmd/ package would bring the
	// harness into a build that passes -tags e2e.
	for _, flags := range [][]string{nil, {"-tags", "e2e"}} {
		graph := productionGraph(t, root, flags...)
		// The graph is the graph of the binaries: each cmd/ package is in it, and so
		// is the standard library. A list that came back without them was read from
		// the wrong place.
		in := map[string]bool{}
		for _, p := range graph {
			in[p] = true
		}
		for _, n := range names {
			if !in[modulePrefix+"cmd/"+n] {
				t.Fatalf("go list %v -deps ./cmd/... does not list cmd/%s (%d packages) — the graph was not read", flags, n, len(graph))
			}
		}
		if !in["net/http"] {
			t.Fatalf("go list %v -deps ./cmd/... has no net/http (%d packages) — the graph was not read", flags, len(graph))
		}
		if hits := testOnlyHits(graph, deps); len(hits) > 0 {
			t.Fatalf("go list %v -deps ./cmd/... includes test-only packages %v — a production binary must never link a test-only dependency (%s; ADR-0035 D4 (a), ADR-0031 V4)", flags, hits, testOnlyDepsFile)
		}
	}
}

// uncoveredTestOnlyModules returns the modules a test reaches that no production
// binary does and that no entry of deps covers. The module's own packages are not
// modules to list (internal/e2e is covered by its own entry, checked by import
// path above).
func uncoveredTestOnlyModules(testModules, prodModules, deps []string) []string {
	prod := map[string]bool{}
	for _, m := range prodModules {
		prod[m] = true
	}
	own := strings.TrimSuffix(modulePrefix, "/")
	seen := map[string]bool{}
	for _, m := range testModules {
		if prod[m] || m == own || seen[m] {
			continue
		}
		// Covered only by an entry that IS the module or lies under it: an entry at an
		// org (github.com/dop251) must not silently cover a sibling module added later.
		covered := false
		for _, d := range deps {
			if hasPathPrefix(d, m) {
				covered = true
				break
			}
		}
		if !covered {
			seen[m] = true
		}
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func moduleOfEveryPackage(t *testing.T, dir string, flags ...string) []string {
	t.Helper()
	args := append(append([]string{}, flags...), "-deps", "-f", "{{with .Module}}{{.Path}}{{end}}", "./...")
	return goList(t, dir, args...)
}

func TestTestOnlyDepsList_CoversEveryTestOnlyModule(t *testing.T) {
	root := repoRoot(t)
	deps := loadTestOnlyDeps(t, root)
	prod := goList(t, root, "-deps", "-f", "{{with .Module}}{{.Path}}{{end}}", "./cmd/...")
	// Every package of the module, its tests, and the e2e-tagged harness.
	tests := moduleOfEveryPackage(t, root, "-test", "-tags", "e2e")
	if len(prod) == 0 || len(tests) <= len(prod) {
		t.Fatalf("the module sets were not read (production %d, with tests %d) — comparing them proves nothing", len(prod), len(tests))
	}
	if missing := uncoveredTestOnlyModules(tests, prod, deps); len(missing) > 0 {
		t.Fatalf("modules that only tests reach and %s does not name: %v — a NEW DIRECT test-only dependency needs its own ADR until workspace #77 is decided (ORGANIZATION §8 criterion 4; ADR-0035 基準④との関係); a transitive dependency that an approved one gained in an update may, provisionally, be added to the list with the D4 table in the PR body (VP ruling)", testOnlyDepsFile, missing)
	}
}

func TestUncoveredTestOnlyModules_CatchesAnUnlistedModule(t *testing.T) {
	deps := []string{"github.com/dop251/goja", "github.com/dlclark/regexp2/v2"}
	prod := []string{"github.com/Qfour/falco-ctf-app", "golang.org/x/net"}
	tests := []string{"github.com/Qfour/falco-ctf-app", "golang.org/x/net", "github.com/dop251/goja", "github.com/dlclark/regexp2/v2", "github.com/go-sourcemap/sourcemap", "github.com/dop251/goja"}
	got := uncoveredTestOnlyModules(tests, prod, deps)
	if len(got) != 1 || got[0] != "github.com/go-sourcemap/sourcemap" {
		t.Fatalf("uncovered = %v, want exactly [github.com/go-sourcemap/sourcemap] (a goja dependency the list forgot)", got)
	}
	if got := uncoveredTestOnlyModules(tests, append(prod, "github.com/go-sourcemap/sourcemap"), deps); len(got) != 0 {
		t.Fatalf("a module the production graph already has is not test-only: uncovered = %v", got)
	}
	if got := uncoveredTestOnlyModules(tests, prod, append(deps, "github.com/go-sourcemap/sourcemap")); len(got) != 0 {
		t.Fatalf("a listed module is covered: uncovered = %v", got)
	}
	// An org entry is not a module entry: a sibling module under the same org (here
	// goja_nodejs, next to the listed goja) is uncovered until it is named itself.
	sibling := append(append([]string{}, tests...), "github.com/dop251/goja_nodejs")
	got = uncoveredTestOnlyModules(sibling, prod, append(deps, "github.com/go-sourcemap/sourcemap"))
	if len(got) != 1 || got[0] != "github.com/dop251/goja_nodejs" {
		t.Fatalf("uncovered = %v, want exactly [github.com/dop251/goja_nodejs]", got)
	}
	if got := uncoveredTestOnlyModules(sibling, prod, []string{"github.com/dop251", "github.com/dlclark/regexp2/v2", "github.com/go-sourcemap/sourcemap"}); len(got) != 2 {
		t.Fatalf("an org-level entry covered a module: uncovered = %v, want goja and goja_nodejs", got)
	}
}

// plantedModule makes a synthetic module that has this module's path, go.mod and
// go.sum (so `go list` resolves the real chromedp / goja / ... from the module
// cache) and the given files.
func plantedModule(t *testing.T, root string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum"} {
		src, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), src, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for rel, src := range files {
		mustWriteGoFile(t, filepath.Dir(filepath.Join(dir, rel)), filepath.Base(rel), src)
	}
	return dir
}

// Planted violations through the real toolchain: the import is direct, goes
// through an ordinary package, names a goja dependency, or sits behind a build
// tag. Each must be flagged; a clean binary must not be.
func TestRealGraphDetector_CatchesPlantedImports(t *testing.T) {
	root := repoRoot(t)
	deps := loadTestOnlyDeps(t, root)
	mainImporting := func(imp string) string {
		return "package main\n\nimport _ \"" + imp + "\"\n\nfunc main() {}\n"
	}
	cases := []struct {
		name  string
		files map[string]string
		flags []string
		want  []string // import paths that must all be flagged; empty = nothing may be
	}{
		{"goja imported directly by the binary", map[string]string{
			"cmd/fakebin/main.go": mainImporting("github.com/dop251/goja"),
		}, nil, []string{"github.com/dop251/goja"}},
		{"goja reached through a non-test file of an internal package", map[string]string{
			"cmd/fakebin/main.go":     mainImporting(modulePrefix + "internal/fixture-a"),
			"internal/fixture-a/a.go": "package fixturea\n\nimport _ \"github.com/dop251/goja\"\n",
		}, nil, []string{"github.com/dop251/goja"}},
		{"goja's dependencies imported directly (regexp2, sourcemap, pprof)", map[string]string{
			"cmd/fakebin/main.go": "package main\n\nimport (\n\t_ \"github.com/dlclark/regexp2/v2\"\n\t_ \"github.com/go-sourcemap/sourcemap\"\n\t_ \"github.com/google/pprof/profile\"\n)\n\nfunc main() {}\n",
		}, nil, []string{"github.com/dlclark/regexp2/v2", "github.com/go-sourcemap/sourcemap", "github.com/google/pprof/profile"}},
		{"the E2E harness reached through two hops", map[string]string{
			"cmd/fakebin/main.go":       mainImporting(modulePrefix + "internal/fixture-a"),
			"internal/fixture-a/a.go":   "package fixturea\n\nimport _ \"" + modulePrefix + "internal/fixture-b\"\n",
			"internal/fixture-b/b.go":   "package fixtureb\n\nimport _ \"" + modulePrefix + "internal/e2e/harness\"\n",
			"internal/e2e/harness/h.go": "package harness\n",
		}, nil, []string{modulePrefix + "internal/e2e/harness"}},
		{"chromedp behind the e2e build tag, built with -tags e2e", map[string]string{
			"cmd/fakebin/main.go": "package main\n\nfunc main() {}\n",
			"cmd/fakebin/e2e.go":  "//go:build e2e\n\npackage main\n\nimport _ \"github.com/chromedp/chromedp\"\n",
		}, []string{"-tags", "e2e"}, []string{"github.com/chromedp/chromedp"}},
		{"an e2e-tagged file in a build that does not pass the tag (the tag keeps test-only code out of an ordinary build)", map[string]string{
			"cmd/fakebin/main.go": "package main\n\nfunc main() {}\n",
			"cmd/fakebin/e2e.go":  "//go:build e2e\n\npackage main\n\nimport _ \"github.com/chromedp/chromedp\"\n",
		}, nil, nil},
		{"a clean binary", map[string]string{
			"cmd/fakebin/main.go": mainImporting("net/http"),
		}, nil, nil},
		{"a clean binary whose test file imports goja", map[string]string{
			"cmd/fakebin/main.go":      "package main\n\nfunc main() {}\n",
			"cmd/fakebin/main_test.go": "package main\n\nimport (\n\t_ \"github.com/dop251/goja\"\n\t\"testing\"\n)\n\nfunc TestX(t *testing.T) {}\n",
		}, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := plantedModule(t, root, c.files)
			graph := productionGraph(t, dir, c.flags...)
			hits := testOnlyHits(graph, deps)
			if len(c.want) == 0 {
				if len(hits) != 0 {
					t.Fatalf("a clean binary was flagged: %v", hits)
				}
				return
			}
			for _, w := range c.want {
				if !slices.Contains(hits, w) {
					t.Errorf("planted import of %s not flagged; hits = %v (graph has %d packages)", w, hits, len(graph))
				}
			}
		})
	}
}

// The completeness check through the real toolchain: a module that only a test
// file imports (kylelemons/godebug is a real test-only module of this repo) is
// uncovered while its entry is missing and covered once it is named; the same
// import in the binary's own file puts it in the production graph instead.
func TestCompletenessCheck_CatchesAPlantedTestOnlyModule(t *testing.T) {
	root := repoRoot(t)
	deps := loadTestOnlyDeps(t, root)
	const mod = "github.com/kylelemons/godebug"
	var without []string
	for _, d := range deps {
		if d != mod {
			without = append(without, d)
		}
	}
	if len(without) == len(deps) {
		t.Fatalf("%s is not an entry of the list; this planted case needs a real test-only module", mod)
	}
	const modFmt = "{{with .Module}}{{.Path}}{{end}}"
	read := func(dir string) (prod, tests []string) {
		return goList(t, dir, "-deps", "-f", modFmt, "./cmd/..."), moduleOfEveryPackage(t, dir, "-test", "-tags", "e2e")
	}

	dir := plantedModule(t, root, map[string]string{
		"cmd/fakebin/main.go":      "package main\n\nfunc main() {}\n",
		"cmd/fakebin/main_test.go": "package main\n\nimport (\n\t_ \"" + mod + "/diff\"\n\t\"testing\"\n)\n\nfunc TestX(t *testing.T) {}\n",
	})
	prod, tests := read(dir)
	if got := uncoveredTestOnlyModules(tests, prod, without); len(got) != 1 || got[0] != mod {
		t.Fatalf("a module only a test imports, with no entry: uncovered = %v, want [%s]", got, mod)
	}
	if got := uncoveredTestOnlyModules(tests, prod, deps); len(got) != 0 {
		t.Fatalf("the module is named in the list but uncovered = %v", got)
	}

	dir = plantedModule(t, root, map[string]string{
		"cmd/fakebin/main.go": "package main\n\nimport _ \"" + mod + "/diff\"\n\nfunc main() {}\n",
	})
	prod, tests = read(dir)
	if len(testOnlyHits(productionGraph(t, dir), deps)) == 0 {
		t.Fatal("the import moved into main.go is not flagged by the production-graph check")
	}
	if got := uncoveredTestOnlyModules(tests, prod, without); len(got) != 0 {
		t.Fatalf("a module in the production graph is not test-only (that check is the graph's): uncovered = %v", got)
	}
}
