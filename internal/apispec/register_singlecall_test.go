package apispec

// ADR-0005 V2's second blocking design constraint (Requirement 3, R4 F1,
// final review round — VP's own repro): TestNoDirectMuxRegistrationOutsideTable
// (staticreg_test.go) guarantees every ROUTE goes through apispec.Register,
// but it says nothing about whether the TABLE that reaches Register is the
// WHOLE table. VP proved the gap: adding
//
//	apispec.Register(h.mux, sneakyRoutes)
//
// immediately after the real `h.routes = apispec.Register(h.mux, declared)`
// line, with the second call's return value discarded, put a spec-less,
// origin-guard-less POST route on the live production mux while every
// ADR-0005 V1-V4 check stayed green (17 ok lines, 0 FAIL, exit 0) — every
// existing check reads Handler.Routes() (== h.routes, the FIRST call's
// return value) as "the" route set, so a second call's routes are on the
// mux but invisible to every parity check. staticreg_test.go cannot see this
// either: route.go — where apispec.Register's own mux.Handle call lives — is
// its ONE named exclusion, and a second apispec.Register call site is,
// syntactically, just another ordinary function call in the calling
// package, not a mux.Handle/HandleFunc reference.
//
// This closes that gap directly: per mux-owning package (declaresServeMux ==
// true, the SAME mechanical predicate V6 — mux_ownership_test.go — uses to
// decide which binaries need a docs/openapi-*.yaml), at most ONE call to
// apispec.Register may exist across that package's non-test .go files, and
// that call's return value may never be discarded (a bare *ast.ExprStmt) —
// a discarded return is itself the smell: every legitimate call site
// (scoreboard/server.go, internal/collector/collector.go,
// internal/authpolicy/server.go) stores the returned installed-subset as
// h.routes specifically so Routes() reports what the mux ACTUALLY serves,
// not what a table merely claimed to install (route.go's own Register doc).
// A second, discarding call has no such feedback loop at all — nothing
// downstream of it can ever learn those routes exist.

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

// apispecImportPath is this package's own module-qualified import path — the
// thing a mux-owning package's Register call site must be selecting off of
// ("apispec.Register", or through an aliased import).
const apispecImportPath = modulePrefix + "internal/apispec"

// importLocalNames returns the local identifier(s) f's import block binds
// path to. Unlike mux_ownership_test.go's httpLocalNames (hardcoded to
// net/http's "http" default), this derives the unaliased default from
// path's own last segment, so it works for any single import path, not just
// net/http.
func importLocalNames(f *ast.File, path string) map[string]bool {
	out := map[string]bool{}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if p != path {
			continue
		}
		switch {
		case imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != ".":
			out[imp.Name.Name] = true
		case imp.Name == nil:
			parts := strings.Split(p, "/")
			out[parts[len(parts)-1]] = true
		}
	}
	return out
}

// muxOwningPackageDirs mechanically enumerates every package directory
// that ITSELF declares/constructs an http.ServeMux (declaresServeMux ==
// true — mux_ownership_test.go's V6 predicate), walking the same
// mux-owning-cmd/* import-graph BFS scanTargets (staticreg_test.go) already
// performs. A route-table sub-package that only HANDS its Routes() up to a
// parent (api/view/ingest) is deliberately excluded from this set — it
// never itself holds a mux, so it structurally cannot be the site of a
// second Register call; only the package holding h.mux can be.
func muxOwningPackageDirs(t *testing.T, root string) []string {
	t.Helper()
	cmdDir := filepath.Join(root, "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read cmd dir: %v", err)
	}
	visited := map[string]bool{}
	seenOwning := map[string]bool{}
	var owning []string
	for _, e := range entries {
		if !e.IsDir() || !cmdOwnsServeMux(t, root, e.Name()) {
			continue
		}
		queue := []string{modulePrefix + "cmd/" + e.Name()}
		for len(queue) > 0 {
			pkg := queue[0]
			queue = queue[1:]
			if visited[pkg] {
				continue
			}
			visited[pkg] = true
			dir := filepath.Join(root, strings.TrimPrefix(pkg, modulePrefix))
			if declaresServeMux(t, dir) && !seenOwning[dir] {
				seenOwning[dir] = true
				owning = append(owning, dir)
			}
			queue = append(queue, importsOf(t, dir)...)
		}
	}
	sort.Strings(owning)
	return owning
}

// registerCallSites parses path and returns every call-site position
// ("file:line:col") whose selector resolves — via apispecImportPath's local
// import name(s) — to Register, split into ALL such sites (calls) and the
// subset that sits directly inside a bare *ast.ExprStmt, i.e. a call whose
// return value is discarded (discarded).
func registerCallSites(t *testing.T, fset *token.FileSet, path string) (calls, discarded []string) {
	t.Helper()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	names := importLocalNames(f, apispecImportPath)
	if len(names) == 0 {
		return nil, nil
	}
	isRegisterCall := func(call *ast.CallExpr) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		ident, ok := sel.X.(*ast.Ident)
		return ok && names[ident.Name] && sel.Sel.Name == "Register"
	}
	// Two independent full-tree walks (rather than one, sharing state across
	// both a CallExpr visit and its enclosing ExprStmt visit) deliberately:
	// ast.Inspect visits a CallExpr's own node AND, separately, any node
	// wrapping it (its ExprStmt, if any) — sharing one pass would either
	// double-count a discarded call (once via the ExprStmt branch, once via
	// the CallExpr branch as Inspect descends into ExprStmt.X) or require
	// extra bookkeeping to avoid it. Two single-purpose walks are simpler and
	// cannot double-count.
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isRegisterCall(call) {
			calls = append(calls, fset.Position(call.Pos()).String())
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		stmt, ok := n.(*ast.ExprStmt)
		if !ok {
			return true
		}
		if call, ok := stmt.X.(*ast.CallExpr); ok && isRegisterCall(call) {
			discarded = append(discarded, fset.Position(call.Pos()).String())
		}
		return true
	})
	return calls, discarded
}

// TestApispecRegisterSingleCallPerMuxOwningPackage is Requirement 3 (R4 F1,
// final review round) — see the package-level doc above for the exploit this
// closes.
func TestApispecRegisterSingleCallPerMuxOwningPackage(t *testing.T) {
	root := repoRoot(t)
	dirs := muxOwningPackageDirs(t, root)
	if len(dirs) == 0 {
		t.Fatal("muxOwningPackageDirs returned zero packages — the BFS/declaresServeMux mechanism is broken (this check must never be a silent no-op, ADR-0005 V8-2)")
	}

	sawAnyRegisterCall := false
	for _, dir := range dirs {
		dir := dir
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			rel = dir
		}
		t.Run(rel, func(t *testing.T) {
			fset := token.NewFileSet()
			var allCalls, allDiscarded []string
			for _, path := range nonTestGoFiles(t, dir) {
				calls, discarded := registerCallSites(t, fset, path)
				allCalls = append(allCalls, calls...)
				allDiscarded = append(allDiscarded, discarded...)
			}
			if len(allCalls) == 0 {
				return // this mux-owning package doesn't itself call Register — nothing to check here.
			}
			sawAnyRegisterCall = true
			if len(allCalls) > 1 {
				t.Fatalf("package %s calls apispec.Register %d times: %v — a mux-owning package must call it exactly once (ADR-0005 V2; a second call installs routes no V1-V4 check ever sees, because every check reads Handler.Routes(), which is only the FIRST call's return value)", rel, len(allCalls), allCalls)
			}
			if len(allDiscarded) > 0 {
				t.Fatalf("package %s calls apispec.Register with its return value discarded: %v — capture and store the returned installed-subset (see the real call sites' own h.routes = apispec.Register(...) pattern in scoreboard/server.go, internal/collector/collector.go, internal/authpolicy/server.go): a discarded return means whatever that call installs is invisible to Routes() and therefore to every ADR-0005 parity check", rel, allDiscarded)
			}
		})
	}
	if !sawAnyRegisterCall {
		t.Fatal("no mux-owning package called apispec.Register at all — the detector or the production wiring is broken (this check must never be a silent no-op, ADR-0005 V8-2)")
	}
}

// TestApispecRegisterSingleCall_CatchesSecondDiscardedCall is ADR-0005 V8's
// "prove the detector isn't vacuous" requirement applied to this specific
// check: a synthetic source string containing a SECOND, return-discarding
// apispec.Register call — VP's exact reproduction shape — must be flagged
// both ways (more than one call site, AND at least one discarded) without
// touching any real file.
func TestApispecRegisterSingleCall_CatchesSecondDiscardedCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sneaky.go")
	src := `package fixture

import (
	"net/http"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

type Handler struct {
	mux    *http.ServeMux
	routes []apispec.Route
}

func New() *Handler {
	h := &Handler{mux: http.NewServeMux()}
	declared := []apispec.Route{}
	h.routes = apispec.Register(h.mux, declared)
	// Simulates a sub-handler wired the "natural mistake" way (Requirement
	// 3's framing): registering its OWN routes directly instead of folding
	// them into declared above.
	sneaky := []apispec.Route{{Method: "POST", Pattern: "/sneaky"}}
	apispec.Register(h.mux, sneaky)
	return h
}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	fset := token.NewFileSet()
	calls, discarded := registerCallSites(t, fset, path)
	if len(calls) != 2 {
		t.Fatalf("expected 2 apispec.Register call sites in the fixture, got %d: %v", len(calls), calls)
	}
	if len(discarded) != 1 {
		t.Fatalf("expected exactly 1 discarded (bare ExprStmt) call site, got %d: %v", len(discarded), discarded)
	}
}

// TestApispecRegisterSingleCall_NoFalsePositiveOnCapturedSingleCall pins the
// non-degenerate baseline: a package that calls apispec.Register exactly
// once and stores its return value must report zero calls-that-are-a-
// problem — i.e. registerCallSites must return exactly one call and zero
// discarded, matching every REAL call site in this codebase today.
func TestApispecRegisterSingleCall_NoFalsePositiveOnCapturedSingleCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.go")
	src := `package fixture

import (
	"net/http"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

type Handler struct {
	mux    *http.ServeMux
	routes []apispec.Route
}

func New() *Handler {
	h := &Handler{mux: http.NewServeMux()}
	declared := []apispec.Route{}
	h.routes = apispec.Register(h.mux, declared)
	return h
}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	fset := token.NewFileSet()
	calls, discarded := registerCallSites(t, fset, path)
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 apispec.Register call site, got %d: %v", len(calls), calls)
	}
	if len(discarded) != 0 {
		t.Fatalf("expected zero discarded call sites, got %d: %v", len(discarded), discarded)
	}
}
