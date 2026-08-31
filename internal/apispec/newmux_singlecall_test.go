package apispec

// ADR-0005 V2's second blocking design constraint (Requirement 3, R4 F1,
// final review round: VP's own repro), NOW ADAPTED FOR NewMux (task #146).
//
// The original finding: adding
//
//	apispec.Register(h.mux, sneakyRoutes)
//
// immediately after the real `h.routes = apispec.Register(h.mux, declared)`
// line, with the second call's return value discarded, put a spec-less,
// origin-guard-less POST route on the live production mux while every
// ADR-0005 V1-V4 check stayed green (17 ok lines, 0 FAIL, exit 0) — every
// existing check reads Handler.Routes() (== h.routes, the FIRST call's
// return value) as "the" route set, so a second call's routes were on the
// mux but invisible to every parity check.
//
// Task #146 closed the STRUCTURAL half of this directly: Register (which
// took an existing *http.ServeMux and mutated it) no longer exists at all —
// NewMux(routes) builds its OWN fresh *http.ServeMux every call and hands it
// back. A second call anywhere can therefore only ever produce a second,
// freestanding mux that nothing wires to a listener; it cannot graft routes
// onto the mux already stored in h.mux, because there is no longer any
// function in this codebase that accepts an existing mux to add routes to
// (and staticreg_test.go separately bans any direct mux.Handle/HandleFunc
// call outside route.go, closing the other possible route to the same live
// object). "Write a second Register call that reaches the live mux" is not
// merely detected now — it does not typecheck, because Register's signature
// is gone.
//
// This file is the REMAINING detective half, retained as defense in depth
// for two things NewMux's structural fix does NOT catch on its own:
//
//  1. A second, wasteful/confusing NewMux call in a mux-owning package
//     (harmless to the LIVE mux, since it produces an orphaned second one,
//     but is either dead code or — worse — a sign the author meant to wire
//     it in and forgot, silently 404ing those routes at runtime).
//  2. A PARTIALLY discarded return value: `h.mux, _ = apispec.NewMux(...)`
//     drops the installed-routes half, so h.routes never reflects what the
//     freshly-built h.mux actually serves — the exact "declared vs what the
//     mux truly serves" gap ADR-0005 V1-V4 exists to close, just reopened by
//     careless capture instead of a second call. `_, h.routes =
//     apispec.NewMux(...)` drops the mux half instead, leaving h.mux nil —
//     a guaranteed nil-pointer panic on the first real request, which is
//     loud rather than silent, but still a defect this check can catch at
//     build/test time instead of at runtime.
//
// Per mux-owning package (declaresServeMux == true, the SAME mechanical
// predicate V6 — mux_ownership_test.go — uses to decide which binaries need
// a docs/openapi-*.yaml), at most ONE call to apispec.NewMux may exist
// across that package's non-test .go files, and that call's return values
// may never be discarded — wholly (a bare *ast.ExprStmt) or partially (an
// assignment with the blank identifier `_` in either LHS slot).

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
// thing a mux-owning package's NewMux call site must be selecting off of
// ("apispec.NewMux", or through an aliased import).
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
// second NewMux call; only the package holding h.mux can be.
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

// isBlankIdent reports whether expr is the bare blank identifier `_`.
func isBlankIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "_"
}

// newMuxCallSites parses path and returns every call-site position
// ("file:line:col") whose selector resolves — via apispecImportPath's local
// import name(s) — to NewMux, split into ALL such sites (calls) and the
// subset whose return value(s) are discarded, wholly or partially
// (discarded): either a bare ExprStmt (both the *http.ServeMux and the
// installed-routes return values thrown away), or an assignment where at
// least one of the two LHS targets is the blank identifier `_` (only one of
// {mux, routes} captured — see the package doc above for why BOTH halves of
// a partial discard are real defects, not just style nits).
func newMuxCallSites(t *testing.T, fset *token.FileSet, path string) (calls, discarded []string) {
	t.Helper()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	names := importLocalNames(f, apispecImportPath)
	if len(names) == 0 {
		return nil, nil
	}
	isNewMuxCall := func(call *ast.CallExpr) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		ident, ok := sel.X.(*ast.Ident)
		return ok && names[ident.Name] && sel.Sel.Name == "NewMux"
	}
	// Three independent full-tree walks (rather than one, sharing state
	// across a CallExpr visit and its enclosing ExprStmt/AssignStmt visit)
	// deliberately: ast.Inspect visits a CallExpr's own node AND, separately,
	// any node wrapping it — sharing one pass would either double-count a
	// discarded call or require extra bookkeeping to avoid it. Three
	// single-purpose walks are simpler and cannot double-count.
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isNewMuxCall(call) {
			calls = append(calls, fset.Position(call.Pos()).String())
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		stmt, ok := n.(*ast.ExprStmt)
		if !ok {
			return true
		}
		if call, ok := stmt.X.(*ast.CallExpr); ok && isNewMuxCall(call) {
			discarded = append(discarded, fset.Position(call.Pos()).String()+" (return value(s) wholly discarded)")
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !isNewMuxCall(call) {
			return true
		}
		for _, lhs := range assign.Lhs {
			if isBlankIdent(lhs) {
				discarded = append(discarded, fset.Position(call.Pos()).String()+" (one of the two return values discarded via `_`)")
				break
			}
		}
		return true
	})
	return calls, discarded
}

// TestApispecNewMuxSingleCallPerMuxOwningPackage is Requirement 3 (R4 F1,
// final review round) — see the package-level doc above for the exploit
// this closes and how task #146's NewMux changed which half of it is
// structural versus detective.
func TestApispecNewMuxSingleCallPerMuxOwningPackage(t *testing.T) {
	root := repoRoot(t)
	dirs := muxOwningPackageDirs(t, root)
	if len(dirs) == 0 {
		t.Fatal("muxOwningPackageDirs returned zero packages — the BFS/declaresServeMux mechanism is broken (this check must never be a silent no-op, ADR-0005 V8-2)")
	}

	sawAnyNewMuxCall := false
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
				calls, discarded := newMuxCallSites(t, fset, path)
				allCalls = append(allCalls, calls...)
				allDiscarded = append(allDiscarded, discarded...)
			}
			if len(allCalls) == 0 {
				return // this mux-owning package doesn't itself call NewMux — nothing to check here.
			}
			sawAnyNewMuxCall = true
			if len(allCalls) > 1 {
				t.Fatalf("package %s calls apispec.NewMux %d times: %v — a mux-owning package must call it exactly once (ADR-0005 V2; a second call only ever produces a second, freestanding *http.ServeMux nothing wires to a listener — but it is dead code at best and a forgotten-to-wire-in defect at worst)", rel, len(allCalls), allCalls)
			}
			if len(allDiscarded) > 0 {
				t.Fatalf("package %s calls apispec.NewMux with (part of) its return value discarded: %v — capture BOTH the *http.ServeMux and the installed-subset return value (see the real call sites' own h.mux, h.routes = apispec.NewMux(...) pattern in scoreboard/server.go, internal/collector/collector.go, internal/authpolicy/server.go): dropping the routes half means h.routes can no longer report what the mux truly serves, and dropping the mux half leaves h.mux nil (a guaranteed nil-pointer panic on the first real request)", rel, allDiscarded)
			}
		})
	}
	if !sawAnyNewMuxCall {
		t.Fatal("no mux-owning package called apispec.NewMux at all — the detector or the production wiring is broken (this check must never be a silent no-op, ADR-0005 V8-2)")
	}
}

// TestApispecNewMuxSingleCall_CatchesSecondDiscardedCall is ADR-0005 V8's
// "prove the detector isn't vacuous" requirement applied to this specific
// check: a synthetic source string containing a SECOND, return-discarding
// apispec.NewMux call — VP's exact reproduction shape, ported to the NewMux
// signature — must be flagged both ways (more than one call site, AND at
// least one discarded) without touching any real file.
func TestApispecNewMuxSingleCall_CatchesSecondDiscardedCall(t *testing.T) {
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
	h := &Handler{}
	declared := []apispec.Route{}
	h.mux, h.routes = apispec.NewMux(declared)
	// Simulates a sub-handler wired the "natural mistake" way (Requirement
	// 3's framing): registering its OWN routes directly instead of folding
	// them into declared above. NewMux's structural fix means this can never
	// reach the SAME mux h.mux already points at — but it is still dead
	// code / a forgotten-wiring smell this check flags.
	sneaky := []apispec.Route{{Method: "POST", Pattern: "/sneaky"}}
	apispec.NewMux(sneaky)
	return h
}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	fset := token.NewFileSet()
	calls, discarded := newMuxCallSites(t, fset, path)
	if len(calls) != 2 {
		t.Fatalf("expected 2 apispec.NewMux call sites in the fixture, got %d: %v", len(calls), calls)
	}
	if len(discarded) != 1 {
		t.Fatalf("expected exactly 1 discarded (bare ExprStmt) call site, got %d: %v", len(discarded), discarded)
	}
}

// TestApispecNewMuxSingleCall_CatchesPartialDiscard is ADR-0005 V8's "prove
// the detector isn't vacuous" requirement applied to the NEW failure shape
// task #146 introduced by making NewMux return two values: capturing only
// ONE of {mux, routes} and discarding the other via `_`. A single-return
// Register(mux, routes) could never have this shape at all — this test
// pins that the two-value discard is caught even though there is only ONE
// call site (so TestApispecNewMuxSingleCall_CatchesSecondDiscardedCall's
// "more than one call" branch would never fire for it).
func TestApispecNewMuxSingleCall_CatchesPartialDiscard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.go")
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
	h := &Handler{}
	declared := []apispec.Route{}
	// BUG: drops the installed-routes half — h.routes never reflects what
	// h.mux actually serves.
	h.mux, _ = apispec.NewMux(declared)
	return h
}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	fset := token.NewFileSet()
	calls, discarded := newMuxCallSites(t, fset, path)
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 apispec.NewMux call site, got %d: %v", len(calls), calls)
	}
	if len(discarded) != 1 {
		t.Fatalf("expected exactly 1 discarded (partial `_`) call site, got %d: %v", len(discarded), discarded)
	}
}

// TestApispecNewMuxSingleCall_NoFalsePositiveOnCapturedSingleCall pins the
// non-degenerate baseline: a package that calls apispec.NewMux exactly once
// and stores BOTH return values must report zero calls-that-are-a-problem —
// i.e. newMuxCallSites must return exactly one call and zero discarded,
// matching every REAL call site in this codebase today.
func TestApispecNewMuxSingleCall_NoFalsePositiveOnCapturedSingleCall(t *testing.T) {
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
	h := &Handler{}
	declared := []apispec.Route{}
	h.mux, h.routes = apispec.NewMux(declared)
	return h
}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	fset := token.NewFileSet()
	calls, discarded := newMuxCallSites(t, fset, path)
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 apispec.NewMux call site, got %d: %v", len(calls), calls)
	}
	if len(discarded) != 0 {
		t.Fatalf("expected zero discarded call sites, got %d: %v", len(discarded), discarded)
	}
}
