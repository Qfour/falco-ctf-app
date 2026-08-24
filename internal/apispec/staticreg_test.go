package apispec

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

// scanTargets computes ADR-0005 V2's file scan set MECHANICALLY instead of
// via a hand-written list: every non-test .go file in every package
// reachable — via this module's own import graph, exactly the BFS
// mux_ownership_test.go's cmdOwnsServeMux already performs for V6 — from an
// http.ServeMux-owning cmd/* binary, EXCLUDING internal/apispec/route.go
// (the ONE file apispec.Register's own doc comment names as the sole
// permitted mux.Handle call site in this codebase).
//
// This replaces the former registrationTargets hand-written 6-file
// allowlist. That list was itself the exact defect ADR-0005 Decision 1 /
// conventions I14 forbid ("no exclusion list") — security-engineer and R3
// (5x review) demonstrated it independently by registering a spec-less,
// origin-guard-less state-changing route from
// internal/scoreboard/view/portal.go (a file the list never named) and
// observing `make test` stay fully green. internal/scoreboard/view/ alone
// had FIVE unscanned non-test files (portal.go, home.go, csp.go,
// vendorassets.go, homefragments_gen.go); internal/collector/metrics.go and
// internal/authpolicy/metrics.go were unscanned too. Deriving the file set
// from the same mux-ownership BFS V6 already trusts means every file in
// every package a mux-owning binary can reach is scanned, with a single,
// explicit, named exception — not six files chosen by hand and frozen at
// review time.
func scanTargets(t *testing.T, root string) []string {
	t.Helper()
	cmdDir := filepath.Join(root, "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read cmd dir: %v", err)
	}

	visitedPkgs := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() || !cmdOwnsServeMux(t, root, e.Name()) {
			continue
		}
		queue := []string{modulePrefix + "cmd/" + e.Name()}
		for len(queue) > 0 {
			pkg := queue[0]
			queue = queue[1:]
			if visitedPkgs[pkg] {
				continue
			}
			visitedPkgs[pkg] = true
			dir := filepath.Join(root, strings.TrimPrefix(pkg, modulePrefix))
			queue = append(queue, importsOf(t, dir)...)
		}
	}

	excluded := filepath.Join(root, "internal", "apispec", "route.go")
	var files []string
	for pkg := range visitedPkgs {
		dir := filepath.Join(root, strings.TrimPrefix(pkg, modulePrefix))
		for _, f := range nonTestGoFiles(t, dir) {
			if f == excluded {
				continue
			}
			files = append(files, f)
		}
	}
	sort.Strings(files)
	return files
}

// TestNoDirectMuxRegistrationOutsideTable is the static half of ADR-0005 V2:
// it parses every file scanTargets returns and fails if it finds a
// SELECTOR EXPRESSION whose name is "Handle" or "HandleFunc" on ANY receiver
// (mux.Handle(...), h.mux.Handle(...), a bare `reg := h.mux.HandleFunc`
// reference later called elsewhere, ...). After the ADR-0005 refactor the
// only such reference in the whole tree is apispec.Register's own mux.Handle
// (route.go, scanTargets' one named exclusion), so a passing result means
// every owning package's route set equals exactly what its
// Routes()/Register() table contains — the precondition the V1
// bidirectional set-equality check depends on.
//
// Requirement 4 (R1#2, final review round): this used to gate on
// `n.(*ast.CallExpr)` FIRST and only then inspect call.Fun — so a selector
// reference that is not ITSELF the direct callee of a CallExpr node (e.g.
// `reg := h.mux.HandleFunc` followed by `reg("POST /api/backdoor", ...)`
// somewhere else) was never visited as a violation candidate at all: the
// bare assignment's RHS is a *ast.SelectorExpr under an *ast.AssignStmt, not
// a *ast.CallExpr, and by the time `reg(...)` executes, call.Fun is an
// *ast.Ident ("reg"), not a *ast.SelectorExpr — so neither node shape ever
// matched. R1 demonstrated this passes `make test` fully green today while
// installing a live, undocumented route neither Routes() nor
// docs/openapi-*.yaml ever mentions. Inspecting every *ast.SelectorExpr
// directly, independent of whether it sits inside a CallExpr, closes this:
// the reference itself is the thing that must not exist outside route.go,
// not the specific call-site shape of that one reference.
//
// This is a MUTATION-PROVEN check, not just a "currently zero" snapshot: see
// TestNoDirectMuxRegistration_CatchesReintroducedDirectCall below, which
// injects a direct mux.Handle call via go/parser on a synthetic source
// string (not by editing a real file) and asserts THIS SAME detector logic
// flags it (ADR-0005 V8-2's "detector must not be a permanently-empty
// no-op" requirement, applied to the static check as well as the YAML-diff
// checks). The non-empty scanTargets() result asserted below is the SAME
// requirement applied to the scan-set derivation itself: a BFS that silently
// returned nothing would make this whole test a permanent no-op.
func TestNoDirectMuxRegistrationOutsideTable(t *testing.T) {
	root := repoRoot(t)
	files := scanTargets(t, root)
	if len(files) == 0 {
		t.Fatal("scanTargets returned zero files — the mux-ownership BFS or dir walk is broken (this check must never be a silent no-op, ADR-0005 V8-2)")
	}

	for _, path := range files {
		path := path
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		t.Run(rel, func(t *testing.T) {
			violations := findDirectMuxCalls(t, path)
			if len(violations) > 0 {
				t.Fatalf("%s: found %d direct mux registration call(s) outside apispec.Register: %v — "+
					"route registration must go through a Route table + apispec.Register (ADR-0005 V2)",
					path, len(violations), violations)
			}
		})
	}
}

// findDirectMuxCalls parses a Go source file and returns a description
// ("line:col selector") for every SELECTOR EXPRESSION `<expr>.Handle` or
// `<expr>.HandleFunc` it finds — a bare reference, not just one that is
// itself the immediate callee of a call expression — regardless of what
// <expr> is (mux, h.mux, a package-qualified value, ...). It is deliberately
// receiver-agnostic: the point is "is there ANY reference to this method
// left in this file", not "is it specifically named mux", and (Requirement
// 4, final review round) not "is it called directly at the point where it is
// referenced" either — `reg := h.mux.HandleFunc` is flagged here even though
// `reg` itself is never named "mux"/"HandleFunc" again.
//
// This does NOT flag `h.mux.Handler(r)` / `promhttp.Handler()` /
// `http.HandlerFunc(...)` — their Sel.Name is "Handler"/"HandlerFunc", a
// different string from "Handle"/"HandleFunc", so broadening from
// call-expressions to all selector expressions adds no false positive here
// (R1 confirmed zero FPs across this scan's files — the file count grows as
// mux-owning source files are added, so it is not pinned to a specific number here).
func findDirectMuxCalls(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
			return true
		}
		pos := fset.Position(sel.Pos())
		violations = append(violations, pos.String()+" "+exprString(sel))
		return true
	})
	return violations
}

// exprString renders a selector expression's textual shape well enough for
// an assertion failure message (e.g. "mux.Handle", "h.mux.HandleFunc") — not
// a general Go printer, just enough for identifiers and one level of nesting.
func exprString(sel *ast.SelectorExpr) string {
	base := "?"
	switch x := sel.X.(type) {
	case *ast.Ident:
		base = x.Name
	case *ast.SelectorExpr:
		base = exprString(x)
	}
	return base + "." + sel.Sel.Name
}

// TestNoDirectMuxRegistration_CatchesReintroducedDirectCall is ADR-0005 V8's
// "prove the detector itself is fail-closed" requirement applied to the
// static half of V2: it feeds findDirectMuxCalls a synthetic source string
// containing a direct h.mux.HandleFunc(...) call NOT in registrationTargets,
// and asserts the detector reports it. Without this, a refactor that
// accidentally makes findDirectMuxCalls always return an empty slice (e.g. a
// typo in the selector name check) would make
// TestNoDirectMuxRegistrationOutsideTable permanently green regardless of
// what the real files contain.
func TestNoDirectMuxRegistration_CatchesReintroducedDirectCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reintroduced.go")
	src := `package fixture

import "net/http"

type Handler struct{ mux *http.ServeMux }

func (h *Handler) Register() {
	// Simulates a route added the OLD way, bypassing the declarative table.
	h.mux.HandleFunc("GET /sneaky", h.sneaky)
}

func (h *Handler) sneaky(w http.ResponseWriter, r *http.Request) {}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	violations := findDirectMuxCalls(t, path)
	if len(violations) == 0 {
		t.Fatal("expected findDirectMuxCalls to flag the injected h.mux.HandleFunc call, found none — " +
			"the detector would be a permanent no-op (ADR-0005 V8)")
	}
}

// TestNoDirectMuxRegistration_CatchesAliasedHandleFuncReference is
// Requirement 4's own V8 proof (final review round, R1#2): R1 demonstrated
// that BEFORE this file's CallExpr-gated check was replaced with a bare
// *ast.SelectorExpr inspection, a route registered via
//
//	reg := h.mux.HandleFunc
//	reg("POST /api/backdoor", h.backdoor)
//
// passed `make test` fully green — the assignment's RHS is a SelectorExpr
// under an AssignStmt (not a CallExpr), and the later call's Fun is a bare
// Ident ("reg"), so the old `n.(*ast.CallExpr)` gate never even looked at
// call.Fun for either node. This fixture reproduces exactly that shape (not
// the direct h.mux.HandleFunc(...) call the OLD detector already caught —
// see TestNoDirectMuxRegistration_CatchesReintroducedDirectCall above) and
// fails if findDirectMuxCalls ever regresses back to missing it.
func TestNoDirectMuxRegistration_CatchesAliasedHandleFuncReference(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aliased.go")
	src := `package fixture

import "net/http"

type Handler struct{ mux *http.ServeMux }

func (h *Handler) Register() {
	// Simulates a route registered through a locally-bound method value,
	// bypassing both the declarative table AND the direct-call shape the
	// pre-Requirement-4 detector already caught.
	reg := h.mux.HandleFunc
	reg("POST /api/backdoor", h.backdoor)
}

func (h *Handler) backdoor(w http.ResponseWriter, r *http.Request) {}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	violations := findDirectMuxCalls(t, path)
	if len(violations) == 0 {
		t.Fatal("expected findDirectMuxCalls to flag the aliased `reg := h.mux.HandleFunc` reference, found none — " +
			"this is exactly the shape a CallExpr-only check misses (Requirement 4, R1#2)")
	}
}

// TestNoDirectMuxRegistration_NoFalsePositiveOnHandlerLookalikes pins
// Requirement 4's other half: broadening from CallExpr-only to every
// *ast.SelectorExpr must not start flagging the THREE real, legitimate
// "Handler"/"HandlerFunc" (not "Handle"/"HandleFunc") shapes R1 found across
// this scan's files (count grows as mux-owning source files are added) —
// h.mux.Handler(r) (server.go's own
// route-label-for-metrics lookup), promhttp.Handler() (the /metrics route's
// own handler value), and http.HandlerFunc(...) (used throughout every
// Routes() table in this codebase to adapt a plain func into an
// http.Handler). All three share a prefix with "Handle"/"HandleFunc" but are
// a DIFFERENT string, so the exact-match check must reject them.
func TestNoDirectMuxRegistration_NoFalsePositiveOnHandlerLookalikes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookalikes.go")
	src := `package fixture

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Handler struct{ mux *http.ServeMux }

func (h *Handler) route(r *http.Request) string {
	_, pattern := h.mux.Handler(r)
	return pattern
}

func (h *Handler) metricsHandler() http.Handler {
	return promhttp.Handler()
}

func (h *Handler) wrapped() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	violations := findDirectMuxCalls(t, path)
	if len(violations) != 0 {
		t.Fatalf("expected zero violations for Handler()/HandlerFunc()-only source, got %v", violations)
	}
}
