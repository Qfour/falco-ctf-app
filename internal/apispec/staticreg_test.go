package apispec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// registrationTargets are the non-test source files owned by an
// http.ServeMux-holding binary (scoreboard, collector, auth-policy — see
// ADR-0005 Decision 2's "cmd/<x> builds a ServeMux" rule; ttyd-proxy is a
// catch-all reverse proxy with no mux and is out of scope). ADR-0005 V2
// requires that NONE of these files call mux.Handle/mux.HandleFunc directly
// — every registration must flow through Register (route.go) via each
// package's declarative route table, or a route can go missing from the
// table without ever being caught by the V1 parity test (the exact hole
// ADR-0005 closes).
var registrationTargets = []string{
	"../scoreboard/server.go",
	"../scoreboard/api/api.go",
	"../scoreboard/view/view.go",
	"../scoreboard/ingest/ingest.go",
	"../collector/collector.go",
	"../authpolicy/server.go",
}

// TestNoDirectMuxRegistrationOutsideTable is the static half of ADR-0005 V2:
// it parses each registrationTargets file and fails if it finds a call
// expression whose selector is "Handle" or "HandleFunc" on ANY receiver
// (mux.Handle(...), h.mux.Handle(...), ...). After the ADR-0005 refactor the
// only such call in the whole tree is apispec.Register's own mux.Handle
// (route.go, not in this list), so a passing result means every owning
// package's route set equals exactly what its Routes()/Register() table
// contains — the precondition the V1 bidirectional set-equality check
// depends on.
//
// This is a MUTATION-PROVEN check, not just a "currently zero" snapshot: see
// TestNoDirectMuxRegistration_CatchesReintroducedDirectCall below, which
// injects a direct mux.Handle call via go/parser on a synthetic source
// string (not by editing a real file) and asserts THIS SAME detector logic
// flags it (ADR-0005 V8-2's "detector must not be a permanently-empty
// no-op" requirement, applied to the static check as well as the YAML-diff
// checks).
func TestNoDirectMuxRegistrationOutsideTable(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — cannot locate this test file to resolve sibling package paths")
	}
	baseDir := filepath.Dir(thisFile)

	for _, rel := range registrationTargets {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(baseDir, rel)
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
// ("line:col selector") for every call expression `<expr>.Handle(...)` or
// `<expr>.HandleFunc(...)` it finds, regardless of what <expr> is (mux, h.mux,
// a package-qualified value, ...). It is deliberately receiver-agnostic: the
// point is "is there ANY direct registration call left in this file", not
// "is it specifically named mux".
func findDirectMuxCalls(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
			return true
		}
		pos := fset.Position(call.Pos())
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
