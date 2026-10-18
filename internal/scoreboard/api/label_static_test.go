package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Static guard: in api.go every WithLabelValues call takes the resolved `label`
// (from Handler.challenge) as its first argument, never the raw path value. The
// raw {cid} is not a safe label until it has been looked up in the catalog.
func TestMetricLabelsUseTheResolvedLabelOnly(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "api.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithLabelValues" {
			return true
		}
		calls++
		if len(call.Args) == 0 {
			t.Errorf("%s: WithLabelValues with no arguments", fset.Position(call.Pos()))
			return true
		}
		if id, ok := call.Args[0].(*ast.Ident); !ok || id.Name != "label" {
			t.Errorf("%s: first WithLabelValues argument must be the resolved `label`", fset.Position(call.Pos()))
		}
		return true
	})
	if calls < 10 {
		t.Fatalf("found only %d WithLabelValues calls in api.go; the scan is not seeing the handlers", calls)
	}
}
