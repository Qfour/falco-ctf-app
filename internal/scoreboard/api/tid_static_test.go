package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Static guard: in package api the only reader of the {tid} path value is
// boardTID, which checks its shape. A handler that read r.PathValue("tid")
// itself would skip the check (and the unlike route would echo the value).
func TestOnlyBoardTIDReadsThePathValueTid(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	inBoardTID := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "PathValue" {
					return true
				}
				if lit, ok := call.Args[0].(*ast.BasicLit); !ok || lit.Value != `"tid"` {
					return true
				}
				if fd.Name.Name == "boardTID" {
					inBoardTID++
				} else {
					t.Errorf("%s: %s reads PathValue(\"tid\"); only boardTID may (it checks the shape)", fset.Position(call.Pos()), fd.Name.Name)
				}
				return true
			})
		}
	}
	if inBoardTID != 1 {
		t.Fatalf("boardTID reads PathValue(\"tid\") %d times, want exactly 1: the scan is not seeing it", inBoardTID)
	}
}
