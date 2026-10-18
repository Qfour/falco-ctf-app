package contractmetrics

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This file is the stdlib-only walker the placement check (ADR-0040 V2) uses. It is a
// non-test file of the package so a test of another package can call it too, and it
// links nothing but the standard library. It reads source text only (no build), the
// same mechanism internal/apispec's dependency_boundary_test.go uses.

// ModulePath reads the module path from root/go.mod.
func ModulePath(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(ln), "module "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("no module line in %s/go.mod", root)
}

// nonTestGoFiles lists dir's .go files that are not tests.
func nonTestGoFiles(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil // a package with no directory is a leaf
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() && strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

// Closure returns the module-internal packages (as paths relative to the module, e.g.
// "internal/scoreboard/metrics") reachable from start (a module-relative path, e.g.
// "cmd/scoreboard") through non-test imports, start included.
func Closure(root, start string) (map[string]bool, error) {
	mod, err := ModulePath(root)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	queue := []string{start}
	fset := token.NewFileSet()
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		for _, f := range nonTestGoFiles(filepath.Join(root, filepath.FromSlash(pkg))) {
			af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				return nil, fmt.Errorf("parse imports of %s: %w", f, err)
			}
			for _, imp := range af.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if rel, ok := strings.CutPrefix(p, mod+"/"); ok {
					queue = append(queue, rel)
				}
			}
		}
	}
	return seen, nil
}

// Binaries lists the module-relative paths of root/cmd/* (every directory is a binary,
// gen-* included).
func Binaries(root string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, "cmd/"+e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// CallsIn reports whether any non-test file of the packages calls a function or method
// named fn (`fn(...)` or `x.fn(...)`). A declaration is not a call.
func CallsIn(root string, pkgs map[string]bool, fn string) (bool, error) {
	fset := token.NewFileSet()
	for pkg := range pkgs {
		for _, f := range nonTestGoFiles(filepath.Join(root, filepath.FromSlash(pkg))) {
			af, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				return false, fmt.Errorf("parse %s: %w", f, err)
			}
			found := false
			ast.Inspect(af, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch c := call.Fun.(type) {
				case *ast.Ident:
					found = found || c.Name == fn
				case *ast.SelectorExpr:
					found = found || c.Sel.Name == fn
				}
				return true
			})
			if found {
				return true, nil
			}
		}
	}
	return false, nil
}
