package apispec

// app#491: the label values of a request-duration histogram are closed sets.
//
//   - method: httpx.MethodLabel is the ONE definition of the fold; every
//     mux-owning package's ServeHTTP that labels a metric calls it for the
//     method; nothing else defines the fold or hands a request's own method to
//     a label.
//   - route: defined once as specparity.RouteLabelViolations and run on every
//     service's Routes() (TestAPISpec_RouteLabelIsClosed, required in every
//     mux-owning package by parity_coverage_test.go).
//
// These STATIC checks are an aid, not the guarantee. They see the shapes written
// here (a function of that name, a `.Method` selector given to WithLabelValues,
// a ServeHTTP whose second WithLabelValues argument is the MethodLabel call); a
// method copied into a local variable first, or a histogram observed outside
// ServeHTTP, is not seen. The guarantee is behavioural: the 53 distinct methods
// (invented, long, non-ASCII, invalid UTF-8) sent at the 404 / 405 / redirect
// surfaces in internal/collector/method_label_test.go
// (TestRequestDurationMethodIsFoldedIntoOneLabelValue) and
// internal/scoreboard/request_duration_method_test.go (the same name), which add
// at most one series.
//
// They live here, next to dependency_boundary_test.go, because they read more
// than one package: cross-package structure checks have one home.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// methodLabelLeaf is the one file that may define the fold (slash-separated,
// relative to the module root).
const methodLabelLeaf = "internal/scoreboard/httpx/methodlabel.go"

// foldViolations lists, in src (a non-test file other than the leaf), what would
// be a second definition of the fold or a bypass of it:
//   - a function named methodLabel (any case);
//   - a WithLabelValues argument that is a bare `<expr>.Method`: a request's own
//     method as a label.
func foldViolations(name, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncDecl:
			if strings.EqualFold(n.Name.Name, "methodlabel") {
				out = append(out, fmt.Sprintf("%s: func %s is a second definition of the method-label fold", fset.Position(n.Pos()), n.Name.Name))
			}
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithLabelValues" {
				for _, a := range n.Args {
					if s, ok := a.(*ast.SelectorExpr); ok && s.Sel.Name == "Method" {
						out = append(out, fmt.Sprintf("%s: WithLabelValues is given .Method, a request's own method", fset.Position(a.Pos())))
					}
				}
			}
		}
		return true
	})
	return out
}

func TestNoOtherMethodLabelFoldInTheProgram(t *testing.T) {
	root := repoRoot(t)
	scanned := 0
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			if filepath.ToSlash(rel) == methodLabelLeaf {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			for _, v := range foldViolations(rel, string(b)) {
				t.Error(v)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 50 {
		t.Fatalf("scanned only %d non-test files; the walk is not seeing the tree", scanned)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(methodLabelLeaf))); err != nil {
		t.Fatalf("the leaf %s is not where the scan expects it: %v", methodLabelLeaf, err)
	}
}

func TestMethodLabelFoldScan_CatchesASecondDefinitionOrABypass(t *testing.T) {
	for name, src := range map[string]string{
		"the same name": "package p\n\nfunc methodLabel(route, method string) string { return method }\n",
		"another case":  "package p\n\nfunc MethodLabel(route, method string) string { return method }\n",
		"a raw label":   "package p\n\nfunc f(h interface{ WithLabelValues(...string) }, r *R) { h.WithLabelValues(\"a\", r.Method) }\n",
	} {
		if v := foldViolations("x.go", src); len(v) == 0 {
			t.Errorf("%s: a second definition / bypass was not found", name)
		}
	}
	for name, src := range map[string]string{
		"another function": "package p\n\nfunc g(a string) string { return a }\n",
		"a folded label":   "package p\n\nfunc f(h interface{ WithLabelValues(...string) }, r *R) { h.WithLabelValues(\"a\", httpx.MethodLabel(\"a\", r.Method)) }\n",
	} {
		if v := foldViolations("x.go", src); len(v) != 0 {
			t.Errorf("%s: flagged although it is not one: %v", name, v)
		}
	}
}

// serveHTTPLabelCalls returns, for each WithLabelValues call inside a ServeHTTP
// method of src, whether its second argument (the method label of the
// route / method / status histograms) is a call to httpx.MethodLabel.
func serveHTTPLabelCalls(t *testing.T, name, src string) (folded []bool) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "ServeHTTP" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "WithLabelValues" {
				return true
			}
			ok = false
			if len(call.Args) >= 2 {
				if c, isCall := call.Args[1].(*ast.CallExpr); isCall {
					if s, isSel := c.Fun.(*ast.SelectorExpr); isSel && s.Sel.Name == "MethodLabel" {
						if x, isID := s.X.(*ast.Ident); isID && x.Name == "httpx" {
							ok = true
						}
					}
				}
			}
			folded = append(folded, ok)
			return true
		})
	}
	return folded
}

// Every mux-owning binary's ServeHTTP that observes a labelled metric gives the
// method label through httpx.MethodLabel. The packages are the ones the ServeMux
// ownership walk (muxOwningDir, the same as ADR-0005 V6) finds for the binaries
// that have a spec, not a list kept here.
func TestEveryServeHTTPLabelsTheMethodThroughTheOneFold(t *testing.T) {
	root := repoRoot(t)
	cmds := make([]string, 0, len(specNameForCmd))
	for c := range specNameForCmd {
		cmds = append(cmds, c)
	}
	sort.Strings(cmds)
	sawCalls := map[string]int{}
	for _, c := range cmds {
		dir, ok := muxOwningDir(t, root, c)
		if !ok {
			t.Fatalf("cmd/%s: no mux-owning package found", c)
		}
		for _, path := range nonTestGoFiles(t, dir) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(root, path)
			for i, folded := range serveHTTPLabelCalls(t, rel, string(b)) {
				sawCalls[c]++
				if !folded {
					t.Errorf("%s (cmd/%s): ServeHTTP's WithLabelValues call #%d does not give httpx.MethodLabel(...) as its second argument", rel, c, i+1)
				}
			}
		}
	}
	// The two binaries that observe a request-duration histogram must be seen, or
	// the walk is looking at nothing.
	for _, c := range []string{"collector", "scoreboard"} {
		if sawCalls[c] == 0 {
			t.Errorf("cmd/%s: no ServeHTTP WithLabelValues call found; the check ran on nothing", c)
		}
	}
}

func TestServeHTTPLabelScan_CatchesAMissingFold(t *testing.T) {
	raw := "package p\n\nfunc (h *H) ServeHTTP(w W, r *R) {\n\tm.WithLabelValues(route, r.Method, \"200\")\n}\n"
	if got := serveHTTPLabelCalls(t, "x.go", raw); len(got) != 1 || got[0] {
		t.Fatalf("a ServeHTTP labelling the raw method: got %v, want [false]", got)
	}
	folded := "package p\n\nfunc (h *H) ServeHTTP(w W, r *R) {\n\tm.WithLabelValues(route, httpx.MethodLabel(route, r.Method), \"200\")\n}\n"
	if got := serveHTTPLabelCalls(t, "x.go", folded); len(got) != 1 || !got[0] {
		t.Fatalf("a ServeHTTP calling httpx.MethodLabel: got %v, want [true]", got)
	}
	other := "package p\n\nfunc (h *H) ServeHTTP(w W, r *R) { h.mux.ServeHTTP(w, r) }\nfunc (h *H) f() { m.WithLabelValues(route, r.Method) }\n"
	if got := serveHTTPLabelCalls(t, "x.go", other); len(got) != 0 {
		t.Fatalf("a WithLabelValues outside ServeHTTP was counted: %v", got)
	}
}
