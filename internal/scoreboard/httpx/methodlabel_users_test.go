package httpx

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// app#491: the closed set of a metric's method label has ONE definition,
// MethodLabel in methodlabel.go. Each histogram that labels a request's method
// calls it; nothing else defines the same fold, and nothing hands a request's own
// method to a label. (The mutations: dropping the call from a file, or a second
// definition or a raw `.Method` label, are red; see the *_Catches* tests.)

// methodLabelUsers: each file that observes a request-duration histogram.
var methodLabelUsers = []string{
	"../../collector/collector.go", // collector_request_duration_seconds
	"../server.go",                 // scoreboard_http_request_duration_seconds
}

// theLeaf is the one file allowed to define the fold (slash-separated, relative
// to this package's directory).
const theLeaf = "methodlabel.go"

func parseSrc(t *testing.T, name, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

// callsMethodLabel reports whether src calls httpx.MethodLabel.
func callsMethodLabel(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "MethodLabel" {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "httpx" {
				found = true
			}
		}
		return true
	})
	return found
}

func TestEveryRequestDurationUsesTheOneMethodLabel(t *testing.T) {
	for _, u := range methodLabelUsers {
		b, err := os.ReadFile(filepath.FromSlash(u))
		if err != nil {
			t.Fatal(err)
		}
		if !callsMethodLabel(parseSrc(t, u, string(b))) {
			t.Errorf("%s does not call httpx.MethodLabel: a request-duration histogram's method label must be the one closed set (app#491)", u)
		}
	}
}

func TestUsersCallCheck_CatchesAMissingCall(t *testing.T) {
	// The scoreboard's server.go with its fold removed.
	raw := "package scoreboard\n\nfunc f(route string, r *Request) {\n\tH.WithLabelValues(route, r.Method, \"200\")\n}\n"
	if callsMethodLabel(parseSrc(t, "x.go", raw)) {
		t.Fatal("a file that labels the raw method was taken for one that calls MethodLabel")
	}
	folded := "package scoreboard\n\nfunc f(route string, r *Request) {\n\tH.WithLabelValues(route, httpx.MethodLabel(route, r.Method), \"200\")\n}\n"
	if !callsMethodLabel(parseSrc(t, "x.go", folded)) {
		t.Fatal("a call to httpx.MethodLabel was not found")
	}
}

// foldViolations lists, in src (a non-test file other than the leaf), what would
// be a second definition of the fold or a bypass of it:
//   - a function named methodLabel (any case);
//   - a function of the shape (string, string) string that splits its first
//     argument at a space, which is how a ServeMux pattern ("GET /x") is cut into
//     its method, whatever the function is called;
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
			} else if isStringPairToString(n.Type) && n.Body != nil && cutsAtSpace(n.Body) {
				out = append(out, fmt.Sprintf("%s: func %s has the shape of the method-label fold (string, string) string splitting at a space", fset.Position(n.Pos()), n.Name.Name))
			}
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithLabelValues" {
				for _, a := range n.Args {
					if s, ok := a.(*ast.SelectorExpr); ok && s.Sel.Name == "Method" {
						out = append(out, fmt.Sprintf("%s: WithLabelValues is given %s, a request's own method", fset.Position(a.Pos()), exprString(s)))
					}
				}
			}
		}
		return true
	})
	return out
}

func exprString(s *ast.SelectorExpr) string {
	if x, ok := s.X.(*ast.Ident); ok {
		return x.Name + "." + s.Sel.Name
	}
	return "<expr>." + s.Sel.Name
}

func isStringPairToString(ft *ast.FuncType) bool {
	if ft.Results == nil || ft.Params == nil {
		return false
	}
	count := func(fl *ast.FieldList) (n int, allString bool) {
		allString = true
		for _, fld := range fl.List {
			id, ok := fld.Type.(*ast.Ident)
			if !ok || id.Name != "string" {
				allString = false
			}
			if len(fld.Names) == 0 {
				n++
			} else {
				n += len(fld.Names)
			}
		}
		return n, allString
	}
	pn, pStr := count(ft.Params)
	rn, rStr := count(ft.Results)
	return pn == 2 && pStr && rn == 1 && rStr
}

// cutsAtSpace: the body calls strings.Cut(x, " ") or strings.SplitN(x, " ", n).
func cutsAtSpace(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Cut" && sel.Sel.Name != "SplitN") {
			return true
		}
		if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, err := strconv.Unquote(lit.Value); err == nil && v == " " {
				found = true
			}
		}
		return true
	})
	return found
}

func TestNoOtherMethodLabelFoldInTheProgram(t *testing.T) {
	scanned := 0
	for _, root := range []string{"../../../cmd", "../../../internal"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if filepath.ToSlash(path) == "../../../internal/scoreboard/httpx/"+theLeaf {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			for _, v := range foldViolations(path, string(b)) {
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
	if _, err := os.Stat(theLeaf); err != nil {
		t.Fatalf("the leaf %s is not where the scan expects it: %v", theLeaf, err)
	}
}

func TestMethodLabelScan_CatchesASecondDefinition(t *testing.T) {
	for name, src := range map[string]string{
		"the same name":  "package p\n\nfunc methodLabel(route, method string) string { return method }\n",
		"another case":   "package p\n\nfunc MethodLabel(route, method string) string { return method }\n",
		"another name":   "package p\n\nimport \"strings\"\n\nfunc declaredOrOther(route, method string) string {\n\tdeclared, _, _ := strings.Cut(route, \" \")\n\tif declared == method {\n\t\treturn method\n\t}\n\treturn \"other\"\n}\n",
		"a raw label":    "package p\n\nfunc f(h interface{ WithLabelValues(...string) }, r *R) { h.WithLabelValues(\"a\", r.Method) }\n",
		"SplitN variant": "package p\n\nimport \"strings\"\n\nfunc g(a string, b string) string { return strings.SplitN(a, \" \", 2)[0] }\n",
		"unnamed params": "package p\n\nimport \"strings\"\n\nfunc g(string, string) string { s, _, _ := strings.Cut(\"x\", \" \"); return s }\n",
	} {
		if v := foldViolations("x.go", src); len(v) == 0 {
			t.Errorf("%s: a second definition / bypass was not found", name)
		}
	}
	for name, src := range map[string]string{
		"an unrelated Cut":      "package p\n\nimport \"strings\"\n\nfunc g(a string) (string, string) { x, y, _ := strings.Cut(a, \" \"); return x, y }\n",
		"a Cut on another rune": "package p\n\nimport \"strings\"\n\nfunc g(a, b string) string { x, _, _ := strings.Cut(a, \":\"); return x }\n",
		"a folded label":        "package p\n\nfunc f(h interface{ WithLabelValues(...string) }, r *R) { h.WithLabelValues(\"a\", httpx.MethodLabel(\"a\", r.Method)) }\n",
	} {
		if v := foldViolations("x.go", src); len(v) != 0 {
			t.Errorf("%s: flagged although it is not one: %v", name, v)
		}
	}
}

// The leaf is standard library only, so the collector (a distroless image whose
// SBOM carries only what runs) imports it without taking a dependency with it.
// (internal/apispec/dependency_boundary_test.go checks the collector's closure;
// this fixes the file itself.)
func TestMethodLabelLeafImportsOnlyTheStandardLibrary(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), theLeaf, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Imports) == 0 {
		t.Fatal("the leaf imports nothing; the check would pass on nothing")
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
			t.Errorf("%s imports %q: the leaf may import the standard library only", theLeaf, path)
		}
	}
}
