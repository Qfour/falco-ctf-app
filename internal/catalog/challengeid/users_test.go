package challengeid

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// app#437: the grammar has ONE definition. Each place that decides "is this a
// challenge id" imports this package; none keeps its own pattern. (The mutation:
// dropping the import from a file, or listing a file that does not import it, is
// red, see TestUsersImportCheck_CatchesAMissingImport.)
var users = []string{
	"../catalog.go",                   // Load: refuses a directory outside the grammar
	"../flags.go",                     // the flags file's challengeId keys
	"../../scoreboard/api/api.go",     // the scoreboard's {cid}
	"../../collector/collector.go",    // the collector's {cid}
	"../../homefragments/manifest.go", // the Home-fragment generator's directory scan
}

const importPath = "github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"

func importsLeaf(t *testing.T, file string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.FromSlash(file), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == importPath {
			return true
		}
	}
	return false
}

func TestEveryChallengeIDCheckUsesTheOneDefinition(t *testing.T) {
	for _, u := range users {
		if !importsLeaf(t, u) {
			t.Errorf("%s does not import %s: a challenge-id check must use the one grammar", u, importPath)
		}
	}
}

func TestUsersImportCheck_CatchesAMissingImport(t *testing.T) {
	// internal/catalog/catalog_test.go is a real file that does not import the leaf.
	if importsLeaf(t, "../catalog_test.go") {
		t.Fatal("the reference file unexpectedly imports the leaf; the check would pass on nothing")
	}
}

// The leaf is standard library only, so the collector (a distroless image whose
// SBOM carries only what runs) can import it without taking a dependency with it
// (internal/apispec/dependency_boundary_test.go checks the collector's closure;
// this fixes the leaf itself, whatever the third-party set there is).
func TestLeafImportsOnlyTheStandardLibrary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports %q: the leaf may import the standard library only", name, path)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no non-test file found; the check would pass on nothing")
	}
}

// challengeIDLiteral matches the shapes a hand-written challenge-id expression
// takes: two digits, then a hyphen.
var challengeIDLiteral = regexp.MustCompile(`\[0-9\]\{2\}-|\[0-9\]\[0-9\]-|\\d\\d\)?-|\\d\{2\}-`)

// regexpLiteralViolations lists the regexp.MustCompile / Compile calls in src
// whose literal argument looks like a challenge-id expression.
func regexpLiteralViolations(name, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "MustCompile" && sel.Sel.Name != "Compile") {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err == nil && challengeIDLiteral.MatchString(val) {
			out = append(out, fmt.Sprintf("%s: regexp literal %s looks like a challenge-id grammar", fset.Position(lit.Pos()), lit.Value))
		}
		return true
	})
	return out
}

// No non-test Go file keeps its own challenge-id expression: the positive test
// above says every user imports the leaf; this one says nothing else defines it.
func TestNoOtherChallengeIDExpressionInTheProgram(t *testing.T) {
	scanned := 0
	for _, root := range []string{"../../../cmd", "../../../internal"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			for _, v := range regexpLiteralViolations(path, string(b)) {
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
}

func TestChallengeIDExpressionScan_CatchesAHandWrittenOne(t *testing.T) {
	for name, src := range map[string]string{
		"two digits":  "package p\nimport \"regexp\"\nvar r = regexp.MustCompile(`^[0-9]{2}-[a-z]+$`)\n",
		"digit class": "package p\nimport \"regexp\"\nvar r = regexp.MustCompile(`^[0-9][0-9]-x`)\n",
		"backslash d": "package p\nimport \"regexp\"\nvar r = regexp.MustCompile(`^(\\d\\d)-[a-z0-9-]+$`)\n",
	} {
		if v := regexpLiteralViolations("x.go", src); len(v) == 0 {
			t.Errorf("%s: a hand-written challenge-id expression was not found", name)
		}
	}
	if v := regexpLiteralViolations("x.go", "package p\nimport \"regexp\"\nvar r = regexp.MustCompile(`^[a-z]+$`)\n"); len(v) != 0 {
		t.Errorf("an unrelated expression was flagged: %v", v)
	}
}
