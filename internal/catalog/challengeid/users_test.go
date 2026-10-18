package challengeid

import (
	"go/parser"
	"go/token"
	"path/filepath"
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
