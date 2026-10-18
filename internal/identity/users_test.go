package identity

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

// app#440: the seat grammar has ONE Go definition (SeatPattern / ValidSeat). Each
// place that decides "is this a seat" imports this package; none keeps its own
// pattern. Three checks hold that: the listed files import identity; no other
// non-test file spells a seat-shaped regexp; and identity itself is stdlib only.
// (The same shape as internal/catalog/challengeid/users_test.go.)

const identityImport = "github.com/Qfour/falco-ctf-app/internal/identity"

// seatUsers are the files that check a seat. Each must import identity.
var seatUsers = []string{
	"../scoreboard/api/api.go",         // path {user}, the three request bodies
	"../scoreboard/api/profile.go",     // profile / profile-reset {user}
	"../scoreboard/ingest/ingest.go",   // the ctf-<seat> namespace of a webhook event
	"../scoreboard/scoring/scoring.go", // the Grader's slug gate, the stored-user count
	"../authpolicy/roster.go",          // the roster's seats
	"../authpolicy/server.go",          // the `host` query parameter
	"../e2e/harness/seed.go",           // `make e2e-serve AS=` and the seeder
}

func importsIdentity(file string, src any) (bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.FromSlash(file), src, parser.ImportsOnly)
	if err != nil {
		return false, err
	}
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == identityImport {
			return true, nil
		}
	}
	return false, nil
}

func TestEverySeatCheckUsesTheOneDefinition(t *testing.T) {
	if len(seatUsers) == 0 {
		t.Fatal("no file listed: the check would pass on nothing")
	}
	for _, u := range seatUsers {
		ok, err := importsIdentity(u, nil)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if !ok {
			t.Errorf("%s does not import %s: a seat check must use the one grammar", u, identityImport)
		}
	}
}

func TestSeatImportCheck_CatchesAMissingImport(t *testing.T) {
	// A real file in the same directory tree that does not import identity.
	ok, err := importsIdentity("../scoreboard/ratelimit/ratelimit.go", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("the reference file unexpectedly imports identity; the check would pass on nothing")
	}
	if ok, _ := importsIdentity("x.go", "package x\nimport \"fmt\"\n"); ok {
		t.Error("a synthetic file without the import was reported as importing it")
	}
	if ok, _ := importsIdentity("x.go", "package x\nimport \""+identityImport+"\"\n"); !ok {
		t.Error("a synthetic file with the import was not recognised")
	}
}

// seatShaped matches a regexp literal spelling a seat-like grammar: the
// character-class pair a seat is built from, followed by a bounded repeat.
var seatShaped = regexp.MustCompile(`\[a-z0-9\]\[a-z0-9-\]\{0,\d+\}`)

// otherGrammars are the literals that look like a seat but are a different
// grammar on purpose, named by exact value so any other shape is still red.
var otherGrammars = map[string]string{
	// internal/e2e/serve: the name of a seed (31 characters), not a seat.
	"^[a-z0-9][a-z0-9-]{0,31}$": "e2e seed name",
}

// seatLiterals returns the string literals of src that spell a seat-shaped
// regexp and are not a named other grammar.
func seatLiterals(name string, src any) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if seatShaped.MatchString(val) {
			if _, other := otherGrammars[val]; !other {
				out = append(out, fmt.Sprintf("%s: %s", fset.Position(lit.Pos()), lit.Value))
			}
		}
		return true
	})
	return out, nil
}

func TestNoOtherFileSpellsTheSeatGrammar(t *testing.T) {
	root := filepath.Join("..", "..")
	scanned := 0
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if filepath.ToSlash(path) == filepath.ToSlash(filepath.Join(root, "internal", "identity", "seat.go")) {
				return nil // the one definition
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			lits, err := seatLiterals(path, src)
			if err != nil {
				return err
			}
			for _, l := range lits {
				t.Errorf("a seat-shaped regexp outside internal/identity/seat.go: %s (import identity.ValidSeat instead)", l)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d non-test files: the walk is not seeing the tree", scanned)
	}
}

func TestSeatLiteralCheck_CatchesACopy(t *testing.T) {
	copyOf := "package x\nimport \"regexp\"\nvar v = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)\n"
	if lits, err := seatLiterals("x.go", copyOf); err != nil || len(lits) != 1 {
		t.Fatalf("a copy of the seat grammar was not found: %v, %v", lits, err)
	}
	// a drifted copy is still caught (it would be a second, different definition)
	drifted := strings.Replace(copyOf, "{0,62}", "{0,50}", 1)
	if lits, _ := seatLiterals("x.go", drifted); len(lits) != 1 {
		t.Fatalf("a drifted copy was not found: %v", lits)
	}
	// the named other grammar is not a seat
	seed := "package x\nvar v = `^[a-z0-9][a-z0-9-]{0,31}$`\n"
	if lits, _ := seatLiterals("x.go", seed); len(lits) != 0 {
		t.Fatalf("the seed-name grammar was flagged: %v", lits)
	}
	// the exact value of the seed grammar is pinned in the real tree
	b, err := os.ReadFile(filepath.Join("..", "e2e", "serve", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "^[a-z0-9][a-z0-9-]{0,31}$") {
		t.Fatal("internal/e2e/serve no longer spells the named seed grammar: update otherGrammars with it")
	}
}

// identity is standard library only: auth-policy's distroless image copies it by
// name, and its third-party import set is pinned (TestAuthPolicyThirdPartyImportsArePinned).
func TestIdentityImportsOnlyTheStandardLibrary(t *testing.T) {
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
				t.Errorf("%s imports %q: identity may import the standard library only", name, path)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no non-test file found; the check would pass on nothing")
	}
}
