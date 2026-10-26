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

	"github.com/Qfour/falco-ctf-app/internal/dnsname"
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

// seatShaped matches a regexp literal spelling a seat-like grammar. Two shapes,
// both caught so tightening the grammar cannot blind the detector (app#480):
//
//	[a-z0-9][a-z0-9-]{0,N}                   the previous one (a trailing "-" allowed)
//	[a-z0-9]([a-z0-9-]{0,N}[a-z0-9])?        the current one (ends in a letter or digit)
var seatShaped = regexp.MustCompile(`\[a-z0-9\](?:\[a-z0-9-\]\{0,\d+\}|\(\[a-z0-9-\]\{0,\d+\}\[a-z0-9\]\)\?)`)

// otherGrammar is a literal that looks like a seat but is a different grammar on
// purpose. It is named by its exact value AND the one file that may spell it, so a copy
// of the same text in any other file is still red (a value alone would exempt a copy:
// the second definition the detector exists to find).
type otherGrammar struct {
	file   string // slash path from the repository root
	reason string
}

var otherGrammars = map[string]otherGrammar{
	// internal/e2e/serve: the name of a seed (31 characters), not a seat.
	"^[a-z0-9][a-z0-9-]{0,31}$": {"internal/e2e/serve/main.go", "e2e seed name"},
	// internal/dnsname: ADR-0047, the RFC 1123 label of --dns-suffix / --app-host and of the
	// host in FRAME_ANCESTORS (ADR-0044). It has the same shape as a seat's but is a
	// different grammar (labels of 1 to 63, joined by `.`). The key IS the constant (not a
	// copy of its text), so this entry cannot drift from it; dnsname's own test holds the
	// patterns built from it equal to deploy-user.sh's literal and the case table's header.
	// ttydproxy composes dnsname.Body and spells no literal of its own.
	dnsname.Label: {"internal/dnsname/dnsname.go", "RFC 1123 label (ADR-0047)"},
}

// seatLiterals returns the string literals of src (a file named name, a slash path from
// the repository root) that spell a seat-shaped regexp and are not a named other grammar
// in its own file, and the keys of otherGrammars it spelled where they belong.
func seatLiterals(name string, src any) (bad []string, exempt []string, err error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, nil, err
	}
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
			if other, named := otherGrammars[val]; named && other.file == name {
				exempt = append(exempt, val)
			} else {
				bad = append(bad, fmt.Sprintf("%s: %s", fset.Position(lit.Pos()), lit.Value))
			}
		}
		return true
	})
	return bad, exempt, nil
}

func TestNoOtherFileSpellsTheSeatGrammar(t *testing.T) {
	root := filepath.Join("..", "..")
	scanned := 0
	spelled := map[string]int{} // key of otherGrammars -> times found in its file
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if rel == "internal/identity/seat.go" {
				return nil // the one definition
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			lits, exempt, err := seatLiterals(rel, src)
			if err != nil {
				return err
			}
			for _, v := range exempt {
				spelled[v]++
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
	for _, d := range deadKeys(otherGrammars, spelled) {
		t.Error(d)
	}
}

// deadKeys names the exemptions whose literal is not spelled in their file: such an entry
// exempts nothing today and would silently exempt a copy placed there tomorrow.
func deadKeys(table map[string]otherGrammar, spelled map[string]int) []string {
	var dead []string
	for key, other := range table {
		if spelled[key] == 0 {
			dead = append(dead, fmt.Sprintf("otherGrammars key %q (%s) is not spelled as a literal in %s: remove the entry or fix its file", key, other.reason, other.file))
		}
	}
	return dead
}

func TestSeatLiteralCheck_CatchesACopy(t *testing.T) {
	// Both shapes of the grammar, and a drifted copy of each (it would be a
	// second, different definition), are found.
	for name, copyOf := range map[string]string{
		"current shape":      "package x\nimport \"regexp\"\nvar v = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)\n",
		"end-anchored shape": "package x\nimport \"regexp\"\nvar v = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$`)\n",
	} {
		if lits, _, err := seatLiterals("x.go", copyOf); err != nil || len(lits) != 1 {
			t.Fatalf("%s: a copy of the seat grammar was not found: %v, %v", name, lits, err)
		}
		drifted := strings.Replace(strings.Replace(copyOf, "{0,62}", "{0,50}", 1), "{0,51}", "{0,40}", 1)
		if drifted == copyOf {
			t.Fatalf("%s: the drift did not change the copy; the mutation tests nothing", name)
		}
		if lits, _, _ := seatLiterals("x.go", drifted); len(lits) != 1 {
			t.Fatalf("%s: a drifted copy was not found: %v", name, lits)
		}
	}
	// the named other grammar is not a seat
	seed := "package x\nvar v = `^[a-z0-9][a-z0-9-]{0,31}$`\n"
	if lits, _, _ := seatLiterals("internal/e2e/serve/main.go", seed); len(lits) != 0 {
		t.Fatalf("the seed-name grammar was flagged in its own file: %v", lits)
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

// ADR-0047 V4: the DNS label has the seat's shape on purpose and is exempt in exactly one
// file. The same text in any other file (a copy of dnsname.Label in another package, or
// in a test-free file of the same one) is a second definition and red; in its own file
// it is found and reported as the exemption, which the dead-key check counts.
func TestDNSLabelExemptionIsScopedToItsFile(t *testing.T) {
	src := "package x\nimport \"regexp\"\nvar v = regexp.MustCompile(`^" + dnsname.Label + "$`)\nconst label = `" + dnsname.Label + "`\n"
	// `^Label$` is not the key (an anchored copy is a different value), so it is flagged
	// anywhere; the bare Label is exempt only in internal/dnsname/dnsname.go.
	if bad, _, err := seatLiterals("internal/other/x.go", src); err != nil || len(bad) != 2 {
		t.Fatalf("a copy of the DNS label in another package: found %v, %v, want 2 (the bare and the anchored one)", bad, err)
	}
	bad, exempt, err := seatLiterals("internal/dnsname/dnsname.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 1 || len(exempt) != 1 || exempt[0] != dnsname.Label {
		t.Fatalf("in its own file: bad %v, exempt %v, want the anchored copy bad and the bare Label exempt", bad, exempt)
	}
}

// ADR-0047 V4, the dead-key side: an exemption spelled nowhere is named; one spelled in
// its file is not.
func TestDeadExemptionKeyIsDetected(t *testing.T) {
	table := map[string]otherGrammar{"^kept$": {"a.go", "kept"}, "^gone$": {"b.go", "gone"}}
	dead := deadKeys(table, map[string]int{"^kept$": 1})
	if len(dead) != 1 || !strings.Contains(dead[0], "^gone$") {
		t.Fatalf("dead keys = %v, want exactly ^gone$", dead)
	}
	if dead := deadKeys(table, map[string]int{"^kept$": 1, "^gone$": 2}); len(dead) != 0 {
		t.Fatalf("every key is spelled, yet dead keys = %v", dead)
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
