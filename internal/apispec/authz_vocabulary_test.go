package apispec

// The x-ctf-authz VOCABULARY is a closed set that is declared in three places
// — the Authz constants (route.go), the Routes that use them (non-test code
// under internal/ and cmd/), and the x-ctf-authz values in every
// docs/openapi-*.yaml — and ADR-0034 judgement (c) says a word is only
// allowed to exist if all three agree and something actually uses it. #374
// (app#346) deleted self-or-admin-write and guarded the deletion with a
// tombstone test naming that one word; #376 replaces it with the general
// form here, so the next dead word is caught without anyone having to know
// its name:
//
//	(a) every Authz constant is used by at least one Route in non-test code
//	(b) every x-ctf-authz value in every spec is a declared constant
//	(c) every declared constant appears in some spec (no dead vocabulary)
//
// plus: the spec files scanned are exactly the ones the mux-owning binaries
// (mux_ownership_test.go) are derived to need, and nothing is scanned empty.
//
// What the general form deliberately does NOT do: forbid a word by name. A
// new word that is declared, used by a Route and written in a spec is a
// deliberate, reviewed vocabulary change, not drift.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// authzConstsInSource returns name -> value for every constant of type Authz
// declared in src (a string-literal initialiser; any other initialiser form is
// reported in bad, so a constant built at run time cannot dodge the scan).
func authzConstsInSource(t *testing.T, file string, src any) (consts map[string]string, bad []string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	consts = map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Authz" {
				continue
			}
			for i, name := range vs.Names {
				var lit *ast.BasicLit
				if i < len(vs.Values) {
					lit, _ = vs.Values[i].(*ast.BasicLit)
				}
				if lit == nil || lit.Kind != token.STRING {
					bad = append(bad, file+": Authz constant "+name.Name+" is not a plain string literal")
					continue
				}
				v, _ := strconv.Unquote(lit.Value)
				consts[name.Name] = v
			}
		}
	}
	return consts, bad
}

// authzUsesInSource counts, per constant name, the Route literals in src whose
// Authz field is set to apispec.<Name> (the import is resolved by path, so an
// aliased import counts). An Authz field set to anything else — a string
// literal, a variable, a call — is reported in bad: that form cannot be
// matched to a constant, and an unmatched use must fail, not vanish.
func authzUsesInSource(t *testing.T, file string, src any) (uses map[string]int, bad []string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	names := importNames(f)
	uses = map[string]int{}
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Authz" {
			return true
		}
		if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && names[x.Name] == apispecImportPath {
				uses[sel.Sel.Name]++
				return true
			}
		}
		bad = append(bad, file+": Route Authz is not an apispec.Authz* constant reference")
		return true
	})
	return uses, bad
}

// repoAuthzSources reads the real vocabulary: the constants declared in this
// package's non-test files, and the Route uses in every non-test Go file under
// internal/ and cmd/. parsed is how many files the use scan covered.
func repoAuthzSources(t *testing.T, root string) (consts map[string]string, uses map[string]int, parsed int, bad []string) {
	t.Helper()
	consts = map[string]string{}
	for _, p := range nonTestGoFiles(t, filepath.Join(root, "internal", "apispec")) {
		c, b := authzConstsInSource(t, p, nil)
		for k, v := range c {
			consts[k] = v
		}
		bad = append(bad, b...)
	}
	uses = map[string]int{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			parsed++
			u, b := authzUsesInSource(t, p, nil)
			for k, n := range u {
				uses[k] += n
			}
			bad = append(bad, b...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return consts, uses, parsed, bad
}

// specAuthzValuesInYAML returns value -> operations ("METHOD path") that
// declare it as x-ctf-authz, plus the number of operations seen.
func specAuthzValuesInYAML(t *testing.T, name string, data []byte) (values map[string][]string, ops int) {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	values = map[string][]string{}
	for path, item := range doc.Paths {
		for method, raw := range item {
			op, ok := raw.(map[string]any)
			if !ok {
				continue // parameters:, summary:, $ref ... are not operations
			}
			switch strings.ToUpper(method) {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE":
			default:
				continue
			}
			ops++
			if v, ok := op["x-ctf-authz"].(string); ok {
				values[v] = append(values[v], name+": "+strings.ToUpper(method)+" "+path)
			}
		}
	}
	return values, ops
}

// repoSpecAuthzValues merges the x-ctf-authz values of every docs/openapi-*.yaml.
func repoSpecAuthzValues(t *testing.T, root string) (values map[string][]string, files []string, ops int) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "docs", "openapi-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	values = map[string][]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		v, n := specAuthzValuesInYAML(t, filepath.Base(p), b)
		ops += n
		for k, where := range v {
			values[k] = append(values[k], where...)
		}
		files = append(files, filepath.Base(p))
	}
	sort.Strings(files)
	return values, files, ops
}

// authzVocabularyViolations is the pure comparison (a)-(c); every input is a
// plain map so the mutation tests below can feed it synthetic vocabularies.
func authzVocabularyViolations(consts map[string]string, uses map[string]int, specValues map[string][]string) []string {
	var out []string
	declaredValues := map[string]string{}
	for name, v := range consts {
		declaredValues[v] = name
	}
	for _, name := range sortedKeys(consts) {
		if uses[name] == 0 {
			out = append(out, "(a) apispec."+name+" ("+strconv.Quote(consts[name])+") is used by no Route in non-test code — dead vocabulary")
		}
		if len(specValues[consts[name]]) == 0 {
			out = append(out, "(c) apispec."+name+" ("+strconv.Quote(consts[name])+") appears in no docs/openapi-*.yaml x-ctf-authz — dead vocabulary")
		}
	}
	for _, name := range sortedKeys(uses) {
		if _, ok := consts[name]; !ok {
			out = append(out, "(a) a Route uses apispec."+name+", which is not a declared Authz constant")
		}
	}
	for _, v := range sortedKeys(specValues) {
		if _, ok := declaredValues[v]; !ok {
			out = append(out, "(b) x-ctf-authz: "+strconv.Quote(v)+" is not a declared Authz constant ("+strings.Join(specValues[v], "; ")+")")
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestAuthzVocabulary_ConstantsRoutesAndSpecsAgree runs (a)-(c) on the repo.
func TestAuthzVocabulary_ConstantsRoutesAndSpecsAgree(t *testing.T) {
	root := repoRoot(t)
	consts, uses, parsed, bad := repoAuthzSources(t, root)
	specValues, files, ops := repoSpecAuthzValues(t, root)

	// Fail-closed: an empty scan is "nothing to compare", never "agreement".
	// No count is hard-coded; non-emptiness is the only requirement.
	if len(consts) == 0 {
		t.Fatal("no Authz constant found in internal/apispec — the declaration scan is broken")
	}
	if parsed == 0 || len(uses) == 0 {
		t.Fatalf("parsed %d non-test Go files and found %d distinct Authz constants in Routes — the use scan is broken", parsed, len(uses))
	}
	if len(files) == 0 || ops == 0 || len(specValues) == 0 {
		t.Fatalf("spec scan saw %d files, %d operations, %d distinct x-ctf-authz values — the spec scan is broken", len(files), ops, len(specValues))
	}
	for _, b := range bad {
		t.Error(b)
	}
	for _, v := range authzVocabularyViolations(consts, uses, specValues) {
		t.Error(v)
	}
}

// TestAuthzVocabulary_ScannedSpecsAreTheMuxOwnersSpecs: the spec set the
// vocabulary scan reads equals the set derived from "which cmd/* binary owns
// an http.ServeMux" (mux_ownership_test.go), so a spec cannot hide from the
// scan by being outside a hand-written list, and the scan is not run on a
// hard-coded number of files.
func TestAuthzVocabulary_ScannedSpecsAreTheMuxOwnersSpecs(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, e := range entries {
		if !e.IsDir() || !cmdOwnsServeMux(t, root, e.Name()) {
			continue
		}
		f, known := specNameForCmd[e.Name()]
		if !known {
			t.Fatalf("cmd/%s owns a ServeMux but has no entry in specNameForCmd", e.Name())
		}
		want = append(want, f)
	}
	sort.Strings(want)
	_, got, _ := repoSpecAuthzValues(t, root)
	if len(want) == 0 {
		t.Fatal("derived no mux-owning binary — the ownership walk is broken")
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("docs/openapi-*.yaml files %v != specs of the mux-owning binaries %v", got, want)
	}
}

// --- the detector is not vacuous: V8 mutations ------------------------------

func baselineVocabulary() (map[string]string, map[string]int, map[string][]string) {
	return map[string]string{"AuthzNone": "none", "AuthzAdmin": "admin"},
		map[string]int{"AuthzNone": 3, "AuthzAdmin": 1},
		map[string][]string{"none": {"s.yaml: GET /healthz"}, "admin": {"s.yaml: POST /api/admin/reset"}}
}

func TestAuthzVocabularyDetector_CleanBaselineIsClean(t *testing.T) {
	c, u, s := baselineVocabulary()
	if v := authzVocabularyViolations(c, u, s); len(v) != 0 {
		t.Fatalf("clean baseline flagged: %v", v)
	}
}

// Each mutation must be red and the message must carry its rule letter, so a
// failure names which half of the vocabulary drifted.
func TestAuthzVocabularyDetector_CatchesMutations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(c map[string]string, u map[string]int, s map[string][]string)
		want   string
	}{
		{"fictional constant: declared, used by a Route, in no spec", func(c map[string]string, u map[string]int, s map[string][]string) {
			c["AuthzGhost"] = "ghost"
			u["AuthzGhost"] = 1
		}, "(c) apispec.AuthzGhost"},
		{"fictional spec value: a spec writes a word no constant declares (the self-or-admin-write shape)", func(c map[string]string, u map[string]int, s map[string][]string) {
			s["self-or-admin-write"] = []string{"s.yaml: POST /api/challenges/{cid}/submit-detect"}
		}, "(b) x-ctf-authz: \"self-or-admin-write\""},
		{"unused constant: declared and in a spec, no Route uses it", func(c map[string]string, u map[string]int, s map[string][]string) {
			c["AuthzOrphan"] = "orphan"
			s["orphan"] = []string{"s.yaml: GET /x"}
		}, "(a) apispec.AuthzOrphan"},
		{"a Route uses a constant that is not declared", func(c map[string]string, u map[string]int, s map[string][]string) {
			u["AuthzUndeclared"] = 1
		}, "(a) a Route uses apispec.AuthzUndeclared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, u, s := baselineVocabulary()
			tc.mutate(c, u, s)
			v := authzVocabularyViolations(c, u, s)
			if len(v) == 0 {
				t.Fatalf("mutation not detected")
			}
			if !strings.Contains(strings.Join(v, "\n"), tc.want) {
				t.Fatalf("violations %v do not name %q", v, tc.want)
			}
		})
	}
}

// The extractors themselves: planted source/spec text must be seen, so an
// extractor that silently returns nothing cannot hide behind the empty-scan
// guard alone.
func TestAuthzVocabularyExtractors_SeePlantedForms(t *testing.T) {
	consts, bad := authzConstsInSource(t, "planted.go", "package apispec\ntype Authz string\nconst (\n\tAuthzA Authz = \"a\"\n\tAuthzB Authz = \"b\" + \"c\"\n)\n")
	if consts["AuthzA"] != "a" || len(bad) != 1 {
		t.Fatalf("consts=%v bad=%v: want AuthzA=a and the computed AuthzB flagged", consts, bad)
	}

	uses, bad := authzUsesInSource(t, "planted.go", `package p
import ap "github.com/Qfour/falco-ctf-app/internal/apispec"
var _ = []ap.Route{{Authz: ap.AuthzA}, {Authz: ap.AuthzA}, {Authz: "none"}}
`)
	if uses["AuthzA"] != 2 || len(bad) != 1 {
		t.Fatalf("uses=%v bad=%v: want AuthzA x2 through the alias and the string-literal Authz flagged", uses, bad)
	}
	// A look-alike package named apispec at another path is not ours.
	uses, _ = authzUsesInSource(t, "other.go", "package p\nimport \"example.com/other/apispec\"\nvar _ = apispec.Route{Authz: apispec.AuthzA}\n")
	if uses["AuthzA"] != 0 {
		t.Fatalf("a foreign apispec package was counted: %v", uses)
	}

	vals, ops := specAuthzValuesInYAML(t, "p.yaml", []byte(`paths:
  /a:
    parameters: []
    get:
      x-ctf-authz: none
    post:
      x-ctf-authz: admin
  /b:
    get:
      summary: no authz key
`))
	if ops != 3 || len(vals["none"]) != 1 || len(vals["admin"]) != 1 || len(vals) != 2 {
		t.Fatalf("ops=%d vals=%v: want 3 operations and none/admin once each", ops, vals)
	}
}
