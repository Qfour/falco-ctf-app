package specparity

// The spec <-> Go parity of identifier grammars, one mechanism for all of them
// (app#440; it replaces the per-identifier checks: the {cid} pattern extracted
// by regex from the raw spec text, the board id's table of YAML node paths, and
// the seat's source-text comparisons of validUser copies).

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
)

// identifierGrammars is THE table: every identifier grammar that a spec repeats
// as `pattern`, with its one Go definition. Add a row when a spec gains a new
// identifier pattern; the test fails until you do.
func identifierGrammars() []Grammar {
	return []Grammar{
		{Name: "seat (identity.SeatPattern)", Pattern: identity.SeatPattern},
		{Name: "challenge id (challengeid.Pattern)", Pattern: challengeid.Pattern},
		{Name: "board id (board.IDPattern)", Pattern: board.IDPattern()},
	}
}

func TestSpecPatternsAreExactlyTheGoGrammars(t *testing.T) {
	docs := filepath.Join("..", "..", "..", "docs")
	paths, err := filepath.Glob(filepath.Join(docs, "openapi-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no docs/openapi-*.yaml under %s", docs)
	}
	specs := map[string]map[string][]string{}
	for _, p := range paths {
		spec, err := LoadSpec(p)
		if err != nil {
			t.Fatal(err)
		}
		specs[filepath.Base(p)] = spec.PatternSites()
	}
	if v := PatternParityViolations(specs, identifierGrammars()); len(v) > 0 {
		t.Fatalf("a spec `pattern` and the Go grammar definitions disagree:\n  %s", strings.Join(v, "\n  "))
	}

	// Every grammar is repeated at the places it must be (not merely somewhere):
	// the seat in all three specs, the challenge id in scoreboard and collector,
	// the board id in the scoreboard. A node that lost its pattern is caught here
	// without a list of nodes.
	where := map[string][]string{
		identity.SeatPattern: {"openapi-auth-policy.yaml", "openapi-collector.yaml", "openapi-scoreboard.yaml"},
		challengeid.Pattern:  {"openapi-collector.yaml", "openapi-scoreboard.yaml"},
		board.IDPattern():    {"openapi-scoreboard.yaml"},
	}
	for pattern, files := range where {
		var got []string
		for f, sites := range specs {
			if len(sites[pattern]) > 0 {
				got = append(got, f)
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(files, ",") {
			t.Errorf("pattern %q is in %v, want exactly %v", pattern, got, files)
		}
	}
}

func TestPatternParity_Mutations(t *testing.T) {
	grammars := []Grammar{{"seat", `^[a-z]+$`}, {"cid", `^[0-9]{2}$`}}
	ok := map[string]map[string][]string{
		"a.yaml": {`^[a-z]+$`: {"/p1", "/p2"}},
		"b.yaml": {`^[0-9]{2}$`: {"/q"}},
	}
	if v := PatternParityViolations(ok, grammars); len(v) != 0 {
		t.Fatalf("the consistent case was flagged: %v", v)
	}
	cases := []struct {
		name     string
		specs    map[string]map[string][]string
		grammars []Grammar
		want     string
	}{
		{"a spec pattern changed by one character",
			map[string]map[string][]string{"a.yaml": {`^[a-y]+$`: {"/p"}}, "b.yaml": {`^[0-9]{2}$`: {"/q"}}}, grammars,
			`a.yaml: pattern "^[a-y]+$" (at /p) is not the Go definition`},
		{"the same spec change leaves the Go grammar unmatched",
			map[string]map[string][]string{"a.yaml": {`^[a-y]+$`: {"/p"}}, "b.yaml": {`^[0-9]{2}$`: {"/q"}}}, grammars,
			`grammar "seat" ("^[a-z]+$") appears in no spec`},
		{"a grammar in the table that no spec repeats",
			ok, append(append([]Grammar{}, grammars...), Grammar{"extra", `^x$`}),
			`grammar "extra" ("^x$") appears in no spec`},
		{"a spec pattern with no Go definition",
			map[string]map[string][]string{"a.yaml": {`^[a-z]+$`: {"/p"}, `^new$`: {"/n"}}, "b.yaml": {`^[0-9]{2}$`: {"/q"}}}, grammars,
			`a.yaml: pattern "^new$" (at /n) is not the Go definition`},
		{"nothing extracted",
			map[string]map[string][]string{"a.yaml": {}}, grammars,
			"no `pattern` found in any spec"},
		{"an empty table",
			ok, nil, "the table of Go grammars is empty"},
		{"two grammars with one pattern",
			ok, []Grammar{{"seat", `^[a-z]+$`}, {"cid", `^[0-9]{2}$`}, {"dup", `^[a-z]+$`}},
			`grammars "seat" and "dup" have the same pattern`},
		{"an empty grammar pattern",
			ok, []Grammar{{"seat", `^[a-z]+$`}, {"cid", `^[0-9]{2}$`}, {"blank", ""}},
			`grammar "blank" has an empty pattern`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := PatternParityViolations(tc.specs, tc.grammars)
			if len(v) == 0 {
				t.Fatal("the mutation was not detected")
			}
			if all := strings.Join(v, "\n"); !strings.Contains(all, tc.want) {
				t.Fatalf("violations do not contain %q; got:\n%s", tc.want, all)
			}
		})
	}
}

func TestSpec_PatternSites(t *testing.T) {
	s := specFromYAML(t, `
openapi: 3.1.0
components:
  schemas:
    A:
      type: object
      properties:
        pattern: {type: string, pattern: '^a$'}
        b: {type: string, pattern: '^a$'}
        c: {type: string, pattern: '^c$'}
        d: {type: string}
`)
	got := s.PatternSites()
	if len(got) != 2 || len(got["^a$"]) != 2 || len(got["^c$"]) != 1 {
		t.Fatalf("PatternSites = %v, want ^a$ at 2 places and ^c$ at 1 (a property merely NAMED pattern is no keyword)", got)
	}
}
