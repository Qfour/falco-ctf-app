package specparity

// The spec <-> Go parity of identifier grammars, one mechanism for all of them
// (app#440; it replaces the per-identifier checks: the {cid} pattern extracted
// by regex from the raw spec text, the board id's table of YAML node paths, and
// the seat's source-text comparisons of validUser copies).

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
)

// identifierGrammars is THE table: every identifier grammar that a spec repeats
// as `pattern`, with its one Go definition and the exact number of sites per
// spec (one each: the scoreboard writes the seat once as components.schemas.Seat
// and the board id once as components.schemas.BoardID, the cid once as the Cid
// parameter; the collector and auth-policy documents, which cannot $ref across
// files, keep one inline copy). Add a row when a spec gains a new identifier
// pattern; the test fails until you do. A node that loses its pattern, or a new
// inline copy, changes a site count and is red, with no list of nodes.
func identifierGrammars() []Grammar {
	return []Grammar{
		{Name: "seat (identity.SeatPattern)", Pattern: identity.SeatPattern, MaxLength: seatMaxLength(),
			Sites: map[string]int{"openapi-scoreboard.yaml": 1, "openapi-collector.yaml": 1, "openapi-auth-policy.yaml": 1}},
		{Name: "challenge id (challengeid.Pattern)", Pattern: challengeid.Pattern,
			Sites: map[string]int{"openapi-scoreboard.yaml": 1, "openapi-collector.yaml": 1}},
		{Name: "board id (board.IDPattern)", Pattern: board.IDPattern(),
			Sites: map[string]int{"openapi-scoreboard.yaml": 1}},
	}
}

// seatMaxLength is the longest seat identity.ValidSeat accepts, found by asking
// it (not a second literal): a spec's `maxLength` is held equal to what the Go
// grammar really allows, and a grammar that accepts no length at all, or is
// unbounded here, fails the test instead of passing vacuously.
func seatMaxLength() int {
	longest := 0
	for n := 1; n <= 256; n++ {
		if identity.ValidSeat(strings.Repeat("a", n)) {
			longest = n
		}
	}
	if longest == 0 || longest == 256 {
		panic("identity.ValidSeat accepts no seat, or an unbounded one: the maxLength comparison would be vacuous")
	}
	return longest
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
	lengths := map[string]map[string]map[string]int{}
	for _, p := range paths {
		spec, err := LoadSpec(p)
		if err != nil {
			t.Fatal(err)
		}
		specs[filepath.Base(p)] = spec.PatternSites()
		lengths[filepath.Base(p)] = spec.PatternMaxLengths()
	}
	if v := PatternParityViolations(specs, identifierGrammars()); len(v) > 0 {
		t.Fatalf("a spec `pattern` and the Go grammar definitions disagree:\n  %s", strings.Join(v, "\n  "))
	}
	// The seat's `maxLength` is the other half of its grammar (the pattern bounds
	// the length too; a client reads maxLength first): every site that carries the
	// pattern carries the same bound.
	if v := MaxLengthViolations(lengths, identifierGrammars()); len(v) > 0 {
		t.Fatalf("a spec `maxLength` and the Go grammar definitions disagree:\n  %s", strings.Join(v, "\n  "))
	}
}

func TestMaxLengthViolations_Mutations(t *testing.T) {
	grammars := []Grammar{{Name: "seat", Pattern: `^[a-z]+$`, MaxLength: 53, Sites: map[string]int{"a.yaml": 1, "b.yaml": 1}},
		{Name: "cid", Pattern: `^[0-9]{2}$`, Sites: map[string]int{"a.yaml": 1}}}
	ok := map[string]map[string]map[string]int{
		"a.yaml": {`^[a-z]+$`: {"/p": 53}, `^[0-9]{2}$`: {"/c": -1}},
		"b.yaml": {`^[a-z]+$`: {"/q": 53}},
	}
	if v := MaxLengthViolations(ok, grammars); len(v) != 0 {
		t.Fatalf("the consistent case was flagged: %v", v)
	}
	for _, tc := range []struct {
		name  string
		specs map[string]map[string]map[string]int
		want  string
	}{
		{"one site's maxLength is 54",
			map[string]map[string]map[string]int{"a.yaml": {`^[a-z]+$`: {"/p": 54}}, "b.yaml": {`^[a-z]+$`: {"/q": 53}}},
			`a.yaml /p has maxLength: 54, want 53`},
		{"one site has no maxLength",
			map[string]map[string]map[string]int{"a.yaml": {`^[a-z]+$`: {"/p": 53}}, "b.yaml": {`^[a-z]+$`: {"/q": -1}}},
			`b.yaml /q carries the pattern but no maxLength`},
		{"the pattern is at no site",
			map[string]map[string]map[string]int{"a.yaml": {}},
			`nothing was compared`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := MaxLengthViolations(tc.specs, grammars)
			if all := strings.Join(v, "\n"); len(v) == 0 || !strings.Contains(all, tc.want) {
				t.Fatalf("violations do not contain %q; got:\n%s", tc.want, all)
			}
		})
	}
}

func TestSpec_PatternMaxLengths(t *testing.T) {
	s := specFromYAML(t, `
openapi: 3.1.0
components:
  schemas:
    A:
      type: string
      pattern: '^a$'
      maxLength: 53
    B:
      type: string
      pattern: '^a$'
    C:
      type: string
      pattern: '^a$'
      maxLength: "53"
`)
	got := s.PatternMaxLengths()["^a$"]
	if len(got) != 3 || got["/components/schemas/A"] != 53 || got["/components/schemas/B"] != -1 || got["/components/schemas/C"] != -1 {
		t.Fatalf("PatternMaxLengths = %v, want A=53, B=-1 (none), C=-1 (not an integer)", got)
	}
}

func TestPatternParity_Mutations(t *testing.T) {
	grammars := []Grammar{
		{Name: "seat", Pattern: `^[a-z]+$`, Sites: map[string]int{"a.yaml": 1}},
		{Name: "cid", Pattern: `^[0-9]{2}$`, Sites: map[string]int{"b.yaml": 1}},
	}
	ok := map[string]map[string][]string{
		"a.yaml": {`^[a-z]+$`: {"/p1"}},
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
			ok, append(append([]Grammar{}, grammars...), Grammar{Name: "extra", Pattern: `^x$`, Sites: map[string]int{"a.yaml": 1}}),
			`grammar "extra" ("^x$") appears in no spec`},
		{"a spec pattern with no Go definition",
			map[string]map[string][]string{"a.yaml": {`^[a-z]+$`: {"/p"}, `^new$`: {"/n"}}, "b.yaml": {`^[0-9]{2}$`: {"/q"}}}, grammars,
			`a.yaml: pattern "^new$" (at /n) is not the Go definition`},
		{"nothing extracted",
			map[string]map[string][]string{"a.yaml": {}}, grammars,
			"no `pattern` found in any spec"},
		{"a node lost its pattern (one site fewer)",
			map[string]map[string][]string{"a.yaml": {}, "b.yaml": {`^[0-9]{2}$`: {"/q"}}}, grammars,
			`grammar "seat" ("^[a-z]+$"): a.yaml has 0 site(s) [], want exactly 1`},
		{"a second inline copy of a grammar",
			map[string]map[string][]string{"a.yaml": {`^[a-z]+$`: {"/p1", "/p2"}}, "b.yaml": {`^[0-9]{2}$`: {"/q"}}}, grammars,
			`a.yaml has 2 site(s) [/p1 /p2], want exactly 1`},
		{"the pattern moved to another document",
			map[string]map[string][]string{"a.yaml": {}, "b.yaml": {`^[0-9]{2}$`: {"/q"}, `^[a-z]+$`: {"/moved"}}}, grammars,
			`grammar "seat" ("^[a-z]+$"): b.yaml has 1 site(s) [/moved], want exactly 0`},
		{"a grammar that names no expected site",
			ok, []Grammar{{Name: "seat", Pattern: `^[a-z]+$`}, grammars[1]},
			`grammar "seat" lists no expected site`},
		{"an empty table",
			ok, nil, "the table of Go grammars is empty"},
		{"two grammars with one pattern",
			ok, append(append([]Grammar{}, grammars...), Grammar{Name: "dup", Pattern: `^[a-z]+$`, Sites: map[string]int{"a.yaml": 1}}),
			`grammars "seat" and "dup" have the same pattern`},
		{"an empty grammar pattern",
			ok, append(append([]Grammar{}, grammars...), Grammar{Name: "blank", Pattern: ""}),
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
