package catalog

// ADR-0055 S3a (D6): the requirements of a scenario are derived from its scope's catalog by
// one function, and the strict decoder holds the block to that function's form.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog/catalogtest"
)

// WriteScenarioFor is catalogtest.WriteScenarioWith with the requirements DeriveRequirements
// gives for the challenges of challengesDir that the scenario lists: the fixture of a test
// that loads the scenario through LoadScored, which compares the block with its scope. It is
// declared in a _test.go file of the package, so the external test package (catalog_test)
// calls it too and no binary holds it.
func WriteScenarioFor(t testing.TB, root, challengesDir, id string, challenges ...string) string {
	t.Helper()
	cat, err := Load(challengesDir)
	if err != nil {
		t.Fatal(err)
	}
	req, err := requirementsOf(cat, challenges)
	if err != nil {
		t.Fatal(err)
	}
	return catalogtest.WriteScenarioWith(t, root, id, FixtureRequirements(req), challenges...)
}

// FixtureRequirements is r as catalogtest's plain values.
func FixtureRequirements(r ScenarioRequirements) catalogtest.Requirements {
	return catalogtest.Requirements{Answers: r.Answers, Detect: r.Detect, Exfil: r.Exfil, Rules: r.Rules}
}

func TestDeriveRequirements(t *testing.T) {
	none := ScenarioRequirements{Answers: []string{}, Rules: []string{}}
	cases := []struct {
		name  string
		scope Catalog
		want  ScenarioRequirements
	}{
		{"an empty scope requires nothing", Catalog{}, none},
		{"an evade challenge with no rule and no exfil requires nothing",
			Catalog{"01-a": {ID: "01-a", Type: TypeEvade, ExpectedFlag: "FALCO{dev-a}"}}, none},
		{"one investigate challenge is one answer",
			Catalog{"50-ir": {ID: "50-ir", Type: TypeInvestigate}},
			ScenarioRequirements{Answers: []string{"50-ir"}, Rules: []string{}}},
		{"one detect challenge is detect",
			Catalog{"02-d": {ID: "02-d", Type: TypeDetect}},
			ScenarioRequirements{Answers: []string{}, Detect: true, Rules: []string{}}},
		{"one exfil challenge is exfil, and its forbidden rule is a rule",
			Catalog{"10-x": {ID: "10-x", Type: TypeEvade, ForbiddenRules: []string{"r"}, RequireExfil: true}},
			ScenarioRequirements{Answers: []string{}, Exfil: true, Rules: []string{"r"}}},
		{"one trigger challenge's expected rule is a rule",
			Catalog{"01-t": {ID: "01-t", Type: TypeTrigger, ExpectedRules: []string{"r"}}},
			ScenarioRequirements{Answers: []string{}, Rules: []string{"r"}}},
		{"several: answers sorted by id, rules the union in byte order, each once",
			Catalog{
				"03-t":  {ID: "03-t", Type: TypeTrigger, ExpectedRules: []string{"b rule", "A rule"}},
				"01-e":  {ID: "01-e", Type: TypeEvade, ExpectedRules: []string{"A rule"}, ForbiddenRules: []string{"c", "b rule"}, RequireExfil: true},
				"04-e":  {ID: "04-e", Type: TypeEvade, ForbiddenRules: []string{"c"}},
				"52-ir": {ID: "52-ir", Type: TypeInvestigate},
				"51-ir": {ID: "51-ir", Type: TypeInvestigate},
				"02-d":  {ID: "02-d", Type: TypeDetect},
				"05-d":  {ID: "05-d", Type: TypeDetect},
			},
			ScenarioRequirements{Answers: []string{"51-ir", "52-ir"}, Detect: true, Exfil: true, Rules: []string{"A rule", "b rule", "c"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i := 0; i < 20; i++ { // map order is random per range: the result is not
				got := DeriveRequirements(c.scope)
				if !reflect.DeepEqual(got, c.want) {
					t.Fatalf("run %d: DeriveRequirements = %#v, want %#v", i, got, c.want)
				}
				if got.Answers == nil || got.Rules == nil {
					t.Fatalf("an empty list is nil (%#v): a decoded [] would not be DeepEqual to it", got)
				}
			}
		})
	}
}

// Compose and ComposeSolo give the requirements of the scope (the flattened challenges), not
// of the pool (the generator's side of the one derivation).
func TestCompose_TheRequirementsAreTheScopes(t *testing.T) {
	c, pool, cat := composeFixture()
	cat["03-c"] = Challenge{ID: "03-c", Type: TypeEvade, ExpectedFlag: "FALCO{x}", ForbiddenRules: []string{"q"}, RequireExfil: true}
	cat["09-z"] = Challenge{ID: "09-z", Type: TypeDetect} // in the pool, not in the course
	got, err := Compose(c, pool, cat)
	if err != nil {
		t.Fatal(err)
	}
	want := ScenarioRequirements{Answers: []string{}, Exfil: true, Rules: []string{"q", "r"}}
	if !reflect.DeepEqual(got.Requirements, want) {
		t.Fatalf("Compose requirements = %#v, want %#v (the scope's, not the pool's)", got.Requirements, want)
	}
	solo, err := ComposeSolo(pool["mod-a"], cat)
	if err != nil {
		t.Fatal(err)
	}
	if want := (ScenarioRequirements{Answers: []string{}, Rules: []string{"r"}}); !reflect.DeepEqual(solo.Requirements, want) {
		t.Fatalf("ComposeSolo requirements = %#v, want %#v", solo.Requirements, want)
	}
}

// One defect per case of the requirements block, each on a file the decoder accepts first.
// Whether the values are the scope's is LoadScored's (requirements_load_test.go); here the
// block is held to its form on its own.
func TestDecodeScenario_RequirementsOneDefectOneCase(t *testing.T) {
	req := catalogtest.Requirements{Answers: []string{"02-b"}, Detect: true, Exfil: true, Rules: []string{"Rule A", "rule b"}}
	good := catalogtest.ScenarioWith("demo", req, "01-a", "02-b")
	two := catalogtest.ScenarioWith("demo", catalogtest.Requirements{Answers: []string{"01-a", "02-b"}}, "01-a", "02-b")
	for _, ok := range []string{good, two} {
		if _, err := DecodeScenario([]byte(ok)); err != nil {
			t.Fatalf("the control was refused (the cases below would prove nothing): %v\n%s", err, ok)
		}
	}
	s, _ := DecodeScenario([]byte(good))
	if want := (ScenarioRequirements{Answers: []string{"02-b"}, Detect: true, Exfil: true, Rules: []string{"Rule A", "rule b"}}); !reflect.DeepEqual(s.Requirements, want) {
		t.Fatalf("requirements = %#v, want %#v", s.Requirements, want)
	}
	noBlock, _, _ := strings.Cut(good, "requirements:\n")
	const (
		answers = "  answers:\n    - 02-b\n"
		rules   = "  rules:\n    - Rule A\n    - rule b\n"
	)
	cases := []struct{ name, body, want string }{
		{"no requirements", noBlock, "requirements is missing"},
		{"requirements null", noBlock + "requirements:\n", "requirements is missing"},
		{"requirements a list", noBlock + "requirements: [a]\n", "requirements is not a mapping"},
		{"requirements a scalar", noBlock + "requirements: none\n", "requirements is not a mapping"},
		{"requirements twice", good + "requirements: {detect: false}\n", `"requirements" already defined`},
		{"no answers", edit(t, good, answers, ""), "requirements.answers is missing or null"},
		{"answers null", edit(t, good, answers, "  answers:\n"), "requirements.answers is missing or null"},
		{"no detect", edit(t, good, "  detect: true\n", ""), "requirements.detect is missing or null"},
		{"detect null", edit(t, good, "  detect: true\n", "  detect: ~\n"), "requirements.detect is missing or null"},
		{"no exfil", edit(t, good, "  exfil: true\n", ""), "requirements.exfil is missing or null"},
		{"no rules", edit(t, good, rules, ""), "requirements.rules is missing or null"},
		{"plantMountDirs (not in D6)", edit(t, good, "  detect: true\n", "  detect: true\n  plantMountDirs: []\n"), "field plantMountDirs not found"},
		{"an unknown key in requirements", edit(t, good, "  exfil: true\n", "  exfil: true\n  tactics: [x]\n"), "field tactics not found"},
		{"a repeated key in requirements", edit(t, good, "  exfil: true\n", "  exfil: true\n  exfil: false\n"), `"exfil" already defined`},
		{"no exfil value", edit(t, good, "  exfil: true\n", "  exfil:\n"), "requirements.exfil is missing or null"},
		{"exfil null", edit(t, good, "  exfil: true\n", "  exfil: null\n"), "requirements.exfil is missing or null"},
		{"answers a scalar", edit(t, good, answers, "  answers: 02-b\n"), "requirements.answers is not a list"},
		{"answers a mapping", edit(t, good, answers, "  answers: {a: b}\n"), "requirements.answers is not a list"},
		{"rules a scalar", edit(t, good, rules, "  rules: r\n"), "requirements.rules is not a list"},
		{"rules a mapping", edit(t, good, rules, "  rules: {a: b}\n"), "requirements.rules is not a list"},
		{"an answer that is not a challenge id", edit(t, good, "    - 02-b\n", "    - b\n"), `"b" is not a challenge id`},
		{"an answer that is not a challenge of the scenario", edit(t, good, "    - 02-b\n", "    - 03-c\n"), `"03-c" is not a challenge of the scenario`},
		{"answers not sorted", edit(t, two, "    - 01-a\n    - 02-b\n", "    - 02-b\n    - 01-a\n"), "requirements.answers is not sorted"},
		{"an answer twice", edit(t, two, "    - 01-a\n    - 02-b\n", "    - 02-b\n    - 02-b\n"), `requirements.answers entry "02-b" is listed more than once`},
		{"rules not sorted", edit(t, good, "    - Rule A\n    - rule b\n", "    - rule b\n    - Rule A\n"), "requirements.rules is not sorted"},
		{"a rule twice", edit(t, good, "    - Rule A\n    - rule b\n", "    - Rule A\n    - Rule A\n"), `requirements.rules entry "Rule A" is listed more than once`},
		{"an empty rule name", edit(t, good, "    - Rule A\n", "    - \"\"\n"), "is not a rule name"},
		{"a rule name with a blank at the end", edit(t, good, "    - Rule A\n", "    - \"Rule A \"\n"), "is not a rule name"},
		{"a rule name with a control character", edit(t, good, "    - Rule A\n", "    - \"Rule\\tA\"\n"), "is not a rule name"},
	}
	// detect and exfil take the generator's plain lower-case true or false only: every other
	// spelling yaml.v3 would decode into a bool, or that is not a bool, is refused.
	for _, key := range []string{"detect", "exfil"} {
		line := "  " + key + ": true\n"
		for _, v := range []string{`"true"`, `'false'`, "yes", "on", "y", "True", "FALSE", "1", "0", "~", "!!bool true", "[true]", "{a: true}"} {
			want := "requirements." + key + " is not true or false"
			if v == "~" {
				want = "requirements." + key + " is missing or null"
			}
			cases = append(cases, struct{ name, body, want string }{key + " " + v, edit(t, good, line, "  "+key+": "+v+"\n"), want})
		}
	}
	// The entries of answers and rules are strings: a number, a bool, a null, a list or a
	// mapping in their place is refused (yaml.v3 would decode a number or a bool into a
	// string).
	for _, l := range []struct{ key, first string }{{"answers", "    - 02-b\n"}, {"rules", "    - Rule A\n"}} {
		for _, v := range []string{"12", "1.5", "true", "~", "[02-b]", "{a: b}"} {
			cases = append(cases, struct{ name, body, want string }{l.key + " entry " + v, edit(t, good, l.first, "    - "+v+"\n"),
				"requirements." + l.key + "[0] is not a string"})
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeScenario([]byte(c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("DecodeScenario = %v, want an error containing %q\n%s", err, c.want, c.body)
			}
		})
	}
}
