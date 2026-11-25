package catalog

// requirements.go is ADR-0055 D6's `requirements` of a scenario (stage S3a): what the
// environment must provide for the challenges of its scope. It is derived from the scope's
// catalog and never declared, by one function (DeriveRequirements) that the generator
// (Compose and ComposeSolo, so cmd/gen-scenarios and its --check) and the scoreboard's start
// (LoadScored) both call. The platform reads the block from the generated file (the contract
// table's row "コースの必要な機能"); the app refuses a file whose block is not the derived one.

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
)

// ScenarioRequirements is the `requirements` block of a scenario.yaml (D6). The generator
// writes its four keys in this order, each one present:
//   - answers: the ids of the scope's investigate challenges, sorted (ADR-0056 D17);
//   - detect: whether the scope has a detect challenge;
//   - exfil: whether a challenge of the scope scores with an exfil receipt (requireExfil);
//   - rules: the rule names of expectedRules ∪ forbiddenRules over the scope, sorted, each
//     once. The app does not tell the default ruleset from customRules: whether each name
//     resolves is the platform's check (C7).
//
// A list is sorted in byte order (sort.Strings) with no name twice, and a list with nothing
// in it is an empty slice, never nil, so a decoded file and a derived value are
// reflect.DeepEqual. D6 has no plantMountDirs (the CTO's decision of 2026-11-25: the
// catalog cannot derive it, and nothing reads it).
type ScenarioRequirements struct {
	Answers []string `yaml:"answers"`
	Detect  bool     `yaml:"detect"`
	Exfil   bool     `yaml:"exfil"`
	Rules   []string `yaml:"rules"`
}

// ErrRequirementsDiffer wraps LoadScored's refusal of a scenario whose requirements are not
// the ones its scope derives (a file generated before a challenge of its scope changed, or
// edited by hand).
var ErrRequirementsDiffer = errors.New("the scenario's requirements are not the ones its scope derives")

// DeriveRequirements is the requirements of scope, the catalog restricted to a scenario's
// challenges (Restrict). It is the one derivation of D6: nothing else computes the block.
// It reads the challenges' fields only (no file, no environment).
func DeriveRequirements(scope Catalog) ScenarioRequirements {
	r := ScenarioRequirements{Answers: []string{}, Rules: []string{}}
	for _, id := range scope.IDs() { // sorted, so answers is too
		ch := scope[id]
		switch ch.Type {
		case TypeInvestigate:
			r.Answers = append(r.Answers, id)
		case TypeDetect:
			r.Detect = true
		}
		if ch.RequireExfil {
			r.Exfil = true
		}
		r.Rules = append(r.Rules, ch.ExpectedRules...)
		r.Rules = append(r.Rules, ch.ForbiddenRules...)
	}
	slices.Sort(r.Rules)
	r.Rules = slices.Compact(r.Rules)
	return r
}

// requirementsOf is DeriveRequirements of cat restricted to ids (fail-closed: an id that is
// not a challenge of cat is Restrict's error).
func requirementsOf(cat Catalog, ids []string) (ScenarioRequirements, error) {
	scope, err := cat.Restrict(ids)
	if err != nil {
		return ScenarioRequirements{}, err
	}
	return DeriveRequirements(scope), nil
}

// checkRequirements is an error wrapping ErrRequirementsDiffer, naming every key whose value
// in s differs from DeriveRequirements(scope), when one does. scope is the catalog restricted
// to s.Challenges.
func (s Scenario) checkRequirements(scope Catalog) error {
	got, want := s.Requirements, DeriveRequirements(scope)
	var diff []string
	if !slices.Equal(got.Answers, want.Answers) {
		diff = append(diff, fmt.Sprintf("answers is %q, the scope derives %q", got.Answers, want.Answers))
	}
	if got.Detect != want.Detect {
		diff = append(diff, fmt.Sprintf("detect is %t, the scope derives %t", got.Detect, want.Detect))
	}
	if got.Exfil != want.Exfil {
		diff = append(diff, fmt.Sprintf("exfil is %t, the scope derives %t", got.Exfil, want.Exfil))
	}
	if !slices.Equal(got.Rules, want.Rules) {
		diff = append(diff, fmt.Sprintf("rules is %q, the scope derives %q", got.Rules, want.Rules))
	}
	if len(diff) == 0 {
		return nil
	}
	return fmt.Errorf("%w (ADR-0055 D6): %s; run make gen-scenarios", ErrRequirementsDiffer, strings.Join(diff, "; "))
}

// requirementsShape holds the requirements block of doc (sourceDocument's node) to the one
// form the generator writes, on the nodes, before the strict decode (which would read a
// missing key or a null as false or an empty list, and yaml.v3 decodes words such as yes
// or a quoted "true" into a bool, and a number into a string). The platform reads the same
// file with its own reader, so the block has one spelling (D6, fail-closed):
//   - requirements is written and is a mapping; each of answers, detect, exfil and rules is
//     written and not null;
//   - detect and exfil are a plain scalar of tag !!bool whose text is true or false;
//   - answers and rules are lists whose entries are each a scalar of tag !!str (plain or
//     quoted: the generator quotes a value YAML would not read plain as itself).
//
// An unknown or repeated key is the strict decode's error; the first occurrence of a key is
// the one looked at here.
func requirementsShape(doc *yaml.Node) error {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("the document is not a mapping")
	}
	req := mappingValue(doc.Content[0], "requirements")
	if req == nil || isNull(req) {
		return errors.New("requirements is missing (ADR-0055 D6: a generated scenario.yaml writes it; run make gen-scenarios)")
	}
	if req.Kind != yaml.MappingNode {
		return errors.New("requirements is not a mapping of answers, detect, exfil and rules (ADR-0055 D6)")
	}
	for _, key := range []string{"answers", "detect", "exfil", "rules"} {
		v := mappingValue(req, key)
		if v == nil || isNull(v) {
			return fmt.Errorf("requirements.%s is missing or null (ADR-0055 D6: the four keys are always written)", key)
		}
		switch key {
		case "detect", "exfil":
			if v.Kind != yaml.ScalarNode || v.Style != 0 || v.ShortTag() != "!!bool" || (v.Value != "true" && v.Value != "false") {
				return fmt.Errorf("requirements.%s is not true or false written plain in lower case, the one form the generator writes (ADR-0055 D6)", key)
			}
		default:
			if v.Kind != yaml.SequenceNode {
				return fmt.Errorf("requirements.%s is not a list (ADR-0055 D6)", key)
			}
			for i, e := range v.Content {
				if e.Kind != yaml.ScalarNode || e.ShortTag() != "!!str" {
					return fmt.Errorf("requirements.%s[%d] is not a string (a YAML scalar of tag !!str, as the generator writes it; ADR-0055 D6)", key, i)
				}
			}
		}
	}
	return nil
}

// mappingValue is the value node of the first key named key in the mapping node m, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i]; k.Kind == yaml.ScalarNode && k.Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// isNull reports whether n is a null scalar (written as nothing, ~ or null).
func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

// validate holds the block to the form DeriveRequirements gives, on its own and against the
// scenario's challenges: answers are challenge ids of the scenario, rules are names written
// on one line without blanks at either end, and each list is sorted with nothing twice.
// Whether the values are the scope's is LoadScored's (it needs the catalog).
func (r ScenarioRequirements) validate(challenges []string) error {
	for _, id := range r.Answers {
		if !challengeid.Valid(id) {
			return fmt.Errorf("requirements.answers: %q is not a challenge id (%s)", id, challengeid.Pattern)
		}
		if !slices.Contains(challenges, id) {
			return fmt.Errorf("requirements.answers: %q is not a challenge of the scenario", id)
		}
	}
	for _, name := range r.Rules {
		if !validRuleName(name) {
			return fmt.Errorf("requirements.rules: %q is not a rule name (not empty, valid UTF-8, no blank at either end, no control character)", name)
		}
	}
	for _, l := range []struct {
		name string
		list []string
	}{{"answers", r.Answers}, {"rules", r.Rules}} {
		if err := noRepeat("requirements."+l.name+" entry", l.list); err != nil {
			return err
		}
		if !slices.IsSorted(l.list) {
			return fmt.Errorf("requirements.%s is not sorted (ADR-0055 D6: byte order)", l.name)
		}
	}
	return nil
}

// validRuleName reports whether s can be a rule name of the block: not empty, valid UTF-8,
// no blank at either end and no control character (a line break would end the line).
func validRuleName(s string) bool {
	if s == "" || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}
