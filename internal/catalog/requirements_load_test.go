package catalog_test

// ADR-0055 S3a (D6): the scoreboard's start (LoadScored) derives the requirements again from
// the catalog restricted to the scenario's challenges and refuses a file whose block differs.
// Each refusal changes one key, either on the file's side (the block a stale or hand-edited
// file holds) or on the catalog's side (a challenge of the scope changed after generation).

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/catalogtest"
)

// reqTree is a pool with every kind the block names: a trigger (rule r1), an evade with exfil
// (rules r2 and r3), a detect and an investigate challenge, and a trigger outside the scope
// (rule r9). The scope (reqScope) puts the evade before the investigate challenge (V39).
func reqTree(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "challenges")
	writeChallenge(t, dir, "01-a", "type: trigger\nexpectedRules: [r1]\n")
	writeChallenge(t, dir, "02-b", "type: evade\nexpectedFlag: FALCO{dev-b}\nforbiddenRules: [r3]\nexpectedRules: [r2]\nrequireExfil: true\n")
	writeChallenge(t, dir, "03-c", "type: detect\ndetect:\n  evasionCapture: captures/evasion.scap\n  benignCapture: captures/benign.scap\n")
	writeChallenge(t, dir, "14-ir-demo", inv("", evMount(invMount), invHexQ))
	writeChallenge(t, dir, "09-out", "type: trigger\nexpectedRules: [r9]\n")
	return dir
}

var reqScope = []string{"01-a", "02-b", "03-c", "14-ir-demo"}

func TestLoadScored_RequirementsMustBeWhatTheScopeDerives(t *testing.T) {
	chal := reqTree(t)
	derived := catalogtest.Requirements{Answers: []string{"14-ir-demo"}, Detect: true, Exfil: true, Rules: []string{"r1", "r2", "r3"}}

	// The control, twice: the test's literal block and the helper's derived one both load,
	// so each refusal below is the changed key's.
	for name, p := range map[string]string{
		"literal": catalogtest.WriteScenarioWith(t, t.TempDir(), "sc", derived, reqScope...),
		"helper":  catalog.WriteScenarioFor(t, t.TempDir(), chal, "sc", reqScope...),
	} {
		if _, err := catalog.LoadScored(chal, p, ""); err != nil {
			t.Fatalf("the %s control was refused (the cases below would prove nothing): %v", name, err)
		}
	}

	// The file's side: one key changed to a value the decoder accepts.
	fileCases := []struct {
		name, key string
		edit      func(r *catalogtest.Requirements)
	}{
		{"answers without the investigate challenge", "answers", func(r *catalogtest.Requirements) { r.Answers = nil }},
		{"answers with a challenge that is not investigate", "answers", func(r *catalogtest.Requirements) { r.Answers = []string{"01-a", "14-ir-demo"} }},
		{"detect false", "detect", func(r *catalogtest.Requirements) { r.Detect = false }},
		{"exfil false", "exfil", func(r *catalogtest.Requirements) { r.Exfil = false }},
		{"rules without one", "rules", func(r *catalogtest.Requirements) { r.Rules = []string{"r1", "r3"} }},
		{"rules with one outside the scope", "rules", func(r *catalogtest.Requirements) { r.Rules = []string{"r1", "r2", "r3", "r9"} }},
		{"rules empty", "rules", func(r *catalogtest.Requirements) { r.Rules = nil }},
	}
	for _, c := range fileCases {
		t.Run("file: "+c.name, func(t *testing.T) {
			r := derived
			r.Answers = append([]string(nil), derived.Answers...)
			r.Rules = append([]string(nil), derived.Rules...)
			c.edit(&r)
			p := catalogtest.WriteScenarioWith(t, t.TempDir(), "sc", r, reqScope...)
			if _, err := catalog.LoadScenario(p); err != nil {
				t.Fatalf("the decoder refused the changed block, so LoadScored's comparison is not what is tested: %v", err)
			}
			wantRefused(t, chal, p, c.key)
		})
	}

	// The catalog's side: the file was generated, then a challenge of the scope changed.
	catalogCases := []struct{ name, key, cid, rule string }{
		{"a rule added to a challenge", "rules", "01-a", "type: trigger\nexpectedRules: [r1, r4]\n"},
		{"exfil dropped from a challenge", "exfil", "02-b", "type: evade\nexpectedFlag: FALCO{dev-b}\nforbiddenRules: [r3]\nexpectedRules: [r2]\n"},
		{"a detect challenge made a trigger", "detect", "03-c", "type: trigger\nexpectedRules: [r1]\n"},
		{"the investigate challenge made a trigger", "answers", "14-ir-demo", "type: trigger\nexpectedRules: [r1]\n"},
	}
	for _, c := range catalogCases {
		t.Run("catalog: "+c.name, func(t *testing.T) {
			chal := reqTree(t)
			p := catalog.WriteScenarioFor(t, t.TempDir(), chal, "sc", reqScope...)
			writeChallenge(t, chal, c.cid, c.rule)
			wantRefused(t, chal, p, c.key)
		})
	}

	// A change outside the scope changes nothing.
	t.Run("catalog: a rule added to a challenge outside the scope", func(t *testing.T) {
		chal := reqTree(t)
		p := catalog.WriteScenarioFor(t, t.TempDir(), chal, "sc", reqScope...)
		writeChallenge(t, chal, "09-out", "type: trigger\nexpectedRules: [r9, r10]\n")
		if _, err := catalog.LoadScored(chal, p, ""); err != nil {
			t.Fatalf("a change outside the scope was refused: %v", err)
		}
	})
}

// wantRefused is LoadScored(chal, p) refused with ErrRequirementsDiffer, naming the file and
// the key.
func wantRefused(t *testing.T, chal, p, key string) {
	t.Helper()
	_, err := catalog.LoadScored(chal, p, "")
	if !errors.Is(err, catalog.ErrRequirementsDiffer) || !strings.Contains(err.Error(), key+" is ") || !strings.Contains(err.Error(), p) {
		t.Fatalf("LoadScored = %v; want ErrRequirementsDiffer naming %s and the key %s", err, p, key)
	}
}

// LoadScored with no scenario has no block to compare (the platform reads the challenges for
// that scope: the contract table's row), and loads the same tree.
func TestLoadScored_NoScenarioComparesNoRequirements(t *testing.T) {
	if _, err := catalog.LoadScored(reqTree(t), "", ""); err != nil {
		t.Fatalf("LoadScored with no scenario: %v", err)
	}
}
