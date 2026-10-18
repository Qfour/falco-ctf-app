package api

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
)

// Every id of the real challenges/ tree is accepted by the {cid} grammar and none
// collides with the folded label value, so the fold can never hide a real id.
func TestRealCatalogIDsFitTheCIDGrammar(t *testing.T) {
	cat, err := catalog.Load(filepath.Join("..", "..", "..", "challenges"))
	if err != nil {
		t.Fatal(err)
	}
	ids := cat.IDs()
	if len(ids) == 0 {
		t.Fatal("the real catalog has no ids; the check below would be vacuous")
	}
	for _, id := range ids {
		if !challengeid.Valid(id) {
			t.Errorf("catalog id %q does not match the {cid} grammar %s", id, challengeid.Pattern)
		}
		if id == unknownCIDLabel {
			t.Errorf("catalog id %q equals the folded label value", id)
		}
	}
}

// Both specs' Cid parameter pattern (scoreboard and collector) is the same
// expression as the one definition, challengeid.Pattern.
func TestSpecCidPatternMatchesTheGrammar(t *testing.T) {
	for _, spec := range []string{"openapi-scoreboard.yaml", "openapi-collector.yaml"} {
		t.Run(spec, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", spec))
			if err != nil {
				t.Fatal(err)
			}
			// The pattern under components.parameters.Cid, in either the flow form
			// (`schema: { type: string, pattern: "<re>" }`) or the block form
			// (`pattern: "<re>"` on its own line).
			re := regexp.MustCompile(`(?m)^    Cid:\n(?:      .*\n)*?.*\bpattern: "([^"]+)"`)
			m := re.FindSubmatch(raw)
			if m == nil {
				t.Fatal("no pattern found for the Cid parameter in the spec (extraction returned nothing)")
			}
			if got, want := string(m[1]), challengeid.Pattern; got != want {
				t.Fatalf("spec Cid.pattern = %q, challengeid.Pattern = %q; keep them identical", got, want)
			}
		})
	}
}
