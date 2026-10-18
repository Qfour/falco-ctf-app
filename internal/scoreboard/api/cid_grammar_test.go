package api

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
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
		if !validCID.MatchString(id) {
			t.Errorf("catalog id %q does not match the {cid} grammar %s", id, validCID)
		}
		if id == unknownCIDLabel {
			t.Errorf("catalog id %q equals the folded label value", id)
		}
	}
}

// The scoreboard spec's Cid parameter pattern is the same expression as the
// handler's grammar.
func TestSpecCidPatternMatchesTheGrammar(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "openapi-scoreboard.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The line `schema: { type: string, pattern: "<re>" }` under components.parameters.Cid.
	re := regexp.MustCompile(`(?m)^    Cid:\n(?:      .*\n)*?      schema: \{[^}]*pattern: "([^"]+)"`)
	m := re.FindSubmatch(raw)
	if m == nil {
		t.Fatal("no pattern found for the Cid parameter in the spec (extraction returned nothing)")
	}
	if got, want := string(m[1]), validCID.String(); got != want {
		t.Fatalf("spec Cid.pattern = %q, handler grammar = %q; keep them identical", got, want)
	}
}
