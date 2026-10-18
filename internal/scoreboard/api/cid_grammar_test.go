package api

import (
	"path/filepath"
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
