package hintleak_test

import (
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// TestFixtures_CarryNoHintOnlyNgrams is ADR-0026 V5 (Hard Invariant I16, second
// sentence): in every scope — the full catalog and each scenarios/*/scenario.yaml
// — no challenges/*/fixtures/** file contains a 10-rune n-gram that appears in a
// hint but in no free-display text of that scope. A violation is fixed by
// rewording the fixture; there is no exclusion list.
func TestFixtures_CarryNoHintOnlyNgrams(t *testing.T) {
	c := loadContent(t)
	scopes := c.scopes()
	if len(scopes) < 2 {
		t.Fatalf("scanned %d scope(s); want the full catalog plus at least one scenarios/*/scenario.yaml", len(scopes))
	}
	if len(c.fixtures) == 0 {
		t.Fatal("0 fixture files found under challenges/*/fixtures/ — a scan of nothing proves nothing")
	}
	for _, s := range scopes {
		t.Run(s.name, func(t *testing.T) {
			in, err := c.input(s)
			if err != nil {
				t.Fatal(err)
			}
			vs, err := hintleak.Check(in)
			if err != nil {
				t.Fatalf("hintleak.Check: %v", err)
			}
			t.Logf("scope %s: %d hint items, %d free items, %d fixture files scanned, %d violation(s)",
				s.name, len(in.Hints), len(in.Free), len(in.Targets), len(vs))
			if len(vs) > 0 {
				t.Fatalf("%d (fixture file, distinct n-gram) violation(s) in scope %s — reword the fixture (ADR-0026 D5; no exclusions):\n%s",
					len(vs), s.name, describe(vs))
			}
		})
	}
}
