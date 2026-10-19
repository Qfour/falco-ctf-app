package challengeid

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for _, c := range []struct {
		id   string
		want bool
	}{
		{"01-initial-recon", true},
		{"10-final-exfil", true},
		{"99-a", true},
		{"00-" + strings.Repeat("a", 60), true},
		{"00-" + strings.Repeat("a", 61), false}, // one over the slug limit
		{"1-short", false},                       // one digit
		{"001-long", false},                      // three digits
		{"ab-slug", false},                       // not digits
		{"01-", false},                           // empty slug
		{"01_underscore", false},
		{"01-Upper", false}, // lower case only
		{"01-dot.in.slug", false},
		{"01-a/b", false},
		{"01-a\n", false}, // a trailing newline is not accepted
		{"", false},
		{"../01-a", false},
		{Unknown, false},
	} {
		if got := Valid(c.id); got != c.want {
			t.Errorf("Valid(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

// Unknown is the label every non-catalog id is folded into; it must not be an id.
func TestUnknownIsNotAnID(t *testing.T) {
	if Valid(Unknown) {
		t.Fatalf("Unknown = %q is inside the grammar %s: a real challenge could collide with the folded label", Unknown, Pattern)
	}
}

func TestNN(t *testing.T) {
	if nn, ok := NN("03-stealth-read"); !ok || nn != "03" {
		t.Errorf("NN(03-stealth-read) = %q, %v", nn, ok)
	}
	for _, bad := range []string{"", "3-x", "ab-x", "01-Upper", Unknown, "../01-a"} {
		if nn, ok := NN(bad); ok || nn != "" {
			t.Errorf("NN(%q) = %q, %v; want no number", bad, nn, ok)
		}
	}
}

// VerifyProbe is the id platform's verify (a-2) submits through the collector
// (platform #264, ADR-0041). It must stay INSIDE the grammar: the collector
// answers an id outside it with its own 404 and forwards nothing, which would
// let the gate go green without reaching the scoreboard. That it is not a
// challenge is pinned against the real challenges/ in the scoreboard's tests.
func TestVerifyProbeIsInsideTheGrammar(t *testing.T) {
	if !Valid("99-verify-probe") {
		t.Fatalf("99-verify-probe is outside the grammar %s", Pattern)
	}
	if Valid("verify-probe") {
		t.Fatalf("the old probe id verify-probe must stay outside the grammar %s (it is what made the gate pass on the collector's own 404)", Pattern)
	}
}
