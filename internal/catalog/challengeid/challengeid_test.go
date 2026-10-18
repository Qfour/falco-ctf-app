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
