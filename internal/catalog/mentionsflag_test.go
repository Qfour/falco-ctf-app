package catalog

import "testing"

// MentionsFlag is the shape question internal/edition asks of an answer value
// (ADR-0056 T7). It must be at least as wide as flagRE, so that a flag the
// scoreboard would accept as a flag can never pass as an answer.
func TestMentionsFlag_IsWiderThanFlagRE(t *testing.T) {
	// Synthetic: placeholders and obviously fake values only.
	flags := []string{
		"FALCO{dev-x}",
		"FALCO{dev-stealth-read}",
		"FALCO{test-event-a_b-1}",
		"FALCO{x}",
	}
	for _, f := range flags {
		if !flagRE.MatchString(f) {
			t.Fatalf("test input %q is not a flag by flagRE; the case would prove nothing", f)
		}
		if !MentionsFlag(f) {
			t.Errorf("flagRE matches %q but MentionsFlag does not", f)
		}
		if !MentionsFlag("prefix " + f + " suffix") {
			t.Errorf("MentionsFlag misses %q inside a longer string", f)
		}
	}
}

func TestMentionsFlag(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"plain word", "FALCO", false},
		{"brace without the word", "{dev-x}", false},
		{"a space inside the opener", "FALCO {x}", false},
		{"opener with no closing brace", "FALCO{dev-x", true},
		{"body outside the flag grammar", "FALCO{a b}", true},
		{"lower case", "falco{x}", true},
		{"mixed case", "FaLcO{x}", true},
		{"inside a path", "/tmp/FALCO{x}/y", true},
		{"a hex id", "aaaaaaaaaaaa", false},
	}
	for _, c := range cases {
		if got := MentionsFlag(c.in); got != c.want {
			t.Errorf("%s: MentionsFlag(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}
