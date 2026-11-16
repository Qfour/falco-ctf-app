package hintleak_test

// normalize_test.go pins hintleak.Normalize, the normalisation of ADR-0026 D5-2
// that ADR-0056 D10 B4 (stage A4c-2) calls for its shingles. It was an unexported
// loop inside the n-gram cutter; exporting it must not change a byte of what the
// rule sees, which TestHintLeakChecker_Mutation (V6) shows from the other side.
// Every rune is written as an escape: this file carries no raw invisible
// character.

import (
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"nothing to remove", "abc", "abc"},
		{"ASCII whitespace is removed", "a b\tc\nd\re\vf\fg", "abcdefg"},
		{"NEL, NBSP and the ideographic space are removed", "a\u0085b c　d", "abcd"},
		{"the Unicode spaces of Zs are removed", "a b c d e", "abcde"},
		{"case is not folded", "AbC", "AbC"},
		{"no NFKC: a full-width letter stays", "Ａb", "Ａb"},
		{"punctuation stays", "a-b_c.d", "a-b_c.d"},
		{"a multi-byte rune is one element", "日 本", "日本"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hintleak.Normalize(tt.in)
			if string(got) != tt.want {
				t.Fatalf("Normalize(%q) = %q, want %q", tt.in, string(got), tt.want)
			}
			if len(got) != len([]rune(tt.want)) {
				t.Fatalf("Normalize(%q) has %d runes, want %d", tt.in, len(got), len([]rune(tt.want)))
			}
		})
	}

	t.Run("the result is a new slice", func(t *testing.T) {
		a := hintleak.Normalize("ab cd")
		a[0] = 'z'
		if b := hintleak.Normalize("ab cd"); string(b) != "abcd" {
			t.Fatalf("a second call returned %q after the first result was modified, want abcd", string(b))
		}
	})

	t.Run("Check sees the same normalisation: a hint and its normalised form match", func(t *testing.T) {
		const hint = "ab cd　ef gh\tij kl"
		target := string(hintleak.Normalize(hint))
		if target != "abcdefghijkl" {
			t.Fatalf("Normalize(%q) = %q, want abcdefghijkl", hint, target)
		}
		vs, err := hintleak.Check(hintleak.Input{Hints: one("h", hint), Targets: one("f", target)})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(vs) == 0 {
			t.Fatal("the normalised form of a hint is not reported as a copy of it: Check and Normalize disagree")
		}
	})
}
