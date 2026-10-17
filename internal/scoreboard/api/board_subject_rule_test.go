package api

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// app#377: a board thread subject is participant-written text rendered INLINE
// next to the author ("subject — author"), so validBoardSubject refuses the same
// invisible characters (Cc, Cf) a display name refuses (app#331), with the same
// ZWJ-between-emoji exception, and none of the metacharacters (a subject is
// prose: "can't", "a & b"). The rule is displayNameHasForbidden's, read from
// testdata/display-name-parity/rule.yaml; nothing here restates the class.

// TestBoardSubject_SweepEveryCodePoint: for EVERY code point c, validBoardSubject
// of "a"+c+"b" rejects exactly what the rule's Cc / Cf categories name (the rule's
// metacharacters are accepted: that is the difference from a display name), except
// U+200D, which is only accepted between two emoji and must be refused between
// letters. So "subject == rule" over all of Unicode, as "display name == rule".
func TestBoardSubject_SweepEveryCodePoint(t *testing.T) {
	rule := loadNameRule(t)
	var disagree []string
	var refused int
	for cp := 0; cp <= unicode.MaxRune; cp++ {
		if cp >= 0xD800 && cp <= 0xDFFF { // surrogates are not code points
			continue
		}
		r := rune(cp)
		_, err := validBoardSubject("a" + string(r) + "b")
		got := err != nil
		if cp == rule.Exempt {
			if !got {
				disagree = append(disagree, fmt.Sprintf("U+%04X between letters is accepted", cp))
			}
			continue
		}
		if got {
			refused++
		}
		if want := rule.forbiddenInvisible(r); got != want {
			disagree = append(disagree, fmt.Sprintf("U+%04X subject-rejects=%v rule=%v", cp, got, want))
		}
	}
	if len(disagree) > 0 {
		t.Fatalf("validBoardSubject and the rule disagree (unicode.Version %s): %v", unicode.Version, disagree)
	}
	if refused < 200 {
		t.Fatalf("the sweep refused only %d code points; the rule is not being applied", refused)
	}
	// The metacharacters stay legal in a subject.
	for _, c := range rule.Meta {
		if _, err := validBoardSubject("a" + string(c) + "b"); err != nil {
			t.Errorf("metacharacter %q refused in a subject: %v", c, err)
		}
	}
}

// TestBoardSubject_AgreesWithDisplayNameTable: on every row of the display-name
// table (cases.yaml, the shared case list) the subject predicate answers as the
// display-name predicate does once each metacharacter is REPLACED by a neutral
// letter "x". Replaced, not deleted: deleting one would join its neighbours (a
// ZWJ that sat next to a metacharacter could end up between two emoji). The
// premise is that "x" is neither an emoji nor a Cc / Cf character, so it changes
// nothing about the rest of the row. This is the "reuse" half: one table, no
// second list of inputs.
func TestBoardSubject_AgreesWithDisplayNameTable(t *testing.T) {
	rule := loadNameRule(t)
	neutral := strings.NewReplacer(metaToX(rule.Meta)...)
	for _, c := range loadNameParityCases(t) {
		in := c.input()
		t.Run(c.Note, func(t *testing.T) {
			if got, want := inlineTextHasForbidden(in), displayNameHasForbidden(neutral.Replace(in)); got != want {
				t.Fatalf("inlineTextHasForbidden(%+q) = %v, displayNameHasForbidden(metacharacters replaced) = %v", in, got, want)
			}
		})
	}
}

// metaToX is the argument list of a Replacer that turns each character of chars into "x".
func metaToX(chars string) []string {
	var out []string
	for _, c := range chars {
		out = append(out, string(c), "x")
	}
	return out
}

// TestBoardSubject_Table: the subject-specific accept / reject rows (the shared
// display-name table has no board rows), and the 400 sentence being fixed.
func TestBoardSubject_Table(t *testing.T) {
	const forbiddenMsg = "subject contains forbidden characters"
	cases := []struct {
		name    string
		in      string
		wantErr string // "" = accept
		stored  string // accept rows: default = trimmed input
	}{
		{"plain", "Stuck on mission 3", "", ""},
		{"apostrophe and quotes are prose", `Can't see "FALCO" output`, "", ""},
		{"ampersand and angle brackets are prose", "a & b <c>", "", ""},
		{"Japanese", "ミッション 3 が進まない", "", ""},
		{"ZWJ emoji sequence", "help \U0001F469\u200D\U0001F4BB", "", ""},
		{"trimmed", "  hello \t", "", "hello"},
		{"RLO unclosed", "reversed \u202E", forbiddenMsg, ""},
		{"RLI isolate", "a \u2067b", forbiddenMsg, ""},
		{"zero width space", "a\u200Bb", forbiddenMsg, ""},
		{"BOM", "a\uFEFFb", forbiddenMsg, ""},
		{"NEL (C1)", "a\u0085b", forbiddenMsg, ""},
		{"newline inside", "a\nb", forbiddenMsg, ""},
		{"tab inside", "a\tb", forbiddenMsg, ""},
		{"NUL", "a\x00b", forbiddenMsg, ""},
		{"ZWJ after a letter", "word\u200D", forbiddenMsg, ""},
		{"tag characters", "\U0001F3F4\U000E0067\U000E0062", forbiddenMsg, ""},
		{"empty", "", "subject required", ""},
		{"only whitespace", " \t ", "subject required", ""},
		{"too long", strings.Repeat("a", maxBoardSubjectRunes+1), "subject too long (max 120 runes)", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := validBoardSubject(c.in)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("validBoardSubject(%+q) = error %v, want accept", c.in, err)
				}
				want := c.stored
				if want == "" {
					want = c.in
				}
				if got != want {
					t.Fatalf("validBoardSubject(%+q) stored %+q, want %+q", c.in, got, want)
				}
				return
			}
			if err == nil {
				t.Fatalf("validBoardSubject(%+q) = %q, nil; want %q", c.in, got, c.wantErr)
			}
			if err.Error() != c.wantErr {
				t.Fatalf("validBoardSubject(%+q) error = %q, want %q", c.in, err, c.wantErr)
			}
		})
	}
}
