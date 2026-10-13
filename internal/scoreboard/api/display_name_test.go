package api

import "testing"

// app#331: validDisplayName rejects Unicode Cf (format: bidi controls,
// zero-width characters) and C1 (U+0080-009F) characters on top of the old
// ASCII metachar / C0 / DEL set. A ZWJ between two emoji is the one allowed Cf.
// This is not an anti-impersonation test: blank-looking characters outside Cf
// (U+3164, U+2800, ...) and duplicate names still pass.

func TestValidDisplayName_RejectsFormatAndC1(t *testing.T) {
	bad := []struct{ name, in string }{
		{"U+200B zero width space, middle", "Ali\u200bce"},
		{"U+200B zero width space, trailing (not trimmed by TrimSpace)", "Alice\u200b"},
		{"U+200B zero width space, leading", "\u200bAlice"},
		{"U+202E right-to-left override", "\u202eecilA"},
		{"U+202D left-to-right override", "Al\u202dice"},
		{"U+2066 left-to-right isolate", "Al\u2066ice"},
		{"U+200E left-to-right mark", "Al\u200eice"},
		{"U+0085 NEL, middle", "Ali\u0085ce"},
		{"U+0080 C1 lower bound", "Ali\u0080ce"},
		{"U+009F C1 upper bound", "Ali\u009fce"},
		{"U+2060 word joiner", "Ali\u2060ce"},
		{"U+FEFF BOM / ZWNBSP", "Ali\ufeffce"},
		{"U+00AD soft hyphen", "Ali\u00adce"},
		{"U+200C zero width non-joiner (letters around it)", "Ali\u200cce"},
		{"U+200D zero width joiner after a letter", "Alice\u200d"},
		{"U+200D zero width joiner between letters", "Ali\u200dce"},
		{"U+200D leading", "\u200d👩"},
		{"U+200D between emoji but doubled", "👩\u200d\u200d💻"},
		{"U+200D after emoji with nothing after it", "👩\u200d"},
		{"U+200D between a letter and an emoji", "A\u200d💻"},
		{"tag character U+E0041 (Cf)", "Ali\U000e0041ce"},
		// The pre-existing rules still hold.
		{"empty", ""},
		{"whitespace only", "   "},
		{"HTML metachar <", "<b>"},
		{"HTML metachar &", "a&b"},
		{"double quote", `a"b`},
		{"single quote", "a'b"},
		{"C0 control NUL", "ab\x00cd"},
		{"DEL", "ab\x7fcd"},
		{"over 32 runes", "123456789012345678901234567890123"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if got, err := validDisplayName(c.in); err == nil {
				t.Fatalf("validDisplayName(%q) = %q, nil; want an error", c.in, got)
			}
		})
	}
}

func TestValidDisplayName_AcceptsOrdinaryNames(t *testing.T) {
	ok := []struct{ name, in, want string }{
		{"ascii", "Alice", "Alice"},
		{"ascii with spaces and symbols", "Alice ★ B-2", "Alice ★ B-2"},
		{"japanese", "山田 太郎", "山田 太郎"},
		{"japanese kana + kanji", "さくら桜サクラ", "さくら桜サクラ"},
		{"fullwidth latin", "Ａｌｉｃｅ", "Ａｌｉｃｅ"},
		{"korean", "한국어", "한국어"},
		{"emoji", "🦊 Fox", "🦊 Fox"},
		{"two plain emoji", "👩💻", "👩💻"},
		{"zwj emoji sequence (technologist)", "👩\u200d💻", "👩\u200d💻"},
		{"zwj emoji sequence with skin tone", "👩🏽\u200d💻", "👩🏽\u200d💻"},
		{"zwj emoji sequence with variation selector", "🏳\ufe0f\u200d🌈", "🏳\ufe0f\u200d🌈"},
		{"zwj emoji family (three joiners)", "👨\u200d👩\u200d👧", "👨\u200d👩\u200d👧"},
		{"combining acute (e + U+0301)", "Cafe\u0301", "Cafe\u0301"},
		{"precomposed e-acute", "Café", "Café"},
		{"combining dakuten (U+3099)", "ま\u3099", "ま\u3099"},
		{"leading/trailing ASCII space trimmed", "  Alice  ", "Alice"},
		{"trailing NEL trimmed like any whitespace", "Alice\u0085", "Alice"},
		{"exactly 32 runes", "12345678901234567890123456789012", "12345678901234567890123456789012"},
	}
	for _, c := range ok {
		t.Run(c.name, func(t *testing.T) {
			got, err := validDisplayName(c.in)
			if err != nil {
				t.Fatalf("validDisplayName(%q) = error %v; want %q", c.in, err, c.want)
			}
			if got != c.want {
				t.Fatalf("validDisplayName(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}
