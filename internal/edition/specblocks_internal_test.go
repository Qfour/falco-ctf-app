package edition

import (
	"slices"
	"testing"
)

// templateTokens (E2 of the blocks) and LayoutOf (the renderer's E3 and B7) place every mark at
// the same token and count the same tokens: both read readMarkedText, the one mapping from a mark
// to its token. A copy of the mapping that drifted would make E2 check other positions than the
// ones the renderer and B7 read.
func TestTemplateTokensAgreeWithLayoutOf(t *testing.T) {
	cases := []struct{ name, in string }{
		{"no text", ""},
		{"a line with no mark", "pod-a shell 2000-01-01T00:00:00Z"},
		{"a mark alone among words", "x {{ctf:a}} y"},
		{"a mark at the start and one at the end of a line", "{{ctf:a}} middle {{ctf:b}}"},
		{"two marks next to each other (one token)", "x {{ctf:a}}{{ctf:b}} y"},
		{"a mark glued to token bytes", "at:{{ctf:a}}-z"},
		{"a token with a mark and literal bytes between two marks", "{{ctf:a}}x{{ctf:b}} {{ctf:c}}"},
		{"marks on several lines", "{{ctf:a}} one\ntwo {{ctf:b}}\n\nx={{ctf:c}}\n"},
		{"a separator between a mark and a word", "a={{ctf:a}},b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			layout, err := LayoutOf([]byte(c.in))
			if err != nil {
				t.Fatalf("LayoutOf: %v", err)
			}
			toks, err := templateTokens([]byte(c.in))
			if err != nil {
				t.Fatalf("templateTokens: %v", err)
			}
			if len(toks) != layout.Tokens {
				t.Fatalf("templateTokens has %d tokens, LayoutOf %d", len(toks), layout.Tokens)
			}
			var got []MarkPosition
			for ti, tok := range toks {
				for _, s := range tok.slots {
					got = append(got, MarkPosition{Slot: s, Token: ti, Alone: tok.alone})
				}
				if len(tok.slots) == 0 && len(tok.lit) == 0 {
					t.Errorf("token %d holds no mark and no byte", ti)
				}
			}
			if !slices.Equal(got, layout.Marks) {
				t.Errorf("templateTokens places the marks at %+v, LayoutOf at %+v", got, layout.Marks)
			}
		})
	}
	// A `{{ctf:` that is not a mark is refused by both.
	if _, err := LayoutOf([]byte("a {{ctf:Bad}}")); err == nil {
		t.Error("LayoutOf accepted a mark outside the grammar")
	}
	if _, err := templateTokens([]byte("a {{ctf:Bad}}")); err == nil {
		t.Error("templateTokens accepted a mark outside the grammar")
	}
}
