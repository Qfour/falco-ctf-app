package homefragments

import (
	"strings"
	"testing"
)

func TestFlattenAdmonitions_BasicBlock(t *testing.T) {
	src := "before\n\n" +
		"!!! note \"難易度の目安\"\n" +
		"    line one.\n" +
		"    line two.\n\n" +
		"after\n"
	got := flattenAdmonitions(src)
	if !strings.Contains(got, "> **難易度の目安**") {
		t.Errorf("expected bolded title inside a blockquote line, got: %q", got)
	}
	if !strings.Contains(got, "> line one.") || !strings.Contains(got, "> line two.") {
		t.Errorf("expected dedented body lines prefixed with '> ', got: %q", got)
	}
	// Body must stay associated with ITS title, not merge into "before".
	beforeIdx := strings.Index(got, "before")
	titleIdx := strings.Index(got, "> **難易度の目安**")
	bodyIdx := strings.Index(got, "line one")
	afterIdx := strings.Index(got, "after")
	if !(beforeIdx < titleIdx && titleIdx < bodyIdx && bodyIdx < afterIdx) {
		t.Errorf("expected before < title < body < after ordering, got: %q", got)
	}
}

func TestFlattenAdmonitions_NonAdmonitionLinesUntouched(t *testing.T) {
	src := "plain paragraph\nsecond line\n"
	got := flattenAdmonitions(src)
	if got != src {
		t.Errorf("expected non-admonition input unchanged, got %q want %q", got, src)
	}
}

func TestParseAdmonitionHeader(t *testing.T) {
	cases := []struct {
		line      string
		wantTitle string
		wantOK    bool
	}{
		{`!!! tip "使い方"`, "使い方", true},
		{`!!! warning "検知される読み方 / されない読み方"`, "検知される読み方 / されない読み方", true},
		{`not an admonition`, "", false},
		{`!!! tip`, "", false},        // no title at all
		{`!!! tip notquoted`, "", false},
	}
	for _, tc := range cases {
		title, ok := parseAdmonitionHeader(tc.line)
		if ok != tc.wantOK || title != tc.wantTitle {
			t.Errorf("parseAdmonitionHeader(%q) = (%q, %v), want (%q, %v)", tc.line, title, ok, tc.wantTitle, tc.wantOK)
		}
	}
}
