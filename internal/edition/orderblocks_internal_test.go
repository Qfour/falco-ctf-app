package edition

// ADR-0056 amendment 28 as revised (A7-x PR 2, review of #698 R2#2): the bounds of orderBlocks,
// the order of a block's lines, fixed on the function itself. A line keeps its bytes (a CR
// included), the file keeps its line feeds (a last line without one stays without one, wherever
// the line that is last after the order came from), two blocks of one file are ordered each on
// its own, and two lines of one time or a line with no time are refused, by a message with no
// value, and through fill as an E3. Every time and word is a placeholder.

import (
	"errors"
	"strings"
	"testing"
)

// oform is a block of n lines from line from+1 (1-based) of a file: orderBlocks reads no more.
func oform(from, n int) blockForm {
	return blockForm{file: "x.txt", from: from, sigs: make([]string, n)}
}

const (
	oT1 = "2000-01-01T00:00:01Z"
	oT2 = "2000-01-01T00:00:02Z"
	oT3 = "2000-01-01T00:00:03Z"
)

func TestOrderBlocks_TheBounds(t *testing.T) {
	cases := []struct {
		name  string
		data  string
		forms []blockForm
		want  string
	}{
		{"a last line without a line feed", "head\n" + oT3 + " c\n" + oT1 + " a\n" + oT2 + " b",
			[]blockForm{oform(1, 3)}, "head\n" + oT1 + " a\n" + oT2 + " b\n" + oT3 + " c"},
		{"a last line with a line feed", "head\n" + oT3 + " c\n" + oT1 + " a\n" + oT2 + " b\n",
			[]blockForm{oform(1, 3)}, "head\n" + oT1 + " a\n" + oT2 + " b\n" + oT3 + " c\n"},
		{"lines that end in a CR keep it", oT2 + " b\r\n" + oT1 + " a\r\n",
			[]blockForm{oform(0, 2)}, oT1 + " a\r\n" + oT2 + " b\r\n"},
		{"two blocks of one file, each on its own", oT2 + " b\n" + oT1 + " a\nmiddle\n" + oT3 + " z\n" + oT1 + " y\n",
			[]blockForm{oform(0, 2), oform(3, 2)}, oT1 + " a\n" + oT2 + " b\nmiddle\n" + oT1 + " y\n" + oT3 + " z\n"},
		{"a block in order already is the same bytes", oT1 + " a\n" + oT2 + " b\n",
			[]blockForm{oform(0, 2)}, oT1 + " a\n" + oT2 + " b\n"},
		{"the time is the first timestamp word of the line", "at " + oT2 + " then " + oT1 + "\nat " + oT1 + " then " + oT3 + "\n",
			[]blockForm{oform(0, 2)}, "at " + oT1 + " then " + oT3 + "\nat " + oT2 + " then " + oT1 + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, msg := orderBlocks([]byte(c.data), c.forms)
			if msg != "" || string(got) != c.want {
				t.Errorf("orderBlocks = %q, %q; want %q", got, msg, c.want)
			}
		})
	}
}

func TestOrderBlocks_RefusesWhatCannotBeOrdered(t *testing.T) {
	cases := []struct {
		name, data string
		form       blockForm
		want       string
	}{
		{"two lines of one time", oT2 + " b\n" + oT2 + " a\n", oform(0, 2), "one time"},
		{"a line with no time", oT2 + " b\nno time here\n", oform(0, 2), "no time"},
		{"a block past the end of the file", oT1 + " a\n", oform(0, 2), "fewer lines"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, msg := orderBlocks([]byte(c.data), []blockForm{c.form})
			if got != nil || !strings.Contains(msg, c.want) {
				t.Fatalf("orderBlocks = %q, %q; want no file and a message saying %q", got, msg, c.want)
			}
			for _, v := range []string{oT1, oT2, "2000", "here"} {
				if strings.Contains(msg, v) {
					t.Errorf("the message holds a value or a word of the file (%q): %q", v, msg)
				}
			}
		})
	}
}

// Through fill, the refusal is an E3 Violation of the seat, the challenge and the file, and its
// text holds no value.
func TestFill_ABlockOfOneTimeIsE3(t *testing.T) {
	parts, err := ScanMarks([]byte("{{ctf:t1}} a\n{{ctf:t2}} b\n"))
	if err != nil {
		t.Fatal(err)
	}
	ct := &compiledTemplate{
		files:  []tmplFile{{name: "x.txt", parts: parts}},
		blocks: map[string][]blockForm{"x.txt": {oform(0, 2)}},
	}
	if _, err := ct.fill("01-demo", "seat-a", map[string]string{"t1": oT2, "t2": oT1}); err != nil {
		t.Fatalf("two times that differ: %v", err)
	}
	_, err = ct.fill("01-demo", "seat-a", map[string]string{"t1": oT2, "t2": oT2})
	var v *Violation
	if !errors.As(err, &v) || v.Rule != RuleSpecRender || v.Seat != "seat-a" || v.CID != "01-demo" || v.File != "x.txt" {
		t.Fatalf("fill = %v; want an E3 of seat-a, 01-demo, x.txt", err)
	}
	if strings.Contains(err.Error(), oT2) || strings.Contains(err.Error(), "2000") {
		t.Errorf("the error holds the value: %v", err)
	}
}
