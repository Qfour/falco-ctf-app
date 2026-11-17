package edition

// ADR-0056 D20, D19 A4e-2: the pieces of CheckEvent that are unexported: the readers of the
// seats and of the render record, B10's function, the kinds of error and the typed note that
// closes a bounded list. Every value is a placeholder. The two invisible characters are built
// from their code points, not written in the source.

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseSeats(t *testing.T) {
	const h = seatsHeader + "\n"
	zeroWidthSpace, byteOrderMark := string(rune(0x200b)), string(rune(0xfeff))
	good := []struct {
		name string
		in   string
		want []string
	}{
		{"one seat", h + "seat-a\n", []string{"seat-a"}},
		{"three seats, in the order of the file", h + "seat-b\nseat-a\nseat-c\n", []string{"seat-b", "seat-a", "seat-c"}},
	}
	for _, c := range good {
		got, err := parseSeats([]byte(c.in))
		if err != nil || strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: (%v, %v), want %v", c.name, got, err, c.want)
		}
	}
	bad := map[string]string{
		"empty":                   "",
		"no header":               "seat-a\n",
		"another header":          "# falco-ctf seats v2\nseat-a\n",
		"a header alone":          h,
		"a blank line":            h + "seat-a\n\nseat-b\n",
		"a trailing blank line":   h + "seat-a\n\n",
		"a comment":               h + "# note\nseat-a\n",
		"the practice seat":       h + "*\n",
		"a seat outside grammar":  h + "Seat_A\n",
		"a repeated seat":         h + "seat-a\nseat-b\nseat-a\n",
		"CRLF":                    "# falco-ctf seats v1\r\nseat-a\r\n",
		"no final newline":        h + "seat-a",
		"not UTF-8":               h + "seat-\xff\n",
		"an invisible character":  h + "seat-a" + zeroWidthSpace + "\n",
		"a seat with a space":     h + "seat a\n",
		"a seat with a tab":       h + "seat-a\tseat-b\n",
		"two seats on one line":   h + "seat-a seat-b\n",
		"an over-long seat":       h + strings.Repeat("a", 60) + "\n",
		"a leading blank":         "\n" + h + "seat-a\n",
		"the header twice":        h + h + "seat-a\n",
		"a bom before the header": byteOrderMark + h + "seat-a\n",
	}
	for name, in := range bad {
		if got, err := parseSeats([]byte(in)); err == nil {
			t.Errorf("%s: accepted as %v", name, got)
		}
	}
}

func TestParseRenderRecord(t *testing.T) {
	const run = "0123456789abcdef0123456789abcdef"
	fp := strings.Repeat("ab", 32)
	rec := func(h, r, f string) string { return h + "\n" + r + "\n" + f + "\n" }
	goodRec := rec(renderRecordHeader, renderRecordRunID+"\t"+run, renderRecordFingerprint+"\t"+fp)
	if id, err := parseRenderRecord([]byte(goodRec)); err != nil || id != run {
		t.Fatalf("a good record: (%q, %v)", id, err)
	}
	// the writer's own output is what the reader accepts
	key, err := NewMasterKey([]byte(strings.Repeat("test-only-key-", 4)))
	if err != nil {
		t.Fatal(err)
	}
	var w strings.Builder
	if err := WriteRenderRecord(&w, run, key); err != nil {
		t.Fatal(err)
	}
	if id, err := parseRenderRecord([]byte(w.String())); err != nil || id != run {
		t.Errorf("WriteRenderRecord's output: (%q, %v), want the run id", id, err)
	}
	bad := map[string]string{
		"empty":                 "",
		"another header":        rec("# falco-ctf render-record v2", renderRecordRunID+"\t"+run, renderRecordFingerprint+"\t"+fp),
		"the run id all zeros":  rec(renderRecordHeader, renderRecordRunID+"\t"+PracticeRunID, renderRecordFingerprint+"\t"+fp),
		"a short run id":        rec(renderRecordHeader, renderRecordRunID+"\t"+run[:31], renderRecordFingerprint+"\t"+fp),
		"an upper-case run id":  rec(renderRecordHeader, renderRecordRunID+"\t"+strings.ToUpper(run), renderRecordFingerprint+"\t"+fp),
		"a short fingerprint":   rec(renderRecordHeader, renderRecordRunID+"\t"+run, renderRecordFingerprint+"\t"+fp[:63]),
		"the keys swapped":      rec(renderRecordHeader, renderRecordFingerprint+"\t"+fp, renderRecordRunID+"\t"+run),
		"a space for the tab":   rec(renderRecordHeader, renderRecordRunID+" "+run, renderRecordFingerprint+"\t"+fp),
		"a fourth line":         goodRec + "extra\n",
		"two lines":             renderRecordHeader + "\n" + renderRecordRunID + "\t" + run + "\n",
		"CRLF":                  strings.ReplaceAll(goodRec, "\n", "\r\n"),
		"no final newline":      strings.TrimSuffix(goodRec, "\n"),
		"the run id of a table": "# falco-ctf answers v1 run=" + run + "\n",
	}
	for name, in := range bad {
		id, err := parseRenderRecord([]byte(in))
		var ie *InputError
		if err == nil || !errors.As(err, &ie) {
			t.Errorf("%s: (%q, %v), want an InputError (the form of an input file is wrong: exit 2)", name, id, err)
		}
	}
}

func TestCheckContinuity(t *testing.T) {
	row := func(seat, d string) DigestRow {
		return DigestRow{Seat: seat, CID: "01-demo", Digest: strings.Repeat(d, 64)}
	}
	cur := []DigestRow{row("seat-a", "a"), row("seat-b", "b")}
	cases := []struct {
		name     string
		previous []DigestRow
		have     bool
		bad      []string // seats named
	}{
		{"a first check compares nothing", nil, false, nil},
		{"the same digests", []DigestRow{row("seat-a", "a"), row("seat-b", "b")}, true, nil},
		{"a seat that was added", []DigestRow{row("seat-a", "a")}, true, nil},
		{"a pair of the previous render that this one does not have", []DigestRow{row("seat-a", "a"), row("seat-b", "b"), row("seat-z", "c")}, true, []string{"seat-z"}},
		{"a previous file of another event: no pair in common", []DigestRow{row("seat-x", "a"), row("seat-y", "b")}, true, []string{"seat-x", "seat-y"}},
		{"one pair in common and one not", []DigestRow{row("seat-a", "a"), row("seat-y", "b")}, true, []string{"seat-y"}},
		{"one digest differs", []DigestRow{row("seat-a", "a"), row("seat-b", "c")}, true, []string{"seat-b"}},
		{"every digest differs", []DigestRow{row("seat-a", "c"), row("seat-b", "c")}, true, []string{"seat-a", "seat-b"}},
		{"a previous file with no row", nil, true, []string{""}},
	}
	for _, c := range cases {
		err := checkContinuity(cur, c.previous, c.have)
		if len(c.bad) == 0 {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: no violation", c.name)
			continue
		}
		var got []string
		for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
			var v *Violation
			if !errors.As(e, &v) || v.Rule != RuleContinuity {
				t.Errorf("%s: %v is not a B10 violation", c.name, e)
				continue
			}
			got = append(got, v.Seat)
		}
		if strings.Join(got, ",") != strings.Join(c.bad, ",") {
			t.Errorf("%s: seats named %v, want %v", c.name, got, c.bad)
		}
	}
}

func TestClassifyGivesEveryErrorItsKind(t *testing.T) {
	plain := errors.New("an operating system's error")
	viol := newViolation(RuleShape, "a rule", 0, cell{}, nil)
	wrapped := fmt.Errorf("context: %w", errors.Join(viol, &MoreViolations{N: 3}))
	input := &InputError{Msg: "m", Err: viol}
	var in *InputError
	if got := classify("c", plain); !errors.As(got, &in) || !errors.Is(got, plain) {
		t.Errorf("a plain error: %v; want an InputError with the cause", got)
	}
	in = nil
	if got := classify("c", wrapped); errors.As(got, &in) || got != wrapped {
		t.Errorf("a wrapped join of violations: %v; want it as it is", got)
	}
	if got := classify("c", input); got != error(input) {
		t.Errorf("an InputError: %v; want it as it is (its cause is a violation, and it is still a usage error)", got)
	}
	if classify("c", nil) != nil {
		t.Error("nil is not nil")
	}
}

func TestMoreViolationsIsTheNoteOfABoundedList(t *testing.T) {
	var c collector
	for i := 0; i < maxViolations+5; i++ {
		c.add(newViolation(RuleShape, "x", 0, cell{}, nil))
	}
	list := c.err().(interface{ Unwrap() []error }).Unwrap()
	if len(list) != maxViolations+1 {
		t.Fatalf("%d entries, want %d violations and the note", len(list), maxViolations)
	}
	var more *MoreViolations
	if !errors.As(list[len(list)-1], &more) || more.N != 5 || more.Error() != "5 further violations are not listed" {
		t.Errorf("the note = %v, want 5 further violations", list[len(list)-1])
	}
}
