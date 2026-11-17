package edition_test

// ADR-0056 D9, D11 and V48 (Go side): the digests file, and the set of (seat, cid) pairs
// it holds.

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// A digest of no meaning: 64 lower-case hex digits.
const (
	dig1 = "1111111111111111111111111111111111111111111111111111111111111111"
	dig2 = "2222222222222222222222222222222222222222222222222222222222222222"
	dig3 = "3333333333333333333333333333333333333333333333333333333333333333"
)

func digestRows() []edition.DigestRow {
	return []edition.DigestRow{
		{Seat: "seat-b", CID: "01-demo", Digest: dig3},
		{Seat: "seat-a", CID: "02-other", Digest: dig2},
		{Seat: "seat-a", CID: "01-demo", Digest: dig1},
	}
}

// digestsText is a digests file with rows as given (a row is its three columns).
func digestsText(header string, rows ...[]string) []byte {
	var b strings.Builder
	b.WriteString(header + "\n")
	for _, r := range rows {
		b.WriteString(strings.Join(r, "\t") + "\n")
	}
	return []byte(b.String())
}

const digestsHeader = "# falco-ctf evidence-digests v1 run=" + runA

func TestWriteDigests_WritesTheCanonicalFile(t *testing.T) {
	var buf bytes.Buffer
	if err := edition.WriteDigests(&buf, edition.CheckedEventForTest(runA, digestRows())); err != nil {
		t.Fatalf("WriteDigests: %v", err)
	}
	want := digestsHeader + "\n" +
		"seat-a\t01-demo\t" + dig1 + "\n" +
		"seat-a\t02-other\t" + dig2 + "\n" +
		"seat-b\t01-demo\t" + dig3 + "\n"
	if buf.String() != want {
		t.Errorf("file =\n%q\nwant (rows in byte order of seat, cid)\n%q", buf.String(), want)
	}
	// What is written is what is read, and the rows of the CheckedEvent are not reordered.
	cb := edition.CheckedEventForTest(runA, digestRows())
	var again bytes.Buffer
	if err := edition.WriteDigests(&again, cb); err != nil || again.String() != want {
		t.Errorf("a second write: %v %q", err, again.String())
	}
	if cb.Rows()[0].Seat != "seat-b" {
		t.Error("WriteDigests reordered the rows it was given")
	}
	id, got, err := edition.ParseDigests(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseDigests: %v", err)
	}
	if id != runA {
		t.Errorf("run id = %q, want %q", id, runA)
	}
	sorted := digestRows()
	slices.SortFunc(sorted, func(a, b edition.DigestRow) int { return strings.Compare(a.Seat+"/"+a.CID, b.Seat+"/"+b.CID) })
	if !slices.Equal(got, sorted) {
		t.Errorf("rows = %v, want %v", got, sorted)
	}
}

func TestWriteDigests_Refuses(t *testing.T) {
	row := func(seat, cid, d string) []edition.DigestRow {
		return []edition.DigestRow{{Seat: seat, CID: cid, Digest: d}}
	}
	cases := []struct {
		name  string
		runID string
		rows  []edition.DigestRow
	}{
		{"no row", runA, nil},
		{"a run id of all zeros", edition.PracticeRunID, digestRows()},
		{"a short run id", "abc", digestRows()},
		{"an upper-case run id", strings.ToUpper(runA), digestRows()},
		{"an empty run id", "", digestRows()},
		{"the practice seat", runA, row("*", "01-demo", dig1)},
		{"a seat outside the grammar", runA, row("Seat_A", "01-demo", dig1)},
		{"a cid outside the grammar", runA, row("seat-a", "demo", dig1)},
		{"a short digest", runA, row("seat-a", "01-demo", dig1[:63])},
		{"an upper-case digest", runA, row("seat-a", "01-demo", strings.ToUpper(dig1[:60])+"ABCD")},
		{"a digest that is not hex", runA, row("seat-a", "01-demo", strings.Repeat("g", 64))},
		{"two rows for one pair", runA, append(row("seat-a", "01-demo", dig1), row("seat-a", "01-demo", dig2)...)},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		err := edition.WriteDigests(&buf, edition.CheckedEventForTest(c.runID, c.rows))
		var v *edition.Violation
		if !errors.As(err, &v) || v.Rule != edition.RuleDigests {
			t.Errorf("%s: err = %v, want a D9 violation", c.name, err)
		}
		if buf.Len() != 0 {
			t.Errorf("%s: %d bytes were written although the call refused", c.name, buf.Len())
		}
	}
	// No *CheckedEvent at all is refused the same way.
	var buf bytes.Buffer
	var v *edition.Violation
	if err := edition.WriteDigests(&buf, nil); !errors.As(err, &v) || v.Rule != edition.RuleDigests || buf.Len() != 0 {
		t.Errorf("a nil CheckedEvent: err = %v, %d bytes written; want a D9 violation and nothing written", err, buf.Len())
	}
}

func TestParseDigests_Accepts(t *testing.T) {
	id, rows, err := edition.ParseDigests(digestsText(digestsHeader, []string{"seat-a", "01-demo", dig1}, []string{"seat-b", "01-demo", dig2}))
	if err != nil || id != runA || len(rows) != 2 {
		t.Fatalf("ParseDigests = (%q, %v, %v), want the run id and two rows", id, rows, err)
	}
	// The order of the rows is the file's; it is not constrained.
	_, rows, err = edition.ParseDigests(digestsText(digestsHeader, []string{"seat-b", "01-demo", dig2}, []string{"seat-a", "01-demo", dig1}))
	if err != nil || rows[0].Seat != "seat-b" {
		t.Errorf("rows in another order: (%v, %v), want them as written", rows, err)
	}
}

func TestParseDigests_Refuses(t *testing.T) {
	good := []string{"seat-a", "01-demo", dig1}
	cases := []struct {
		name string
		data []byte
		line int // 0 = no line
	}{
		{"empty", nil, 0},
		{"no row", digestsText(digestsHeader), 0},
		{"no header", digestsText("seat-a\t01-demo\t"+dig1, good), 1},
		{"another version", digestsText("# falco-ctf evidence-digests v2 run="+runA, good), 1},
		{"the answers table's header", digestsText("# falco-ctf answers v1 run="+runA, good), 1},
		{"no run id", digestsText("# falco-ctf evidence-digests v1 run=", good), 1},
		{"a short run id", digestsText("# falco-ctf evidence-digests v1 run=abc", good), 1},
		{"an upper-case run id", digestsText("# falco-ctf evidence-digests v1 run="+strings.ToUpper(runA), good), 1},
		{"a run id of all zeros", digestsText("# falco-ctf evidence-digests v1 run="+edition.PracticeRunID, good), 1},
		{"no final newline", []byte(strings.TrimSuffix(string(digestsText(digestsHeader, good)), "\n")), 2},
		{"a carriage return", []byte(strings.Replace(string(digestsText(digestsHeader, good)), "\n", "\r\n", 1)), 1},
		{"a double quote", digestsText(digestsHeader, []string{"seat-a", "01-demo", "\"" + dig1[1:]}), 2},
		{"a zero-width space", digestsText(digestsHeader, []string{"seat-a", "01-demo\xe2\x80\x8b", dig1}), 2},
		{"not UTF-8", append(digestsText(digestsHeader, good), 0xff, '\n'), 0},
		{"two columns", digestsText(digestsHeader, []string{"seat-a", "01-demo"}), 2},
		{"four columns", digestsText(digestsHeader, []string{"seat-a", "01-demo", dig1, "x"}), 2},
		{"an empty column", digestsText(digestsHeader, []string{"seat-a", "", dig1}), 2},
		{"the practice seat", digestsText(digestsHeader, []string{"*", "01-demo", dig1}), 2},
		{"a seat outside the grammar", digestsText(digestsHeader, []string{"Seat_A", "01-demo", dig1}), 2},
		{"a cid outside the grammar", digestsText(digestsHeader, []string{"seat-a", "demo", dig1}), 2},
		{"a short digest", digestsText(digestsHeader, []string{"seat-a", "01-demo", dig1[:63]}), 2},
		{"an upper-case digest", digestsText(digestsHeader, []string{"seat-a", "01-demo", strings.ToUpper(dig1[:60]) + "ABCD"}), 2},
		{"a repeated pair", digestsText(digestsHeader, good, []string{"seat-a", "01-demo", dig2}), 3},
		{"too large", bytes.Repeat([]byte("x"), edition.MaxTableBytes+1), 0},
	}
	for _, c := range cases {
		_, _, err := edition.ParseDigests(c.data)
		var v *edition.Violation
		if !errors.As(err, &v) || v.Rule != edition.RuleDigests {
			t.Errorf("%s: err = %v, want a D9 violation", c.name, err)
			continue
		}
		if v.Line != c.line {
			t.Errorf("%s: line = %d, want %d (%v)", c.name, v.Line, c.line, err)
		}
	}
}

func TestCheckDigestSet(t *testing.T) {
	scope := edition.Scope{"01-demo": demoScope["01-demo"], "02-other": demoScope["01-demo"]}
	seats := []string{"seat-a", "seat-b"}
	full := func() []edition.DigestRow {
		var rows []edition.DigestRow
		for _, s := range seats {
			for _, cid := range []string{"01-demo", "02-other"} {
				rows = append(rows, edition.DigestRow{Seat: s, CID: cid, Digest: dig1})
			}
		}
		return rows
	}
	if err := edition.CheckDigestSet(full(), seats, scope); err != nil {
		t.Fatalf("the exact set was refused: %v", err)
	}
	cases := []struct {
		name  string
		rows  []edition.DigestRow
		seats []string
		scope edition.Scope
		want  string
	}{
		{"a pair is missing", full()[1:], seats, scope, "no digest row for this seat and challenge"},
		{"a seat is missing", full()[:2], seats, scope, "no digest row for this seat and challenge"},
		{"a seat that is not listed", append(full(), edition.DigestRow{Seat: "seat-c", CID: "01-demo", Digest: dig1}), seats, scope, "not for a seat of the seat list"},
		{"a challenge that is not in the scope", append(full(), edition.DigestRow{Seat: "seat-a", CID: "03-x", Digest: dig1}), seats, scope, "not for a seat of the seat list"},
		{"a pair twice", append(full(), edition.DigestRow{Seat: "seat-a", CID: "01-demo", Digest: dig2}), seats, scope, "two digest rows"},
		{"no rows", nil, seats, scope, "no digest row for this seat and challenge"},
		{"an empty seat list", full(), nil, scope, "the seat list is empty"},
		{"an empty scope", full(), seats, edition.Scope{}, "the scope has no investigate challenge"},
	}
	for _, c := range cases {
		err := edition.CheckDigestSet(c.rows, c.seats, c.scope)
		if err == nil {
			t.Errorf("%s: no violation was reported", c.name)
			continue
		}
		if got := rules(err); !slices.Equal(got, []string{edition.RuleDigests}) {
			t.Errorf("%s: rules = %v, want [D9]", c.name, got)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error does not hold %q: %v", c.name, c.want, err)
		}
	}
}
