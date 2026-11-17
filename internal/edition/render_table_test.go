package edition_test

// ADR-0056 D9, D12, amendment 9 and D19 A4d-2: what the renderer writes (the answers
// table, the practice digests file, the files of practice/) and that what it writes is
// read back by the readers the scoreboard uses. The test of the table calls Parse, Check
// and NewJudge: a _test.go file is outside the one-door source test, which reads the
// non-test files.

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// A render written as a table is a table the scoreboard accepts: Parse reads it, Check
// (the event mode: every seat x every question, formats, T5-T8: the renderer's assignment
// of values to seats is what makes T8 hold) accepts it, and a Judge made of it says
// "correct" for each seat's own answers and not for another seat's.
func TestWriteAnswers_ARenderIsATableTheScoreboardAccepts(t *testing.T) {
	seats := rdSeatNames(5)
	r := rdRender(t, rdInput(t, seats...))
	var buf bytes.Buffer
	if err := edition.WriteAnswers(&buf, runA, r.Rows); err != nil {
		t.Fatalf("WriteAnswers: %v", err)
	}
	tb, err := edition.Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("Parse of what WriteAnswers wrote: %v", err)
	}
	wantSeats := slices.Clone(seats)
	slices.Sort(wantSeats)
	if tb.RunID() != runA || !slices.Equal(tb.Seats(), wantSeats) {
		t.Errorf("the table has run id %s and seats %v, want %s and %v", tb.RunID(), tb.Seats(), runA, wantSeats)
	}
	scope := edition.Scope{demoCID: rdQuestions()}
	if err := edition.Check(tb, scope, eventOpts()); err != nil {
		t.Fatalf("Check refuses the table of a render: %v", err)
	}
	j, err := edition.NewJudge(tb)
	if err != nil {
		t.Fatalf("NewJudge: %v", err)
	}
	for _, row := range r.Rows {
		if ok, known := j.Match(row.Seat, row.CID, row.QID, row.Value); !ok || !known {
			t.Errorf("seat %s, question %s: Match = %v, %v; want the row's own value to be correct", row.Seat, row.QID, ok, known)
		}
	}
	var a1, b1 string
	for _, row := range r.Rows {
		switch {
		case row.Seat == seats[0] && row.QID == "q1":
			a1 = row.Value
		case row.Seat == seats[1] && row.QID == "q1":
			b1 = row.Value
		}
	}
	if ok, _ := j.Match(seats[1], demoCID, "q1", a1); ok {
		t.Error("another seat's answer was correct")
	}
	if ok, _ := j.Match(seats[0], demoCID, "q1", b1); ok {
		t.Error("another seat's answer was correct")
	}
}

// One set of rows is one file: the order of the rows given does not matter, and the rows are
// in byte order of (seat, cid, qid) under the header.
func TestWriteAnswers_IsInByteOrder(t *testing.T) {
	rows := []edition.AnswerRow{
		{Seat: "seat-b", CID: demoCID, QID: "q2", Value: "v1"},
		{Seat: "seat-a", CID: demoCID, QID: "q2", Value: "v2"},
		{Seat: "seat-b", CID: demoCID, QID: "q1", Value: "v3"},
		{Seat: "seat-a", CID: demoCID, QID: "q1", Value: "v4"},
	}
	var fwd, rev bytes.Buffer
	if err := edition.WriteAnswers(&fwd, runA, rows); err != nil {
		t.Fatalf("WriteAnswers: %v", err)
	}
	back := slices.Clone(rows)
	slices.Reverse(back)
	if err := edition.WriteAnswers(&rev, runA, back); err != nil {
		t.Fatalf("WriteAnswers: %v", err)
	}
	want := "# falco-ctf answers v1 run=" + runA + "\n" +
		"seat-a\t" + demoCID + "\tq1\tv4\n" +
		"seat-a\t" + demoCID + "\tq2\tv2\n" +
		"seat-b\t" + demoCID + "\tq1\tv3\n" +
		"seat-b\t" + demoCID + "\tq2\tv1\n"
	if fwd.String() != want || rev.String() != want {
		t.Errorf("the table is %q (reversed input: %q), want %q", fwd.String(), rev.String(), want)
	}
}

// What a table must not hold is refused, nothing is written, and the message names the cell
// and not the value.
func TestWriteAnswers_Refuses(t *testing.T) {
	good := edition.AnswerRow{Seat: "seat-a", CID: demoCID, QID: "q1", Value: "alpha"}
	with := func(f func(*edition.AnswerRow)) []edition.AnswerRow {
		r := good
		f(&r)
		return []edition.AnswerRow{r}
	}
	star := with(func(r *edition.AnswerRow) { r.Seat = edition.AnySeat })
	bidi := string(rune(0x202e))
	cases := []struct {
		name  string
		runID string
		rows  []edition.AnswerRow
		rule  string
	}{
		{"a run id of 31 digits", "0123456789abcdef0123456789abcde", []edition.AnswerRow{good}, "T3"},
		{"a run id in capitals", "0123456789ABCDEF0123456789ABCDEF", []edition.AnswerRow{good}, "T3"},
		{"no row", runA, nil, "T3"},
		{"the practice run id and a seat of the grammar", edition.PracticeRunID, []edition.AnswerRow{good}, "T3"},
		{"an event run id and the seat *", runA, star, "T3"},
		{"a seat outside the grammar", runA, with(func(r *edition.AnswerRow) { r.Seat = "Seat_A" }), "T3"},
		{"a cid that is not a challenge id", runA, with(func(r *edition.AnswerRow) { r.CID = "nope" }), "T3"},
		{"a qid outside the grammar", runA, with(func(r *edition.AnswerRow) { r.QID = "Q1" }), "T3"},
		{"an empty value", runA, with(func(r *edition.AnswerRow) { r.Value = "" }), "T3"},
		{"a value with a tab", runA, with(func(r *edition.AnswerRow) { r.Value = sentinel + "\t" + sentinel }), "T3"},
		{"a value with a line break", runA, with(func(r *edition.AnswerRow) { r.Value = sentinel + "\n" + sentinel }), "T3"},
		{"a value with a carriage return", runA, with(func(r *edition.AnswerRow) { r.Value = sentinel + "\r" }), "T3"},
		{"a value with a double quote", runA, with(func(r *edition.AnswerRow) { r.Value = sentinel + "\"" }), "T3"},
		{"a value that is not UTF-8", runA, with(func(r *edition.AnswerRow) { r.Value = sentinel + string([]byte{0xff}) }), "T3"},
		{"a value with a bidi control character", runA, with(func(r *edition.AnswerRow) { r.Value = sentinel + bidi }), "T3"},
		{"a cell twice", runA, []edition.AnswerRow{good, good}, "T4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := edition.WriteAnswers(&buf, c.runID, c.rows)
			if err == nil {
				t.Fatal("WriteAnswers accepted it")
			}
			if buf.Len() != 0 {
				t.Errorf("%d bytes were written for a refused table", buf.Len())
			}
			if got := rules(err); !slices.Equal(got, []string{c.rule}) {
				t.Errorf("rules = %v, want [%s]: %v", got, c.rule, err)
			}
			noSecret(t, c.name, err)
		})
	}
}

// A practice render gives a practice table: the run id of zeros, the seat *, and every
// question of the challenge (the `fixed` one too), which the practice mode of the scoreboard
// checks at start-up (Check, event mode off).
func TestPracticeOutput_AnswersAreAPracticeTable(t *testing.T) {
	spec := rdSpec(t, rdDoc())
	r, err := edition.RenderPractice(demoCID, spec, rdQuestions(), rdTemplate(spec))
	if err != nil {
		t.Fatalf("RenderPractice: %v", err)
	}
	pf, err := edition.PracticeOutput(r)
	if err != nil {
		t.Fatalf("PracticeOutput: %v", err)
	}
	tb, err := edition.Parse(pf.Answers)
	if err != nil {
		t.Fatalf("Parse of the practice answers: %v", err)
	}
	if tb.RunID() != edition.PracticeRunID || !slices.Equal(tb.Seats(), []string{edition.AnySeat}) {
		t.Errorf("the table has run id %s and seats %v, want the practice run id and [*]", tb.RunID(), tb.Seats())
	}
	if err := edition.Check(tb, edition.Scope{demoCID: rdQuestions()}, edition.Options{EventMode: false}); err != nil {
		t.Errorf("Check (practice) refuses the practice answers: %v", err)
	}
}

// The files of practice/: the bundle of the seat *, the table, and a digests file with one
// row, the digest of the bundle (D9); a render that is not a practice render is refused.
func TestPracticeOutput_FilesAndDigests(t *testing.T) {
	spec := rdSpec(t, rdDoc())
	r, err := edition.RenderPractice(demoCID, spec, rdQuestions(), rdTemplate(spec))
	if err != nil {
		t.Fatalf("RenderPractice: %v", err)
	}
	pf, err := edition.PracticeOutput(r)
	if err != nil {
		t.Fatalf("PracticeOutput: %v", err)
	}
	if len(pf.Evidence) != len(r.Bundles[0].Files) || !rdSameBundle(&edition.Bundle{Seat: "*", CID: demoCID, Files: pf.Evidence}, r.Bundles[0]) {
		t.Error("the evidence of the practice output is not the bundle of the seat *")
	}
	wantDigests := "# falco-ctf evidence-digests v1 run=" + edition.PracticeRunID + "\n" +
		"*\t" + demoCID + "\t" + edition.BundleDigest(pf.Evidence) + "\n"
	if string(pf.Digests) != wantDigests {
		t.Errorf("digests.tsv = %q, want %q", pf.Digests, wantDigests)
	}
	if _, err := edition.PracticeOutput(nil); err == nil {
		t.Error("a nil render was accepted")
	}
	if _, err := edition.PracticeOutput(&edition.Rendered{}); err == nil {
		t.Error("a render with no bundle was accepted")
	}
	if _, err := edition.PracticeOutput(rdRender(t, rdInput(t, "seat-a"))); err == nil {
		t.Error("the render of an event seat was accepted as a practice output")
	}
}

// WritePracticeDigests: the file the digests.tsv of practice/ is. The run id of zeros and the
// seat * are what it writes, and everything else is refused.
func TestWritePracticeDigests(t *testing.T) {
	d1, d2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var buf bytes.Buffer
	rows := []edition.DigestRow{
		{Seat: "*", CID: "02-other", Digest: d2},
		{Seat: "*", CID: demoCID, Digest: d1},
	}
	if err := edition.WritePracticeDigests(&buf, edition.PracticeRunID, rows); err != nil {
		t.Fatalf("WritePracticeDigests: %v", err)
	}
	want := "# falco-ctf evidence-digests v1 run=" + edition.PracticeRunID + "\n" +
		"*\t" + demoCID + "\t" + d1 + "\n" +
		"*\t02-other\t" + d2 + "\n"
	if buf.String() != want {
		t.Errorf("the file is %q, want %q", buf.String(), want)
	}

	row := edition.DigestRow{Seat: "*", CID: demoCID, Digest: d1}
	cases := []struct {
		name  string
		runID string
		rows  []edition.DigestRow
	}{
		{"an event run id", runA, []edition.DigestRow{row}},
		{"31 zeros and a one", strings.Repeat("0", 31) + "1", []edition.DigestRow{row}},
		{"no row", edition.PracticeRunID, nil},
		{"a seat of the grammar", edition.PracticeRunID, []edition.DigestRow{{Seat: "seat-a", CID: demoCID, Digest: d1}}},
		{"a cid that is not a challenge id", edition.PracticeRunID, []edition.DigestRow{{Seat: "*", CID: "nope", Digest: d1}}},
		{"a digest of 63 digits", edition.PracticeRunID, []edition.DigestRow{{Seat: "*", CID: demoCID, Digest: d1[:63]}}},
		{"a digest in capitals", edition.PracticeRunID, []edition.DigestRow{{Seat: "*", CID: demoCID, Digest: strings.Repeat("A", 64)}}},
		{"a cid twice", edition.PracticeRunID, []edition.DigestRow{row, row}},
	}
	for _, c := range cases {
		var out bytes.Buffer
		err := edition.WritePracticeDigests(&out, c.runID, c.rows)
		if err == nil || out.Len() != 0 {
			t.Errorf("%s: err = %v, %d bytes written; want a refusal and nothing written", c.name, err, out.Len())
			continue
		}
		if got := rules(err); !slices.Equal(got, []string{"D9"}) {
			t.Errorf("%s: rules = %v, want [D9]", c.name, got)
		}
	}
}

// V66's Go side, on the writing doors: the event's WriteDigests and the practice's
// WritePracticeDigests take opposite inputs, so neither writes what the other does, and the
// event's reader refuses the practice's file. (The practice reader is A5c-2's.)
func TestDigestDoors_NeitherAcceptsTheOthersInput(t *testing.T) {
	d := strings.Repeat("a", 64)
	star := []edition.DigestRow{{Seat: "*", CID: demoCID, Digest: d}}
	seat := []edition.DigestRow{{Seat: "seat-a", CID: demoCID, Digest: d}}

	var practice bytes.Buffer
	if err := edition.WritePracticeDigests(&practice, edition.PracticeRunID, star); err != nil {
		t.Fatalf("WritePracticeDigests: %v", err)
	}
	if _, _, err := edition.ParseDigests(practice.Bytes()); err == nil {
		t.Error("ParseDigests (event) read a practice digests file")
	}

	var event bytes.Buffer
	if err := edition.WriteDigests(&event, edition.CheckedBundlesForTest(runA, seat)); err != nil {
		t.Fatalf("WriteDigests: %v", err)
	}
	if _, _, err := edition.ParseDigests(event.Bytes()); err != nil {
		t.Errorf("ParseDigests (event) refuses an event digests file: %v", err)
	}

	for name, f := range map[string]func(w *bytes.Buffer) error{
		"WriteDigests with the practice run id and the seat *":      func(w *bytes.Buffer) error { return edition.WriteDigests(w, edition.CheckedBundlesForTest(edition.PracticeRunID, star)) },
		"WriteDigests with an event run id and the seat *":          func(w *bytes.Buffer) error { return edition.WriteDigests(w, edition.CheckedBundlesForTest(runA, star)) },
		"WriteDigests with the practice run id and a seat":          func(w *bytes.Buffer) error { return edition.WriteDigests(w, edition.CheckedBundlesForTest(edition.PracticeRunID, seat)) },
		"WritePracticeDigests with an event run id and the seat *":  func(w *bytes.Buffer) error { return edition.WritePracticeDigests(w, runA, star) },
		"WritePracticeDigests with an event run id and a seat":      func(w *bytes.Buffer) error { return edition.WritePracticeDigests(w, runA, seat) },
		"WritePracticeDigests with the practice run id and a seat": func(w *bytes.Buffer) error { return edition.WritePracticeDigests(w, edition.PracticeRunID, seat) },
	} {
		var out bytes.Buffer
		if err := f(&out); err == nil || out.Len() != 0 {
			t.Errorf("%s: err = %v, %d bytes written; want a refusal and nothing written", name, err, out.Len())
		}
	}
}
