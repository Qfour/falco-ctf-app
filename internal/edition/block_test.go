package edition_test

// ADR-0056 D10 "the order of the lines" (amendment 28 as revised, A7-x PR 2), V113 and V4's
// block part: the renderer orders the lines of a block by their times, keeps the column of a
// block's group apart between seats (r1) and the times of a block apart within a seat (r2), and
// B7 reads a group in a block as the set of its lines ((1), (2), (o1) to (o3)), never by
// position. The example is rdDoc with where's group (a path answer and 6 decoys, 1000 paths) in a
// block of c.txt, a time filler of its own on each line. Every value is a placeholder.
//
// V113's other two negative cases are PR 1's: two lines that share a time slot are refused by E2
// (TestCheckBlocksAndClues_Refusals, "two lines share a time slot"), and S < 2N(K + 1) by B8 (a2)
// (TestCheckSeatSpace_AGroupInABlockNeedsTwiceTheSeatsTimesTheGroup).

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/bits"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

const (
	bkFile = "c.txt"
	// bkDay is the window of the time fillers: a day, so that two lines of a seat are drawn one
	// time rarely (and drawn again when they are, r2).
	bkDay = "{from: 0, to: 86400}"
)

// bkLine is a line of the block for the i-th slot of where's group (the answer first).
type bkLine func(i int, slot string) string

// The lines of the block end with a key of their own (key-1 ...), the filler each shares with its
// clue line in k.txt (ADR-0056 amendment 31, E2 (e2)): bkTemplate writes the clue lines.

// bkPlain is the lines of a group that no clue tells apart: one signature for all.
func bkPlain(i int, slot string) string {
	return fmt.Sprintf("{{ctf:tick-%d}} {{ctf:%s}} host {{ctf:key-%d}}", i+1, slot, i+1)
}

// bkClued is the lines of a group with a literal word of each line's own (B7's (o3) as it is
// before PR 4c: B17 refuses such a block, B7 is what is looked at here).
func bkClued(i int, slot string) string {
	return fmt.Sprintf("{{ctf:tick-%d}} {{ctf:%s}} pod-%d {{ctf:key-%d}}", i+1, slot, i, i+1)
}

// bkFilled is bkPlain with a path filler of its own (pf-1 ...) as the third word of each line.
func bkFilled(i int, slot string) string {
	return fmt.Sprintf("{{ctf:tick-%d}} {{ctf:%s}} {{ctf:pf-%d}} {{ctf:key-%d}}", i+1, slot, i+1, i+1)
}

// bkDoc is rdDoc with where's clues (editiontest.Clues), the time fillers tick-1 .. tick-7 of
// window, the keys key-1 .. key-7, the path fillers pf-1 .. pf-7 when paths is set, and where's
// group in a block of c.txt's lines 2 to 8 when blocked is set.
func bkDoc(window string, blocked, paths bool) specDoc {
	d := rdDoc().with(slotWhere, func(s *specSlot) { s.clues = editiontest.Clues("where") })
	if blocked {
		d = d.withBlocks("[{file: " + bkFile + ", from: 2, to: 8}]")
	}
	for j := 1; j <= 7; j++ {
		d = sbWithFillers(d, sbTick(fmt.Sprintf("tick-%d", j), window))
		d = sbWithFillers(d, specSlot{name: fmt.Sprintf("key-%d", j), role: "filler", format: "name", vocab: "[[ka, kb, kc]]"})
		if paths {
			d = sbWithFillers(d, specSlot{name: fmt.Sprintf("pf-%d", j), role: "filler", format: "path", vocab: specVocab("[opt]", "[y]", specWords("e", 10))})
		}
	}
	return d
}

// bkTemplate is a.txt, a line `<slot>={{ctf:<slot>}}` for every slot that is not of where's group
// nor a filler of the block, c.txt: the line `begin`, then a line of line for each slot of
// where's group (the answer first, then its decoys), and k.txt: the clue line of each key (its
// clue columns editiontest.ClueTuple's words).
func bkTemplate(spec *edition.Spec, line bkLine) []edition.BundleFile {
	ofBlock := func(name string) bool {
		return strings.HasPrefix(name, "tick-") || strings.HasPrefix(name, "pf-") || strings.HasPrefix(name, "key-")
	}
	var a []string
	group := []string{"where"}
	for _, s := range spec.Slots {
		if s.Name != "where" && !ofBlock(s.Name) {
			a = append(a, fmt.Sprintf("%s={{ctf:%s}}", s.Name, s.Name))
		}
	}
	for _, d := range spec.ImpliedDecoys {
		if d.DecoyOf == "where" {
			group = append(group, d.Name)
		} else {
			a = append(a, fmt.Sprintf("%s={{ctf:%s}}", d.Name, d.Name))
		}
	}
	c := []string{"begin"}
	var k []string
	for i, s := range group {
		c = append(c, line(i, s))
		w1, w2 := editiontest.ClueTuple("where", i)
		k = append(k, fmt.Sprintf("clue {{ctf:key-%d}} %s %s", i+1, w1, w2))
	}
	return []edition.BundleFile{sbFile("a.txt", a), sbFile(bkFile, c), sbFile("k.txt", k)}
}

// bkRender renders d with the template of line for the seats.
func bkRender(t *testing.T, d specDoc, line bkLine, seats ...string) (*edition.Spec, []edition.BundleFile, *edition.Rendered) {
	t.Helper()
	spec := rdSpec(t, d)
	tmpl := bkTemplate(spec, line)
	r := rdRender(t, edition.RenderInput{
		CID: demoCID, Questions: rdQuestions(), Spec: spec, Template: tmpl,
		Key: rdKey(t, rdKeyText), Seats: seats, Previous: edition.NoPreviousSeats(),
	})
	return spec, tmpl, r
}

// bkAnswers is the answer rows of a render as B7 reads them.
func bkAnswers(r *edition.Rendered) edition.SeatAnswers {
	out := edition.SeatAnswers{}
	for _, row := range r.Rows {
		if out[row.Seat] == nil {
			out[row.Seat] = map[string]string{}
		}
		out[row.Seat][row.QID] = row.Value
	}
	return out
}

func bkCheck(spec *edition.Spec, tmpl []edition.BundleFile, bundles []*edition.Bundle, answers edition.SeatAnswers) error {
	return edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, bundles, answers)
}

// bkBlock is the 7 lines of the block of a bundle (c.txt after `begin`), each as its 4 words (the
// time, the column, the third word, the key).
func bkBlock(t *testing.T, b *edition.Bundle) [][]string {
	t.Helper()
	for _, f := range b.Files {
		if f.Name != bkFile {
			continue
		}
		lines := strings.Split(strings.TrimSuffix(string(f.Data), "\n"), "\n")
		if len(lines) != 8 || lines[0] != "begin" {
			t.Fatalf("seat %s: %s has %d lines, want begin and 7", b.Seat, bkFile, len(lines))
		}
		var out [][]string
		for _, ln := range lines[1:] {
			fs := strings.Fields(ln)
			if len(fs) != 4 {
				t.Fatalf("seat %s: a line of the block has %d words, want 4", b.Seat, len(fs))
			}
			out = append(out, fs)
		}
		return out
	}
	t.Fatalf("seat %s has no %s", b.Seat, bkFile)
	return nil
}

// bkWithBlock is a copy of b with the block's lines replaced: a bundle the renderer did not make.
func bkWithBlock(b *edition.Bundle, block [][]string) *edition.Bundle {
	out := &edition.Bundle{Seat: b.Seat, CID: b.CID}
	for _, f := range b.Files {
		if f.Name == bkFile {
			lines := []string{"begin"}
			for _, fs := range block {
				lines = append(lines, strings.Join(fs, " "))
			}
			f = sbFile(bkFile, lines)
		}
		out.Files = append(out.Files, f)
	}
	return out
}

// bkCopy is a deep copy of a block.
func bkCopy(block [][]string) [][]string {
	out := make([][]string, len(block))
	for i, fs := range block {
		out[i] = slices.Clone(fs)
	}
	return out
}

// bkRank is the index of the line whose column holds v, or -1.
func bkRank(block [][]string, v string) int {
	for i, fs := range block {
		if fs[1] == v {
			return i
		}
	}
	return -1
}

// bkWantOne fails unless err is one B7 violation, of the seat, whose message says what.
func bkWantOne(t *testing.T, err error, seat, what string, r *edition.Rendered) {
	t.Helper()
	specWantRules(t, err, edition.RuleDecoySpread)
	vs := rdViolations(err)
	if len(vs) != 1 || vs[0].Seat != seat || vs[0].QID != "q2" || !strings.Contains(vs[0].Msg, what) {
		t.Fatalf("violations = %v, want one of %s, q2, saying %q", err, seat, what)
	}
	rdNoLeak(t, what, err, rdSecretValues(r))
}

// V113: the renderer orders the lines of a block by their times, strictly, in every seat, and
// the answer's line is not at one place: 20 seats do not all have it at one rank (so two seats
// differ). B7 passes the render.
func TestBlock_TheRenderOrdersTheLinesAndTheAnswersRankVaries(t *testing.T) {
	spec, tmpl, r := bkRender(t, bkDoc(bkDay, true, false), bkPlain, rdSeatNames(20)...)
	answers := bkAnswers(r)
	ranks := map[int]int{}
	for _, b := range r.Bundles {
		block := bkBlock(t, b)
		for i := 1; i < len(block); i++ {
			if block[i-1][0] >= block[i][0] {
				t.Errorf("seat %s: line %d of the block is not after line %d in time", b.Seat, i+1, i)
			}
		}
		rank := bkRank(block, answers[b.Seat]["q2"])
		if rank < 0 {
			t.Fatalf("seat %s: the answer is not in the column of the block", b.Seat)
		}
		ranks[rank]++
	}
	if len(ranks) < 2 {
		t.Errorf("the answer's line has one rank in all 20 seats (%v): the order does not hide it", ranks)
	}
	if err := bkCheck(spec, tmpl, r.Bundles, answers); err != nil {
		t.Errorf("B7 on the render: %v", err)
	}
}

// V4 (block part): the columns of the block in 8 seats, 7 values each, meet in no subset of 2 seats
// or more.
func TestBlock_V4TheColumnsOfEightSeatsMeetInNoSubset(t *testing.T) {
	_, _, r := bkRender(t, bkDoc(bkDay, true, false), bkPlain, rdSeatNames(8)...)
	var cols []map[string]bool
	for _, b := range r.Bundles {
		col := map[string]bool{}
		for _, fs := range bkBlock(t, b) {
			col[fs[1]] = true
		}
		if len(col) != 7 {
			t.Errorf("seat %s: the column has %d values, want 7", b.Seat, len(col))
		}
		cols = append(cols, col)
	}
	subsets := 0
	for mask := 0; mask < 1<<len(cols); mask++ {
		if bits.OnesCount(uint(mask)) < 2 {
			continue
		}
		subsets++
		var common map[string]bool
		for i := range cols {
			if mask&(1<<i) == 0 {
				continue
			}
			if common == nil {
				common = maps.Clone(cols[i])
				continue
			}
			for v := range common {
				if !cols[i][v] {
					delete(common, v)
				}
			}
		}
		if len(common) != 0 {
			t.Errorf("the seats of %08b have %d values of the column in common", mask, len(common))
		}
	}
	if subsets != 247 {
		t.Fatalf("%d subsets were looked at, want 247", subsets)
	}
}

// V113 (r1): a renderer that keeps each slot apart between seats, and not the group, is red. Its
// output is made here: the same seats rendered without the block (U2 by slot), each block then put
// in the order of its times. 70 seats take 490 values of 1000 paths, so two seats' columns meet;
// B7 names it, while the render with the block (r1) passes.
func TestBlock_R1AnAssignmentBySlotIsRed(t *testing.T) {
	seats := rdSeatNames(70)
	spec, tmpl, r := bkRender(t, bkDoc(bkDay, true, false), bkPlain, seats...)
	if err := bkCheck(spec, tmpl, r.Bundles, bkAnswers(r)); err != nil {
		t.Fatalf("the render with the block: %v", err)
	}
	_, _, bySlot := bkRender(t, bkDoc(bkDay, false, false), bkPlain, seats...)
	var ordered []*edition.Bundle
	for _, b := range bySlot.Bundles {
		block := bkBlock(t, b)
		slices.SortStableFunc(block, func(x, y []string) int { return strings.Compare(x[0], y[0]) })
		ordered = append(ordered, bkWithBlock(b, block))
	}
	err := bkCheck(spec, tmpl, ordered, bkAnswers(bySlot))
	specWantRules(t, err, edition.RuleDecoySpread)
	if !strings.Contains(err.Error(), "an earlier seat holds a value of the column") {
		t.Errorf("the columns of two seats meet and B7 does not say so: %v", err)
	}
	rdNoLeak(t, "an assignment by slot", err, rdSecretValues(bySlot))
}

// V113 (B7 (1)): K counts the decoys' values in the column only. A block whose decoys are K - 1
// distinct values is red though a path filler of each line gives 7 more paths; with K distinct it
// passes. The answer in the column twice, or not at all, is red too.
func TestBlock_B7CountsTheColumnOnly(t *testing.T) {
	spec, tmpl, r := bkRender(t, bkDoc(bkDay, true, true), bkFilled, "seat-a")
	answers := bkAnswers(r)
	own := rdBundle(t, r, "seat-a")
	ans := answers["seat-a"]["q2"]
	base := bkBlock(t, own)
	at := bkRank(base, ans)
	if at < 0 {
		t.Fatal("the answer is not in the column")
	}
	with := func(decoys, fillers []string) *edition.Bundle {
		block := bkCopy(base)
		d := 0
		for i := range block {
			block[i][2] = fillers[i]
			if i != at {
				block[i][1] = decoys[d]
				d++
			}
		}
		return bkWithBlock(own, block)
	}
	fillers := []string{"/f/0", "/f/1", "/f/2", "/f/3", "/f/4", "/f/5", "/f/6"}
	if err := bkCheck(spec, tmpl, []*edition.Bundle{with([]string{"/d/0", "/d/1", "/d/2", "/d/3", "/d/3", "/d/3"}, fillers)}, answers); err != nil {
		t.Errorf("4 distinct decoys (K): %v", err)
	}
	bkWantOne(t, bkCheck(spec, tmpl, []*edition.Bundle{with([]string{"/d/0", "/d/0", "/d/1", "/d/1", "/d/2", "/d/2"}, fillers)}, answers),
		"seat-a", "holds 3 distinct decoy tokens", r)
	bkWantOne(t, bkCheck(spec, tmpl, []*edition.Bundle{with([]string{ans, "/d/1", "/d/2", "/d/3", "/d/4", "/d/5"}, fillers)}, answers),
		"seat-a", "answer 2 times", r)
	gone := bkCopy(base)
	gone[at][1] = "/d/9"
	vs := rdViolations(bkCheck(spec, tmpl, []*edition.Bundle{bkWithBlock(own, gone)}, answers))
	if len(vs) != 1 || !strings.Contains(vs[0].Msg, "answer 0 times") {
		t.Errorf("the answer out of the column: violations %v, want one, 'answer 0 times'", vs)
	}
}

// V113 (o1) (o2): a block the renderer did not order (its lines in the reverse order of their
// times), a block with two lines of one time, and a block with a literal word changed are red,
// one violation each.
func TestBlock_O1O2AnUnorderedOrChangedBlockIsRed(t *testing.T) {
	spec, tmpl, r := bkRender(t, bkDoc(bkDay, true, false), bkPlain, "seat-a")
	answers := bkAnswers(r)
	own := rdBundle(t, r, "seat-a")
	base := bkBlock(t, own)

	reversed := bkCopy(base)
	slices.Reverse(reversed)
	bkWantOne(t, bkCheck(spec, tmpl, []*edition.Bundle{bkWithBlock(own, reversed)}, answers), "seat-a", "strictly ascending", r)

	tie := bkCopy(base)
	tie[1][0] = tie[0][0]
	bkWantOne(t, bkCheck(spec, tmpl, []*edition.Bundle{bkWithBlock(own, tie)}, answers), "seat-a", "strictly ascending", r)

	word := bkCopy(base)
	word[3][2] = "hast"
	bkWantOne(t, bkCheck(spec, tmpl, []*edition.Bundle{bkWithBlock(own, word)}, answers), "seat-a", "signatures", r)
}

// V113 (o3): where a clue tells the lines apart, the answer on a decoy's line (the two values of
// the column swapped, the times kept) is red; where no clue does, the same swap says nothing (the
// two lines have one signature).
// The (o3) before its replacement: PR 4c makes it the match of the key words (ADR-0056 amend. 31).
func TestBlock_O3TheAnswerOnADecoysLine(t *testing.T) {
	for _, c := range []struct {
		name string
		line bkLine
		red  bool
	}{
		{"lines a clue tells apart", bkClued, true},
		{"lines no clue tells apart", bkPlain, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			spec, tmpl, r := bkRender(t, bkDoc(bkDay, true, false), c.line, "seat-a")
			answers := bkAnswers(r)
			own := rdBundle(t, r, "seat-a")
			block := bkBlock(t, own)
			at := bkRank(block, answers["seat-a"]["q2"])
			other := (at + 1) % len(block)
			block[at][1], block[other][1] = block[other][1], block[at][1]
			err := bkCheck(spec, tmpl, []*edition.Bundle{bkWithBlock(own, block)}, answers)
			if !c.red {
				if err != nil {
					t.Errorf("a swap that no signature shows: %v", err)
				}
				return
			}
			bkWantOne(t, err, "seat-a", "signature is not the one of the template's line of the answer", r)
		})
	}
}

// V113 (r2): times that cannot all differ (7 lines, a window of 3 seconds) fail the render (E3,
// fail-closed); a window of 12 seconds makes the times meet often and is drawn again, and every
// block is in the strictly ascending order of its times.
func TestBlock_R2TimesOfABlockAreDrawnApart(t *testing.T) {
	spec := rdSpec(t, bkDoc("{from: 0, to: 3}", true, false))
	_, err := edition.Render(edition.RenderInput{
		CID: demoCID, Questions: rdQuestions(), Spec: spec, Template: bkTemplate(spec, bkPlain),
		Key: rdKey(t, rdKeyText), Seats: []string{"seat-a"}, Previous: edition.NoPreviousSeats(),
	})
	specWantRules(t, err, edition.RuleSpecRender)
	if !strings.Contains(err.Error(), "could not be drawn") {
		t.Errorf("the times that must meet: %v", err)
	}
	spec, tmpl, r := bkRender(t, bkDoc("{from: 0, to: 12}", true, false), bkPlain, rdSeatNames(30)...)
	for _, b := range r.Bundles {
		block := bkBlock(t, b)
		for i := 1; i < len(block); i++ {
			if block[i-1][0] >= block[i][0] {
				t.Errorf("seat %s: two lines of the block are not in strictly ascending time", b.Seat)
			}
		}
	}
	if err := bkCheck(spec, tmpl, r.Bundles, bkAnswers(r)); err != nil {
		t.Errorf("B7 on the render of a narrow window: %v", err)
	}
}

// V113, the revision's case, kept as a negative case for good: B7 by position (the form before
// blocks, which a template without a block still gets) passes two bundles that the block form
// refuses. (a) Seat b holds seat a's answer in its column, on a line where seat a holds another
// value: by position the two seats differ everywhere, but their columns meet, and two seats that
// compare their columns learn something of a role. (b) A block in the reverse order of its times:
// by position every value is one of the group's, and only (o2) sees that the order is not the
// renderer's. Reading by position must not be what judges a block.
func TestBlock_ReadingByPositionMissesWhatTheBlockFormSees(t *testing.T) {
	spec, tmpl, r := bkRender(t, bkDoc(bkDay, true, false), bkPlain, "seat-a", "seat-b")
	byPosition := rdSpec(t, bkDoc(bkDay, false, false))
	answers := bkAnswers(r)
	a, b := rdBundle(t, r, "seat-a"), rdBundle(t, r, "seat-b")
	blockA, blockB := bkBlock(t, a), bkBlock(t, b)
	ansA := answers["seat-a"]["q2"]
	skip := []int{0, bkRank(blockA, ansA), bkRank(blockB, answers["seat-b"]["q2"])}
	j := 0
	for slices.Contains(skip, j) {
		j++
	}
	blockB[j][1] = ansA
	pair := []*edition.Bundle{a, bkWithBlock(b, blockB)}
	if err := edition.CheckDecoySpread(demoCID, byPosition, rdQuestions(), tmpl, pair, nil); err != nil {
		t.Fatalf("(a) by position the pair passes (the case does not show the miss): %v", err)
	}
	bkWantOne(t, bkCheck(spec, tmpl, pair, answers), "seat-b", "an earlier seat holds a value of the column", r)

	reversed := bkCopy(blockA)
	slices.Reverse(reversed)
	alone := []*edition.Bundle{bkWithBlock(a, reversed)}
	if err := edition.CheckDecoySpread(demoCID, byPosition, rdQuestions(), tmpl, alone, nil); err != nil {
		t.Fatalf("(b) by position the reversed block passes (the case does not show the miss): %v", err)
	}
	bkWantOne(t, bkCheck(spec, tmpl, alone, answers), "seat-a", "strictly ascending", r)
}

// B7 does not run on a block it cannot read or without the answers: a block whose file the
// template does not have (E2 refuses it) and a render's bundles with no answers are refused, not
// passed.
func TestBlock_B7RefusesWhatItCannotRead(t *testing.T) {
	spec, tmpl, r := bkRender(t, bkDoc(bkDay, true, false), bkPlain, "seat-a", "seat-b")
	err := bkCheck(spec, tmpl, r.Bundles, nil)
	specWantRules(t, err, edition.RuleDecoySpread)
	if !strings.Contains(err.Error(), "have no value") {
		t.Errorf("no answers: %v", err)
	}
	moved := rdSpec(t, bkDoc(bkDay, false, false).withBlocks("[{file: d.txt, from: 2, to: 8}]"))
	err = bkCheck(moved, tmpl, r.Bundles, bkAnswers(r))
	specWantRules(t, err, edition.RuleDecoySpread)
	if !strings.Contains(err.Error(), "do not hold to E2") {
		t.Errorf("a block of a file the template does not have: %v", err)
	}
	rdNoLeak(t, "a block B7 cannot read", err, rdSecretValues(r))
}

// The digest of a practice render with a block is the digest of the ordered bytes: PracticeOutput
// writes the digest of the files it holds, and their block is in the order of its times.
func TestBlock_ThePracticeDigestIsOfTheOrderedBytes(t *testing.T) {
	spec := rdSpec(t, bkDoc(bkDay, true, false))
	p, err := edition.RenderPractice(demoCID, spec, rdQuestions(), bkTemplate(spec, bkPlain))
	if err != nil {
		t.Fatalf("RenderPractice: %v", err)
	}
	pf, err := edition.PracticeOutput(p)
	if err != nil {
		t.Fatalf("PracticeOutput: %v", err)
	}
	if !rdSameBundle(&edition.Bundle{Seat: edition.AnySeat, CID: demoCID, Files: pf.Evidence}, p.Bundles[0]) {
		t.Fatal("the practice files are not the render's bundle")
	}
	block := bkBlock(t, p.Bundles[0])
	for i := 1; i < len(block); i++ {
		if block[i-1][0] >= block[i][0] {
			t.Errorf("the practice block is not in strictly ascending time at line %d", i+1)
		}
	}
	if want := "*\t" + demoCID + "\t" + edition.BundleDigest(pf.Evidence) + "\n"; !strings.Contains(string(pf.Digests), want) {
		t.Errorf("the digests file does not hold the digest of the ordered bundle")
	}
}

// The answers RenderEvent's self check hands B7 are the rows it writes (seatAnswersOfRows): with
// all of them B7 passes the render, and with one seat's answer of the block's question taken out
// it refuses that seat (fail-closed), naming no value.
func TestBlock_TheSelfChecksAnswersAreTheRows(t *testing.T) {
	spec, tmpl, r := bkRender(t, bkDoc(bkDay, true, false), bkPlain, "seat-a", "seat-b")
	all := edition.SeatAnswersOfRowsForTest(r.Rows)[demoCID]
	if err := bkCheck(spec, tmpl, r.Bundles, all); err != nil {
		t.Fatalf("B7 with the answers of the rows: %v", err)
	}
	delete(all["seat-b"], "q2")
	bkWantOne(t, bkCheck(spec, tmpl, r.Bundles, all), "seat-b", "have no value", r)
}

// SeatAnswers holds plaintext answers: it prints as a fixed string under every fmt verb and under
// encoding/json, alone, through a pointer, as a field, in a map and in a slice. Reading it is
// not changed (B7 reads the map).
func TestSeatAnswers_PrintsNoValue(t *testing.T) {
	const secret = "/SECRET-answer/0001"
	a := edition.SeatAnswers{"seat-a": {"q2": secret}}
	type holder struct{ A edition.SeatAnswers }
	for name, v := range map[string]any{
		"the value":   a,
		"a pointer":   &a,
		"in a struct": holder{A: a},
		"in a map":    map[string]edition.SeatAnswers{demoCID: a},
		"in a slice":  []edition.SeatAnswers{a},
	} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, "SECRET") {
				t.Errorf("%s under %s prints a value: %q", name, verb, out)
			}
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Errorf("%s: json.Marshal: %v", name, err)
		}
		if strings.Contains(string(b), "SECRET") {
			t.Errorf("%s: json.Marshal prints a value: %s", name, b)
		}
	}
	if a.String() != a.GoString() || !strings.Contains(a.String(), "redacted") {
		t.Errorf("String %q and GoString %q, want one fixed string that says it is redacted", a.String(), a.GoString())
	}
	if a["seat-a"]["q2"] != secret {
		t.Error("the value cannot be read back: the redaction is of printing only")
	}
}

// R2's question (review of #698): an answer slot or a decoy written both in its block and on a
// line outside it (so that some of a question's marks would be read by position and the others
// in the block, and K counted twice or in part) is not an edition: E2 refuses it (a mark of a
// group that has a block is on no line outside its blocks), the renderer refuses it with E2, and
// B7 refuses to run on it. A second answer slot of one question is CheckQuestions's (E2:
// exactly one answer slot per per-seat question).
func TestBlock_AGroupBothInAndOutOfItsBlockIsRefused(t *testing.T) {
	spec, tmpl, r := bkRender(t, bkDoc(bkDay, true, false), bkPlain, "seat-a")
	for _, mark := range []string{"where", "where-d1"} {
		t.Run(mark, func(t *testing.T) {
			mixed := slices.Clone(tmpl)
			mixed[0] = edition.BundleFile{Name: mixed[0].Name, Data: append(slices.Clone(mixed[0].Data), []byte("again={{ctf:"+mark+"}}\n")...)}
			sbWantOne(t, spec.CheckBlocksAndClues(demoCID, mixed), edition.RuleSpecQuestion)
			_, err := edition.Render(edition.RenderInput{
				CID: demoCID, Questions: rdQuestions(), Spec: spec, Template: mixed,
				Key: rdKey(t, rdKeyText), Seats: []string{"seat-a"}, Previous: edition.NoPreviousSeats(),
			})
			specWantRules(t, err, edition.RuleSpecQuestion)
			err = bkCheck(spec, mixed, r.Bundles, bkAnswers(r))
			specWantRules(t, err, edition.RuleDecoySpread)
			if !strings.Contains(err.Error(), "do not hold to E2") {
				t.Errorf("B7 on the mixed template: %v", err)
			}
		})
	}
}
