package edition

// spreadblock.go is B7 for the groups in a block (ADR-0056 D10, "the order of the lines",
// amendment 28 as revised, the second PR of A7-x). The renderer puts the lines of a block in the
// order of their times, which differs from seat to seat, so the line a bundle's line came from (σ)
// cannot be read back from the bundle, and B7's reading by position (spread.go) does not apply to
// the marks of such a group. Nothing here uses σ: a block is read as the set of its lines.
//
//   - (1) per seat: the COLUMN of the block (the word of its group's marks, the same in every line,
//     blockorder.go) holds the seat's answer (the answers table's value) exactly once, and the
//     other values of the column that fit the question are at least K = DecoyK(attempts), counted
//     once each. E2 makes every line of a block a line of its group, so the other values are the
//     decoys' and no filler's: a value of a filler is at another word and is not counted;
//   - (2) between seats: the values of the columns of a group (the answer's and the decoys') in two
//     seats have none in common. A comparison of two bundles, or of more, then rules out no value
//     of a column. The fillers' words are not compared (they are drawn alike for the answer's
//     line and the decoys' lines, so a value in common says nothing of a role);
//   - (o1) the signatures of the lines of the block (blockorder.go) are, as a multiset, the
//     signatures of the template's lines of the block;
//   - (o2) the times of the lines (their first timestamp words) are in strictly ascending order:
//     a block the renderer did not order, and a block with two lines of one time, are refused;
//   - (o3) the seat's answer is on a line whose signature is the one of the template's line of
//     the answer slot. Where the group's lines have one signature (no clue tells them apart), this
//     says nothing, as the ADR means it to.
//
// Like spread.go, it holds no key and calls nothing of the renderer. A violation names a rule, a
// seat, a challenge, a question, the group's answer slot and a file, never a value: the answers
// it is given (SeatAnswers) print as a fixed string.

import (
	"fmt"
	"io"
	"slices"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

// SeatAnswers is the answers table's value of each seat and per-seat question of one challenge
// (seat -> question id -> value), which B7 needs for a group in a block: where the answer's line
// is cannot be read from the bundle, so the value is what (1) and (o3) look for. It holds
// plaintext answers, and prints as a fixed string under every fmt verb and under encoding/json.
type SeatAnswers map[string]map[string]string

const redactedSeatAnswers = "edition.SeatAnswers{redacted}"

// Format, String, GoString and MarshalJSON make SeatAnswers print as a fixed string.
func (SeatAnswers) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedSeatAnswers) }

// String: see Format.
func (SeatAnswers) String() string { return redactedSeatAnswers }

// GoString: see Format.
func (SeatAnswers) GoString() string { return redactedSeatAnswers }

// MarshalJSON: see Format.
func (SeatAnswers) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedSeatAnswers + `"`), nil
}

// blockSpread is B7 over the blocks of one challenge, across the seats (held keeps what (2)
// compares with).
type blockSpread struct {
	cid   string
	forms []blockForm
	// slots is every slot of a group in a block, and qids the questions of those groups.
	slots map[string]bool
	qids  map[string]bool
	// held is, for each group in a block, the values of its columns in the seats checked so far.
	held map[string]map[string]struct{}
}

// blockSpreadOf reads the blocks of spec from template, or is nil when spec has none (then B7 is
// spread.go's alone, as before blocks). The blocks are held to E2 first (CheckBlocksAndClues): a
// block that does not hold to it cannot be read as one group's lines, and B7 refuses to run on it
// (fail-closed) rather than read it otherwise.
func blockSpreadOf(cid string, spec *Spec, template []BundleFile) (*blockSpread, error) {
	if len(spec.Blocks) == 0 {
		return nil, nil
	}
	if err := spec.CheckBlocksAndClues(cid, template); err != nil {
		return nil, newViolation(RuleDecoySpread, "the blocks of the edition do not hold to E2, so the lines of a block cannot be read as the lines of one group", 0, cell{cid: cid}, nil)
	}
	forms, err := spec.blockForms(template)
	if err != nil {
		return nil, newViolation(RuleDecoySpread, "a block cannot be read as the lines of one group", 0, cell{cid: cid}, err)
	}
	gi := spec.newGroupIndex()
	bs := &blockSpread{cid: cid, forms: forms, slots: map[string]bool{}, qids: map[string]bool{}, held: map[string]map[string]struct{}{}}
	for _, f := range forms {
		bs.qids[f.qid] = true
		for _, m := range gi.members[f.group] {
			bs.slots[m] = true
		}
	}
	return bs, nil
}

// outside is the positions that are not of a group in a block, which spread.go reads by position
// as before, and the questions whose every position is of a group in a block (spread.go does not
// count their decoys: (1) does). With no block it is positions itself and nothing.
func (bs *blockSpread) outside(positions []slotPosition) ([]slotPosition, map[string]bool) {
	if bs == nil {
		return positions, nil
	}
	var out []slotPosition
	left := map[string]bool{}
	for _, p := range positions {
		if !bs.slots[p.slot] {
			out = append(out, p)
			left[p.qid] = true
		}
	}
	skip := map[string]bool{}
	for q := range bs.qids {
		if !left[q] {
			skip[q] = true
		}
	}
	return out, skip
}

// checkSeat is (1), (2) and (o1) to (o3) for one seat, whose bundle has the template's files and
// numbers of tokens (spread.go checked that). The seats come in byte order, so (2) names the later
// seat of two.
func (bs *blockSpread) checkSeat(c *collector, s *spreadSeat, per []catalog.Question, answers SeatAnswers) {
	if bs == nil {
		return
	}
	cols := map[string]map[string]struct{}{}
	var groups []string
	for i := range bs.forms {
		f := &bs.forms[i]
		col, ok := bs.checkForm(c, s, f, per, answers)
		if !ok {
			continue
		}
		if cols[f.group] == nil {
			cols[f.group] = map[string]struct{}{}
			groups = append(groups, f.group)
		}
		for _, v := range col {
			cols[f.group][v] = struct{}{}
		}
	}
	for _, g := range groups {
		if bs.held[g] == nil {
			bs.held[g] = map[string]struct{}{}
		}
		shared := false
		for v := range cols[g] {
			if _, dup := bs.held[g][v]; dup {
				shared = true
			}
			bs.held[g][v] = struct{}{}
		}
		if shared {
			v := spreadViolation(RuleDecoySpread, "an earlier seat holds a value of the column of the group's block (the columns of two seats have a value in common), so a comparison of the two bundles rules a candidate out", s.seat, bs.cid, bs.qidOf(g))
			if answerformat.ValidID(g) {
				v.Slot = g
			}
			c.add(v)
		}
	}
}

func (bs *blockSpread) qidOf(group string) string {
	for _, f := range bs.forms {
		if f.group == group {
			return f.qid
		}
	}
	return ""
}

// checkForm is (1) and (o1) to (o3) for one block of one seat. It returns the values of the
// block's column (for (2)), or false when the lines cannot be read into words at all.
func (bs *blockSpread) checkForm(c *collector, s *spreadSeat, f *blockForm, per []catalog.Question, answers SeatAnswers) ([]string, bool) {
	bad := func(msg string) {
		v := spreadViolation(RuleDecoySpread, msg, s.seat, bs.cid, f.qid)
		if answerformat.ValidID(f.group) {
			v.Slot = f.group
		}
		v.File = shownName(f.file)
		c.add(v)
	}
	q, ok := findQuestion(per, f.qid)
	if !ok {
		bad("the question of the block's group is not a per-seat question of the challenge")
		return nil, false
	}
	fi := slices.Index(s.names, f.file)
	if fi < 0 {
		bad("the bundle of the seat has no file of the block")
		return nil, false
	}
	lines := templateLines(s.data[fi])
	n := f.lines()
	if f.from+n > len(lines) {
		bad("the file of the block has fewer lines than the block")
		return nil, false
	}
	col := make([]string, n)
	sigs := make([]string, n)
	ordered := true
	prev := ""
	for j, ln := range lines[f.from : f.from+n] {
		toks := fileTokens(ln)
		if len(toks) != f.tokens {
			bad("a line of the block has another number of words than the template's lines, so its column cannot be read")
			return nil, false
		}
		col[j] = toks[f.column]
		sigs[j] = lineSignature(ln, f.masked)
		t, ok := lineTime(ln)
		if !ok || (j > 0 && t <= prev) {
			ordered = false
		}
		prev = t
	}
	// (o1)
	want := slices.Clone(f.sigs)
	slices.Sort(want)
	got := slices.Clone(sigs)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		bad("the lines of the block are not the template's lines of the block (the multiset of their signatures differs)")
	}
	// (o2)
	if !ordered {
		bad("the lines of the block are not in the strictly ascending order of their first times")
	}
	// (1)
	ans, ok := answers[s.seat][f.qid]
	if !ok {
		bad("the answers of the seat have no value for the question of the block, so its column cannot be checked")
		return col, true
	}
	at, times := -1, 0
	decoys := map[string]struct{}{}
	for j, v := range col {
		if v == ans {
			at, times = j, times+1
			continue
		}
		if fitsFormat(q, v) {
			decoys[v] = struct{}{}
		}
	}
	if times != 1 {
		bad(fmt.Sprintf("the column of the block holds the seat's answer %d times; B7 needs it once", times))
	}
	if k := DecoyK(q.Attempts); len(decoys) < k {
		bad(fmt.Sprintf("the column of the block holds %d distinct decoy tokens of the format of the question; B7 needs K = %d", len(decoys), k))
	}
	// (o3)
	if times == 1 && sigs[at] != f.sigs[f.answer] {
		bad("the seat's answer is on a line whose signature is not the one of the template's line of the answer")
	}
	return col, true
}
