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
//   - (o3) (amendment 31, implemented by PR 4c) the line of the block that holds the seat's answer
//     has the key of the answer's clue line: the words of its key marks (the fillers the
//     template's answer line shares with its clue line, keySlots) are the words of the same key
//     marks of the bundle's answer clue line. That clue line is found by the words of its clue
//     columns (the literal tuple of the template's answer clue line, unique in the block by
//     (b17-3) (i)), never by its line number: exactly one line of the bundle has the clue lines'
//     shape (their marks and clue columns put out of sight, E2 (e4)) and that tuple; none, or two,
//     is a violation. The (o3) before it compared the signature of the answer's line, which says
//     nothing once a block's lines are the same but for their marks (amendment 31). A render that
//     put the answer's value on another line than the answer's key (a decoy's clue line would lead
//     to it) is what it catches;
//   - the keys (amendment 32, security's condition): in a seat, the keys of the lines of a block
//     differ, and so do the keys of the clue lines of its group (each found by its tuple, once),
//     so the answer's key is on one line of the block and on one clue line. Every key of the
//     group is held, not the answer's only: a decoy's key met twice would tie a decoy's clue line
//     to two lines, or the answer's line to a decoy's clue line, as well. The renderer draws the
//     keys of a block apart (render.go) within E2 (e5)'s space. The keys are read at the words of
//     the template's answer line and answer clue line, so a template whose lines have their keys
//     at other words, or a key mark that is not a word alone, cannot be read and is refused
//     (fail-closed, blockKeyOf).
//
// Like spread.go, it holds no key and calls nothing of the renderer. A violation names a rule, a
// seat, a challenge, a question, the group's answer slot and a file, never a value: the answers
// it is given (SeatAnswers) print as a fixed string, and a key's word is not named either.

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
	// keys is what (o3) and the keys read of each block (keys[i] is forms[i]'s).
	keys []blockKey
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
	x, badFile := newRowIndex(template, forms)
	if badFile != "" {
		return nil, newViolation(RuleDecoySpread, "a file of the template has a "+MarkOpen+" that is not a mark, so the clue lines of the blocks cannot be read", 0, cell{cid: cid}, nil)
	}
	clues, ok := blockCluesOf(forms, gi, x)
	if !ok {
		return nil, newViolation(RuleDecoySpread, "the clue lines of a block cannot be read, so (o3) cannot find the answer's clue line", 0, cell{cid: cid}, nil)
	}
	bs := &blockSpread{cid: cid, forms: forms, slots: map[string]bool{}, qids: map[string]bool{}, held: map[string]map[string]struct{}{}}
	for _, bc := range clues {
		k, msg := blockKeyOf(bc, gi)
		if msg != "" {
			return nil, newViolation(RuleDecoySpread, msg, 0, cell{cid: cid}, nil)
		}
		bs.keys = append(bs.keys, k)
	}
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

// checkSeat is (1), (2), (o1) to (o3) and the keys for one seat, whose bundle has the template's files and
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
		col, ok := bs.checkForm(c, s, f, &bs.keys[i], per, answers)
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

// checkForm is (1), (o1) to (o3) and the keys for one block of one seat (bk: what (o3) reads of
// the block). It returns the values of the block's column (for (2)), or false when the lines
// cannot be read into words at all.
func (bs *blockSpread) checkForm(c *collector, s *spreadSeat, f *blockForm, bk *blockKey, per []catalog.Question, answers SeatAnswers) ([]string, bool) {
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
	words := make([][]string, n)
	ordered := true
	prev := ""
	for j, ln := range lines[f.from : f.from+n] {
		toks := fileTokens(ln)
		if len(toks) != f.tokens {
			bad("a line of the block has another number of words than the template's lines, so its column cannot be read")
			return nil, false
		}
		words[j] = toks
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
	// (o3) and the keys
	if times != 1 {
		at = -1
	}
	checkKeys(bad, s, bk, f.answer, words, at)
	return col, true
}

// blockKey is what (o3) and the keys read of a block from the template (amendment 31 and 32, PR
// 4c): where the keys are, and how the clue lines of its group are found in a bundle.
type blockKey struct {
	// rowAt and clueAt are the words of the key marks, in a line of the block and in its clue line:
	// rowAt[i] and clueAt[i] hold one key slot (the same words in every line of the block, and in
	// every clue line).
	rowAt, clueAt []int
	// clueMasked and clueSig are the shape of the group's clue lines (their marks and clue columns
	// put out of sight, E2 (e4)); cols the clue columns, and tuples the words in them of each
	// line's clue line, in the block's order.
	clueMasked []int
	clueSig    string
	cols       []int
	tuples     [][]string
}

// blockKeyOf reads the blockKey of a block of the template, or why it cannot (a message that
// names no word): a line of the block with no key (E2 (e2) ties each to its clue line by one), a
// key mark that is not a word alone (its word in a bundle would hold more than the key's value),
// keys at other words in another line of the block or in another clue line (a bundle's block is
// in another order than the template's, so the keys are read at one set of words), and a clue
// column that does not hold a literal word (E2 (e4)).
func blockKeyOf(bc *blockClue, gi *groupIndex) (blockKey, string) {
	var k blockKey
	for j, r := range bc.rows {
		l := bc.lines[j]
		var rowAt, clueAt []int
		for _, sl := range keySlots(r, l, gi) {
			ri, ci := markWord(r, sl), markWord(l, sl)
			if ri < 0 || ci < 0 || !r.toks[ri].alone || !l.toks[ci].alone {
				return blockKey{}, "a key of a line of a block (a filler it shares with its clue line) is not a mark alone as a word, so B7 cannot read the keys of a bundle ((o3), amendment 32)"
			}
			rowAt, clueAt = append(rowAt, ri), append(clueAt, ci)
		}
		switch {
		case len(rowAt) == 0:
			return blockKey{}, "a line of a block shares no filler with its clue line, so B7 cannot read its key ((o3))"
		case j == 0:
			k.rowAt, k.clueAt = rowAt, clueAt
		case !slices.Equal(rowAt, k.rowAt) || !slices.Equal(clueAt, k.clueAt):
			return blockKey{}, "the keys of the lines of a block, or of their clue lines, are not at the same words, so B7 cannot read the keys of a bundle, whose block is in another order ((o3), amendment 32)"
		}
	}
	a := bc.f.answer
	k.cols = bc.cols
	k.clueMasked = clueMasked(bc.lines[a], bc.cols)
	k.clueSig = lineSignature(bc.lines[a].pseudo, k.clueMasked)
	k.tuples = make([][]string, len(bc.lines))
	for j, l := range bc.lines {
		for _, col := range bc.cols {
			if col >= len(l.toks) || len(l.toks[col].slots) > 0 {
				return blockKey{}, "a clue column of a clue line of a block does not hold a literal word (E2 (e4)), so B7 cannot find the clue lines of a bundle ((o3))"
			}
			k.tuples[j] = append(k.tuples[j], string(l.toks[col].lit))
		}
	}
	return k, ""
}

// checkKeys is (o3) and the keys for one block of one seat. rows are the words of the bundle's
// lines of the block, in the bundle's order; at is the index in rows of the line that holds the
// seat's answer (-1 when the column does not hold it once: (1) refused the block, and (o3) is not
// looked at); ans is the index of the answer's line in the template's block (its tuple is
// tuples[ans]).
func checkKeys(bad func(string), s *spreadSeat, k *blockKey, ans int, rows [][]string, at int) {
	// The keys of the lines of the block differ.
	for _, p := range k.rowAt {
		if !wordsDiffer(rows, p) {
			bad("two lines of the block hold one key, so a key ties a clue line to two lines (the keys of a group differ in a seat: each is on one line of the block and on one clue line, amendment 32)")
			break
		}
	}
	// The clue lines of the group: each line of the bundle of their shape, by its tuple.
	count := make([]int, len(k.tuples))
	found := make([][]string, len(k.tuples))
	for _, data := range s.data {
		for _, ln := range templateLines(data) {
			if lineSignature(ln, k.clueMasked) != k.clueSig {
				continue
			}
			toks := fileTokens(ln)
			for j, tu := range k.tuples {
				if wordsAre(toks, k.cols, tu) {
					count[j]++
					found[j] = toks
				}
			}
		}
	}
	// (o3)
	if at >= 0 {
		switch {
		case count[ans] != 1:
			bad(fmt.Sprintf("the bundle has %d lines of the shape of the block's clue lines that hold the words of the clue columns of the answer's clue line; (o3) finds the answer's clue line by those words, and needs exactly one", count[ans]))
		case !sameKey(rows[at], k.rowAt, found[ans], k.clueAt):
			bad("the line of the block that holds the seat's answer has another key than the answer's clue line, so the answer is tied to the clues of another line ((o3))")
		}
	}
	// The keys of the clue lines differ.
	for j := range count {
		if count[j] != 1 {
			if j != ans {
				bad(fmt.Sprintf("the bundle has %d lines of the shape of the block's clue lines that hold the words of the clue columns of a decoy's clue line; each clue line of the group is there once, so that its key can be read", count[j]))
			}
			return
		}
	}
	for _, p := range k.clueAt {
		if !wordsDiffer(found, p) {
			bad("two clue lines of the block's group hold one key, so a key ties a line of the block to two clue lines (the keys of a group differ in a seat: each is on one line of the block and on one clue line, amendment 32)")
			return
		}
	}
}

// wordsDiffer reports whether the words at index p of the lines differ from each other.
func wordsDiffer(lines [][]string, p int) bool {
	seen := make(map[string]bool, len(lines))
	for _, ws := range lines {
		if seen[ws[p]] {
			return false
		}
		seen[ws[p]] = true
	}
	return true
}

// wordsAre reports whether the words of toks at cols are tuple.
func wordsAre(toks []string, cols []int, tuple []string) bool {
	for i, col := range cols {
		if col >= len(toks) || toks[col] != tuple[i] {
			return false
		}
	}
	return true
}

// sameKey reports whether the words of a line of the block at rowAt are the words of a clue line
// at clueAt, pairwise.
func sameKey(row []string, rowAt []int, clue []string, clueAt []int) bool {
	for i := range rowAt {
		if rowAt[i] >= len(row) || clueAt[i] >= len(clue) || row[rowAt[i]] != clue[clueAt[i]] {
			return false
		}
	}
	return true
}
