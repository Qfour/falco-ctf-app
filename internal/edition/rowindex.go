package edition

// rowindex.go is the model of the lines of a template that the rules on the lines of an answer's
// group share (ADR-0056 D10, amendments 27 to 32, D19 A7-x PR 4 to 4c): E2's clue lines
// (specblocks.go, (e1) to (e5)), B17 and B19 (rowsymmetry.go), B18 (practiceclues.go), B7's (o3)
// and the keys of a block (spreadblock.go), and the keys the renderer draws apart (render.go
// calls keyBlocks).
//
// It reads the template once with the lexer of the marks (readMarkedText and templateTokens, the
// one mapping from a mark to its word) into a rowIndex, and the blocks with blockForms (the
// reading the renderer and B7 share). A block of a group is read as the lines of its group and
// their clue lines in ONE place, deriveBlockClue: its lines (blockRows), the clue line of each
// (E2 (e2), clueLinesOf: the one line outside every block that shares a filler mark with it, its
// key) and the clue columns (E2 (e3), clueColumns). E2 calls it block by block and names what it
// cannot read; every other reader takes the result of blockCluesOf (once per edition: readRows for
// B17, B18 and B19, blockSpreadOf for B7, keyBlocks for the renderer), which gives nothing for an
// edition E2 refuses (fail-closed). The key of a line is the fillers it shares with its clue line
// (keySlots).
//
// It holds no key and no answer, draws nothing, and is not a render file: nothing here calls the
// renderer. A message here names no word of the template.

import (
	"errors"
	"fmt"
	"slices"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// rowLine is one line of the template as the rules on the lines of a group read it.
type rowLine struct {
	at fileLine
	// pseudo is the line with each mark one token byte (readMarkedText), toks its tokens.
	pseudo []byte
	toks   []templateToken
	// slots are the slots of the marks of the line, each once, in order; words its literal tokens.
	slots []string
	words map[string]bool
	// inBlock says the line is in a block of the spec.
	inBlock bool
}

// rowIndex is every line of the template, and where each slot's marks are.
type rowIndex struct {
	lines []*rowLine
	byAt  map[fileLine]*rowLine
	// count is the number of marks of each slot in the whole template; bySlot the lines that hold
	// a mark of it (each line once).
	count  map[string]int
	bySlot map[string][]*rowLine
}

// newRowIndex reads every line of the template, in the order of the files and of their lines,
// and marks the lines of the blocks. A file the lexer of the marks refuses is returned by its name
// (and no index): its lines are not known.
func newRowIndex(template []BundleFile, forms []blockForm) (*rowIndex, string) {
	x := &rowIndex{byAt: make(map[fileLine]*rowLine), count: make(map[string]int), bySlot: make(map[string][]*rowLine)}
	for _, f := range template {
		if _, err := ScanMarks(f.Data); err != nil {
			return nil, f.Name
		}
		for li, raw := range templateLines(f.Data) {
			mt, err := readMarkedText(raw)
			if err != nil {
				return nil, f.Name
			}
			toks, err := templateTokens(raw)
			if err != nil {
				return nil, f.Name
			}
			ln := &rowLine{at: fileLine{f.Name, li + 1}, pseudo: mt.pseudo, toks: toks, words: make(map[string]bool)}
			for _, t := range toks {
				if len(t.slots) == 0 {
					ln.words[string(t.lit)] = true
				}
				for _, sl := range t.slots {
					x.count[sl]++
					if !slices.Contains(ln.slots, sl) {
						ln.slots = append(ln.slots, sl)
						x.bySlot[sl] = append(x.bySlot[sl], ln)
					}
				}
			}
			x.lines = append(x.lines, ln)
			x.byAt[ln.at] = ln
		}
	}
	for _, fm := range forms {
		for j := range fm.lines() {
			if ln := x.byAt[fileLine{fm.file, fm.from + j + 1}]; ln != nil {
				ln.inBlock = true
			}
		}
	}
	return x, ""
}

// tied is the lines that share a filler mark with ln (the key of a clue line), ln left out, each
// once, in the order of the template. With outside, only the lines that are in no block.
func (x *rowIndex) tied(ln *rowLine, gi *groupIndex, outside bool) []*rowLine {
	var out []*rowLine
	seen := map[*rowLine]bool{ln: true}
	for _, sl := range ln.slots {
		if d := gi.decl[sl]; d == nil || d.Role != RoleFiller {
			continue
		}
		for _, o := range x.bySlot[sl] {
			if seen[o] || (outside && o.inBlock) {
				continue
			}
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}

// editionRows is what B17, B18 and B19 read of an edition: the forms of its blocks, the index of
// its template's lines, its group index, and each block read as the lines of its group and their
// clue lines (clues[i] is forms[i]'s, blockCluesOf).
type editionRows struct {
	forms []blockForm
	x     *rowIndex
	gi    *groupIndex
	clues []*blockClue
}

// readRows reads them for the edition of challenge cid (qs: its questions), or returns no rows,
// why they cannot be read (a clause, for the caller's message) and the file it is about (""
// when it is no one file): the edition does not hold to E2 (CheckQuestions, CheckBlocksAndClues:
// a refused edition is not compared, fail-closed), its blocks cannot be read, a file of the
// template has a mark opener that is not a mark, or the clue lines of a block cannot be read (E2
// holds them, so this is fail-closed only). It reads no file.
func (s *Spec) readRows(cid string, qs []catalog.Question, template []BundleFile) (*editionRows, string, string) {
	if errors.Join(s.CheckQuestions(cid, qs), s.CheckBlocksAndClues(cid, template)) != nil {
		return nil, "the edition does not hold to E2 (its questions, blocks or clues)", ""
	}
	forms, err := s.blockForms(template)
	if err != nil {
		return nil, "the blocks of the edition cannot be read", ""
	}
	x, bad := newRowIndex(template, forms)
	if bad != "" {
		return nil, "the template has a " + MarkOpen + " that is not a mark", bad
	}
	gi := s.newGroupIndex()
	clues, ok := blockCluesOf(forms, gi, x)
	if !ok {
		return nil, "the clue lines of a block of the edition cannot be read", ""
	}
	return &editionRows{forms: forms, x: x, gi: gi, clues: clues}, "", ""
}

// clueSet is the clues of an answer slot, as a set.
func clueSet(sl *Slot) map[string]bool {
	out := make(map[string]bool, len(sl.Clues))
	for _, w := range sl.Clues {
		out[w] = true
	}
	return out
}

// holdsAll reports whether every word of p is in e.
func holdsAll(e, p map[string]bool) bool {
	for w := range p {
		if !e[w] {
			return false
		}
	}
	return true
}

// clueCombination is the combination of clue words of a line of a group ((b17-3), amendments 29
// and 31): the declared clues that ln holds and that the lines outside every block that share a
// filler mark with it (its clue line, one step) hold. (b17-3) (ii) and B18 read it.
func clueCombination(ln *rowLine, clues map[string]bool, gi *groupIndex, x *rowIndex) map[string]bool {
	m := make(map[string]bool)
	for _, l := range append([]*rowLine{ln}, x.tied(ln, gi, true)...) {
		for w := range l.words {
			if clues[w] {
				m[w] = true
			}
		}
	}
	return m
}

// blockRows is the lines of block f in x, in its order, or nil when one of them is not the line
// the blocks were read from (blockForms read the same template: fail-closed all the same).
func blockRows(f *blockForm, x *rowIndex) []*rowLine {
	rows := make([]*rowLine, f.lines())
	for j := range rows {
		rows[j] = x.byAt[fileLine{f.file, f.from + j + 1}]
		if rows[j] == nil || len(rows[j].toks) != f.tokens {
			return nil
		}
	}
	return rows
}

// clueLinesOf is (e2) for the lines of one block (amendment 31): the clue line of each, the one
// line outside every block that shares a filler mark with it, which no other line of a group
// shares a filler mark with (owner: each clue line seen so far, by the line of a group it is
// tied to). A line with no clue line or with two, and a clue line of two lines, are given to bad,
// and the result is then not ok.
func clueLinesOf(rows []*rowLine, gi *groupIndex, x *rowIndex, owner map[*rowLine]*rowLine, bad func(string, fileLine)) ([]*rowLine, bool) {
	out := make([]*rowLine, len(rows))
	ok := true
	for j, r := range rows {
		t := x.tied(r, gi, true)
		if len(t) != 1 {
			bad(fmt.Sprintf("the line of the group shares a filler mark with %d lines outside the blocks; it has exactly one clue line, its key's (E2 (e2))", len(t)), r.at)
			ok = false
			continue
		}
		if o := owner[t[0]]; o != nil && o != r {
			bad("the clue line shares a filler mark with two lines of groups; a clue line is of one line of a group (E2 (e2))", t[0].at)
			ok = false
			continue
		}
		owner[t[0]] = r
		out[j] = t[0]
	}
	return out, ok
}

// clueColumns is (e3): the clue columns of a group, the words of the answer's clue line ans that
// are its declared clues (the first such word of each clue), in ascending order. A clue that is
// not a literal word of ans is returned by its index (and no columns).
func clueColumns(sl *Slot, ans *rowLine) ([]int, int) {
	cols := make([]int, 0, len(sl.Clues))
	for i, w := range sl.Clues {
		at := -1
		for ti, t := range ans.toks {
			if len(t.slots) == 0 && string(t.lit) == w {
				at = ti
				break
			}
		}
		if at < 0 {
			return nil, i
		}
		cols = append(cols, at)
	}
	slices.Sort(cols)
	return cols, -1
}

// clueMasked is the words of a clue line that are put out of sight when the clue lines are
// compared ((e4)): its marks and the clue columns, in ascending order.
func clueMasked(ln *rowLine, cols []int) []int {
	var out []int
	for ti, t := range ln.toks {
		if len(t.slots) > 0 || slices.Contains(cols, ti) {
			out = append(out, ti)
		}
	}
	return out
}

// markCountsDiffer reports whether a mark at a word of cols of line l occurs in the whole template
// another number of times than the mark at the same word of ref ((b17-1), its second half).
func markCountsDiffer(ref, l *rowLine, cols []int, x *rowIndex) bool {
	for _, col := range cols {
		a, b := ref.toks[col].slots, l.toks[col].slots
		if len(a) != len(b) {
			return true
		}
		for k := range a {
			if x.count[a[k]] != x.count[b[k]] {
				return true
			}
		}
	}
	return false
}

// blockClue is one block of a group read as the lines of its group and their clue lines
// (amendment 31): what E2's (e2) and (e3) hold, read once (deriveBlockClue).
type blockClue struct {
	f *blockForm
	// rows are the lines of the block in its order (rows[f.answer] the answer's), lines the clue
	// line of each (E2 (e2)), cols the clue columns (E2 (e3)), ascending.
	rows  []*rowLine
	lines []*rowLine
	cols  []int
}

// deriveBlockClue reads block f, of the group of answer slot sl (which declares clues), as the
// lines of its group and their clue lines, or gives what it cannot read to bad (the message and
// the line it is about) and returns nil: a line of the block that is not the line the blocks were
// read from, a line with no clue line or with two, a clue line of two lines of groups (owner: the
// clue lines seen so far, across the blocks), and a clue that is not a literal word of the answer's
// clue line. It is the one derivation of a block's clue lines and clue columns.
func deriveBlockClue(f *blockForm, sl *Slot, gi *groupIndex, x *rowIndex, owner map[*rowLine]*rowLine, bad func(string, fileLine)) *blockClue {
	rows := blockRows(f, x)
	if rows == nil {
		bad("a line of the block is not the line the blocks were read from", fileLine{f.file, f.from + 1})
		return nil
	}
	lines, ok := clueLinesOf(rows, gi, x, owner, bad)
	if !ok {
		return nil
	}
	cols, missing := clueColumns(sl, lines[f.answer])
	if missing >= 0 {
		bad(fmt.Sprintf("clues[%d] is not a literal word of the answer's clue line (E2 (e3): each clue is a word of it, and the place of that word is a clue column)", missing), lines[f.answer].at)
		return nil
	}
	return &blockClue{f: f, rows: rows, lines: lines, cols: cols}
}

// blockCluesOf is deriveBlockClue for every block of forms, in their order and with one owner (a
// clue line is of one line of a group across the blocks, as E2 reads it): clues[i] is forms[i]'s.
// It is false, and gives nothing, when the group of a block declares no clue (E2 (e1)) or a block
// cannot be read: E2 refuses both, so a reader that gets false refuses (fail-closed).
func blockCluesOf(forms []blockForm, gi *groupIndex, x *rowIndex) ([]*blockClue, bool) {
	owner := make(map[*rowLine]*rowLine)
	out := make([]*blockClue, len(forms))
	for i := range forms {
		f := &forms[i]
		sl := gi.decl[f.group]
		if sl == nil || len(sl.Clues) == 0 {
			return nil, false
		}
		ok := true
		out[i] = deriveBlockClue(f, sl, gi, x, owner, func(string, fileLine) { ok = false })
		if !ok || out[i] == nil {
			return nil, false
		}
	}
	return out, true
}

// keySlots is the key of line r of a group and its clue line l (amendment 32, PR 4c): the fillers
// whose marks are on both, each once, in the order of r. E2 (e2) ties the two by them.
func keySlots(r, l *rowLine, gi *groupIndex) []string {
	var out []string
	for _, sl := range r.slots {
		if d := gi.decl[sl]; d != nil && d.Role == RoleFiller && slices.Contains(l.slots, sl) {
			out = append(out, sl)
		}
	}
	return out
}

// keys is the keys of every line of the block (keySlots), each once, in the order of the lines.
func (bc *blockClue) keys(gi *groupIndex) []string {
	var out []string
	for j, r := range bc.rows {
		for _, k := range keySlots(r, bc.lines[j], gi) {
			if !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	return out
}

// markWord is the index of the first word of ln that holds a mark of slot, or -1.
func markWord(ln *rowLine, slot string) int {
	for ti, t := range ln.toks {
		if slices.Contains(t.slots, slot) {
			return ti
		}
	}
	return -1
}

// rowHolds reports whether a row of a group (line r and its clue line l) holds every word of q
// as a literal word of one of the two.
func rowHolds(r, l *rowLine, q map[string]bool) bool {
	for w := range q {
		if !r.words[w] && !l.words[w] {
			return false
		}
	}
	return true
}

// keyBlocks is the block of every key of the blocks of s (amendment 32, PR 4c): each filler that a
// line of a block shares with its clue line (keySlots), by slot, to the index of its block in
// forms. The renderer reads it to draw the keys of a block apart in a seat (E2 (e5) holds each
// key to a space of at least the block's number of keys). With no block it is nil. It reads the
// template as E2 does, and refuses what E2 refuses (an error that names no word): a file the
// lexer of the marks refuses, and a block whose clue lines cannot be read.
func (s *Spec) keyBlocks(template []BundleFile, forms []blockForm) (map[string]int, error) {
	if len(forms) == 0 {
		return nil, nil
	}
	gi := s.newGroupIndex()
	x, bad := newRowIndex(template, forms)
	if bad != "" {
		return nil, errors.New("a file of the template has a " + MarkOpen + " that is not a mark")
	}
	clues, ok := blockCluesOf(forms, gi, x)
	if !ok {
		return nil, errors.New("the clue lines of a block cannot be read")
	}
	out := make(map[string]int)
	for i, bc := range clues {
		for _, k := range bc.keys(gi) {
			out[k] = i
		}
	}
	return out, nil
}
