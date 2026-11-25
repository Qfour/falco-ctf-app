package edition

// rowsymmetry.go is D10 B17 and B19 (ADR-0056 amendments 27 to 31, D19 A7-x PR 4 and 4b): the
// lines of an answer's group in the template, and what a part of its clues leaves to guess among.
//
// The shape is the two-step one (amendments 29 and 31): a block holds the answer's line and one
// line of each decoy, the same but for their marks; outside the blocks, each line of the group has
// one clue line (a line that shares a filler mark with it, its key), and the clue lines are the
// same but for their marks and their clue columns (the words of the answer's clue line that are
// the declared clues). That much is E2's (specblocks.go, (e1) to (e4)), on the helpers of this file
// (blockRows, clueLinesOf, clueColumns, clueMasked).
//
//   - B17: every line of the template that holds the mark of an answer slot is in a block (D12,
//     amendment 28), so it is a line of a group (E2, CheckBlocksAndClues, holds a block to one
//     group, each slot once). In a block, the lines have the answer's line's signature with their
//     marks put out of sight (lineSignature), and nothing else: a clue word in the lines of a block
//     (the one-step shape) is no longer one of the words they may differ in (amendment 31). And
//     (b17-1, its second half) each mark at a word of a line occurs in the whole template as many
//     times as the mark at the same word of the answer's line. (b17-1, its first half, and
//     (b17-2) are E2's.) (b17-3), as amendment 31 revised it, on the words of the clue columns of
//     each line's clue line (its tuple, declared clue or not: the reader of the public template
//     sees the words, not which of them are declared): (i) the tuples of a block differ; (ii) only
//     the answer's combination (clueCombination: the declared clues of the line and of its clue
//     line) holds every declared clue; (iii) the answer's line is not alone the line that shares a
//     word of a clue column with the most lines; (iv) it is not alone the line with the largest sum,
//     over the clue columns, of the lines that hold its word there. The machine stops at (iv): any
//     other way to find an outlier is the content review's (R1).
//   - B19: for an answer slot with clues, every subset of them with one clue fewer leaves at least
//     the threshold (clueSpaceThreshold: 2 x attempts, amendment 31, security's condition) of values
//     declared as the answer slot: in the lines that hold every word of the subset, and in the lines
//     tied to those by a filler mark (one step), only the lines of the group's shape are counted
//     (groupShapes: the signature of its block's lines, and that of its clue lines), and in them a
//     mark (the mark alone as a word) of a slot of the answer slot's declaration (valueSpace:
//     format, length, vocabulary and window) is one value. A literal word is not one (amendment
//     30), and a line of another shape is not looked at (a reader tells it from the group's lines
//     by its form). A smaller subset leaves no fewer lines, so the subsets of one clue fewer are the
//     ones that decide. With c clues, (ii) leaves each of these subsets at most the answer and the
//     decoys that hold every clue but one, so c x (threshold - 1) <= K is needed: a slot that
//     declares more clues cannot have a template B19 accepts, and B19 refuses it (E2 does not
//     count them). B19 runs on a slot B17 accepted only: a slot B17 refused has no group of a
//     settled shape to count in, and it is refused already (fail-closed). So a slot with no clue
//     (no proper subset: nothing to say) is one outside every block, which B17 refuses. A
//     narrowing by a time range or by joining files is not counted (the review's).
//
// They read the template once with the lexer of the marks (readMarkedText and templateTokens,
// the one mapping from a mark to its word), and the blocks with blockForms (the reading the
// renderer and B7 share): readRows. They need E2: an edition that CheckQuestions or
// CheckBlocksAndClues refuses is refused here too, as B17, and is not compared (fail-closed). B18
// (practiceclues.go) reads the clue lines of an answer with the same readRows and clueCombination.
// They hold no key, no answer and draw nothing, and are not a render file. A violation names the
// rule, the challenge, the question, the slot, the file and the line, never a word of the template
// or a clue (a clue is named by its index).

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// The rules of D10 on the lines of an answer's group (amendments 27 and 28).
const (
	RuleRowSymmetry = "B17"
	RuleClueSpace   = "B19"
)

// RowReport is what B17 and B19 compared, for a caller (a test) to hold to "not nothing". It
// holds counts only.
type RowReport struct {
	// AnswerSlots is how many answer slots B17 looked at.
	AnswerSlots int
	// Blocks is how many blocks of a group B17 compared line by line.
	Blocks int
	// ClueSets is how many subsets of the clues of one fewer B19 counted the values of.
	ClueSets int
}

// rowLine is one line of the template as B17 and B19 read it.
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
// its template's lines and its group index.
type editionRows struct {
	forms []blockForm
	x     *rowIndex
	gi    *groupIndex
}

// readRows reads them for the edition of challenge cid (qs: its questions), or returns no rows,
// why they cannot be read (a clause, for the caller's message) and the file it is about (""
// when it is no one file): the edition does not hold to E2 (CheckQuestions, CheckBlocksAndClues:
// a refused edition is not compared, fail-closed), its blocks cannot be read, or a file of the
// template has a mark opener that is not a mark. It reads no file.
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
	return &editionRows{forms: forms, x: x, gi: s.newGroupIndex()}, "", ""
}

// clueSet is the clues of an answer slot, as a set.
func clueSet(sl *Slot) map[string]bool {
	out := make(map[string]bool, len(sl.Clues))
	for _, w := range sl.Clues {
		out[w] = true
	}
	return out
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

// uniqueMax reports whether n[at] is larger than every other n[j] (and there is another).
func uniqueMax(n []int, at int) bool {
	if len(n) < 2 {
		return false
	}
	for j, v := range n {
		if j != at && v >= n[at] {
			return false
		}
	}
	return true
}

// CheckRowRules applies B17 and B19 to the edition of challenge cid (qs: its questions, the ones
// CheckQuestions is given; template: the files of template/). It returns what it compared, and nil
// or an errors.Join of *Violation (at most maxViolations listed: the answer slots in the order of
// edition.yaml, B17 then B19 for each). An edition that E2 refuses is one violation of B17, and
// nothing is compared. It reads no file.
func (s *Spec) CheckRowRules(cid string, qs []catalog.Question, template []BundleFile) (RowReport, error) {
	var rep RowReport
	if s == nil {
		return rep, errors.New("edition: the spec is missing")
	}
	refuse := func(msg, file string) (RowReport, error) {
		v := newSpecViolation(RuleRowSymmetry, msg, 0, cid, "", "", "", nil)
		if file != "" {
			v.File = shownName(file)
		}
		return rep, v
	}
	rows, why, file := s.readRows(cid, qs, template)
	if rows == nil {
		return refuse(why+", so B17 and B19 cannot compare its lines", file)
	}
	forms, x, gi := rows.forms, rows.x, rows.gi
	var c collector
	for i := range s.Slots {
		sl := &s.Slots[i]
		if sl.Role != RoleAnswer {
			continue
		}
		rep.AnswerSlots++
		q, ok := findQuestion(qs, sl.Question)
		if !ok {
			// E2 holds every answer slot to a question; one that is not found is not compared.
			c.add(newSpecViolation(RuleRowSymmetry, "the answer slot names no question of the challenge, so B17 and B19 cannot run on it", 0, cid, sl.Question, sl.Name, fmt.Sprintf("slots[%d]", i), nil))
			continue
		}
		before := len(c.errs) + c.dropped
		checkGroupRows(cid, sl, forms, gi, x, &c, &rep)
		if len(c.errs)+c.dropped != before {
			// B17 refused the slot: its group has no shape B19 could count in, and the slot is
			// refused already (fail-closed). B19 runs on a slot that B17 accepted only.
			continue
		}
		checkClueSpace(cid, i, sl, q, qs, forms, gi, x, &c, &rep)
	}
	return rep, c.err()
}

// checkGroupRows is B17 for one answer slot.
func checkGroupRows(cid string, sl *Slot, forms []blockForm, gi *groupIndex, x *rowIndex, c *collector, rep *RowReport) {
	bad := func(msg string, at fileLine) {
		v := newSpecViolation(RuleRowSymmetry, msg, at.line, cid, sl.Question, sl.Name, "", nil)
		v.File = shownName(at.file)
		c.add(v)
	}
	lines := x.bySlot[sl.Name]
	if len(lines) == 0 {
		c.add(newSpecViolation(RuleRowSymmetry, "the mark of the answer slot is on no line of the template, so it has no group to compare", 0, cid, sl.Question, sl.Name, "", nil))
		return
	}
	var outside []*rowLine
	for _, ln := range lines {
		if !ln.inBlock {
			outside = append(outside, ln)
		}
	}
	if len(outside) > 0 {
		bad(fmt.Sprintf("%d of the %d lines that hold the mark of the answer slot are in no block, the first of them here (the lines of a group, the answer's and one of each decoy's, are in one block: blocks)", len(outside), len(lines)), outside[0].at)
	}
	for i := range forms {
		f := &forms[i]
		if f.group != sl.Name {
			continue
		}
		rep.Blocks++
		rows := blockRows(f, x)
		if rows == nil {
			bad("a line of the block is not the line the blocks were read from", fileLine{f.file, f.from + 1})
			continue
		}
		checkRowWords(f, rows, bad)
		checkRowMarkCounts(f, rows, x, bad)
		checkRowClues(f, rows, sl, gi, x, bad)
	}
}

// checkRowWords: the lines of a block have the answer's line's signature with their marks put out
// of sight, and with nothing else put out of sight (amendment 31: the clues are on the clue lines
// outside the block; a block whose lines differ in a clue word is the one-step shape, which is
// not taken).
func checkRowWords(f *blockForm, rows []*rowLine, bad func(string, fileLine)) {
	want := lineSignature(rows[f.answer].pseudo, f.masked)
	for j, r := range rows {
		if j != f.answer && lineSignature(r.pseudo, f.masked) != want {
			bad("the line differs from the line of the answer of its block outside the marks (every word, and the text between the words, is the same in the lines of a group; the clues are on the clue lines outside the block, amendment 31)", r.at)
		}
	}
}

// checkRowMarkCounts is the second half of (b17-1): each mark at a word of a line of the block
// occurs in the whole template as many times as the mark at the same word of the answer's line.
func checkRowMarkCounts(f *blockForm, rows []*rowLine, x *rowIndex, bad func(string, fileLine)) {
	ref := rows[f.answer]
	for j, r := range rows {
		if j != f.answer && markCountsDiffer(ref, r, f.masked, x) {
			bad("a mark at a word of the line occurs in the template another number of times than the mark at the same word of the line of the answer of its block (b17-1)", r.at)
		}
	}
}

// checkRowClues is (b17-3) for one block (amendment 31): (i) to (iv) on the tuples of the words of
// the clue columns of each line's clue line, and (ii) on the combinations of declared clues. E2
// holds the clue lines and their columns ((e2), (e3)); if they cannot be read here they are given
// to bad (fail-closed).
func checkRowClues(f *blockForm, rows []*rowLine, sl *Slot, gi *groupIndex, x *rowIndex, bad func(string, fileLine)) {
	lines, ok := clueLinesOf(rows, gi, x, make(map[*rowLine]*rowLine), bad)
	if !ok {
		return
	}
	cols, missing := clueColumns(sl, lines[f.answer])
	if missing >= 0 {
		bad(fmt.Sprintf("clues[%d] is not a literal word of the answer's clue line, so (b17-3) has no clue columns (E2 (e3))", missing), lines[f.answer].at)
		return
	}
	tuples := make([][]string, len(lines))
	keys := make([]string, len(lines))
	for j, l := range lines {
		for _, col := range cols {
			if col >= len(l.toks) {
				bad("the clue line has fewer words than the answer's clue line, so its clue columns cannot be read (E2 (e4))", l.at)
				return
			}
			tuples[j] = append(tuples[j], string(l.toks[col].lit))
		}
		// A word is one token, so it holds no line feed.
		keys[j] = strings.Join(tuples[j], "\n")
	}
	// (i)
	for j := range keys {
		for i := range j {
			if keys[i] == keys[j] {
				bad(fmt.Sprintf("the clue line of the line holds, in the clue columns, the words of the clue line of line %d of its block's file ((b17-3) (i): the words of the clue columns differ between the lines of a group, declared clues or not)", rows[i].at.line), rows[j].at)
				break
			}
		}
	}
	// (ii)
	clues := clueSet(sl)
	for j, r := range rows {
		if j != f.answer && holdsAll(clueCombination(r, clues, gi, x), clues) {
			bad("the line and its clue line hold every declared clue, as the answer's do ((b17-3) (ii): only the answer's combination holds them all)", r.at)
		}
	}
	// (iii) and (iv)
	shared := make([]int, len(rows))
	sums := make([]int, len(rows))
	for j := range tuples {
		for i := range tuples {
			if i == j {
				continue
			}
			one := false
			for c := range cols {
				if tuples[i][c] == tuples[j][c] {
					sums[j]++
					one = true
				}
			}
			if one {
				shared[j]++
			}
		}
	}
	if uniqueMax(shared, f.answer) {
		bad("the clue line of the answer shares a word of a clue column with more lines of its block than any other line's does, so it stands out as the centre of the clues ((b17-3) (iii))", rows[f.answer].at)
	}
	if uniqueMax(sums, f.answer) {
		bad("the clue line of the answer holds the most frequent words of the clue columns, more than any other line's does, so it stands out as their centre ((b17-3) (iv))", rows[f.answer].at)
	}
}

// clueSpaceThreshold is B19's threshold for question q: 2 x attempts (amendment 31, security's
// condition). It is the one place the threshold is taken.
func clueSpaceThreshold(q catalog.Question) int {
	return 2 * q.Attempts
}

// rowShape is a shape of the lines of a group: the words put out of sight, and the signature.
type rowShape struct {
	masked []int
	sig    string
}

// holds reports whether ln has the shape.
func (s rowShape) holds(ln *rowLine) bool {
	return lineSignature(ln.pseudo, s.masked) == s.sig
}

// groupShapes is the shapes of the lines of sl's group that B19 counts in (amendment 31, security's
// condition): for each block of the group, the signature of its lines (their marks put out of
// sight) and that of its clue lines (their marks and their clue columns put out of sight). It is
// read for a slot B17 accepted (its lines are all in blocks, of one shape, with their clue lines).
func groupShapes(sl *Slot, forms []blockForm, gi *groupIndex, x *rowIndex) []rowShape {
	var out []rowShape
	for i := range forms {
		f := &forms[i]
		if f.group != sl.Name {
			continue
		}
		rows := blockRows(f, x)
		if rows == nil {
			continue
		}
		out = append(out, rowShape{masked: f.masked, sig: lineSignature(rows[f.answer].pseudo, f.masked)})
		lines, ok := clueLinesOf(rows, gi, x, make(map[*rowLine]*rowLine), func(string, fileLine) {})
		if !ok {
			continue
		}
		cols, missing := clueColumns(sl, lines[f.answer])
		if missing >= 0 {
			continue
		}
		masked := clueMasked(lines[f.answer], cols)
		out = append(out, rowShape{masked: masked, sig: lineSignature(lines[f.answer].pseudo, masked)})
	}
	return out
}

// checkClueSpace is B19 for one answer slot (the idx-th of edition.yaml).
func checkClueSpace(cid string, idx int, sl *Slot, q catalog.Question, qs []catalog.Question, forms []blockForm, gi *groupIndex, x *rowIndex, c *collector, rep *RowReport) {
	need := clueSpaceThreshold(q)
	shapes := groupShapes(sl, forms, gi, x)
	for omit := range sl.Clues {
		rep.ClueSets++
		var part []string
		for i, w := range sl.Clues {
			if i != omit {
				part = append(part, w)
			}
		}
		if n := x.candidates(part, sl, qs, gi, shapes); n < need {
			c.add(newSpecViolation(RuleClueSpace, fmt.Sprintf("with every clue but clues[%d], the lines of the group's shape (its block's lines and its clue lines) that hold those clue words, and those tied to them by a filler mark, hold %d values declared as the answer slot (a literal word, and a line of another shape, are not counted), below the threshold of B19, 2 x attempts (%d): a part of the clues leaves fewer candidates than the threshold", omit, n, need), 0, cid, sl.Question, sl.Name, fmt.Sprintf("slots[%d].clues", idx), nil))
		}
	}
}

// candidates is how many values declared as the answer slot sl are in the lines that hold every
// word of part (every line, for no word) and in the lines tied to them by a filler mark (one step),
// of those lines the ones of one of shapes only: a mark (a token that is the mark alone) of sl, of
// a decoy of it or of a slot whose valueSpace is sl's is one value. A literal word is not counted
// (amendment 30: it is in the public template), and neither is a mark glued to other token bytes.
func (x *rowIndex) candidates(part []string, sl *Slot, qs []catalog.Question, gi *groupIndex, shapes []rowShape) int {
	reach := make(map[*rowLine]bool)
	for _, ln := range x.lines {
		holds := true
		for _, w := range part {
			if !ln.words[w] {
				holds = false
				break
			}
		}
		if !holds {
			continue
		}
		reach[ln] = true
		for _, o := range x.tied(ln, gi, false) {
			reach[o] = true
		}
	}
	want := valueSpace(sl, qs)
	kinds := make(map[string]bool)
	for ln := range reach {
		if !slices.ContainsFunc(shapes, func(s rowShape) bool { return s.holds(ln) }) {
			continue
		}
		for _, t := range ln.toks {
			if !t.alone || kinds[t.slots[0]] {
				continue
			}
			if name := t.slots[0]; name == sl.Name || sameDeclaration(want, valueSpace(gi.decl[name], qs), false) {
				kinds[name] = true
			}
		}
	}
	return len(kinds)
}

// valueSpace is the declaration of the values of slot d as B19 compares two slots
// (sameDeclaration, with no role: a filler and an answer declared alike draw from one space): a
// filler's own format, length, vocabulary and window; an answer's and a decoy's format and length
// are those of its question (a decoy carries its answer's question, vocabulary and window). It is
// nil for a slot that is not declared, or whose question is not one of qs.
func valueSpace(d *Slot, qs []catalog.Question) *Slot {
	if d == nil {
		return nil
	}
	if d.Role == RoleFiller {
		return &Slot{Format: d.Format, Length: d.Length, Vocab: d.Vocab, Window: d.Window}
	}
	q, ok := findQuestion(qs, d.Question)
	if !ok {
		return nil
	}
	return &Slot{Format: q.Format, Length: q.Params.Length, Vocab: d.Vocab, Window: d.Window}
}
