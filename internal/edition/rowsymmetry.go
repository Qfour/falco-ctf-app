package edition

// rowsymmetry.go is D10 B17 and B19 (ADR-0056 amendments 27 to 31, D19 A7-x PR 4 and 4b): the
// lines of an answer's group in the template, and what a part of its clues leaves to guess among.
//
// The shape is the two-step one (amendments 29 and 31): a block holds the answer's line and one
// line of each decoy, the same but for their marks; outside the blocks, each line of the group has
// one clue line (a line that shares a filler mark with it, its key), and the clue lines are the
// same but for their marks and their clue columns (the words of the answer's clue line that are
// the declared clues). That much is E2's (specblocks.go, (e1) to (e5)), on the model of the lines
// that E2 and these rules share (rowindex.go: the index of the lines, and each block read as the
// lines of its group and their clue lines once, deriveBlockClue).
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
// They read the template once with readRows (rowindex.go). They need E2: an edition that
// CheckQuestions or CheckBlocksAndClues refuses is refused here too, as B17, and is not compared
// (fail-closed). B18 (practiceclues.go) reads the same rows. They hold no key, no answer and draw
// nothing, and are not a render file. A violation names the rule, the challenge, the question,
// the slot, the file and the line, never a word of the template or a clue (a clue is named by its
// index).

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
		checkGroupRows(cid, sl, rows, &c, &rep)
		if len(c.errs)+c.dropped != before {
			// B17 refused the slot: its group has no shape B19 could count in, and the slot is
			// refused already (fail-closed). B19 runs on a slot that B17 accepted only.
			continue
		}
		checkClueSpace(cid, i, sl, q, qs, rows, &c, &rep)
	}
	return rep, c.err()
}

// checkGroupRows is B17 for one answer slot.
func checkGroupRows(cid string, sl *Slot, rows *editionRows, c *collector, rep *RowReport) {
	bad := func(msg string, at fileLine) {
		v := newSpecViolation(RuleRowSymmetry, msg, at.line, cid, sl.Question, sl.Name, "", nil)
		v.File = shownName(at.file)
		c.add(v)
	}
	lines := rows.x.bySlot[sl.Name]
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
	for i := range rows.forms {
		f := &rows.forms[i]
		if f.group != sl.Name {
			continue
		}
		rep.Blocks++
		bc := rows.clues[i]
		if bc == nil {
			// readRows reads the clue lines of every block (E2 holds them); kept, fail-closed.
			bad("the lines of the block and their clue lines cannot be read", fileLine{f.file, f.from + 1})
			continue
		}
		checkRowWords(f, bc.rows, bad)
		checkRowMarkCounts(f, bc.rows, rows.x, bad)
		checkRowClues(bc, sl, rows.gi, rows.x, bad)
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
// the clue columns of each line's clue line, and (ii) on the combinations of declared clues. The
// clue lines and their columns are the block's one derivation (bc: E2's (e2), (e3)); a clue line
// whose clue columns cannot be read is given to bad (fail-closed).
func checkRowClues(bc *blockClue, sl *Slot, gi *groupIndex, x *rowIndex, bad func(string, fileLine)) {
	f, rows, lines, cols := bc.f, bc.rows, bc.lines, bc.cols
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
// condition). It is the one place the threshold is taken (B18's Q2-1 reads it too).
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
func groupShapes(sl *Slot, rows *editionRows) []rowShape {
	var out []rowShape
	for _, bc := range rows.clues {
		if bc == nil || bc.f.group != sl.Name {
			continue
		}
		f := bc.f
		out = append(out, rowShape{masked: f.masked, sig: lineSignature(bc.rows[f.answer].pseudo, f.masked)})
		masked := clueMasked(bc.lines[f.answer], bc.cols)
		out = append(out, rowShape{masked: masked, sig: lineSignature(bc.lines[f.answer].pseudo, masked)})
	}
	return out
}

// checkClueSpace is B19 for one answer slot (the idx-th of edition.yaml).
func checkClueSpace(cid string, idx int, sl *Slot, q catalog.Question, qs []catalog.Question, rows *editionRows, c *collector, rep *RowReport) {
	need := clueSpaceThreshold(q)
	shapes := groupShapes(sl, rows)
	for omit := range sl.Clues {
		rep.ClueSets++
		var part []string
		for i, w := range sl.Clues {
			if i != omit {
				part = append(part, w)
			}
		}
		if n := rows.x.candidates(part, sl, qs, rows.gi, shapes); n < need {
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
