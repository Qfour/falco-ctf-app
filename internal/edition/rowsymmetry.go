package edition

// rowsymmetry.go is D10 B17 and B19 (ADR-0056 amendments 27 and 28, D19 A7-x PR 4): the lines of
// an answer's group in the template, and what a part of its clues leaves to guess among.
//
//   - B17: every line of the template that holds the mark of an answer slot is in a block (D12,
//     amendment 28), so it is a line of a group: the answer's line and one line of each of its
//     decoys (E2, CheckBlocksAndClues, holds a block to one group, each slot once). In a block,
//     the lines are compared with the line of the answer word by word (B7's TOKEN): with the
//     marks put out of sight they have one signature (lineSignature, the signature of a block's
//     line), but for the words where every line holds a clue of the answer slot (`clues`). And
//     (b17-1, its second half) each mark at a word of a line occurs in the whole template as
//     many times as the mark at the same word of the answer's line. (b17-1, its first half, and
//     (b17-2) are E2's.) When the slot declares clues, (b17-3): the combination of clue words of
//     a line of the group is the set of the clue words in it and in the lines outside every
//     block that share a filler mark with it (the clue lines of the group, tied to it by a key,
//     one step); the combinations of the lines of a block differ from each other, and the
//     answer's line is not alone the line that shares a clue word with the most lines of the
//     block.
//   - B19: for an answer slot with clues, every proper subset S of them (the empty one included)
//     leaves at least k + 1 values of the answer's format (k: groupDecoys, the decoys of the
//     group): in the lines that hold every word of S, and in the lines tied to those by a filler
//     mark (one step), a mark of a slot of the answer's format is one value, and a literal word
//     the format takes (answerformat.Canonical) is one value. A smaller S leaves no fewer lines,
//     so the subsets of one clue fewer are the ones that decide. A slot with no clue has no
//     proper subset: B19 says nothing of it (the CTO's decision, 2026-11-26). A narrowing by a
//     time range or by joining files is not counted (the review's).
//
// They read the template once with the lexer of the marks (readMarkedText and templateTokens,
// the one mapping from a mark to its word), and the blocks with blockForms (the reading the
// renderer and B7 share). They need E2: an edition that CheckQuestions or CheckBlocksAndClues
// refuses is refused here too, as B17, and is not compared (fail-closed). They hold no key, no
// answer and draw nothing, and are not a render file. A violation names the rule, the challenge,
// the question, the slot, the file and the line, never a word of the template or a clue (a clue
// is named by its index).

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
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
	if errors.Join(s.CheckQuestions(cid, qs), s.CheckBlocksAndClues(cid, template)) != nil {
		return refuse("the edition does not hold to E2 (its questions, blocks or clues), so B17 and B19 cannot compare its lines", "")
	}
	forms, err := s.blockForms(template)
	if err != nil {
		return refuse("the blocks of the edition cannot be read, so B17 and B19 cannot compare its lines", "")
	}
	x, bad := newRowIndex(template, forms)
	if bad != "" {
		return refuse("the template has a "+MarkOpen+" that is not a mark, so B17 and B19 cannot read its lines", bad)
	}
	gi := s.newGroupIndex()
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
		checkGroupRows(cid, sl, forms, gi, x, &c, &rep)
		checkClueSpace(cid, i, sl, q, qs, gi, x, &c, &rep)
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
	clues := make(map[string]bool, len(sl.Clues))
	for _, w := range sl.Clues {
		clues[w] = true
	}
	for i := range forms {
		f := &forms[i]
		if f.group != sl.Name {
			continue
		}
		rep.Blocks++
		rows := make([]*rowLine, f.lines())
		ok := true
		for j := range rows {
			rows[j] = x.byAt[fileLine{f.file, f.from + j + 1}]
			if rows[j] == nil || len(rows[j].toks) != f.tokens {
				ok = false
			}
		}
		if !ok {
			// blockForms read these lines from the same template: fail-closed all the same.
			bad("a line of the block is not the line the blocks were read from", fileLine{f.file, f.from + 1})
			continue
		}
		checkRowWords(f, rows, clues, bad)
		checkRowMarkCounts(f, rows, x, bad)
		if len(clues) > 0 {
			checkRowClues(f, rows, clues, gi, x, bad)
		}
	}
}

// checkRowWords: the lines of a block have the answer's line's signature with the marks and the
// words of the clues put out of sight. A word is put out of sight when the lines do not all hold
// the same word there and every one of them holds a clue there.
func checkRowWords(f *blockForm, rows []*rowLine, clues map[string]bool, bad func(string, fileLine)) {
	ref := rows[f.answer]
	masked := slices.Clone(f.masked)
	for ti := range f.tokens {
		if slices.Contains(f.masked, ti) {
			continue
		}
		same, allClues := true, true
		for _, r := range rows {
			w := string(r.toks[ti].lit)
			if w != string(ref.toks[ti].lit) {
				same = false
			}
			if !clues[w] {
				allClues = false
			}
		}
		if !same && allClues {
			masked = append(masked, ti)
		}
	}
	slices.Sort(masked)
	want := lineSignature(ref.pseudo, masked)
	for j, r := range rows {
		if j != f.answer && lineSignature(r.pseudo, masked) != want {
			bad("the line differs from the line of the answer of its block outside the marks and the words where every line holds a declared clue (every other word, and the text between the words, is the same in the lines of a group)", r.at)
		}
	}
}

// checkRowMarkCounts is the second half of (b17-1): each mark at a word of a line of the block
// occurs in the whole template as many times as the mark at the same word of the answer's line.
func checkRowMarkCounts(f *blockForm, rows []*rowLine, x *rowIndex, bad func(string, fileLine)) {
	ref := rows[f.answer]
	for j, r := range rows {
		if j == f.answer {
			continue
		}
		for _, col := range f.masked {
			a, b := ref.toks[col].slots, r.toks[col].slots
			differs := len(a) != len(b)
			for k := 0; !differs && k < len(a); k++ {
				differs = x.count[a[k]] != x.count[b[k]]
			}
			if differs {
				bad("a mark at a word of the line occurs in the template another number of times than the mark at the same word of the line of the answer of its block (b17-1)", r.at)
				break
			}
		}
	}
}

// checkRowClues is (b17-3) for one block of a slot that declares clues.
func checkRowClues(f *blockForm, rows []*rowLine, clues map[string]bool, gi *groupIndex, x *rowIndex, bad func(string, fileLine)) {
	combos := make([]map[string]bool, len(rows))
	keys := make([]string, len(rows))
	for j, r := range rows {
		m := make(map[string]bool)
		for _, ln := range append([]*rowLine{r}, x.tied(r, gi, true)...) {
			for w := range ln.words {
				if clues[w] {
					m[w] = true
				}
			}
		}
		combos[j] = m
		// A clue is one token, so it holds no line feed.
		keys[j] = strings.Join(slices.Sorted(maps.Keys(m)), "\n")
	}
	for j := range rows {
		for i := range j {
			if keys[i] == keys[j] {
				bad(fmt.Sprintf("the line has the same combination of clue words (in it, and in the lines outside the blocks that share a filler mark with it) as line %d of its block's file (b17-3)", rows[i].at.line), rows[j].at)
				break
			}
		}
	}
	shared := make([]int, len(rows))
	for j := range rows {
		for i := range rows {
			if i == j {
				continue
			}
			for w := range combos[i] {
				if combos[j][w] {
					shared[j]++
					break
				}
			}
		}
	}
	alone := len(rows) > 1
	for j := range rows {
		if j != f.answer && shared[j] >= shared[f.answer] {
			alone = false
		}
	}
	if alone {
		bad("the line of the answer shares a clue word with more lines of its block than any other line does, so it stands out as the centre of the clues (b17-3)", rows[f.answer].at)
	}
}

// checkClueSpace is B19 for one answer slot (the idx-th of edition.yaml).
func checkClueSpace(cid string, idx int, sl *Slot, q catalog.Question, qs []catalog.Question, gi *groupIndex, x *rowIndex, c *collector, rep *RowReport) {
	need := groupDecoys(q.Attempts, sl) + 1
	for omit := range sl.Clues {
		rep.ClueSets++
		var part []string
		for i, w := range sl.Clues {
			if i != omit {
				part = append(part, w)
			}
		}
		if n := x.candidates(part, q, qs, gi); n < need {
			c.add(newSpecViolation(RuleClueSpace, fmt.Sprintf("with every clue but clues[%d], the lines that hold those clue words and the lines tied to them by a filler mark hold %d values of the answer's format, below the decoys of the group + 1 (%d): a part of the clues leaves fewer candidates than a guess among the group", omit, n, need), 0, cid, sl.Question, sl.Name, fmt.Sprintf("slots[%d].clues", idx), nil))
		}
	}
}

// candidates is how many values of the format of question q are in the lines that hold every word
// of part (every line, for no word) and in the lines tied to them by a filler mark (one step): a
// mark (a token that is the mark alone) of a slot of q's format is one value, and a literal word
// that q's format takes is one value. A mark glued to other token bytes is not counted.
func (x *rowIndex) candidates(part []string, q catalog.Question, qs []catalog.Question, gi *groupIndex) int {
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
	kinds := make(map[string]bool)
	for ln := range reach {
		for _, t := range ln.toks {
			switch {
			case len(t.slots) == 0:
				if answerformat.Canonical(q.Format, q.Params, string(t.lit)) == nil {
					kinds["v"+string(t.lit)] = true
				}
			case t.alone:
				if slotFormat(t.slots[0], qs, gi) == q.Format {
					kinds["m"+t.slots[0]] = true
				}
			}
		}
	}
	return len(kinds)
}

// slotFormat is the format of a slot: a filler's own, an answer's and a decoy's the question's
// (a decoy carries its answer's question), "" for a slot that is not declared.
func slotFormat(slot string, qs []catalog.Question, gi *groupIndex) string {
	d := gi.decl[slot]
	switch {
	case d == nil:
		return ""
	case d.Role == RoleFiller:
		return d.Format
	}
	if q, ok := findQuestion(qs, d.Question); ok {
		return q.Format
	}
	return ""
}
