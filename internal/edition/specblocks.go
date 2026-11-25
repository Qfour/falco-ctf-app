package edition

// specblocks.go is the part of edition.yaml that needs the template (ADR-0056 D10 E2 as
// amendment 28 extends it, the first PR of A7-x): `blocks` and `clues` held to the files of
// template/. Their schema and their shape (E1) are spec.go. B8 (a2)'s bound for a group in a
// block is seatspace.go's, which reads the groups of the blocks with blockGroups below.
//
// The renderer and B7 read the blocks this check accepted with blockForms (blockorder.go, A7-x
// PR 2: the lines of a block in the order of their times, and B7 on the set of a block's lines).
// Nothing reads `clues` but this check yet (B17 and B19 are a later PR).
//
// It is not a render file: it holds no answer and no key, and it reads the template with the
// lexer of the marks (slotmark.go, ScanMarks and tokenSpans), so `edition check` calls it as the
// renderer does. A message names a block, a slot, a file and a line, never a word of the
// template or a clue.

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

// CheckBlocksAndClues holds the `blocks` and the `clues` of the edition of challenge cid to its
// template (the files of template/). It returns nil, or an errors.Join of *Violation (at most
// maxViolations listed: the blocks in file order, then the marks of a group outside its blocks,
// then the clues in the order of the slots). The rule is E2 (RuleSpecQuestion); a block that is
// not of E1's shape (a Spec not made by ParseSpec) is E1.
//
// A group is an answer slot and its implied decoys. Of a block (amendment 28, as revised):
//
//   - it names a file of the template, its lines from..to are in the file (a line ends at a line
//     feed; a last line without one counts), and the file is read by the lexer of the marks;
//   - one group in a block: every line holds the mark of exactly one slot of a group (so a line
//     is of one group, (b17-2), and a line that is of no group is not in a block), all of them of
//     one group, and every slot of the group is in the block exactly once. A group may have more
//     than one block (one block for each place it is written), and a mark of a group that has a
//     block is nowhere outside its blocks;
//   - every line has a time slot (blockLineKey): the slot whose value will be the first
//     timestamp word of the line, which is what the lines of a block are to be ordered by. A slot
//     with a window is a time slot (E1 lets only a timestamp filler have one, E2 only a timestamp
//     answer, and a decoy takes its answer's). No two lines of a block have the same time slot;
//   - the lines have one shape (the first half of (b17-1)): as many words (B7's TOKEN, the mark
//     counted as one token byte), the group's mark at the same word, the marks at the same words,
//     and at each word the same declaration of the slot (format, length, vocabulary and window:
//     a decoy is its answer's by construction, so this holds the fillers). The time slots of the
//     lines are then of one window.
//
// A clue is a literal word of the template: a TOKEN (B7's, tokenSpans) of some file that holds no
// mark. A slot name inside a mark, or a word glued to a mark, is not one.
//
// It reads no file: the caller gives the template's bytes.
func (s *Spec) CheckBlocksAndClues(cid string, template []BundleFile) error {
	if s == nil {
		return errors.New("edition: the spec is missing")
	}
	var c collector
	gi := s.newGroupIndex()
	files := templateFiles(template)
	// covered is the lines of the blocks of each group, inBlock the lines of every block that
	// could be read (a block that could not is refused, and its lines are not known).
	covered := make(map[string]map[fileLine]bool)
	inBlock := make(map[fileLine]bool)
	for i := range s.Blocks {
		b := &s.Blocks[i]
		g, lines := checkBlock(cid, i, b, files, gi, &c)
		for _, ln := range lines {
			at := fileLine{b.File, ln.n}
			inBlock[at] = true
			if g != "" {
				if covered[g] == nil {
					covered[g] = make(map[fileLine]bool)
				}
				covered[g][at] = true
			}
		}
	}
	checkMarksOutsideBlocks(cid, template, gi, covered, inBlock, &c)
	s.checkClues(cid, template, &c)
	return c.err()
}

// fileLine is one line (1-based) of one template file.
type fileLine struct {
	file string
	line int
}

// groupIndex is what the checks of a block read of the spec: the group of every slot of a group,
// the slots of each group (the answer first, then its decoys in order), the declaration of every
// slot by name, and the window of every time slot.
type groupIndex struct {
	groupOf map[string]string
	members map[string][]string
	decl    map[string]*Slot
	windows map[string][2]int64
}

func (s *Spec) newGroupIndex() *groupIndex {
	gi := &groupIndex{
		groupOf: make(map[string]string), members: make(map[string][]string),
		decl: make(map[string]*Slot), windows: make(map[string][2]int64),
	}
	add := func(sl *Slot) {
		gi.decl[sl.Name] = sl
		if w := sl.Window; w != nil && w.From != nil && w.To != nil {
			gi.windows[sl.Name] = [2]int64{*w.From, *w.To}
		}
	}
	for i := range s.Slots {
		sl := &s.Slots[i]
		add(sl)
		if sl.Role == RoleAnswer {
			gi.groupOf[sl.Name] = sl.Name
			gi.members[sl.Name] = append(gi.members[sl.Name], sl.Name)
		}
	}
	for i := range s.ImpliedDecoys {
		dc := &s.ImpliedDecoys[i]
		add(dc)
		if _, ok := gi.members[dc.DecoyOf]; ok {
			gi.groupOf[dc.Name] = dc.DecoyOf
			gi.members[dc.DecoyOf] = append(gi.members[dc.DecoyOf], dc.Name)
		}
	}
	return gi
}

// templateFiles is the bytes of the template's files by name.
func templateFiles(template []BundleFile) map[string][]byte {
	files := make(map[string][]byte, len(template))
	for _, f := range template {
		files[f.Name] = f.Data
	}
	return files
}

// blockLine is one line of a block: its number in the file and its tokens.
type blockLine struct {
	n    int
	toks []templateToken
}

// readBlock is the lines of a block, or the rule and the reason they cannot be read.
func readBlock(b *Block, files map[string][]byte) ([]blockLine, string, string) {
	if b.From == nil || b.To == nil || *b.From < 1 || *b.From > *b.To {
		return nil, RuleSpecShape, "the block has no lines 1 <= from <= to (the spec did not come from ParseSpec)"
	}
	data, ok := files[b.File]
	if !ok {
		return nil, RuleSpecQuestion, "the block names a file that the template does not have"
	}
	if _, err := ScanMarks(data); err != nil {
		return nil, RuleSpecQuestion, "the block's file has a " + MarkOpen + " that is not a mark, so its lines cannot be read"
	}
	lines := templateLines(data)
	if *b.To > len(lines) {
		return nil, RuleSpecQuestion, "the block ends after the last line of its file"
	}
	out := make([]blockLine, 0, *b.To-*b.From+1)
	for n := *b.From; n <= *b.To; n++ {
		toks, err := templateTokens(lines[n-1])
		if err != nil {
			// The file was read by the lexer, and a mark has no line feed in it.
			return nil, RuleSpecQuestion, "a line of the block cannot be read by the lexer of the marks"
		}
		out = append(out, blockLine{n: n, toks: toks})
	}
	return out, "", ""
}

// groupMark is the mark of a slot of a group in a line, and the word (token) it is in.
type groupMark struct {
	slot  string
	token int
}

func groupMarksOf(toks []templateToken, gi *groupIndex) []groupMark {
	var out []groupMark
	for ti, t := range toks {
		for _, sl := range t.slots {
			if _, ok := gi.groupOf[sl]; ok {
				out = append(out, groupMark{slot: sl, token: ti})
			}
		}
	}
	return out
}

// blockGroups is the answer slots whose group is in a block of the template (for B8 (a2),
// seatspace.go), and whether a block could not be read (then it is not known which group it
// holds; E2 refuses such a block). It reads the blocks as checkBlock does.
func (s *Spec) blockGroups(template []BundleFile) (map[string]bool, bool) {
	out := make(map[string]bool)
	if len(s.Blocks) == 0 {
		return out, false
	}
	gi := s.newGroupIndex()
	files := templateFiles(template)
	unread := false
	for i := range s.Blocks {
		lines, _, msg := readBlock(&s.Blocks[i], files)
		if msg != "" {
			unread = true
			continue
		}
		for _, ln := range lines {
			for _, m := range groupMarksOf(ln.toks, gi) {
				out[gi.groupOf[m.slot]] = true
			}
		}
	}
	return out, unread
}

// checkBlock holds one block to the rules of CheckBlocksAndClues. It returns the group the block
// holds ("" when it holds none or more than one) and the block's lines (none when they cannot be
// read). A line is reported once, for the first rule it breaks, in the order of the header.
func checkBlock(cid string, i int, b *Block, files map[string][]byte, gi *groupIndex, c *collector) (string, []blockLine) {
	bad := func(rule, msg, slot string, line int) {
		v := newSpecViolation(rule, msg, line, cid, "", slot, fmt.Sprintf("blocks[%d]", i), nil)
		v.File = shownName(b.File)
		c.add(v)
	}
	lines, rule, msg := readBlock(b, files)
	if msg != "" {
		bad(rule, msg, "", 0)
		return "", nil
	}
	var groups []string
	// seen is how many lines of the block hold each slot of a group, keys the line that has each
	// time slot, and ref the shape of the first line that has a group's mark and a time slot.
	seen := make(map[string]int)
	keys := make(map[string]int)
	var ref *lineShape
	for _, ln := range lines {
		marks := groupMarksOf(ln.toks, gi)
		switch {
		case len(marks) == 0:
			bad(RuleSpecQuestion, "a line of the block holds no mark of an answer or of a decoy (every line of a block is a line of its group)", "", ln.n)
			continue
		case len(marks) > 1:
			bad(RuleSpecQuestion, "a line of the block holds the marks of two slots of groups (a line is of one group)", "", ln.n)
			continue
		}
		m := marks[0]
		if g := gi.groupOf[m.slot]; !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
		seen[m.slot]++
		key, kmsg := blockLineKey(ln.toks, gi.windows)
		if kmsg != "" {
			bad(RuleSpecQuestion, kmsg, "", ln.n)
			continue
		}
		sh := shapeOf(ln.toks, m.token)
		if ref == nil {
			ref = &sh
		} else if d := ref.differs(sh, gi); d != "" {
			bad(RuleSpecQuestion, d, "", ln.n)
			continue
		}
		if at, dup := keys[key]; dup {
			bad(RuleSpecQuestion, fmt.Sprintf("the line has the time slot of line %d of the block (every line of a block has a time slot of its own)", at), key, ln.n)
			continue
		}
		keys[key] = ln.n
	}
	switch len(groups) {
	case 0:
		return "", lines
	case 1:
	default:
		bad(RuleSpecQuestion, "the block holds the lines of more than one answer's group (one group in a block)", "", 0)
		return "", lines
	}
	g := groups[0]
	for _, m := range gi.members[g] {
		switch seen[m] {
		case 1:
		case 0:
			bad(RuleSpecQuestion, "a slot of the block's group is in no line of the block (a block holds the answer and every decoy, once each)", m, 0)
		default:
			bad(RuleSpecQuestion, "a slot of the block's group is in more than one line of the block (a block holds the answer and every decoy, once each)", m, 0)
		}
	}
	return g, lines
}

// markColumn is a word of a line that holds a mark: its index, whether it is the mark alone,
// and the slots of the marks in it.
type markColumn struct {
	token int
	alone bool
	slots []string
}

// lineShape is the shape of a line of a block: its number of words, the word of the group's
// mark, and the words that hold marks.
type lineShape struct {
	tokens int
	group  int
	marks  []markColumn
}

func shapeOf(toks []templateToken, group int) lineShape {
	sh := lineShape{tokens: len(toks), group: group}
	for ti, t := range toks {
		if len(t.slots) > 0 {
			sh.marks = append(sh.marks, markColumn{token: ti, alone: t.alone, slots: t.slots})
		}
	}
	return sh
}

// differs is why the line of shape o has another shape than the block's first line (r), or "".
func (r *lineShape) differs(o lineShape, gi *groupIndex) string {
	switch {
	case r.tokens != o.tokens:
		return "the line has another number of words than the block's first line (the lines of a group have one shape)"
	case r.group != o.group:
		return "the mark of the group is at another word of the line than in the block's first line"
	case len(r.marks) != len(o.marks):
		return "the line has marks at other words than the block's first line"
	}
	for j, rc := range r.marks {
		oc := o.marks[j]
		if rc.token != oc.token || rc.alone != oc.alone || len(rc.slots) != len(oc.slots) {
			return "the line has marks at other words than the block's first line"
		}
		if rc.token == r.group {
			continue // the group's slots: a decoy is declared as its answer by construction
		}
		for k := range rc.slots {
			if !sameDeclaration(gi.decl[rc.slots[k]], gi.decl[oc.slots[k]], rc.slots[k] == oc.slots[k]) {
				return "a slot at a word of the line is declared otherwise than the slot at the same word of the block's first line (format, length, vocabulary and window are the same in a column)"
			}
		}
	}
	return ""
}

// sameDeclaration reports whether two slots are declared alike: role, format, length,
// vocabulary and window. The same slot is (same); an undeclared slot is like no other (E3
// refuses its mark).
func sameDeclaration(a, b *Slot, same bool) bool {
	switch {
	case same:
		return true
	case a == nil || b == nil:
		return false
	}
	intEq := func(x, y *int) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	i64Eq := func(x, y *int64) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	winEq := func(x, y *Window) bool {
		return (x == nil) == (y == nil) && (x == nil || (i64Eq(x.From, y.From) && i64Eq(x.To, y.To)))
	}
	return a.Role == b.Role && a.Format == b.Format && intEq(a.Length, b.Length) && winEq(a.Window, b.Window) &&
		slices.EqualFunc(a.Vocab, b.Vocab, func(x, y []string) bool { return slices.Equal(x, y) })
}

// checkMarksOutsideBlocks: a mark of a group that has a block is on no line outside the blocks.
// A line in a block of another group is that block's to refuse (one group in a block), so only
// the lines that are in no block are looked at, once each. A file the lexer refuses is E3's.
func checkMarksOutsideBlocks(cid string, template []BundleFile, gi *groupIndex, covered map[string]map[fileLine]bool, inBlock map[fileLine]bool, c *collector) {
	if len(covered) == 0 {
		return
	}
	for _, f := range template {
		if _, err := ScanMarks(f.Data); err != nil {
			continue
		}
		for li, line := range templateLines(f.Data) {
			at := fileLine{f.Name, li + 1}
			if inBlock[at] {
				continue
			}
			toks, err := templateTokens(line)
			if err != nil {
				continue
			}
			for _, m := range groupMarksOf(toks, gi) {
				if covered[gi.groupOf[m.slot]] != nil {
					v := newSpecViolation(RuleSpecQuestion, "a mark of a group that has a block is on a line outside its blocks (every line of the group is in a block of the group)", at.line, cid, "", m.slot, "", nil)
					v.File = shownName(f.Name)
					c.add(v)
					break
				}
			}
		}
	}
}

// templateLines is the lines of a file: the text between line feeds, without them. A line feed
// at the end does not start another line; a last line without one is a line.
func templateLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// templateToken is one TOKEN of a template text (B7's, tokenSpans) in which each mark counts
// as one token byte, as LayoutOf counts it: the bytes of a token that holds no mark, or the
// slots of the marks it holds.
type templateToken struct {
	// lit is the token's bytes when it holds no mark (it refers to a copy: do not write
	// through it).
	lit []byte
	// slots are the slots of the marks the token holds, in order; alone says the token is one
	// mark and nothing else (no token byte next to it).
	slots []string
	alone bool
}

// templateTokens is the tokens of a template text, in order (ScanMarks, so a `{{ctf:` that is
// not a mark is a *MarkError). The token of each mark is readMarkedText's, the one mapping that
// LayoutOf reads too (slotmark.go), so the two never place a mark differently.
func templateTokens(data []byte) ([]templateToken, error) {
	mt, err := readMarkedText(data)
	if err != nil {
		return nil, err
	}
	out := make([]templateToken, len(mt.spans))
	for _, m := range mt.marks {
		out[m.token].slots = append(out[m.token].slots, m.slot)
	}
	for ti, sp := range mt.spans {
		if len(out[ti].slots) == 0 {
			out[ti].lit = mt.pseudo[sp[0]:sp[1]]
		}
		out[ti].alone = len(out[ti].slots) == 1 && mt.alone(ti)
	}
	return out, nil
}

// isTimestampWord reports whether a token is a value of the timestamp format (answerformat's
// normalised form, as B7 judges a token by Canonical).
func isTimestampWord(tok []byte) bool {
	one := int64(1)
	return answerformat.Canonical(answerformat.Timestamp, answerformat.Params{WindowSeconds: &one}, string(tok)) == nil
}

// blockLineKey is the time slot of one line of a block: the slot whose value will be the first
// timestamp word of the line once the marks are filled. It returns the slot, or the reason the
// line has none, which is one of: a literal timestamp word comes first (the line would be
// ordered by a time that is the same for every seat); a mark with a token byte next to it comes
// first (its value and those bytes make one word, which could read as a time); there is no mark
// of a time slot. The mark of a slot of another format may come first: a name has no `:`, a
// path starts with `/` and a hexid is hex digits, so no value of theirs is a timestamp word.
func blockLineKey(toks []templateToken, windows map[string][2]int64) (string, string) {
	for _, t := range toks {
		switch {
		case len(t.slots) == 0:
			if isTimestampWord(t.lit) {
				return "", "the first time of a line of the block is literal text, not a time slot"
			}
		case !t.alone:
			return "", "a mark with a token byte next to it comes before the time slot of a line of the block"
		default:
			if _, ok := windows[t.slots[0]]; ok {
				return t.slots[0], ""
			}
		}
	}
	return "", "a line of the block has no time slot"
}

// checkClues: every clue of an answer slot is a literal word of the template.
func (s *Spec) checkClues(cid string, template []BundleFile, c *collector) {
	var words map[string]struct{}
	for i := range s.Slots {
		sl := &s.Slots[i]
		for j, w := range sl.Clues {
			if words == nil {
				words = literalWords(template)
			}
			if _, ok := words[w]; !ok {
				c.add(newSpecViolation(RuleSpecQuestion, "a clue is not a literal word of the template (a token outside every mark)", 0, cid, sl.Question, sl.Name, fmt.Sprintf("slots[%d].clues[%d]", i, j), nil))
			}
		}
	}
}

// literalWords is the set of the tokens of the template that hold no mark. A file the lexer of
// the marks refuses gives none (it is refused as E3 by the renderer and by `edition check`).
func literalWords(template []BundleFile) map[string]struct{} {
	out := make(map[string]struct{})
	for _, f := range template {
		toks, err := templateTokens(f.Data)
		if err != nil {
			continue
		}
		for _, t := range toks {
			if len(t.slots) == 0 {
				out[string(t.lit)] = struct{}{}
			}
		}
	}
	return out
}
