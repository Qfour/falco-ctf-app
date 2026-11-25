package edition

// blockorder.go is how the lines of a block are read (ADR-0056 D10, "the order of the lines",
// amendment 28 as revised, the second PR of A7-x): by the renderer, which puts them in the order of
// their times, and by B7 (spreadblock.go), which reads the bundle that came out of it. Both read
// the same three things from this one file, so the two never read a block differently:
//
//   - the TIME of a line, lineTime: its first TOKEN that is a timestamp word (isTimestampWord, the
//     predicate E2's blockLineKey holds the time slot of every line of a block to). E2 makes that
//     token the value of the line's time slot once the marks are filled: no literal time and no
//     mark glued to a token byte comes before it, and a value of a name, a path or a hexid is not a
//     timestamp word;
//   - the SIGNATURE of a line, lineSignature: the line with the words that hold a mark put out of
//     sight and the literal words and the bytes between the words kept (the form B17 compares the
//     lines of a group in). E2 gives every line of a block one shape, so the words that hold a
//     mark are the same words in every line, and a bundle's line is masked at the template's
//     words;
//   - the COLUMN of a block: the word of its group's marks (the answer's and each decoy's), the
//     same word in every line.
//
// A value of a per-seat format is one TOKEN (a name, a path, a hexid and a timestamp are runs of
// [A-Za-z0-9._:/-], and none is empty), so a line of a bundle has the template line's words at the
// template line's indices, and the word of the column is the value of the mark (LayoutOf's
// argument, line by line). No value holds a line feed, so the lines of a bundle are the lines of
// the template it was rendered from.
//
// It is not a render file: it holds no answer and no key, and it names nothing of the renderer.

import (
	"errors"
	"slices"
	"strconv"
	"strings"
)

// lineTime is the time of a line: its first token that is a timestamp word, and whether it has
// one. The timestamp words are answerformat's normalised form (RFC 3339, UTC, `Z`, whole seconds):
// they are all of one width, so their byte order is their order in time.
func lineTime(line []byte) (string, bool) {
	for _, sp := range tokenSpans(line) {
		if tok := line[sp[0]:sp[1]]; isTimestampWord(tok) {
			return string(tok), true
		}
	}
	return "", false
}

// lineSignature is the signature of a line of a block: its tokens and the bytes between them, in
// order, with the token at each word of masked (in ascending order) put out of sight. text is a
// line of a bundle, or a line of the template with each mark one token byte (readMarkedText's
// pseudo text): their tokens are at the same words, so the line of a bundle and the line of the
// template it was rendered from have one signature. Every part is written with its length, so two
// lines have one signature only when they are the same outside those words.
func lineSignature(text []byte, masked []int) string {
	var b strings.Builder
	writePart := func(kind byte, p []byte) {
		b.WriteByte(kind)
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.Write(p)
	}
	prev, mi := 0, 0
	for ti, sp := range tokenSpans(text) {
		writePart('s', text[prev:sp[0]])
		if mi < len(masked) && masked[mi] == ti {
			b.WriteByte('m')
			mi++
		} else {
			writePart('t', text[sp[0]:sp[1]])
		}
		prev = sp[1]
	}
	writePart('s', text[prev:])
	return b.String()
}

// blockForm is a block of edition.yaml read from the template for the renderer and for B7: the
// file and the place of its lines, its group, the shape its lines share and, for each line in
// the template's order, the slot of the group, the time slot and the signature.
type blockForm struct {
	// file is the block's file; from the index (0-based) of its first line in the file.
	file string
	from int
	// group is the answer slot of the block's group, qid its question.
	group string
	qid   string
	// tokens is the number of words of every line, column the word of the group's marks, and
	// masked the words that hold a mark (ascending; the column is one of them).
	tokens int
	column int
	masked []int
	// slots, keys and sigs are, for each line in the template's order, the slot of the group,
	// the time slot (blockLineKey) and the signature.
	slots []string
	keys  []string
	sigs  []string
	// answer is the index (in the block) of the line of the answer slot.
	answer int
}

// lines is the number of lines of the block.
func (f *blockForm) lines() int { return len(f.sigs) }

// blockForms is every block of s, in the order of s.Blocks, read from template. It assumes that
// the blocks hold to E2 (CheckBlocksAndClues), and refuses what it needs and does not find (fail-
// closed): a block it cannot read, a line that is not of the block's one group, a line of another
// shape than the first, a line with no time slot, and a group whose answer is not in the block
// once. Its errors name no word of the template.
func (s *Spec) blockForms(template []BundleFile) ([]blockForm, error) {
	if len(s.Blocks) == 0 {
		return nil, nil
	}
	gi := s.newGroupIndex()
	files := templateFiles(template)
	out := make([]blockForm, 0, len(s.Blocks))
	for i := range s.Blocks {
		b := &s.Blocks[i]
		lines, _, msg := readBlock(b, files)
		if msg != "" {
			return nil, errors.New(msg)
		}
		raw := templateLines(files[b.File])
		f := blockForm{file: b.File, from: *b.From - 1, answer: -1}
		for j, ln := range lines {
			marks := groupMarksOf(ln.toks, gi)
			if len(marks) != 1 {
				return nil, errors.New("a line of a block does not hold the mark of exactly one slot of a group")
			}
			key, kmsg := blockLineKey(ln.toks, gi.windows)
			if kmsg != "" {
				return nil, errors.New(kmsg)
			}
			sh := shapeOf(ln.toks, marks[0].token)
			var masked []int
			for _, m := range sh.marks {
				masked = append(masked, m.token)
			}
			g := gi.groupOf[marks[0].slot]
			if j == 0 {
				f.group, f.tokens, f.column, f.masked = g, sh.tokens, sh.group, masked
				if decl := gi.decl[g]; decl != nil {
					f.qid = decl.Question
				}
			} else if g != f.group || sh.tokens != f.tokens || sh.group != f.column || !slices.Equal(masked, f.masked) {
				return nil, errors.New("the lines of a block are not of one group and one shape")
			}
			mt, err := readMarkedText(raw[ln.n-1])
			if err != nil {
				return nil, errors.New("a line of a block cannot be read by the lexer of the marks")
			}
			if marks[0].slot == g {
				if f.answer >= 0 {
					return nil, errors.New("a block holds its answer slot more than once")
				}
				f.answer = j
			}
			f.slots = append(f.slots, marks[0].slot)
			f.keys = append(f.keys, key)
			f.sigs = append(f.sigs, lineSignature(mt.pseudo, f.masked))
		}
		if f.answer < 0 || f.qid == "" {
			return nil, errors.New("a block does not hold its group's answer slot")
		}
		out = append(out, f)
	}
	return out, nil
}
