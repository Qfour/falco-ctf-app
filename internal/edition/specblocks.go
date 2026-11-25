package edition

// specblocks.go is the part of edition.yaml that needs the template (ADR-0056 D10 E2 as
// amendment 28 extends it, the first PR of A7-x): `blocks` and `clues` held to the files of
// template/. Their schema and their shape (E1) are spec.go.
//
// This stage declares and checks only. The renderer does not read `blocks` (it does not put
// the lines of a block in the order of their times: that is the next PR of A7-x), and nothing
// reads `clues` but this check (B17 and B19 are a later PR). So a template with blocks and
// clues renders to the same bytes as without them, and the practice golden (V67) does not move.
//
// It is not a render file: it holds no answer and no key, and it reads the template with the
// lexer of the marks (slotmark.go, ScanMarks and tokenSpans), so `edition check` calls it as the
// renderer does. A message names a block, a slot, a file and a line, never a word of the
// template or a clue.

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

// CheckBlocksAndClues holds the `blocks` and the `clues` of the edition of challenge cid to its
// template (the files of template/). It returns nil, or an errors.Join of *Violation (at most
// maxViolations listed: the blocks in file order, then the clues in the order of the slots).
// The rule is E2 (RuleSpecQuestion); a block that is not of E1's shape (a Spec not made by
// ParseSpec) is E1.
//
//   - a block names a file of the template, its lines from..to are in the file (a line ends at
//     a line feed; a last line without one counts), and the file is read by the lexer of the
//     marks;
//   - every line of a block has a time slot (blockLineKey): the slot whose value will be the
//     first timestamp word of the line, which is what the lines of a block are to be ordered
//     by. A slot with a window is a time slot (E1 lets only a timestamp filler have one, E2 only
//     a timestamp answer, and a decoy takes its answer's);
//   - the time slots of the lines of one block have the same window (from and to), so that the
//     order of the lines is drawn for every seat from one range and is fixed by no window;
//   - a clue is a literal word of the template: a TOKEN (B7's, tokenSpans) of some file that
//     holds no mark. A slot name inside a mark, or a word glued to a mark, is not one.
//
// It reads no file: the caller gives the template's bytes.
func (s *Spec) CheckBlocksAndClues(cid string, template []BundleFile) error {
	if s == nil {
		return errors.New("edition: the spec is missing")
	}
	var c collector
	files := make(map[string][]byte, len(template))
	for _, f := range template {
		files[f.Name] = f.Data
	}
	windows := s.timeSlotWindows()
	for i := range s.Blocks {
		checkBlock(cid, i, &s.Blocks[i], files, windows, &c)
	}
	s.checkClues(cid, template, &c)
	return c.err()
}

// timeSlotWindows is the window of every slot that has one, the implied decoys included, by
// slot name.
func (s *Spec) timeSlotWindows() map[string][2]int64 {
	out := make(map[string][2]int64)
	add := func(sl *Slot) {
		if w := sl.Window; w != nil && w.From != nil && w.To != nil {
			out[sl.Name] = [2]int64{*w.From, *w.To}
		}
	}
	for i := range s.Slots {
		add(&s.Slots[i])
	}
	for i := range s.ImpliedDecoys {
		add(&s.ImpliedDecoys[i])
	}
	return out
}

func checkBlock(cid string, i int, b *Block, files map[string][]byte, windows map[string][2]int64, c *collector) {
	bad := func(rule, msg string, line int) {
		v := newSpecViolation(rule, msg, line, cid, "", "", fmt.Sprintf("blocks[%d]", i), nil)
		v.File = shownName(b.File)
		c.add(v)
	}
	if b.From == nil || b.To == nil || *b.From < 1 || *b.From > *b.To {
		bad(RuleSpecShape, "the block has no lines 1 <= from <= to (the spec did not come from ParseSpec)", 0)
		return
	}
	data, ok := files[b.File]
	if !ok {
		bad(RuleSpecQuestion, "the block names a file that the template does not have", 0)
		return
	}
	if _, err := ScanMarks(data); err != nil {
		bad(RuleSpecQuestion, "the block's file has a "+MarkOpen+" that is not a mark, so its lines cannot be read", 0)
		return
	}
	lines := templateLines(data)
	if *b.To > len(lines) {
		bad(RuleSpecQuestion, "the block ends after the last line of its file", 0)
		return
	}
	var first [2]int64
	have := false
	for n := *b.From; n <= *b.To; n++ {
		toks, err := templateTokens(lines[n-1])
		if err != nil {
			bad(RuleSpecQuestion, "a line of the block cannot be read by the lexer of the marks", n)
			continue
		}
		slot, msg := blockLineKey(toks, windows)
		if msg != "" {
			bad(RuleSpecQuestion, msg, n)
			continue
		}
		switch w := windows[slot]; {
		case !have:
			first, have = w, true
		case w != first:
			bad(RuleSpecQuestion, "the time slot of a line of the block has another window than the block's first time slot (the lines of a block share one window)", n)
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
// not a mark is a *MarkError).
func templateTokens(data []byte) ([]templateToken, error) {
	parts, err := ScanMarks(data)
	if err != nil {
		return nil, err
	}
	// pseudo is the text with each mark one token byte, and offs where each mark is in it.
	var pseudo []byte
	var offs []int
	var slots []string
	for _, p := range parts {
		pseudo = append(pseudo, p.Lit...)
		if p.Slot == "" {
			continue
		}
		offs = append(offs, len(pseudo))
		slots = append(slots, p.Slot)
		pseudo = append(pseudo, 'M')
	}
	spans := tokenSpans(pseudo)
	out := make([]templateToken, len(spans))
	mi := 0
	for ti, sp := range spans {
		// The byte of a mark is a token byte, so it is inside a span, and the spans are in order.
		for mi < len(offs) && offs[mi] < sp[1] {
			out[ti].slots = append(out[ti].slots, slots[mi])
			mi++
		}
		if len(out[ti].slots) == 0 {
			out[ti].lit = pseudo[sp[0]:sp[1]]
		}
		out[ti].alone = len(out[ti].slots) == 1 && sp[1]-sp[0] == 1
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
