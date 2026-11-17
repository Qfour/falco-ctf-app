package edition

// slotmark.go is the lexer of the marks of a template (ADR-0056 D12, amendment 10): the ONE
// definition of what `{{ctf:<slot>}}` is. The renderer (rendertemplate.go) fills the marks
// with it, and B4 (the comparison of the templates with the practice editions', which takes
// the marks out first) reads a template with it too: nobody keeps a second regular
// expression of the mark. It is not a renderer file: it holds no answer and no key, reads
// no file, and names nothing of the renderer, so the validator may call it.
//
// A mark is  {{ctf:  a slot name (answerformat.IDPattern)  }}  and nothing else: a `{{ctf:`
// that is not followed by a slot name and `}}` is a mark outside the grammar, and the
// scan refuses it (it is never left as text). The text is read once, from left to right:
// a mark does not start inside another and a value put in is never read again.

import (
	"bytes"
	"fmt"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

const (
	// MarkOpen and MarkClose are the two ends of a mark.
	MarkOpen  = "{{ctf:"
	MarkClose = "}}"
)

// TemplatePart is a stretch of literal text and the mark after it; the last part of a text
// has no mark (Slot is empty). Lit refers to the text scanned: do not write through it.
type TemplatePart struct {
	Lit  []byte
	Slot string
}

// MarkError is a `{{ctf:` that is not a mark, at a line (1-based). It holds no text of the
// template.
type MarkError struct{ Line int }

func (e *MarkError) Error() string {
	return fmt.Sprintf("a %s is not a mark %s<slot>%s with a slot name (line %d)", MarkOpen, MarkOpen, MarkClose, e.Line)
}

// isTokenByte is a byte of a TOKEN (ADR-0056 D10 B7, amendment 10): a maximal run of
// [A-Za-z0-9._:/-], which is every byte a value of the per-seat formats (a name, a path, a
// hexid, a timestamp) is made of. Everything else separates two tokens. This is the one
// place that spells it; B7 and B8 (b) (renderspread.go) count tokens, and the renderer
// (E3) needs a mark of an answer or a decoy to be a token of its own.
func isTokenByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
}

// tokenSpans is the [start, end) of the tokens of data, in order.
func tokenSpans(data []byte) [][2]int {
	var out [][2]int
	start := -1
	for i, c := range data {
		if isTokenByte(c) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out = append(out, [2]int{start, i})
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, [2]int{start, len(data)})
	}
	return out
}

// MarkPosition is where one mark is in the tokens of a text: Token is the index of the token
// that holds it, and Alone says whether the token is the mark and nothing else (no token
// byte before or after it).
type MarkPosition struct {
	Slot  string
	Token int
	Alone bool
}

// Layout is the marks of a text and how many tokens it has once each mark is one token byte
// (a value is a run of token bytes, so every text rendered from the template has exactly
// this many tokens, and the token of a mark is at the same index in it).
type Layout struct {
	Marks  []MarkPosition
	Tokens int
}

// LayoutOf is the Layout of a template text: the marks in order (ScanMarks, so a `{{ctf:`
// that is not a mark is a *MarkError), each with the index of its token. The renderer (E3:
// the mark of an answer or a decoy is Alone) and the validator (B7: the token at that
// index of a bundle is the value) read the same positions from this one function.
func LayoutOf(data []byte) (Layout, error) {
	parts, err := ScanMarks(data)
	if err != nil {
		return Layout{}, err
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
	out := Layout{Tokens: len(spans)}
	ti := 0
	for i, off := range offs {
		for ti < len(spans) && spans[ti][1] <= off {
			ti++
		}
		// The mark's byte is a token byte, so a span holds it.
		out.Marks = append(out.Marks, MarkPosition{Slot: slots[i], Token: ti, Alone: spans[ti][1]-spans[ti][0] == 1})
	}
	return out, nil
}

// isMarkIDByte is a byte a slot name is made of (answerformat.IDPattern's alphabet; the
// first-byte rule and the length are answerformat.ValidID's).
func isMarkIDByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
}

// ScanMarks reads data into parts, from left to right, once: the literal text and the marks,
// in order, ending with a part that has no mark (so a text with no mark is one part). A
// `{{ctf:` that is not a mark is a *MarkError and no parts.
func ScanMarks(data []byte) ([]TemplatePart, error) {
	var parts []TemplatePart
	off := 0
	for {
		i := bytes.Index(data[off:], []byte(MarkOpen))
		if i < 0 {
			return append(parts, TemplatePart{Lit: data[off:]}), nil
		}
		at := off + i
		rest := data[at+len(MarkOpen):]
		n := 0
		for n < len(rest) && isMarkIDByte(rest[n]) {
			n++
		}
		id := string(rest[:n])
		if !answerformat.ValidID(id) || !bytes.HasPrefix(rest[n:], []byte(MarkClose)) {
			return nil, &MarkError{Line: lineAt(data, at)}
		}
		parts = append(parts, TemplatePart{Lit: data[off:at], Slot: id})
		off = at + len(MarkOpen) + n + len(MarkClose)
	}
}
