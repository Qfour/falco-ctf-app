// Package sourcehygiene holds the rules for what a tracked source file may contain
// that a reviewer cannot see (app#511, after the bidi rule of app#501).
//
// The rule is one table (invisibleRanges) and one scanner (Invisible), so a consumer
// outside this package imports the same table and the same context rules instead of
// keeping a copy. Hidden is the one entry point that covers both sets (these rows and
// the nine bidi controls of chars.go). Today the only candidate consumer, hintleak,
// decides with unicode.Cf alone (ADR-0026 D5); moving it onto this table needs the
// ADR-0026 D5 wording and the ADR-0029 D1 import closure revised first (issue #526).
//
// What is forbidden raw: the union of Unicode's Default_Ignorable_Code_Point and
// General_Category Cf (what a renderer is told to draw as nothing), plus the C0 / C1
// control characters, U+2028 / U+2029 and a lone CR (Tier B: they change what a reader
// sees in a terminal or what a parser takes for a line). The nine bidi controls
// (U+202A-202E, U+2066-2069) are NOT in this table: bidiControls (bidi_test.go) owns
// them, so one character is never reported twice. TestInvisibleTable_CoversCfAndDICP
// proves the two tables together cover every Cf, Variation_Selector and
// Other_Default_Ignorable_Code_Point rune of the Unicode version Go ships.
//
// An escape is ASCII and is never flagged: write the character as an escape (in Go a
// backslash, u and four hex digits; in a case table {U+200B}; in prose U+200B).
//
// Context rules (a rune that is legitimate in exactly one place):
//   - U+FE0E / U+FE0F: only directly after a non-ASCII unicode.So rune, one per base;
//   - U+200D: only after a non-ASCII So, a skin-tone modifier (U+1F3FB-1F3FF) or an
//     allowed U+FE0F, and directly before a non-ASCII So (an emoji ZWJ sequence);
//   - U+FEFF: only as the first rune of the file (a byte order mark);
//   - U+000D: only directly before LF (CRLF).
//
// A hidden payload can then ride only on one visible symbol per invisible rune: the
// capacity is bounded by the number of visible symbols. The diff does NOT show whether
// a symbol carries a variation selector or a ZWJ, so that residue is accepted, not
// prevented. "Allowed in this file" by path is not used: it would let that file carry
// anything.
package sourcehygiene

import (
	"fmt"
	"sort"
	"unicode"
	"unicode/utf8"
)

// ruleKind says when a rune of a range is forbidden.
type ruleKind int

const (
	always        ruleKind = iota // forbidden wherever it appears
	vsAfterSymbol                 // U+FE0E / U+FE0F: allowed once, right after a non-ASCII So
	zwjInEmoji                    // U+200D: allowed between an emoji base and a non-ASCII So
	bomAtStart                    // U+FEFF: allowed as the first rune of the file
	loneCR                        // U+000D: allowed right before LF
)

// invisibleRanges is the one table: ascending, no overlap (TestInvisibleTable_Shape).
var invisibleRanges = []struct {
	lo, hi rune
	name   string
	rule   ruleKind
}{
	{0x0000, 0x0008, "C0 CONTROL", always},
	{0x000B, 0x000C, "C0 CONTROL (VT, FF)", always},
	{0x000D, 0x000D, "CARRIAGE RETURN", loneCR},
	{0x000E, 0x001F, "C0 CONTROL (includes ESC)", always},
	{0x007F, 0x007F, "DELETE", always},
	{0x0080, 0x009F, "C1 CONTROL (includes NEL)", always},
	{0x00AD, 0x00AD, "SOFT HYPHEN", always},
	{0x034F, 0x034F, "COMBINING GRAPHEME JOINER", always},
	{0x0600, 0x0605, "ARABIC NUMBER SIGN (Cf)", always},
	{0x061C, 0x061C, "ARABIC LETTER MARK", always},
	{0x06DD, 0x06DD, "ARABIC END OF AYAH", always},
	{0x070F, 0x070F, "SYRIAC ABBREVIATION MARK", always},
	{0x0890, 0x0891, "ARABIC POUND MARK ABOVE (Cf)", always},
	{0x08E2, 0x08E2, "ARABIC DISPUTED END OF AYAH", always},
	{0x115F, 0x1160, "HANGUL CHOSEONG / JUNGSEONG FILLER", always},
	{0x17B4, 0x17B5, "KHMER INHERENT VOWEL", always},
	{0x180B, 0x180F, "MONGOLIAN FREE VARIATION SELECTOR / VOWEL SEPARATOR", always},
	{0x200B, 0x200B, "ZERO WIDTH SPACE", always},
	{0x200C, 0x200C, "ZERO WIDTH NON-JOINER", always},
	{0x200D, 0x200D, "ZERO WIDTH JOINER", zwjInEmoji},
	{0x200E, 0x200F, "LEFT-TO-RIGHT / RIGHT-TO-LEFT MARK", always},
	{0x2028, 0x2029, "LINE / PARAGRAPH SEPARATOR", always},
	{0x2060, 0x2065, "WORD JOINER / INVISIBLE OPERATOR", always},
	{0x206A, 0x206F, "DEPRECATED FORMAT CHARACTER", always},
	{0x3164, 0x3164, "HANGUL FILLER", always},
	{0xFE00, 0xFE0D, "VARIATION SELECTOR-1..14", always},
	{0xFE0E, 0xFE0F, "VARIATION SELECTOR-15 / 16", vsAfterSymbol},
	{0xFEFF, 0xFEFF, "ZERO WIDTH NO-BREAK SPACE (BOM)", bomAtStart},
	{0xFFA0, 0xFFA0, "HALFWIDTH HANGUL FILLER", always},
	{0xFFF0, 0xFFF8, "UNASSIGNED (Default_Ignorable)", always},
	{0xFFF9, 0xFFFB, "INTERLINEAR ANNOTATION", always},
	{0x110BD, 0x110BD, "KAITHI NUMBER SIGN", always},
	{0x110CD, 0x110CD, "KAITHI NUMBER SIGN ABOVE", always},
	{0x13430, 0x1343F, "EGYPTIAN HIEROGLYPH FORMAT CONTROL", always},
	{0x1BCA0, 0x1BCA3, "SHORTHAND FORMAT CONTROL", always},
	{0x1D173, 0x1D17A, "MUSICAL SYMBOL FORMAT CONTROL", always},
	{0xE0000, 0xE0FFF, "TAG CHARACTER / VARIATION SELECTOR SUPPLEMENT (plane 14)", always},
}

// lookup returns the table row of cp, if cp is in the table.
func lookup(cp rune) (name string, rule ruleKind, ok bool) {
	i := sort.Search(len(invisibleRanges), func(i int) bool { return invisibleRanges[i].hi >= cp })
	if i < len(invisibleRanges) && invisibleRanges[i].lo <= cp {
		return invisibleRanges[i].name, invisibleRanges[i].rule, true
	}
	return "", 0, false
}

// Finding is one forbidden raw rune. Line and Col are 1-based; Col counts runes (an
// invalid byte counts as one). Why is empty for an always-forbidden rune and names the
// broken context rule otherwise.
type Finding struct {
	Line, Col int
	CP        rune
	Name      string
	Why       string
}

func (f Finding) String() string {
	s := fmt.Sprintf("%d:%d U+%04X %s", f.Line, f.Col, f.CP, f.Name)
	if f.Why != "" {
		s += ": " + f.Why
	}
	return s
}

func isNonASCIISymbol(r rune) bool { return r >= 0x80 && unicode.Is(unicode.So, r) }
func isSkinTone(r rune) bool       { return r >= 0x1F3FB && r <= 0x1F3FF }
func isVS(r rune) bool             { return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) }

// Invisible returns every forbidden raw rune of text that invisibleRanges holds, in
// order. text is decoded rune by rune: an invalid UTF-8 byte is one rune outside the
// table and the scan goes on. It reports U+0000 like any other C0 control; a caller
// that already reports NUL bytes (checkTree does) drops it. The bidi controls are not
// reported here (the gate has a rule of its own for them): see Hidden.
func Invisible(text []byte) []Finding { return scan(text, false) }

// Hidden is Invisible plus the nine bidi controls (bidiControls), in one pass and one
// order: every rune that must not appear raw in a file a reader trusts. Context rules
// apply as in Invisible.
func Hidden(text []byte) []Finding { return scan(text, true) }

func scan(text []byte, withBidi bool) []Finding {
	var out []Finding
	line, col := 1, 1
	var prev rune = -1     // the previous rune, -1 at the start of the file
	prevAllowedVS := false // the previous rune is a U+FE0F that is allowed (so ZWJ may follow it)
	for i := 0; i < len(text); {
		r, w := utf8.DecodeRune(text[i:])
		if r == utf8.RuneError && w == 1 {
			r = -2 // an invalid byte: no table row, no symbol
		}
		allowedVS := false
		if bname, isBidi := bidiControls[r]; withBidi && isBidi {
			out = append(out, Finding{line, col, r, bname, ""})
		} else if name, rule, ok := lookup(r); ok {
			why, bad := "", false
			switch rule {
			case always:
				bad = true
			case vsAfterSymbol:
				switch {
				case isNonASCIISymbol(prev):
					allowedVS = r == 0xFE0F
				case isVS(prev):
					bad, why = true, "second variation selector on one base"
				default:
					bad, why = true, fmt.Sprintf("U+%04X not directly after a non-ASCII symbol (So)", r)
				}
			case zwjInEmoji:
				// The next rune must be a real non-ASCII symbol: the end of the file (width 0)
				// and an invalid byte (RuneError, width 1) are not one.
				next, nw := utf8.DecodeRune(text[i+w:])
				nextIsSymbol := nw > 0 && !(next == utf8.RuneError && nw == 1) && isNonASCIISymbol(next)
				before := isNonASCIISymbol(prev) || isSkinTone(prev) || (prev == 0xFE0F && prevAllowedVS)
				if !before || !nextIsSymbol {
					bad, why = true, "U+200D not between two pictographic symbols"
				}
			case bomAtStart:
				if i != 0 {
					bad, why = true, "U+FEFF not at the start of the file"
				}
			case loneCR:
				if i+w >= len(text) || text[i+w] != '\n' {
					bad, why = true, "CR not followed by LF"
				}
			}
			if bad {
				out = append(out, Finding{line, col, r, name, why})
			}
		}
		prev, prevAllowedVS = r, allowedVS
		i += w
		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return out
}
