// Package avatar is the single table of prepared avatar ids (ADR-0034 D9).
//
// A participant never uploads an image: the profile stores only an id from
// this table, and the portal draws it from a static SVG asset. The table is
// the one source of truth for validation (the profile API), the default
// derivation (a seat that never chose), and the asset/colour names the static
// files and tokens.css must provide (File, ColorToken).
//
// An id is "<glyph>-<color>". Glyphs (8) are the outer axis and colours (6)
// the inner one, so the 48 ids run falcon-cyan (1st) ... flame-slate (48th).
package avatar

import (
	"hash/fnv"
	"regexp"
	"strconv"
)

// Glyphs and Colors are ordered: the order defines every id's 1-based number,
// and therefore which seat gets which default. Appending is safe; reordering
// or inserting changes existing seats' defaults.
var (
	Glyphs = [...]string{"falcon", "shield", "key", "terminal", "radar", "lock", "bug", "flame"}
	Colors = [...]string{"cyan", "magenta", "amber", "lime", "violet", "slate"}
)

const (
	// Count is len(Glyphs) * len(Colors).
	Count = 48
	// ReservedCount is the tail of the table kept for seats that are not
	// "user<N>" with N in 1..SeatCapacity (test1, user01, an out-of-range N).
	ReservedCount = 8
	// SeatCapacity is how many "user<N>" seats own a distinct default.
	SeatCapacity = Count - ReservedCount

	// StaffID is the fixed id carried by an operator-authored board message.
	// It is not derived from any seat. It is also an ordinary table entry
	// (user12's default), so it is NOT a proof of staff by itself: the board
	// message's authorRole is.
	StaffID = "shield-slate"

	// ColorTokenPrefix + colour is the CSS custom property tokens.css must
	// define for each colour; FileSuffix follows the glyph for the asset name.
	ColorTokenPrefix = "--avatar-"
	FileSuffix       = ".svg"
)

// ids is the full ordered table, built once from the two axes.
var ids = func() [Count]string {
	var out [Count]string
	for gi, g := range Glyphs {
		for ci, c := range Colors {
			out[gi*len(Colors)+ci] = g + "-" + c
		}
	}
	return out
}()

// index maps an id to its 0-based position.
var index = func() map[string]int {
	m := make(map[string]int, Count)
	for i, id := range ids {
		m[id] = i
	}
	return m
}()

func init() {
	// A compile-time-shaped guard: the constant and the axes must agree, or the
	// reserved-tail arithmetic below silently points at the wrong entries.
	if len(Glyphs)*len(Colors) != Count || len(index) != Count {
		panic("avatar: table size drifted from Count (duplicate glyph/colour?)")
	}
}

// IDs returns the full ordered table (a copy).
func IDs() []string {
	out := make([]string, Count)
	copy(out, ids[:])
	return out
}

// Valid reports whether id is in the table.
func Valid(id string) bool {
	_, ok := index[id]
	return ok
}

// Number returns the 1-based position of id, or 0 when id is not in the table.
func Number(id string) int {
	if i, ok := index[id]; ok {
		return i + 1
	}
	return 0
}

// Parse splits a valid id into its glyph and colour.
func Parse(id string) (glyph, color string, ok bool) {
	i, found := index[id]
	if !found {
		return "", "", false
	}
	return Glyphs[i/len(Colors)], Colors[i%len(Colors)], true
}

// File returns the asset file name for id's glyph ("falcon.svg"), served from
// view/static/avatars/. The colour is NOT in the file: it is applied from
// ColorToken on the <img> background, so 8 files cover 48 ids.
func File(id string) (string, bool) {
	g, _, ok := Parse(id)
	if !ok {
		return "", false
	}
	return g + FileSuffix, true
}

// ColorToken returns the CSS custom property name for id's colour
// ("--avatar-cyan").
func ColorToken(id string) (string, bool) {
	_, c, ok := Parse(id)
	if !ok {
		return "", false
	}
	return ColorTokenPrefix + c, true
}

// seatN matches "user<N>" with N a decimal number with no leading zero.
var seatN = regexp.MustCompile(`^user([1-9][0-9]*)$`)

// Default derives a seat's avatar when it never chose one (ADR-0034 D9).
// "user<N>" with N in 1..SeatCapacity gets the N-th id, so those seats are
// pairwise distinct. Every other seat (test1, user01, user0, N > SeatCapacity)
// gets one of the last ReservedCount ids by a stable hash, so it can never
// collide with a numbered seat.
func Default(seat string) string {
	if m := seatN.FindStringSubmatch(seat); m != nil {
		// A very long digit string overflows ParseUint; that is "out of range",
		// and falls through to the reserved tail like any other N.
		if n, err := strconv.ParseUint(m[1], 10, 32); err == nil && n <= SeatCapacity {
			return ids[n-1]
		}
	}
	h := fnv.New32a()
	h.Write([]byte(seat)) //nolint:errcheck // hash.Hash.Write never returns an error
	return ids[SeatCapacity+int(h.Sum32()%ReservedCount)]
}

// Resolve is the value every response carries: the stored id when it is still
// in the table, otherwise the seat's default. A row naming an id that a later
// build removed (or a hand-edited DB) therefore degrades to the default rather
// than to a broken image.
func Resolve(stored, seat string) string {
	if Valid(stored) {
		return stored
	}
	return Default(seat)
}
