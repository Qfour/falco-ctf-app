package answerformat

// fold.go is the other half of Normalize (ADR-0056 D10 B9, addendum 7 M4, V55):
// Normalize maps a raw answer to the one value grading compares; Fold maps a TEXT
// (a corpus file, a bundle file) the other way, so that a search of the folded text for
// a normalised value finds the value in every spelling that Normalize would accept.
// Normalize is idempotent and many-to-one; Fold is the cheapest transform that makes
// "the text holds some accepted spelling of v" the same as "Fold(text) holds v".
//
// Fold is only defined for the formats that vary per seat (PerSeat): they are the
// ones whose answers B9 and B4 look for in a text. Whoever adds a per-seat format, or
// widens what Normalize accepts for one, adds its fold here in the same change; the
// test of fold_test.go that every per-seat format has a fold, and the property test
// (V55), are what turn a forgotten fold red (ADR-0056 Signpost 9).
//
// The search that follows a fold is a substring search, so a value is also found inside a
// longer token, and that false hit is on the safe side for B9 and B4, which refuse on a
// hit: it is cured by a re-render.

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrNoFold is returned by Fold for a format it has no fold for: an unknown one, one that
// does not vary per seat, or a per-seat one whose fold was never written (fail-closed:
// the caller must not read it as "nothing to fold").
var ErrNoFold = errors.New("answerformat: no fold for this format")

var (
	foldOffsetUTC = []byte("+00:00")
	foldZulu      = []byte("Z")
	foldSlashRun  = []byte("//")
	foldSlash     = []byte("/")
)

// Fold returns text folded for the per-seat format f:
//
//   - name: unchanged (Normalize only trims, and a search of a text covers the ends);
//   - path: every run of slashes becomes one slash (Normalize does the same, and drops a
//     trailing one, which a search for the normalised value covers);
//   - hexid: ASCII upper case becomes lower case (only ASCII, as Normalize does);
//   - timestamp: "+00:00" becomes "Z" (the two spellings of UTC that Normalize accepts).
//
// text is any bytes, valid UTF-8 or not (a corpus holds binary files too): Fold works on
// bytes and never decodes them. The result may share memory with text (when nothing had to
// change, it is text itself): neither is to be modified. Fold never returns, formats or
// logs the text.
func Fold(f string, text []byte) ([]byte, error) {
	spec, ok := formats[f]
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: unknown format %q", ErrNoFold, f)
	case !spec.perSeat:
		return nil, fmt.Errorf("%w: format %q does not vary per seat", ErrNoFold, f)
	}
	switch f {
	case Name:
		return text, nil
	case Path:
		if !bytes.Contains(text, foldSlashRun) {
			return text, nil
		}
		return slashRunRE.ReplaceAll(text, foldSlash), nil
	case HexID:
		return foldASCIILower(text), nil
	case Timestamp:
		if !bytes.Contains(text, foldOffsetUTC) {
			return text, nil
		}
		return bytes.ReplaceAll(text, foldOffsetUTC, foldZulu), nil
	}
	return nil, fmt.Errorf("%w: format %q varies per seat but has no fold", ErrNoFold, f)
}

// foldASCIILower is text with A-Z turned into a-z, and text itself when it has no capital.
func foldASCIILower(text []byte) []byte {
	first := -1
	for i, b := range text {
		if b >= 'A' && b <= 'Z' {
			first = i
			break
		}
	}
	if first < 0 {
		return text
	}
	out := make([]byte, len(text))
	copy(out, text)
	for i := first; i < len(out); i++ {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return out
}
