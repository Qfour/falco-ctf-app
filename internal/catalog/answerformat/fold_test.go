package answerformat_test

// ADR-0056 V55 (A4c-2, M4): answerformat.Fold is Normalize's other half. The property
// that fixes it: every spelling Normalize accepts for a value v, put in a text, leaves
// Fold(text) holding v. The spellings are generated per format from what Normalize's
// implementation accepts (answerformat.go: normPath, normName, normHexID, normTimestamp),
// and each one is first shown to BE accepted, so a generator that drifts from Normalize
// is red rather than silently weaker. Every value here is a placeholder.

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

type foldCase struct {
	format    string
	params    answerformat.Params
	value     string
	spellings []string
}

func foldCases() []foldCase {
	// path: 1 to 3 slashes at every separator, none to 3 at the end, ASCII space around.
	const pathValue = "/srv/data/alpha.log"
	var paths []string
	for _, lead := range []int{1, 2, 3} {
		for _, mid1 := range []int{1, 2, 3} {
			for _, mid2 := range []int{1, 2, 3} {
				for _, tail := range []int{0, 1, 2, 3} {
					p := strings.Repeat("/", lead) + "srv" + strings.Repeat("/", mid1) + "data" +
						strings.Repeat("/", mid2) + "alpha.log" + strings.Repeat("/", tail)
					paths = append(paths, p, " \t"+p+"\n")
				}
			}
		}
	}

	// hexid: every upper / lower mix of the six letters of the value, with and without space.
	const hexValue = "abcdef012345"
	var hexes []string
	for mask := 0; mask < 1<<6; mask++ {
		b := []byte(hexValue)
		for i := 0; i < 6; i++ {
			if mask&(1<<i) != 0 {
				b[i] -= 'a' - 'A'
			}
		}
		hexes = append(hexes, string(b), "  "+string(b)+"\t")
	}

	// timestamp: the two spellings of UTC, with and without space.
	const tsValue = "2026-01-02T03:04:05Z"
	tsOffset := strings.TrimSuffix(tsValue, "Z") + "+00:00"
	stamps := []string{tsValue, tsOffset, " " + tsValue + "\n", "\t" + tsOffset + " "}

	// name: Normalize only trims.
	const nameValue = "alpha-1.beta_x"
	names := []string{nameValue, " " + nameValue + " ", "\t" + nameValue + "\n"}

	return []foldCase{
		{answerformat.Path, answerformat.Params{}, pathValue, paths},
		{answerformat.HexID, answerformat.Params{Length: ip(12)}, hexValue, hexes},
		{answerformat.Timestamp, answerformat.Params{WindowSeconds: i64p(3600)}, tsValue, stamps},
		{answerformat.Name, answerformat.Params{}, nameValue, names},
	}
}

func TestFold_KeepsTheNormalisedValueOfEveryAcceptedSpelling(t *testing.T) {
	for _, c := range foldCases() {
		t.Run(c.format, func(t *testing.T) {
			if len(c.spellings) == 0 {
				t.Fatal("no spelling was generated")
			}
			missedByAByteSearch := 0
			for _, s := range c.spellings {
				got, err := answerformat.Normalize(c.format, c.params, s)
				if err != nil || got != c.value {
					t.Fatalf("the generator made %q, which Normalize maps to (%q, %v), not to %q: it is not an accepted spelling", s, got, err, c.value)
				}
				if !bytes.Contains([]byte(s), []byte(c.value)) {
					missedByAByteSearch++
				}
				// bare, and inside a text with other characters on both sides
				for _, text := range []string{s, "before " + s + " after", "x" + s + "y"} {
					folded, err := answerformat.Fold(c.format, []byte(text))
					if err != nil {
						t.Fatalf("Fold(%q): %v", text, err)
					}
					if !bytes.Contains(folded, []byte(c.value)) {
						t.Errorf("Fold(%q) = %q, which does not hold the normalised value %q", text, folded, c.value)
					}
				}
			}
			// The generator must include spellings that a plain byte search of the value
			// misses (the case before A4c-2), or this test would pass with an identity Fold.
			if c.format != answerformat.Name && missedByAByteSearch == 0 {
				t.Errorf("every spelling of %s holds the value as it is: the property would pass for an identity fold", c.format)
			}
		})
	}
}

func TestFold_Folds(t *testing.T) {
	tests := []struct {
		name, format, in, want string
	}{
		{"path: runs of slashes", answerformat.Path, "/a//b///c", "/a/b/c"},
		{"path: nothing to fold", answerformat.Path, "/a/b/c", "/a/b/c"},
		{"path: a run of slashes inside other text", answerformat.Path, "x//y", "x/y"},
		{"hexid: upper case", answerformat.HexID, "AbC0F", "abc0f"},
		{"hexid: non-ASCII bytes are not decoded or changed", answerformat.HexID, "\xff\xc3\x80AB", "\xff\xc3\x80ab"},
		{"hexid: nothing to fold", answerformat.HexID, "abc012", "abc012"},
		{"timestamp: every +00:00", answerformat.Timestamp, "a+00:00b+00:00", "aZbZ"},
		{"timestamp: another offset stays", answerformat.Timestamp, "a+01:00b", "a+01:00b"},
		{"timestamp: nothing to fold", answerformat.Timestamp, "2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z"},
		{"name: identity", answerformat.Name, " A//b+00:00 ", " A//b+00:00 "},
		{"empty text", answerformat.Path, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := answerformat.Fold(tt.format, []byte(tt.in))
			if err != nil {
				t.Fatalf("Fold: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("Fold(%s, %q) = %q, want %q", tt.format, tt.in, got, tt.want)
			}
		})
	}
}

// A fold never changes the text it was given (a corpus file is folded once per format and
// the next fold starts from the original).
func TestFold_DoesNotChangeItsInput(t *testing.T) {
	const text = "A//B+00:00 /c///d"
	for _, f := range []string{answerformat.Path, answerformat.Name, answerformat.HexID, answerformat.Timestamp} {
		in := []byte(text)
		if _, err := answerformat.Fold(f, in); err != nil {
			t.Fatalf("Fold(%s): %v", f, err)
		}
		if string(in) != text {
			t.Errorf("Fold(%s) changed its input to %q", f, in)
		}
	}
}

// Fold is defined for the formats that vary per seat and for no other: every per-seat
// format has a fold (Signpost 9: a format added to the per-seat set without one is red
// here), and nothing else gets a silent identity.
func TestFold_IsDefinedForExactlyThePerSeatFormats(t *testing.T) {
	perSeat := 0
	for _, f := range answerformat.Formats() {
		got, err := answerformat.Fold(f, []byte("text"))
		if answerformat.PerSeat(f) {
			perSeat++
			if err != nil || got == nil {
				t.Errorf("Fold(%s) = (%q, %v): a per-seat format has no fold", f, got, err)
			}
			continue
		}
		if !errors.Is(err, answerformat.ErrNoFold) || got != nil {
			t.Errorf("Fold(%s) = (%q, %v), want ErrNoFold and no text", f, got, err)
		}
	}
	if perSeat != 4 {
		t.Errorf("%d per-seat formats, want the 4 of ADR-0056 D2 (name, path, hexid, timestamp)", perSeat)
	}
	if got, err := answerformat.Fold("no-such-format", []byte("text")); !errors.Is(err, answerformat.ErrNoFold) || got != nil {
		t.Errorf("Fold(unknown format) = (%q, %v), want ErrNoFold and no text", got, err)
	}
}
