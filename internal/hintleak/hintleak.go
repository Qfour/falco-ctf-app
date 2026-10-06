// Package hintleak implements the n-gram rule of ADR-0026 D5: text that exists
// only as a hint (a journey `hints[].text`) must not appear in a file the
// participant can read for free (a challenge fixture). It is deliberately a
// pure function over already-loaded text so that ADR-0030 (Quest content) can
// reuse the SAME rule on its own inputs — the rule has exactly one
// implementation, and callers only assemble [Input] for their own scope.
//
// The rule (ADR-0026 D5, one scope S at a time):
//
//  1. Items. Hint items = every hint text of S. Free items = every text the
//     participant sees without paying (briefing, step label/detail, rule.yaml,
//     ... — the caller decides, see the ADR). Target items = the texts that
//     must stay clean: for ADR-0026, every fixture file (all challenges, NOT
//     narrowed to S). Items are read as UTF-8; a
//     non-UTF-8 item is an error. So is a hint item or target item containing
//     an invisible format character (Unicode category Cf: U+200B, U+FEFF,
//     U+00AD, U+2060, ...): it is not White_Space, so it would silently split a
//     copied run and let it through. The normalisation below is unchanged.
//  2. Normalise. Remove every rune for which [unicode.IsSpace] is true. Nothing
//     else changes: no NFC/NFKC, no case folding, no punctuation stripping.
//  3. n-gram. n = [GramRunes] runes, cut PER ITEM (items are never joined, so a
//     run of runes that straddles two items is not counted as appearing in
//     either).
//  4. Violation. A pair (target item f, n-gram g) where g occurs in at least
//     one hint item, in NO free item, and in f. Reported once per distinct
//     (f, g).
//
// There is no exclusion list: a violation is fixed by rewording the target.
package hintleak

import (
	"errors"
	"fmt"
	"sort"
	"unicode"
	"unicode/utf8"
)

// GramRunes is n of ADR-0026 D5: one above the noise knee (n=9 still matches
// generic technical tokens such as a 9-character shebang) and below the
// shortest expected answer in the catalog (14 runes without whitespace).
const GramRunes = 10

// Item is one piece of text with a label for reports.
type Item struct {
	Source string // e.g. "02-credential-files hints[3]" — only used in messages
	Text   string // read as UTF-8
}

// Input is everything the rule needs for ONE scope.
type Input struct {
	Hints   []Item
	Free    []Item
	Targets []Item // the texts that must not carry hint-only n-grams (ADR-0026: fixture files)
}

// Violation is one (target item, n-gram) pair.
type Violation struct {
	Target      string   // Item.Source of the target item
	Gram        string   // the normalised 10-rune run
	HintSources []string // every hint item carrying Gram (sorted)
}

// ErrEmptyInput is returned when there is nothing to scan. A scan that covers
// zero items proves nothing, so it is an error rather than a clean result.
var ErrEmptyInput = errors.New("hintleak: no hint items or no target items to scan")

// ErrFormatChar is returned (wrapped) when a hint item or a target item
// contains a Unicode Cf (format) code point.
var ErrFormatChar = errors.New("hintleak: item contains an invisible format character (Unicode Cf)")

// Check applies the rule to in and returns the violations, sorted by
// (Target, Gram). It returns [ErrEmptyInput] (wrapped) when in has no hint
// item or no target item, an error naming the item when any item is not valid
// UTF-8, and [ErrFormatChar] (wrapped, naming the item and code point) when a
// hint or target item contains a Cf code point.
func Check(in Input) ([]Violation, error) {
	if len(in.Hints) == 0 || len(in.Targets) == 0 {
		return nil, fmt.Errorf("%w (hints=%d targets=%d)", ErrEmptyInput, len(in.Hints), len(in.Targets))
	}
	for _, group := range [][]Item{in.Hints, in.Free, in.Targets} {
		for _, it := range group {
			if !utf8.ValidString(it.Text) {
				return nil, fmt.Errorf("hintleak: %s is not valid UTF-8", it.Source)
			}
		}
	}

	for _, group := range [][]Item{in.Hints, in.Targets} {
		for _, it := range group {
			for _, r := range it.Text {
				if unicode.Is(unicode.Cf, r) {
					return nil, fmt.Errorf("%w: %s has U+%04X", ErrFormatChar, it.Source, r)
				}
			}
		}
	}

	hintGrams := map[string][]string{} // gram -> hint sources
	for _, it := range in.Hints {
		for g := range gramSet(it.Text) {
			hintGrams[g] = append(hintGrams[g], it.Source)
		}
	}
	free := map[string]struct{}{}
	for _, it := range in.Free {
		for g := range gramSet(it.Text) {
			free[g] = struct{}{}
		}
	}

	var out []Violation
	for _, f := range in.Targets {
		for g := range gramSet(f.Text) {
			srcs, isHint := hintGrams[g]
			if !isHint {
				continue
			}
			if _, isFree := free[g]; isFree {
				continue
			}
			src := append([]string(nil), srcs...)
			sort.Strings(src)
			out = append(out, Violation{Target: f.Source, Gram: g, HintSources: src})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Gram < out[j].Gram
	})
	return out, nil
}

// gramSet returns the distinct n-grams of one item (D5-2, D5-3).
func gramSet(text string) map[string]struct{} {
	runes := make([]rune, 0, len(text))
	for _, r := range text {
		if !unicode.IsSpace(r) {
			runes = append(runes, r)
		}
	}
	set := map[string]struct{}{}
	for i := 0; i+GramRunes <= len(runes); i++ {
		set[string(runes[i:i+GramRunes])] = struct{}{}
	}
	return set
}
