// Package answerformat is the closed list of answer formats of an investigate
// challenge (ADR-0056 D2) and the three things a format decides: whether a
// params block is well formed, how an answer is normalised (idempotently), and
// how large the answer space is (D3 (a)). It is the ONE definition of these
// rules: the catalog (load time), the grader (A3) and the edition validator
// (A2/A4) import it and never copy it.
//
// Nothing here ever returns, formats or logs a participant's input or an
// expected value: every error describes the rule that failed, not the text.
// (ADR-0056 D4/D13: an error that echoes the input is an oracle.)
package answerformat

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The seven formats of v1. Adding one is an amendment of ADR-0056 D2.
const (
	Path      = "path"
	Name      = "name"
	HexID     = "hexid"
	Timestamp = "timestamp"
	Technique = "technique"
	ChoiceSet = "choice-set"
	Sequence  = "sequence"
)

const (
	// MaxAnswerLen is the longest raw answer any format accepts (ADR-0056 D4:
	// AnswerRequest.answer maxLength 256).
	MaxAnswerLen = 256
	// SpaceFactor is D3 (a): the answer space must be at least SpaceFactor x attempts.
	SpaceFactor = 100
	// MaxLabels bounds the declared option ids of a choice-set / sequence. It is a
	// sanity bound on the params block (the ADR leaves n open); the space check is
	// what makes small n unusable.
	MaxLabels = 32

	minHexLength = 12
	maxHexLength = 64
	maxPathLen   = 255
)

// IDPattern is the grammar of a question id (ADR-0056 D1) and, reused, of a
// choice / label id. One definition: the route (A3) imports it.
const IDPattern = `^[a-z][a-z0-9-]{0,30}$`

var (
	idRE        = regexp.MustCompile(IDPattern)
	elemRE      = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	nameRE      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	hexRE       = regexp.MustCompile(`^[0-9a-f]+$`)
	timestampRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	techniqueRE = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	slashRunRE  = regexp.MustCompile(`/{2,}`)
)

// ValidID reports whether s is a question / choice / label id.
func ValidID(s string) bool { return idRE.MatchString(s) }

// Params is the union of the closed `params:` keys of every format. The catalog
// decodes it strictly (an unknown key fails); ValidateParams then requires, per
// format, exactly the keys that format takes and none of the others. A pointer
// or nil slice means "not written".
type Params struct {
	// Length: hexid = digits (12..64); sequence = how many labels are ordered (1..len(Labels)).
	Length *int `yaml:"length"`
	// WindowSeconds: timestamp = the width of the window the answer lies in (>= 1).
	WindowSeconds *int64 `yaml:"windowSeconds"`
	// Choices: choice-set = the declared option ids (n).
	Choices []string `yaml:"choices"`
	// Labels: sequence = the declared labels (m).
	Labels []string `yaml:"labels"`
}

// Errors the callers branch on. Each is wrapped with a message that names the
// rule, never the text.
var (
	// ErrFormat: a raw answer does not fit the format (the route's 400, no attempt spent).
	ErrFormat = errors.New("answer does not fit the format")
	// ErrNotCanonical: an expected value is not already in normalised form (ADR-0056 D2).
	ErrNotCanonical = errors.New("value is not in normalised form")
	// ErrSpaceFromVocabulary: the space of this format comes from the renderer's
	// vocabulary (D12), which only the edition validator has. Not a failure: the
	// catalog cannot size it and the validator must (D3 (a), B8).
	ErrSpaceFromVocabulary = errors.New("answer space comes from the edition vocabulary")
	// ErrSpaceUnavailable: the space cannot be computed at all, so the format cannot
	// be used (fail-closed).
	ErrSpaceUnavailable = errors.New("answer space cannot be computed")
)

type format struct {
	perSeat   bool
	check     func(p Params) error
	space     func(p Params) (*big.Int, error)
	normalize func(p Params, raw string) (string, error)
}

var formats = map[string]format{
	Path:      {perSeat: true, check: noParams, space: vocabSpace, normalize: normPath},
	Name:      {perSeat: true, check: noParams, space: vocabSpace, normalize: normName},
	HexID:     {perSeat: true, check: checkHexID, space: spaceHexID, normalize: normHexID},
	Timestamp: {perSeat: true, check: checkTimestamp, space: spaceTimestamp, normalize: normTimestamp},
	// technique: ADR-0056 D2 sizes it by the number of ATT&CK v19 technique ids. That
	// table is not in this repo (only the few ids the 14 challenges use, in
	// challenges/attack-navigator-layer.json), so the space is unavailable and a
	// catalog that asks a technique question is refused until the table lands.
	Technique: {perSeat: false, check: noParams, space: unavailableSpace, normalize: normTechnique},
	ChoiceSet: {perSeat: false, check: checkChoiceSet, space: spaceChoiceSet, normalize: normChoiceSet},
	Sequence:  {perSeat: false, check: checkSequence, space: spaceSequence, normalize: normSequence},
}

// Formats returns the closed list, sorted.
func Formats() []string {
	out := make([]string, 0, len(formats))
	for f := range formats {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Known reports whether f is one of the closed list.
func Known(f string) bool {
	_, ok := formats[f]
	return ok
}

// PerSeat reports whether the edition renderer can vary this format's answer
// per seat (D2). false for an unknown format.
func PerSeat(f string) bool { return formats[f].perSeat }

// ValidateParams requires exactly the params keys the format takes (ADR-0056 D2:
// "format ごとに閉じた key の集合") and their ranges.
func ValidateParams(f string, p Params) error {
	spec, ok := formats[f]
	if !ok {
		return fmt.Errorf("unknown format %q (want one of %s)", f, strings.Join(Formats(), ", "))
	}
	return spec.check(p)
}

// Space is the size of the answer space, from the format and params alone.
// ErrSpaceFromVocabulary and ErrSpaceUnavailable are the two ways it has no number.
func Space(f string, p Params) (*big.Int, error) {
	spec, ok := formats[f]
	if !ok {
		return nil, fmt.Errorf("unknown format %q", f)
	}
	if err := spec.check(p); err != nil {
		return nil, err
	}
	return spec.space(p)
}

// CheckSpaceN is D3 (a) on a known size: n must be >= SpaceFactor x attempts.
// The edition validator (A4) calls it with the size of the renderer vocabulary.
func CheckSpaceN(n *big.Int, attempts int) error {
	need := big.NewInt(int64(SpaceFactor) * int64(attempts))
	if n.Cmp(need) < 0 {
		return fmt.Errorf("answer space %s is below %d x attempts (%d x %d = %s)", n, SpaceFactor, SpaceFactor, attempts, need)
	}
	return nil
}

// CheckSpace is D3 (a) for the catalog: the space computed from format and
// params must be >= SpaceFactor x attempts. A vocabulary-sized format returns
// nil here ON PURPOSE: the catalog has no vocabulary, and the same rule is
// applied to the vocabulary by the edition validator through CheckSpaceN. A
// space that cannot be computed at all is an error (fail-closed).
func CheckSpace(f string, p Params, attempts int) error {
	n, err := Space(f, p)
	switch {
	case errors.Is(err, ErrSpaceFromVocabulary):
		return nil
	case err != nil:
		return err
	}
	return CheckSpaceN(n, attempts)
}

// Normalize is the format's normalisation of a raw answer, or an error wrapping
// ErrFormat. It is idempotent: Normalize(Normalize(x)) == Normalize(x).
func Normalize(f string, p Params, raw string) (string, error) {
	spec, ok := formats[f]
	if !ok {
		return "", fmt.Errorf("unknown format %q", f)
	}
	// The normalisers read params through pointers; a params block that was never
	// validated must be an error here, not a nil dereference.
	if err := spec.check(p); err != nil {
		return "", err
	}
	if len(raw) > MaxAnswerLen {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrFormat, MaxAnswerLen)
	}
	return spec.normalize(p, raw)
}

// Canonical requires an expected value (an answers-table cell) to fit the format
// AND to be in normalised form already: normalize(v) == v (ADR-0056 D2). A table
// value that is not would never match any input that is normalised.
func Canonical(f string, p Params, v string) error {
	n, err := Normalize(f, p, v)
	if err != nil {
		return err
	}
	if n != v {
		return fmt.Errorf("%w (format %s)", ErrNotCanonical, f)
	}
	return nil
}

// ---- params ----

func noParams(p Params) error {
	if p.Length != nil || p.WindowSeconds != nil || p.Choices != nil || p.Labels != nil {
		return errors.New("this format takes no params")
	}
	return nil
}

func checkHexID(p Params) error {
	if p.WindowSeconds != nil || p.Choices != nil || p.Labels != nil {
		return errors.New("hexid takes only params.length")
	}
	if p.Length == nil || *p.Length < minHexLength || *p.Length > maxHexLength {
		return fmt.Errorf("hexid needs params.length in %d..%d", minHexLength, maxHexLength)
	}
	return nil
}

func checkTimestamp(p Params) error {
	if p.Length != nil || p.Choices != nil || p.Labels != nil {
		return errors.New("timestamp takes only params.windowSeconds")
	}
	if p.WindowSeconds == nil || *p.WindowSeconds < 1 {
		return errors.New("timestamp needs params.windowSeconds >= 1")
	}
	return nil
}

func checkIDList(key string, ids []string) error {
	if len(ids) < 1 || len(ids) > MaxLabels {
		return fmt.Errorf("params.%s needs 1..%d entries", key, MaxLabels)
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !ValidID(id) {
			return fmt.Errorf("params.%s has an entry outside the id grammar %s", key, IDPattern)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("params.%s has a duplicate entry", key)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func checkChoiceSet(p Params) error {
	if p.Length != nil || p.WindowSeconds != nil || p.Labels != nil {
		return errors.New("choice-set takes only params.choices")
	}
	return checkIDList("choices", p.Choices)
}

func checkSequence(p Params) error {
	if p.WindowSeconds != nil || p.Choices != nil {
		return errors.New("sequence takes only params.labels and params.length")
	}
	if err := checkIDList("labels", p.Labels); err != nil {
		return err
	}
	if p.Length == nil || *p.Length < 1 || *p.Length > len(p.Labels) {
		return errors.New("sequence needs params.length in 1..len(labels)")
	}
	return nil
}

// ---- space ----

func vocabSpace(Params) (*big.Int, error) { return nil, ErrSpaceFromVocabulary }

func unavailableSpace(Params) (*big.Int, error) {
	return nil, fmt.Errorf("%w: the ATT&CK v19 technique table is not in this repository", ErrSpaceUnavailable)
}

func spaceHexID(p Params) (*big.Int, error) {
	return new(big.Int).Exp(big.NewInt(16), big.NewInt(int64(*p.Length)), nil), nil
}

func spaceTimestamp(p Params) (*big.Int, error) { return big.NewInt(*p.WindowSeconds), nil }

// spaceChoiceSet is 2^n - 1: the non-empty subsets of n options.
func spaceChoiceSet(p Params) (*big.Int, error) {
	n := new(big.Int).Lsh(big.NewInt(1), uint(len(p.Choices)))
	return n.Sub(n, big.NewInt(1)), nil
}

// spaceSequence is m!/(m-k)!: ordered arrangements of k of m labels.
func spaceSequence(p Params) (*big.Int, error) {
	m := len(p.Labels)
	n := big.NewInt(1)
	for i := 0; i < *p.Length; i++ {
		n.Mul(n, big.NewInt(int64(m-i)))
	}
	return n, nil
}

// ---- normalisation ----

const asciiSpace = " \t\n\v\f\r"

func trimASCII(s string) string { return strings.Trim(s, asciiSpace) }

// asciiLower / asciiUpper fold ASCII only: strings.ToLower would also map some
// non-ASCII code points onto ASCII letters, widening what an answer may be typed as.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

func asciiUpper(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - ('a' - 'A')
		}
		return r
	}, s)
}

func errFmt(rule string) error { return fmt.Errorf("%w: %s", ErrFormat, rule) }

func normPath(_ Params, raw string) (string, error) {
	s := slashRunRE.ReplaceAllString(trimASCII(raw), "/")
	if len(s) > 1 {
		s = strings.TrimSuffix(s, "/")
	}
	if !strings.HasPrefix(s, "/") || len(s) > maxPathLen {
		return "", errFmt("path must be absolute and at most 255 bytes")
	}
	if s == "/" {
		return s, nil
	}
	for _, elem := range strings.Split(s[1:], "/") {
		if !elemRE.MatchString(elem) {
			return "", errFmt("path element outside [A-Za-z0-9._-]")
		}
	}
	return s, nil
}

func normName(_ Params, raw string) (string, error) {
	s := trimASCII(raw)
	if !nameRE.MatchString(s) {
		return "", errFmt("name must match [A-Za-z0-9._-]{1,64}")
	}
	return s, nil
}

func normHexID(p Params, raw string) (string, error) {
	s := asciiLower(trimASCII(raw))
	if len(s) != *p.Length || !hexRE.MatchString(s) {
		return "", errFmt("hexid must be lower-case hex of the declared length")
	}
	return s, nil
}

func normTimestamp(_ Params, raw string) (string, error) {
	s := trimASCII(raw)
	if strings.HasSuffix(s, "+00:00") {
		s = strings.TrimSuffix(s, "+00:00") + "Z"
	}
	if !timestampRE.MatchString(s) {
		return "", errFmt("timestamp must be RFC 3339 UTC at second precision")
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return "", errFmt("timestamp is not a real date and time")
	}
	return s, nil
}

// normTechnique checks the id's shape only; membership in the ATT&CK v19 table
// needs the table (see the technique entry of formats).
func normTechnique(_ Params, raw string) (string, error) {
	s := asciiUpper(trimASCII(raw))
	if !techniqueRE.MatchString(s) {
		return "", errFmt("technique must look like T1234 or T1234.567")
	}
	return s, nil
}

func idSet(ids []string) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

// normChoiceSet drops every ASCII whitespace, splits on ",", requires each
// element to be a declared option, removes duplicates and sorts.
func normChoiceSet(p Params, raw string) (string, error) {
	s := strings.Map(func(r rune) rune {
		if strings.ContainsRune(asciiSpace, r) {
			return -1
		}
		return r
	}, raw)
	if s == "" {
		return "", errFmt("choice-set must not be empty")
	}
	declared := idSet(p.Choices)
	picked := make(map[string]struct{})
	for _, el := range strings.Split(s, ",") {
		if _, ok := declared[el]; !ok {
			return "", errFmt("choice-set has an entry that is not a declared option")
		}
		picked[el] = struct{}{}
	}
	out := make([]string, 0, len(picked))
	for el := range picked {
		out = append(out, el)
	}
	sort.Strings(out)
	return strings.Join(out, ","), nil
}

// normSequence trims the ends only, splits on ",", and requires exactly
// params.length distinct declared labels (an arrangement, not a multiset).
func normSequence(p Params, raw string) (string, error) {
	s := trimASCII(raw)
	els := strings.Split(s, ",")
	if len(els) != *p.Length {
		return "", errFmt("sequence has the wrong number of labels")
	}
	declared := idSet(p.Labels)
	seen := make(map[string]struct{}, len(els))
	for _, el := range els {
		if _, ok := declared[el]; !ok {
			return "", errFmt("sequence has an entry that is not a declared label")
		}
		if _, dup := seen[el]; dup {
			return "", errFmt("sequence repeats a label")
		}
		seen[el] = struct{}{}
	}
	return s, nil
}
