package edition

// spec.go is edition.yaml (ADR-0056 D12 and its amendment 8, D19 A4d-1a): the schema, the
// parser, and D10 E1, the rule of the file's shape. The rules that need the challenge's
// questions (E2) and the sizing of the answer space (B8 (a)) are the next stage (A4d-1b).
//
//	version: 1                       # required, 1 only
//	time: {base: <RFC 3339 UTC>}     # required if a slot has a window
//	fixed: {<qid>: <value>}          # the answers of the questions that cannot vary per seat
//	slots:
//	  - name: <slot>                 # answerformat.IDPattern; an answer slot's is at most 27 bytes
//	    role: answer
//	    question: <qid>              # answer only. The format and params come from the question
//	    decoys: <n>                  # answer only, 1..MaxDecoys: makes <name>-d1 .. <name>-d<n>
//	    vocab: [[word, ...], ...]    # path and name questions only
//	    window: {from: <s>, to: <s>} # timestamp questions only; half-open, seconds from time.base
//	  - name: <slot>
//	    role: filler
//	    format: <path | name | hexid | timestamp>
//	    length: <n>                  # a hexid filler only
//	    vocab / window               # as the format needs
//
// vocab is a list of lists of words. A name has exactly one list: its value is one of the
// words. A path has one list per path element: its value is one word of each list, joined
// by `/`. A word is written in the normalised form of its format (answerformat.Normalize
// leaves it unchanged); a path word is one element, so it never holds a `/`.
//
// The decoys are not written: an answer slot's `decoys: <n>` makes n implicit slots
// (Spec.ImpliedDecoys) that inherit the answer's question, vocab and window, so a decoy
// cannot differ from its answer in format, params, vocabulary or window (D12). A slot
// declared as a decoy, or an anchor or alias that would share a vocabulary, is refused.
//
// An answer slot has no format in the file, so E1 can hold its vocabulary only to what
// every format that takes one has in common (a list of 1..MaxVocabWords distinct path
// elements in normalised form, a path that fits); that the vocabulary suits the question's
// format is checked in A4d-1b, which has the question.
//
// What is NOT here (A4d-2 and A4e): the template files and the marks `{{ctf:<slot>}}`, the
// renderer and its DRBG, B7, B8 (b), reading the file from disk, the CLI. This file takes
// the bytes of an edition.yaml; it reads nothing and logs nothing. A message names a rule,
// a slot, a qid and a position (Violation.At), and never a word of a vocabulary: yaml's own
// error text quotes the offending value, so it is never passed on (yamlErrLine keeps its
// line number only).

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/sourcehygiene"
)

// RuleSpecShape is D10 E1: the shape of edition.yaml (ADR-0056 amendment 8).
const RuleSpecShape = "E1"

// Bounds on the file (ADR-0056 D10 E1). At most 8 questions of at most 10 attempts need at
// most 20 decoys each (K = max(2 x attempts, 4)), so 168 slots of answers and decoys; the
// rest are fillers. A path is at most 255 bytes, so 16 positions are enough.
const (
	MaxSpecBytes      = 1 << 20
	MaxSlots          = 512
	MaxVocabPositions = 16
	MaxVocabWords     = 1024
	// MaxDecoys is the most decoys one answer slot may declare: the largest K.
	MaxDecoys = 20
	// MaxAnswerSlotName keeps `<name>-d<i>` (i <= MaxDecoys) inside answerformat.IDPattern's
	// 31 bytes.
	MaxAnswerSlotName = 27
	// SpecVersion is the one version of the schema.
	SpecVersion = 1
)

// The role of a slot. A decoy has none: it is made from an answer slot.
const (
	RoleAnswer = "answer"
	RoleFiller = "filler"
)

// Spec is a parsed edition.yaml.
type Spec struct {
	// VersionDeclared is `version:` as written (nil: not written), the decode target;
	// read Version.
	VersionDeclared *int              `yaml:"version"`
	Time            SpecTime          `yaml:"time"`
	Fixed           map[string]string `yaml:"fixed"`
	Slots           []Slot            `yaml:"slots"`
	// Version is SpecVersion in a parsed Spec.
	Version int `yaml:"-"`
	// ImpliedDecoys are the decoy slots of every answer slot, in the order of the answer
	// slots and then of their numbers. A decoy shares its answer's Vocab and Window
	// (read-only: never write through them) and has no Role and no Format of its own.
	ImpliedDecoys []Slot `yaml:"-"`
}

// SpecTime is `time:`.
type SpecTime struct {
	Base string `yaml:"base"`
}

// Window is `window: {from, to}`: seconds from time.base, half-open.
type Window struct {
	From *int64 `yaml:"from"`
	To   *int64 `yaml:"to"`
}

// Slot is one slot, as declared, or one implied decoy (DecoyOf is not empty).
type Slot struct {
	Name     string     `yaml:"name"`
	Role     string     `yaml:"role"`
	Question string     `yaml:"question"`
	Decoys   *int       `yaml:"decoys"`
	Format   string     `yaml:"format"`
	Length   *int       `yaml:"length"`
	Vocab    [][]string `yaml:"vocab"`
	Window   *Window    `yaml:"window"`
	// DecoyOf is the name of the answer slot an implied decoy comes from; empty for a
	// declared slot.
	DecoyOf string `yaml:"-"`
}

func newSpecViolation(rule, msg string, line int, cid, qid, slot, at string, err error) *Violation {
	v := newViolation(rule, msg, line, cell{cid: cid, qid: qid}, err)
	if answerformat.ValidID(slot) {
		v.Slot = slot
	}
	v.At = at
	return v
}

// decoyName is the name of the j-th (1-based) implied decoy of answer slot name.
func decoyName(name string, j int) string { return fmt.Sprintf("%s-d%d", name, j) }

// ParseSpec parses an edition.yaml and holds it to D10 E1. The first failure of the
// file's syntax is returned as one *Violation; once the file decodes, the failures of its
// content are an errors.Join of *Violation (at most maxViolations listed, in the order of
// the file). E1 is, in this order:
//
//   - UTF-8, no rune sourcehygiene.Hidden reports, at most MaxSpecBytes, one document, and
//     no anchor and no alias (a decoy inherits its answer's vocabulary, so nothing needs
//     to share one);
//   - strict: a key that is not in the schema, a repeated key and a value of the wrong
//     type are refused at every depth (KnownFields(true), as the catalog's investigate
//     block);
//   - `version` is written and is 1; a key of `fixed` is a question id;
//   - 1..MaxSlots slots, each name in answerformat.IDPattern, an answer slot's in at most
//     MaxAnswerSlotName bytes, all distinct, the implied decoys' included;
//   - an answer slot has `question` (an id) and `decoys` (1..MaxDecoys) and no `format`
//     and no `length`; a filler has a `format` that can vary per seat and no `question`
//     and no `decoys`;
//   - a path or name filler has a `vocab`; a hexid or timestamp filler has none; `length`
//     is a hexid filler's and is a length answerformat takes; `window` is a timestamp
//     slot's (a filler of that format must have it) with 0 <= from < to; a slot that has a
//     window needs `time.base`, and `time.base` is an RFC 3339 UTC time at second
//     precision;
//   - a vocab is 1..MaxVocabPositions lists (a name filler: exactly one) of 1..MaxVocabWords
//     words, every word in the normalised form of the format (an answer slot's: of a path
//     element), no word twice in a list, and the longest path it can make fits.
//
// Whether the slots fit a challenge's questions is E2's, in A4d-1b.
func ParseSpec(data []byte) (*Spec, error) {
	shape := func(msg string, line int) error {
		return newSpecViolation(RuleSpecShape, msg, line, "", "", "", "", nil)
	}
	switch {
	case len(data) == 0:
		return nil, shape("edition.yaml is empty", 0)
	case len(data) > MaxSpecBytes:
		return nil, shape("edition.yaml is larger than the size limit", 0)
	case !utf8.Valid(data):
		return nil, shape("edition.yaml is not valid UTF-8", 0)
	}
	if found := sourcehygiene.Hidden(data); len(found) > 0 {
		return nil, shape("invisible or bidi control character", found[0].Line)
	}
	// First read: the nodes, for the document count and for anchors and aliases.
	nodes := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := nodes.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, shape("edition.yaml holds no document", 0)
		}
		return nil, shape("edition.yaml is not valid yaml", yamlErrLine(err))
	}
	var extra yaml.Node
	if err := nodes.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, shape("edition.yaml holds more than one document", 0)
	}
	if n := findAnchorOrAlias(&doc); n != nil {
		return nil, shape("an anchor or an alias is not allowed", n.Line)
	}
	// Second read: the strict decode, on the original bytes so that a line number is the
	// file's own.
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	var spec Spec
	if err := strict.Decode(&spec); err != nil {
		return nil, shape("edition.yaml does not decode (an unknown or repeated key, or a value of the wrong type)", yamlErrLine(err))
	}
	if err := validateSpec(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// findAnchorOrAlias is the first node, in document order, that carries an anchor or is an
// alias.
func findAnchorOrAlias(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return n
	}
	for _, c := range n.Content {
		if f := findAnchorOrAlias(c); f != nil {
			return f
		}
	}
	return nil
}

// yamlErrLine is the line number of a yaml error, or 0. It is all of yaml's message that
// is passed on: the rest quotes the value that did not decode.
func yamlErrLine(err error) int {
	s := err.Error()
	i := strings.Index(s, "line ")
	if i < 0 {
		return 0
	}
	s = s[i+len("line "):]
	j := 0
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	n, convErr := strconv.Atoi(s[:j])
	if convErr != nil {
		return 0
	}
	return n
}

// usesVocabulary reports whether the answer space of a format comes from a vocabulary
// (D2: path and name). It asks answerformat, which is the one place that knows, instead
// of listing the two formats here.
func usesVocabulary(format string) bool {
	_, err := answerformat.Space(format, answerformat.Params{})
	return errors.Is(err, answerformat.ErrSpaceFromVocabulary)
}

func validateSpec(spec *Spec) error {
	var c collector
	top := func(at, msg string, err error) {
		c.add(newSpecViolation(RuleSpecShape, msg, 0, "", "", "", at, err))
	}
	switch {
	case spec.VersionDeclared == nil:
		top("version", "version is required", nil)
	case *spec.VersionDeclared != SpecVersion:
		top("version", fmt.Sprintf("version must be %d", SpecVersion), nil)
	default:
		spec.Version = SpecVersion
	}
	keys := make([]string, 0, len(spec.Fixed))
	for k := range spec.Fixed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !answerformat.ValidID(k) {
			top("fixed", "a key of fixed is outside the id grammar "+answerformat.IDPattern, nil)
		}
	}
	switch n := len(spec.Slots); {
	case n == 0:
		top("slots", "edition.yaml declares no slot", nil)
		return c.err()
	case n > MaxSlots:
		top("slots", fmt.Sprintf("edition.yaml declares more than %d slots", MaxSlots), nil)
		return c.err()
	}
	names := make(map[string]struct{}, len(spec.Slots))
	needsBase := false
	for i := range spec.Slots {
		if validateSlot(i, &spec.Slots[i], names, &c) {
			needsBase = true
		}
	}
	switch base := spec.Time.Base; {
	case base == "" && needsBase:
		top("time.base", "time.base is required: a slot has a window", nil)
	case base != "":
		one := int64(1)
		if err := answerformat.Canonical(answerformat.Timestamp, answerformat.Params{WindowSeconds: &one}, base); err != nil {
			top("time.base", "time.base is not an RFC 3339 UTC time at second precision", err)
		}
	}
	if err := c.err(); err != nil {
		return err
	}
	for i := range spec.Slots {
		s := &spec.Slots[i]
		if s.Role != RoleAnswer {
			continue
		}
		for j := 1; j <= *s.Decoys; j++ {
			spec.ImpliedDecoys = append(spec.ImpliedDecoys, Slot{
				Name: decoyName(s.Name, j), Question: s.Question, Vocab: s.Vocab, Window: s.Window, DecoyOf: s.Name,
			})
		}
	}
	return nil
}

// validateSlot reports whether the slot needs time.base (it has a window).
func validateSlot(i int, s *Slot, names map[string]struct{}, c *collector) bool {
	base := fmt.Sprintf("slots[%d]", i)
	bad := func(where, msg string, err error) {
		c.add(newSpecViolation(RuleSpecShape, msg, 0, "", s.Question, s.Name, base+where, err))
	}
	declare := func(name string) {
		if _, dup := names[name]; dup {
			bad("", "this slot name, or an implied decoy name, is declared twice", nil)
		}
		names[name] = struct{}{}
	}
	if !answerformat.ValidID(s.Name) {
		bad("", "name is outside the id grammar "+answerformat.IDPattern, nil)
	} else {
		declare(s.Name)
	}
	switch s.Role {
	case RoleAnswer:
		validateAnswer(s, bad, declare)
	case RoleFiller:
		validateFiller(s, bad)
	default:
		bad("", "role must be answer or filler", nil)
	}
	return s.Window != nil
}

func validateAnswer(s *Slot, bad func(where, msg string, err error), declare func(name string)) {
	if s.Format != "" {
		bad("", "an answer slot has no format: it takes its question's", nil)
	}
	if s.Length != nil {
		bad("", "length is a hexid filler's", nil)
	}
	if !answerformat.ValidID(s.Question) {
		bad("", "an answer slot needs question: <qid>", nil)
	}
	if len(s.Name) > MaxAnswerSlotName {
		bad("", fmt.Sprintf("an answer slot's name is at most %d bytes", MaxAnswerSlotName), nil)
	}
	switch {
	case s.Decoys == nil:
		bad("", "an answer slot needs decoys", nil)
	case *s.Decoys < 1 || *s.Decoys > MaxDecoys:
		bad("", fmt.Sprintf("decoys must be in 1..%d", MaxDecoys), nil)
	case answerformat.ValidID(s.Name) && len(s.Name) <= MaxAnswerSlotName:
		for j := 1; j <= *s.Decoys; j++ {
			declare(decoyName(s.Name, j))
		}
	}
	if len(s.Vocab) != 0 {
		// The format is the question's, which E1 does not have: hold the words to what a path
		// element and a name have in common (A4d-1b narrows it to the question's).
		validateVocab(s, answerformat.Path, bad)
	}
	validateWindow(s, bad)
}

func validateFiller(s *Slot, bad func(where, msg string, err error)) {
	if s.Question != "" {
		bad("", "a filler has no question", nil)
	}
	if s.Decoys != nil {
		bad("", "a filler has no decoys", nil)
	}
	switch {
	case !answerformat.Known(s.Format):
		bad("", "a filler needs a format of the closed list", nil)
	case !answerformat.PerSeat(s.Format):
		bad("", "format cannot vary per seat, so a slot cannot use it", nil)
	case usesVocabulary(s.Format):
		if len(s.Vocab) == 0 {
			bad("", "this format needs a vocabulary", nil)
		} else {
			validateVocab(s, s.Format, bad)
		}
		noLengthNoWindow(s, bad)
	case s.Format == answerformat.HexID:
		if len(s.Vocab) != 0 {
			bad("", "this format takes no vocabulary", nil)
		}
		if s.Window != nil {
			bad("", "window is a timestamp slot's", nil)
		}
		if err := answerformat.ValidateParams(answerformat.HexID, answerformat.Params{Length: s.Length}); err != nil {
			bad("", "a hexid filler needs a length answerformat takes", err)
		}
	case s.Format == answerformat.Timestamp:
		if len(s.Vocab) != 0 {
			bad("", "this format takes no vocabulary", nil)
		}
		if s.Length != nil {
			bad("", "length is a hexid filler's", nil)
		}
		if s.Window == nil {
			bad("", "a timestamp filler needs a window", nil)
		}
		validateWindow(s, bad)
	}
}

func noLengthNoWindow(s *Slot, bad func(where, msg string, err error)) {
	if s.Length != nil {
		bad("", "length is a hexid filler's", nil)
	}
	if s.Window != nil {
		bad("", "window is a timestamp slot's", nil)
	}
}

// validateWindow holds a window that is there to 0 <= from < to.
func validateWindow(s *Slot, bad func(where, msg string, err error)) {
	w := s.Window
	switch {
	case w == nil:
	case w.From == nil || w.To == nil:
		bad(".window", "a window needs from and to", nil)
	case *w.From < 0 || *w.From >= *w.To:
		bad(".window", "a window needs 0 <= from < to", nil)
	}
}

func validateVocab(s *Slot, format string, bad func(where, msg string, err error)) {
	switch n := len(s.Vocab); {
	case format == answerformat.Name && n != 1:
		bad(".vocab", "a name vocabulary is exactly one list of words", nil)
		return
	case n > MaxVocabPositions:
		bad(".vocab", fmt.Sprintf("a vocabulary has at most %d lists", MaxVocabPositions), nil)
		return
	}
	ok := true
	for pi, words := range s.Vocab {
		if wi, err := checkWords(format, words); err != nil {
			where := fmt.Sprintf(".vocab[%d]", pi)
			if wi >= 0 {
				where += fmt.Sprintf("[%d]", wi)
			}
			bad(where, "a vocabulary list or word is refused", err)
			ok = false
		}
	}
	if ok && format == answerformat.Path {
		if err := checkLongestPath(s.Vocab); err != nil {
			bad(".vocab", "the longest path of the vocabulary does not fit the path format", err)
		}
	}
}

// checkWords holds one list of words to the grammar of the format, in normalised form,
// without a repeat. It returns the index of the word that is refused, or -1 when the
// list as a whole is. Its errors describe the rule, never the word.
func checkWords(format string, words []string) (int, error) {
	if len(words) < 1 || len(words) > MaxVocabWords {
		return -1, fmt.Errorf("a list needs 1..%d words", MaxVocabWords)
	}
	seen := make(map[string]struct{}, len(words))
	for wi, w := range words {
		v, err := normalizeWord(format, w)
		if err != nil {
			return wi, err
		}
		if v != w {
			return wi, fmt.Errorf("a word: %w", answerformat.ErrNotCanonical)
		}
		if _, dup := seen[v]; dup {
			return wi, errors.New("a word is repeated in its list")
		}
		seen[v] = struct{}{}
	}
	return -1, nil
}

// normalizeWord is the format's normalisation (answerformat.Normalize, the one
// definition) of one word of a vocabulary. A name word is a name. A path word is one path
// element: it is normalised as the path `/<word>` and the `/` is taken off again, so an
// empty word (which would normalise to the root) and a word with a `/` in it are refused
// first.
func normalizeWord(format, w string) (string, error) {
	switch format {
	case answerformat.Name:
		return answerformat.Normalize(format, answerformat.Params{}, w)
	case answerformat.Path:
		if w == "" || strings.Contains(w, "/") {
			return "", errors.New("a path word is empty or holds a slash")
		}
		n, err := answerformat.Normalize(format, answerformat.Params{}, "/"+w)
		if err != nil {
			return "", err
		}
		return strings.TrimPrefix(n, "/"), nil
	}
	return "", errors.New("this format has no vocabulary")
}

// checkLongestPath builds the longest path the vocabulary can make (the longest word of
// each list) and has the path format normalise it: every other combination is no longer,
// so if this one fits, they all do.
func checkLongestPath(vocab [][]string) error {
	var b strings.Builder
	for _, words := range vocab {
		longest := ""
		for _, w := range words {
			if len(w) > len(longest) {
				longest = w
			}
		}
		b.WriteString("/" + longest)
	}
	_, err := answerformat.Normalize(answerformat.Path, answerformat.Params{}, b.String())
	return err
}
