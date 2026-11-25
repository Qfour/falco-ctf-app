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
//	    clues: [<word>, ...]         # answer only, optional: literal words of the template
//	  - name: <slot>
//	    role: filler
//	    format: <path | name | hexid | timestamp>
//	    length: <n>                  # a hexid filler only
//	    vocab / window               # as the format needs
//	blocks:                          # optional (amendment 28): line ranges of template files
//	  - {file: <name>, from: <line>, to: <line>}  # 1-based, both lines included
//
// `clues` (amendment 28, B17) are the words in which the lines of an answer's group may
// differ: how the answer is told apart. `blocks` are the ranges of lines that a render puts
// in the order of their times (A7-x PR 2). Both are declared and checked here and in
// specblocks.go only: the renderer does not read them yet, and B17 and B19 are later stages.
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
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
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
	// MaxDecoys is the most decoys one answer slot may declare: the largest K, which is
	// DecoyK(answerformat.MaxAttempts) = 2 x MaxAttempts. A test pins the two equal.
	MaxDecoys = 2 * answerformat.MaxAttempts
	// MaxAnswerSlotName keeps `<name>-d<i>` (i <= MaxDecoys) inside answerformat.IDPattern's
	// 31 bytes: 31 - len("-d") - 2 digits. A test pins it: the longest name with the
	// longest suffix is an id, one byte more is not.
	MaxAnswerSlotName = 27
	// MaxFixed bounds the keys of `fixed`: one per question that cannot vary per seat, so
	// at most the number of questions of a challenge (catalog.MaxQuestions).
	MaxFixed = catalog.MaxQuestions
	// MaxBlocks bounds `blocks` (amendment 28). The blocks of a file do not overlap, and a
	// template has at most MaxBundleFiles files.
	MaxBlocks = 256
	// MaxClues bounds the clues of one answer slot, and MaxClueBytes one clue: the longest
	// path the path format takes (a clue is one token, and a path is the longest token a
	// value of a format can be).
	MaxClues     = 16
	MaxClueBytes = 255
	// SpecVersion is the one version of the schema. `blocks` and `clues` did not raise it:
	// an image older than them refuses a file that has them (the decode is strict), so a new
	// file is never read by an old image as if it had no blocks.
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
	Blocks          []Block           `yaml:"blocks"`
	// Version is SpecVersion in a parsed Spec.
	Version int `yaml:"-"`
	// ImpliedDecoys are the decoy slots of every answer slot, in the order of the answer
	// slots and then of their numbers. A decoy shares its answer's Vocab and Window
	// (read-only: never write through them) and has no Role and no Format of its own.
	ImpliedDecoys []Slot `yaml:"-"`
	// parsed is true in a Spec that ParseSpec returned (E1 held): the renderer refuses a Spec
	// made by hand, whose Version and ImpliedDecoys could be written to look like one.
	parsed bool
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

// Block is one entry of `blocks` (ADR-0056 amendment 28): the lines From..To of the
// template file File, 1-based and both included.
type Block struct {
	File string `yaml:"file"`
	From *int   `yaml:"from"`
	To   *int   `yaml:"to"`
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
	// Clues are an answer slot's literal words of the template in which the lines of its
	// group may differ (amendment 28, B17). An implied decoy has none: B17 reads its answer's.
	Clues []string `yaml:"clues"`
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

// DecoyK is K (D12): the number of decoys an answer slot must declare for a question of
// this many attempts, max(2 x attempts, 4). With 2 x attempts, two seats that pool their
// pages cannot try every candidate within their attempts. It is the one definition of K:
// the largest declarable number, MaxDecoys, is derived from it.
func DecoyK(attempts int) int { return max(2*attempts, 4) }

// decoyName is the name of the j-th (1-based) implied decoy of answer slot name.
func decoyName(name string, j int) string { return fmt.Sprintf("%s-d%d", name, j) }

// ParseSpec parses an edition.yaml and holds it to D10 E1. The first failure of the
// file's syntax is returned as one *Violation; once the file decodes, the failures of its
// content are an errors.Join of *Violation (at most maxViolations listed, in the order of
// the file). E1 is, in this order:
//
//   - UTF-8, no rune sourcehygiene.Hidden reports, at most MaxSpecBytes, one document, and
//     no anchor, no alias and no merge key (a decoy inherits its answer's vocabulary, so
//     nothing needs to share one), and at most MaxFixed keys in `fixed`;
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
//     element), no word twice in a list, and the longest path it can make fits;
//   - `clues` is an answer slot's: at most MaxClues words, each of 1..MaxClueBytes bytes that
//     are all token bytes (B7's TOKEN, so no space and no control character), none twice;
//   - `blocks` has at most MaxBlocks entries, each a file name of B2's grammar and lines
//     1 <= from <= to, and two blocks of one file do not overlap.
//
// Whether the slots fit a challenge's questions is E2's, in A4d-1b; whether `blocks` and
// `clues` fit the template is E2's too, in specblocks.go.
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
		return nil, shape("an anchor, an alias or a merge key is not allowed", n.Line)
	}
	// Before the strict decode, whose repeated-key check costs the square of a mapping's
	// size: the keys of `fixed`, counted on the nodes.
	if line := fixedOverLimit(&doc); line > 0 {
		return nil, shape(fmt.Sprintf("fixed has more than %d keys", MaxFixed), line)
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
	spec.parsed = true
	return &spec, nil
}

// fixedOverLimit is the line of the top-level `fixed` mapping if it has more than MaxFixed
// keys (counted as written, a repeated key included), or 0.
func fixedOverLimit(doc *yaml.Node) int {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return 0
	}
	top := doc.Content[0].Content
	for i := 0; i+1 < len(top); i += 2 {
		if top[i].Value == "fixed" && top[i+1].Kind == yaml.MappingNode && len(top[i+1].Content)/2 > MaxFixed {
			return top[i+1].Line
		}
	}
	return 0
}

// findAnchorOrAlias is the first node, in document order, that carries an anchor, is an
// alias, or is a merge key (yaml.v3 gives the plain scalar `<<` the tag !!merge, and
// merges the mapping it points at, an inline one included).
func findAnchorOrAlias(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || (n.Kind == yaml.ScalarNode && n.ShortTag() == "!!merge") {
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
		} else {
			checkWindowEnds(spec, base, &c)
		}
	}
	validateBlocks(spec.Blocks, &c)
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

// lastTimestamp is the last second the timestamp format takes: answerformat's normal
// form is what time.Parse and Format give back unchanged, and RFC 3339 has four digits of
// year. A window that ends after it would make a value no answer can be typed as.
var lastTimestamp = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC).Unix()

// checkWindowEnds is E1's hold on the end of a window: the last value of
// [base + from, base + to) is base + to - 1, and it must be a timestamp the format takes.
// The comparison is on the seconds left after base, so no sum can overflow (to may be
// near the largest int64). It is for the windows that are otherwise well formed; base is
// already a canonical time.
func checkWindowEnds(spec *Spec, base string, c *collector) {
	t, err := time.Parse(time.RFC3339, base)
	if err != nil {
		return
	}
	left := lastTimestamp - t.Unix()
	for i := range spec.Slots {
		s := &spec.Slots[i]
		w := s.Window
		if w == nil || w.From == nil || w.To == nil || *w.From < 0 || *w.From >= *w.To {
			continue
		}
		if *w.To-1 > left {
			c.add(newSpecViolation(RuleSpecShape, "the window ends after the last second a timestamp can be written (year 9999)", 0, "", s.Question, s.Name, fmt.Sprintf("slots[%d].window", i), nil))
		}
	}
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
	validateClues(s, bad)
}

func validateFiller(s *Slot, bad func(where, msg string, err error)) {
	if s.Question != "" {
		bad("", "a filler has no question", nil)
	}
	if s.Decoys != nil {
		bad("", "a filler has no decoys", nil)
	}
	if len(s.Clues) != 0 {
		bad(".clues", "clues are an answer slot's", nil)
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

// validateClues holds the clues of an answer slot to their shape (E1): at most MaxClues, each
// one TOKEN (isTokenByte, so no space and no control character) of 1..MaxClueBytes bytes, none
// twice. That each is a literal word of the template is E2's (specblocks.go). A message names
// the position of a clue, never the clue.
func validateClues(s *Slot, bad func(where, msg string, err error)) {
	if len(s.Clues) > MaxClues {
		bad(".clues", fmt.Sprintf("an answer slot has at most %d clues", MaxClues), nil)
		return
	}
	seen := make(map[string]struct{}, len(s.Clues))
	for i, w := range s.Clues {
		where := fmt.Sprintf(".clues[%d]", i)
		if len(w) == 0 || len(w) > MaxClueBytes {
			bad(where, fmt.Sprintf("a clue is a word of 1..%d bytes", MaxClueBytes), nil)
			continue
		}
		if !isTokenWord(w) {
			bad(where, "a clue is one word of [A-Za-z0-9._:/-] (no space, no control character)", nil)
			continue
		}
		if _, dup := seen[w]; dup {
			bad(where, "a clue is repeated", nil)
		}
		seen[w] = struct{}{}
	}
}

// isTokenWord reports whether every byte of w is a token byte (B7's TOKEN): w is one token.
func isTokenWord(w string) bool {
	for i := 0; i < len(w); i++ {
		if !isTokenByte(w[i]) {
			return false
		}
	}
	return true
}

// validateBlocks holds `blocks` to their shape (E1): at most MaxBlocks, each a file name of
// B2's grammar (the template's) and lines 1 <= from <= to, and no two blocks of one file
// overlapping (a line is in one block at most, so the order of a block is well defined). That
// the file is in the template, that the lines are in it and that every line has a time slot
// is E2's (specblocks.go).
func validateBlocks(blocks []Block, c *collector) {
	bad := func(i int, file, msg string) {
		v := newSpecViolation(RuleSpecShape, msg, 0, "", "", "", fmt.Sprintf("blocks[%d]", i), nil)
		v.File = shownName(file)
		c.add(v)
	}
	if len(blocks) > MaxBlocks {
		c.add(newSpecViolation(RuleSpecShape, fmt.Sprintf("edition.yaml declares more than %d blocks", MaxBlocks), 0, "", "", "", "blocks", nil))
		return
	}
	ranged := func(b Block) bool { return b.From != nil && b.To != nil && *b.From >= 1 && *b.From <= *b.To }
	for i, b := range blocks {
		if !ValidFileName(b.File) {
			bad(i, b.File, "a block's file is outside the grammar "+NamePattern)
		}
		if !ranged(b) {
			bad(i, b.File, "a block needs from and to with 1 <= from <= to (line numbers of its file)")
			continue
		}
		for j := 0; j < i; j++ {
			p := blocks[j]
			if p.File == b.File && ranged(p) && *b.From <= *p.To && *p.From <= *b.To {
				bad(i, b.File, fmt.Sprintf("the block overlaps blocks[%d] of the same file", j))
				break
			}
		}
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
