package edition_test

// ADR-0056 D12 and amendment 8 / D19 A4d-1a: edition.yaml's parser and D10 E1 (V61, V18's
// E1 part). One case, one defect, and the rule that must name it. Every word, slot and
// question is a placeholder of no meaning. The helpers (specDoc and its builders) are
// shared with the tests of A4d-1b, which build on this file and not the other way round.

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// specSlot is a slot as text: a field that is "" is not written.
type specSlot struct {
	name, role, question, decoys, format, length, vocab, window string
}

// specDoc is an edition.yaml as text. A version, base or fixed that is "" is not written.
type specDoc struct {
	version, base, fixed string
	slots                []specSlot
}

func (d specDoc) yaml() []byte {
	var b strings.Builder
	if d.version != "" {
		b.WriteString("version: " + d.version + "\n")
	}
	if d.base != "" {
		b.WriteString("time:\n  base: " + d.base + "\n")
	}
	if d.fixed != "" {
		b.WriteString("fixed: " + d.fixed + "\n")
	}
	if len(d.slots) == 0 {
		b.WriteString("slots: []\n")
		return []byte(b.String())
	}
	b.WriteString("slots:\n")
	for _, s := range d.slots {
		b.WriteString("  - name: " + s.name + "\n")
		for _, f := range [][2]string{
			{"role", s.role}, {"question", s.question}, {"decoys", s.decoys}, {"format", s.format},
			{"length", s.length}, {"vocab", s.vocab}, {"window", s.window},
		} {
			if f[1] != "" {
				b.WriteString("    " + f[0] + ": " + f[1] + "\n")
			}
		}
	}
	return []byte(b.String())
}

// with is a copy of d with f applied to slots[i].
func (d specDoc) with(i int, f func(*specSlot)) specDoc {
	d.slots = slices.Clone(d.slots)
	f(&d.slots[i])
	return d
}

// without is a copy of d without slots[i].
func (d specDoc) without(i int) specDoc {
	d.slots = slices.Delete(slices.Clone(d.slots), i, i+1)
	return d
}

// specWords is the flow list [<prefix>000, <prefix>001, ...]: n distinct words.
func specWords(prefix string, n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("%s%03d", prefix, i)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// specVocab is a vocab: a list of lists.
func specVocab(lists ...string) string { return "[" + strings.Join(lists, ", ") + "]" }

// Indexes of the slots of specGoodDoc.
const (
	slotWho = iota
	slotWhere
	slotTag
	slotWhen
	slotOther
)

// specGoodDoc is the minimal example of ADR-0056 amendment 8: four answer slots (a name,
// a path of 1 x 1 x 10 x 10 x 10, a hexid, a timestamp of an hour) with 4 decoys each, and
// a name filler. q1's vocabulary is 200 words, the least for 2 attempts.
func specGoodDoc() specDoc {
	return specDoc{
		version: "1",
		base:    `"2000-01-01T00:00:00Z"`,
		fixed:   "{}",
		slots: []specSlot{
			{name: "who", role: "answer", question: "q1", decoys: "4", vocab: specVocab(specWords("w", 200))},
			{name: "where", role: "answer", question: "q2", decoys: "4",
				vocab: specVocab("[opt]", "[x]", specWords("a", 10), specWords("b", 10), specWords("c", 10))},
			{name: "tag", role: "answer", question: "q3", decoys: "4"},
			{name: "when", role: "answer", question: "q4", decoys: "4", window: "{from: 0, to: 3600}"},
			{name: "other", role: "filler", format: "name", vocab: specVocab(specWords("n", 3))},
		},
	}
}

func specWantRules(t *testing.T, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want a refusal by %v", want)
	}
	if got := rules(err); !slices.Equal(got, want) {
		t.Errorf("rules = %v, want %v: %v", got, want, err)
	}
}

func TestParseSpec_AcceptsTheExample(t *testing.T) {
	spec, err := edition.ParseSpec(specGoodDoc().yaml())
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if spec.Version != 1 || spec.Time.Base != "2000-01-01T00:00:00Z" || len(spec.Fixed) != 0 || len(spec.Slots) != 5 {
		t.Errorf("version %d, base %q, %d fixed, %d slots", spec.Version, spec.Time.Base, len(spec.Fixed), len(spec.Slots))
	}
	if s := spec.Slots[slotWho]; s.Role != edition.RoleAnswer || s.Question != "q1" || s.Decoys == nil || *s.Decoys != 4 || s.Format != "" {
		t.Errorf("who = %+v", s)
	}
	if s := spec.Slots[slotOther]; s.Role != edition.RoleFiller || s.Format != "name" || s.DecoyOf != "" {
		t.Errorf("other = %+v", s)
	}
	if w := spec.Slots[slotWhen].Window; w == nil || *w.From != 0 || *w.To != 3600 {
		t.Errorf("when's window = %+v", w)
	}
}

// The decoys are an outcome of the parse: <name>-d1 .. -dn of every answer slot, in the
// order of the answer slots, inheriting the answer's question, vocabulary and window.
func TestParseSpec_ExpandsTheImpliedDecoys(t *testing.T) {
	spec, err := edition.ParseSpec(specGoodDoc().yaml())
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	var names []string
	for _, d := range spec.ImpliedDecoys {
		names = append(names, d.Name)
	}
	want := []string{
		"who-d1", "who-d2", "who-d3", "who-d4", "where-d1", "where-d2", "where-d3", "where-d4",
		"tag-d1", "tag-d2", "tag-d3", "tag-d4", "when-d1", "when-d2", "when-d3", "when-d4",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("implied decoys = %v, want %v", names, want)
	}
	d := spec.ImpliedDecoys[4] // where-d1
	if d.DecoyOf != "where" || d.Question != "q2" || len(d.Vocab) != 5 || d.Role != "" || d.Format != "" {
		t.Errorf("where-d1 = %+v", d)
	}
	if w := spec.ImpliedDecoys[12].Window; w == nil || *w.To != 3600 {
		t.Errorf("when-d1's window = %+v", w)
	}
	if len(spec.Slots) != 5 {
		t.Errorf("the decoys were added to Slots (%d)", len(spec.Slots))
	}
}

func TestParseSpec_TheBoundsAreExact(t *testing.T) {
	t.Run("a 27-byte answer name with 20 decoys: the longest decoy name is 31 bytes", func(t *testing.T) {
		name := strings.Repeat("a", edition.MaxAnswerSlotName)
		d := specGoodDoc().with(slotTag, func(s *specSlot) { s.name = name; s.decoys = "20" })
		spec, err := edition.ParseSpec(d.yaml())
		if err != nil {
			t.Fatalf("ParseSpec: %v", err)
		}
		longest := 0
		for _, dc := range spec.ImpliedDecoys {
			longest = max(longest, len(dc.Name))
		}
		if longest != 31 {
			t.Errorf("the longest decoy name is %d bytes, want 31", longest)
		}
	})
	t.Run("MaxSlots slots", func(t *testing.T) {
		var slots []specSlot
		for i := 0; i < edition.MaxSlots; i++ {
			slots = append(slots, specSlot{name: fmt.Sprintf("s%d", i), role: "filler", format: "name", vocab: specVocab(specWords("p", 1))})
		}
		if _, err := edition.ParseSpec(specDoc{version: "1", slots: slots}.yaml()); err != nil {
			t.Fatalf("%d slots were refused: %v", edition.MaxSlots, err)
		}
	})
	t.Run("decoys 1 and decoys MaxDecoys", func(t *testing.T) {
		for _, n := range []int{1, edition.MaxDecoys} {
			d := specGoodDoc().with(slotWho, func(s *specSlot) { s.decoys = fmt.Sprint(n) })
			if _, err := edition.ParseSpec(d.yaml()); err != nil {
				t.Errorf("decoys %d was refused: %v", n, err)
			}
		}
	})
	t.Run("a path of 255 bytes is the longest", func(t *testing.T) {
		path := func(n int) []byte {
			return specGoodDoc().with(slotOther, func(s *specSlot) {
				s.format = "path"
				s.vocab = specVocab("[" + strings.Repeat("a", n) + "]")
			}).yaml()
		}
		if _, err := edition.ParseSpec(path(254)); err != nil {
			t.Errorf("a path of 255 bytes was refused: %v", err)
		}
		_, err := edition.ParseSpec(path(255))
		specWantRules(t, err, edition.RuleSpecShape)
	})
	t.Run("a list of MaxVocabWords words and MaxVocabPositions lists", func(t *testing.T) {
		lists := make([]string, edition.MaxVocabPositions)
		for i := range lists {
			lists[i] = specWords("w", 2)
		}
		d := specGoodDoc().with(slotOther, func(s *specSlot) {
			s.format = "path"
			s.vocab = specVocab(lists...)
		})
		if _, err := edition.ParseSpec(d.yaml()); err != nil {
			t.Errorf("%d lists were refused: %v", edition.MaxVocabPositions, err)
		}
		d = specGoodDoc().with(slotOther, func(s *specSlot) { s.vocab = specVocab(specWords("w", edition.MaxVocabWords)) })
		if _, err := edition.ParseSpec(d.yaml()); err != nil {
			t.Errorf("%d words were refused: %v", edition.MaxVocabWords, err)
		}
	})
}

// V61: the file.
func TestParseSpec_RefusesTheFile(t *testing.T) {
	good := string(specGoodDoc().yaml())
	cases := []struct {
		name string
		in   []byte
	}{
		{"an empty file", []byte("")},
		{"comments only", []byte("# nothing here\n")},
		{"a null document", []byte("null\n")},
		{"invalid UTF-8", []byte("version: 1\n# \xff\n")},
		{"a bidi control character", []byte("version: 1\n# x" + string(rune(0x202e)) + "y\n")},
		{"a syntax error", []byte("version: [\n")},
		{"a file over the size limit", bytes.Repeat([]byte("#"), edition.MaxSpecBytes+1)},

		// V61: an unknown key at each depth.
		{"an unknown top-level key", []byte(strings.Replace(good, "fixed: {}\n", "fixed: {}\nextra: 1\n", 1))},
		{"an unknown key in a slot", []byte(strings.Replace(good, "    role: answer\n", "    role: answer\n    colour: red\n", 1))},
		{"an unknown key in a window", specGoodDoc().with(slotWhen, func(s *specSlot) { s.window = "{from: 0, to: 3600, step: 1}" }).yaml()},
		{"an unknown key in time", []byte(strings.Replace(good, "  base:", "  zone: utc\n  base:", 1))},
		{"a repeated top-level key", []byte(good + "version: 1\n")},
		{"a repeated key in a slot", []byte(strings.Replace(good, "    decoys: 4\n", "    decoys: 4\n    decoys: 4\n", 1))},

		// V61: version.
		{"no version", specGoodDoc().withVersion("").yaml()},
		{"version 2", specGoodDoc().withVersion("2").yaml()},
		{"version 0", specGoodDoc().withVersion("0").yaml()},
		{"a version that is a string", specGoodDoc().withVersion(`"1"`).yaml()},

		// V61: anchors, aliases, a second document.
		{"an anchor", specGoodDoc().with(slotWho, func(s *specSlot) { s.vocab = "&v " + specVocab(specWords("w", 200)) }).yaml()},
		{"an alias (with its anchor)", specGoodDoc().
			with(slotWho, func(s *specSlot) { s.vocab = "&v " + specVocab(specWords("w", 200)) }).
			with(slotOther, func(s *specSlot) { s.vocab = "*v" }).yaml()},
		{"a second document", []byte(good + "---\nversion: 1\n")},
		{"a merge key (an inline mapping, no anchor)", []byte(strings.Replace(good, "    role: answer\n", "    <<: {decoys: 4}\n    role: answer\n", 1))},
		{"more keys in fixed than the limit", specGoodDoc().withFixed(specFixedKeys(edition.MaxFixed + 1)).yaml()},

		// V61: the types.
		{"slots is a string", []byte("version: 1\nslots: nope\n")},
		{"a slot is a string", []byte("version: 1\nslots:\n  - nope\n")},
		{"a name that is a list", specGoodDoc().with(slotOther, func(s *specSlot) { s.name = "[a]" }).yaml()},
		{"a flat vocabulary", specGoodDoc().with(slotOther, func(s *specSlot) { s.vocab = "[a, b]" }).yaml()},
		{"fixed is a list", specGoodDoc().withFixed("[a]").yaml()},
		{"a window that is a number", specGoodDoc().with(slotWhen, func(s *specSlot) { s.window = "5" }).yaml()},

		// V61: the number of slots.
		{"no slot", specDoc{version: "1"}.yaml()},
		{"more slots than the limit", func() []byte {
			var slots []specSlot
			for i := 0; i <= edition.MaxSlots; i++ {
				slots = append(slots, specSlot{name: fmt.Sprintf("s%d", i), role: "filler", format: "name", vocab: specVocab(specWords("p", 1))})
			}
			return specDoc{version: "1", slots: slots}.yaml()
		}()},

		// time and fixed.
		{"a time.base that is not canonical", specGoodDoc().withBase(`"2000-01-01T00:00:00+00:00"`).yaml()},
		{"a time.base that is not a time", specGoodDoc().withBase(`"nope"`).yaml()},
		{"a time.base with a fraction", specGoodDoc().withBase(`"2000-01-01T00:00:00.5Z"`).yaml()},
		{"a key of fixed outside the id grammar", specGoodDoc().withFixed(`{Bad_Key: x}`).yaml()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, err := edition.ParseSpec(c.in)
			specWantRules(t, err, edition.RuleSpecShape)
			if spec != nil {
				t.Error("a Spec came back with the error")
			}
		})
	}
}

func (d specDoc) withVersion(v string) specDoc { d.version = v; return d }
func (d specDoc) withBase(v string) specDoc    { d.base = v; return d }
func (d specDoc) withFixed(v string) specDoc   { d.fixed = v; return d }

// V61 and V18: one slot with one defect (the edited slot is the filler unless a case
// says another).
func TestParseSpec_RefusesASlot(t *testing.T) {
	set := func(f func(*specSlot)) func(*specSlot) { return f }
	filler := func(format, vocab, length, window string) func(*specSlot) {
		return set(func(s *specSlot) { s.format, s.vocab, s.length, s.window = format, vocab, length, window })
	}
	lists17 := make([]string, edition.MaxVocabPositions+1)
	for i := range lists17 {
		lists17[i] = specWords("x", 2)
	}
	longWord := strings.Repeat("a", 100)

	cases := []struct {
		name string
		at   int
		f    func(*specSlot)
	}{
		// names
		{"no name", slotOther, set(func(s *specSlot) { s.name = "" })},
		{"a name outside the id grammar", slotOther, set(func(s *specSlot) { s.name = "Bad_Name" })},
		{"a name used twice", slotOther, set(func(s *specSlot) { s.name = "who" })},
		{"a 28-byte answer name", slotTag, set(func(s *specSlot) { s.name = strings.Repeat("a", edition.MaxAnswerSlotName+1) })},
		{"a filler named like an implied decoy (who-d1)", slotOther, set(func(s *specSlot) { s.name = "who-d1" })},

		// role
		{"no role", slotOther, set(func(s *specSlot) { s.role = "" })},
		{"a role of another case", slotOther, set(func(s *specSlot) { s.role = "Filler" })},
		{"a slot that declares a decoy", slotOther, set(func(s *specSlot) { s.role = "decoy"; s.question = "q1" })},
		{"a decoy written as an answer-like role", slotOther, set(func(s *specSlot) { s.role = "answer(q1)" })},

		// an answer slot
		{"an answer with a format", slotWho, set(func(s *specSlot) { s.format = "name" })},
		{"an answer with a length", slotTag, set(func(s *specSlot) { s.length = "12" })},
		{"an answer with no question", slotWho, set(func(s *specSlot) { s.question = "" })},
		{"an answer with a question outside the id grammar", slotWho, set(func(s *specSlot) { s.question = "Bad" })},
		{"an answer with no decoys", slotWho, set(func(s *specSlot) { s.decoys = "" })},
		{"an answer with 0 decoys", slotWho, set(func(s *specSlot) { s.decoys = "0" })},
		{"an answer with more decoys than the limit", slotWho, set(func(s *specSlot) { s.decoys = fmt.Sprint(edition.MaxDecoys + 1) })},
		{"an answer whose vocabulary has a path word with a slash", slotWho, set(func(s *specSlot) { s.vocab = specVocab("[a/b]") })},
		{"an answer whose vocabulary has too many lists", slotWho, set(func(s *specSlot) { s.vocab = specVocab(lists17...) })},
		{"an answer whose window has no to", slotWhen, set(func(s *specSlot) { s.window = "{from: 0}" })},

		// a filler
		{"a filler with a question", slotOther, set(func(s *specSlot) { s.question = "q1" })},
		{"a filler with decoys", slotOther, set(func(s *specSlot) { s.decoys = "4" })},
		{"a filler with no format", slotOther, filler("", specVocab(specWords("n", 3)), "", "")},
		{"a filler with an unknown format", slotOther, filler("regex", specVocab(specWords("n", 3)), "", "")},
		{"a filler of technique (cannot vary per seat)", slotOther, filler("technique", "", "", "")},
		{"a filler of choice-set (cannot vary per seat)", slotOther, filler("choice-set", "", "", "")},

		// vocabulary
		{"a name filler with no vocabulary", slotOther, filler("name", "", "", "")},
		{"a name vocabulary of two lists", slotOther, filler("name", specVocab(specWords("a", 3), specWords("b", 3)), "", "")},
		{"a name vocabulary with an empty list", slotOther, filler("name", "[[]]", "", "")},
		{"a list of more words than the limit", slotOther, filler("name", specVocab(specWords("a", edition.MaxVocabWords+1)), "", "")},
		{"an empty word", slotOther, filler("name", `[[""]]`, "", "")},
		{"a name word with a space inside", slotOther, filler("name", `[["a b"]]`, "", "")},
		{"a name word not in normalised form", slotOther, filler("name", `[[" a", b]]`, "", "")},
		{"a word twice in a list", slotOther, filler("name", "[[a, a]]", "", "")},
		{"a name word over 64 bytes", slotOther, filler("name", specVocab("["+strings.Repeat("a", 65)+"]"), "", "")},
		{"a path vocabulary of too many lists", slotOther, filler("path", specVocab(lists17...), "", "")},
		{"a path vocabulary with an empty list", slotOther, filler("path", specVocab(specWords("d", 3), "[]"), "", "")},
		{"a path word with a slash", slotOther, filler("path", specVocab("[a/b]", specWords("f", 3)), "", "")},
		{"an empty path word", slotOther, filler("path", specVocab(`[""]`, specWords("f", 3)), "", "")},
		{"a path word not in normalised form", slotOther, filler("path", `[["a "]]`, "", "")},
		{"a path longer than the format allows", slotOther, filler("path", specVocab("["+longWord+"]", "["+longWord+"]", "["+longWord+"]"), "", "")},
		{"a hexid filler with a vocabulary", slotOther, filler("hexid", specVocab(specWords("h", 3)), "12", "")},
		{"a timestamp filler with a vocabulary", slotOther, filler("timestamp", specVocab(specWords("h", 3)), "", "{from: 0, to: 60}")},

		// length
		{"a hexid filler with no length", slotOther, filler("hexid", "", "", "")},
		{"a hexid filler of length 11", slotOther, filler("hexid", "", "11", "")},
		{"a hexid filler of length 65", slotOther, filler("hexid", "", "65", "")},
		{"a name filler with a length", slotOther, filler("name", specVocab(specWords("n", 3)), "12", "")},
		{"a timestamp filler with a length", slotOther, filler("timestamp", "", "12", "{from: 0, to: 60}")},

		// window
		{"a timestamp filler with no window", slotOther, filler("timestamp", "", "", "")},
		{"a name filler with a window", slotOther, filler("name", specVocab(specWords("n", 3)), "", "{from: 0, to: 60}")},
		{"a hexid filler with a window", slotOther, filler("hexid", "", "12", "{from: 0, to: 60}")},
		{"a window with no from", slotOther, filler("timestamp", "", "", "{to: 60}")},
		{"a window with no to", slotOther, filler("timestamp", "", "", "{from: 0}")},
		{"a window that starts before 0", slotOther, filler("timestamp", "", "", "{from: -1, to: 60}")},
		{"a window with from equal to to", slotOther, filler("timestamp", "", "", "{from: 5, to: 5}")},
		{"a window with from above to", slotOther, filler("timestamp", "", "", "{from: 6, to: 5}")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := edition.ParseSpec(specGoodDoc().with(c.at, c.f).yaml())
			specWantRules(t, err, edition.RuleSpecShape)
		})
	}

	t.Run("a filler declared before the answer whose decoy it collides with", func(t *testing.T) {
		d := specGoodDoc()
		d.slots = append([]specSlot{{name: "who-d1", role: "filler", format: "name", vocab: specVocab(specWords("n", 3))}}, d.slots...)
		_, err := edition.ParseSpec(d.yaml())
		specWantRules(t, err, edition.RuleSpecShape)
	})
	t.Run("a timestamp slot with no time.base", func(t *testing.T) {
		_, err := edition.ParseSpec(specGoodDoc().withBase("").yaml())
		specWantRules(t, err, edition.RuleSpecShape)
	})
	t.Run("a timestamp filler with no time.base", func(t *testing.T) {
		d := specGoodDoc().withBase("").without(slotWhen).with(slotOther-1, filler("timestamp", "", "", "{from: 0, to: 60}"))
		_, err := edition.ParseSpec(d.yaml())
		specWantRules(t, err, edition.RuleSpecShape)
	})
	t.Run("no window needs no time.base", func(t *testing.T) {
		if _, err := edition.ParseSpec(specGoodDoc().withBase("").without(slotWhen).yaml()); err != nil {
			t.Errorf("a file with no timestamp slot and no time.base was refused: %v", err)
		}
	})
}

// A message names a rule, a slot and a position; it never carries a word of a
// vocabulary, nor the text yaml quotes when a value does not decode.
func TestParseSpec_MessagesCarryNoVocabularyWord(t *testing.T) {
	filler := func(format, vocab string) string {
		return string(specGoodDoc().with(slotOther, func(s *specSlot) { s.format = format; s.vocab = vocab }).yaml())
	}
	cases := []struct {
		name string
		in   string
	}{
		{"a value of the wrong type", "version: 1\nslots: " + sentinel + "\n"},
		{"an unknown key named like a word", "version: 1\n" + sentinel + ": 1\n"},
		{"a version that is the word", "version: " + sentinel + "\nslots: []\n"},
		{"a repeated word", filler("name", specVocab("["+sentinel+", "+sentinel+"]"))},
		{"a word not in normalised form", filler("name", specVocab(`["`+sentinel+` "]`))},
		{"a path word with a slash", filler("path", specVocab("["+sentinel+"/x]"))},
		{"a name, a role, a format and a question that are the word", string(specDoc{version: "1", slots: []specSlot{
			{name: sentinel, role: sentinel, question: sentinel, format: sentinel, vocab: specVocab("[" + sentinel + "]")},
		}}.yaml())},
		{"an answer with a question that is the word", string(specGoodDoc().with(slotWho, func(s *specSlot) { s.question = sentinel }).yaml())},
		{"a key of fixed that is the word", string(specGoodDoc().withFixed("{" + sentinel + ": x}").yaml())},
		{"a time.base that is the word", string(specGoodDoc().withBase(sentinel).yaml())},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := edition.ParseSpec([]byte(c.in))
			if err == nil {
				t.Fatal("accepted")
			}
			noSecret(t, c.name, err)
		})
	}
}

func TestParseSpec_ADecodeErrorKeepsOnlyItsLine(t *testing.T) {
	_, err := edition.ParseSpec([]byte("version: 1\nslots: " + sentinel + "\n"))
	var v *edition.Violation
	if !errors.As(err, &v) {
		t.Fatalf("not a *Violation: %v", err)
	}
	if v.Rule != edition.RuleSpecShape || v.Line != 2 {
		t.Errorf("violation = %s line %d, want %s line 2", v.Rule, v.Line, edition.RuleSpecShape)
	}
}

// A violation of a slot names the slot and the position in the file: the slot, the list,
// the word.
func TestParseSpec_AViolationNamesItsPosition(t *testing.T) {
	d := specGoodDoc().with(slotOther, func(s *specSlot) { s.vocab = "[[a, b, a]]" })
	_, err := edition.ParseSpec(d.yaml())
	var v *edition.Violation
	if !errors.As(err, &v) {
		t.Fatalf("not a *Violation: %v", err)
	}
	if v.Slot != "other" || v.At != "slots[4].vocab[0][2]" {
		t.Errorf("slot %q at %q, want other at slots[4].vocab[0][2]", v.Slot, v.At)
	}
	for _, part := range []string{"E1", "slot=other", "at=slots[4].vocab[0][2]"} {
		if !strings.Contains(v.Error(), part) {
			t.Errorf("%q is not in %q", part, v.Error())
		}
	}

	d = specGoodDoc().with(slotWhere, func(s *specSlot) { s.vocab = specVocab("[opt]", "[]") })
	_, err = edition.ParseSpec(d.yaml())
	if !errors.As(err, &v) || v.At != "slots[1].vocab[1]" {
		t.Errorf("an empty list: at %q (%v), want slots[1].vocab[1]", v.At, err)
	}
}

// specFixedKeys is a flow mapping of n keys (k1 .. kn), for the limit on fixed.
func specFixedKeys(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("k%d: x", i+1)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// The four kinds of slot defect a reader most often fixes (a name, a length, a window, a
// word) name the slot and the place.
func TestParseSpec_RepresentativeViolationsNameTheirSlotAndPlace(t *testing.T) {
	cases := []struct {
		name     string
		doc      specDoc
		slot, at string
	}{
		{"a name used twice", specGoodDoc().with(slotOther, func(s *specSlot) { s.name = "who" }), "who", "slots[4]"},
		{"a name too long for an answer", specGoodDoc().with(slotTag, func(s *specSlot) { s.name = strings.Repeat("a", edition.MaxAnswerSlotName+1) }),
			strings.Repeat("a", edition.MaxAnswerSlotName+1), "slots[2]"},
		{"a window with from equal to to", specGoodDoc().with(slotOther, func(s *specSlot) {
			s.format, s.vocab, s.window = "timestamp", "", "{from: 5, to: 5}"
		}), "other", "slots[4].window"},
		{"a word with a slash, in the second list", specGoodDoc().with(slotWhere, func(s *specSlot) { s.vocab = specVocab("[opt]", "[a/b]") }), "where", "slots[1].vocab[1][0]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := edition.ParseSpec(c.doc.yaml())
			var v *edition.Violation
			if !errors.As(err, &v) {
				t.Fatalf("not a *Violation: %v", err)
			}
			if v.Rule != edition.RuleSpecShape || v.Slot != c.slot || v.At != c.at {
				t.Errorf("violation = %s slot %q at %q, want E1 slot %q at %q", v.Rule, v.Slot, v.At, c.slot, c.at)
			}
		})
	}
}

// V18: K = max(2 x attempts, 4), and the bounds that are derived from it.
func TestDecoyKAndTheBoundsDerivedFromIt(t *testing.T) {
	for attempts, want := range map[int]int{1: 4, 2: 4, 3: 6, 5: 10, 10: 20} {
		if got := edition.DecoyK(attempts); got != want {
			t.Errorf("DecoyK(%d) = %d, want %d", attempts, got, want)
		}
	}
	if got := edition.DecoyK(answerformat.MaxAttempts); got != edition.MaxDecoys {
		t.Errorf("DecoyK(MaxAttempts) = %d, MaxDecoys = %d: a slot could not declare as many decoys as the largest K", got, edition.MaxDecoys)
	}
	// The longest answer name with the longest decoy suffix is an id; one byte more is not.
	suffix := fmt.Sprintf("-d%d", edition.MaxDecoys)
	if name := strings.Repeat("a", edition.MaxAnswerSlotName) + suffix; !answerformat.ValidID(name) {
		t.Errorf("a %d-byte name with the suffix %s (%d bytes) is not an id", edition.MaxAnswerSlotName, suffix, len(name))
	}
	if name := strings.Repeat("a", edition.MaxAnswerSlotName+1) + suffix; answerformat.ValidID(name) {
		t.Errorf("a %d-byte name with the suffix is an id: MaxAnswerSlotName is not the longest", edition.MaxAnswerSlotName+1)
	}
	if edition.MaxFixed != catalog.MaxQuestions {
		t.Errorf("MaxFixed = %d, catalog.MaxQuestions = %d", edition.MaxFixed, catalog.MaxQuestions)
	}
}

func TestParseSpec_TheFixedLimitIsExact(t *testing.T) {
	if _, err := edition.ParseSpec(specGoodDoc().withFixed(specFixedKeys(edition.MaxFixed)).yaml()); err != nil {
		t.Errorf("%d keys in fixed were refused: %v", edition.MaxFixed, err)
	}
}

// E1 holds the end of a window: base + to - 1, the last value, must be a second the
// timestamp format takes (year 9999 at the latest), and the sum must not overflow.
func TestParseSpec_AWindowMustEndWhereATimestampCanBeWritten(t *testing.T) {
	window := func(to string) func(*specSlot) {
		return func(s *specSlot) { s.window = "{from: 0, to: " + to + "}" }
	}
	cases := []struct {
		name, base, to string
		ok             bool
	}{
		{"the last second of year 9999 is the last value", `"9999-12-31T23:59:00Z"`, "60", true},
		{"one second past it", `"9999-12-31T23:59:00Z"`, "61", false},
		{"a base at the last second: a window of 1", `"9999-12-31T23:59:59Z"`, "1", true},
		{"a base at the last second: a window of 2", `"9999-12-31T23:59:59Z"`, "2", false},
		{"to at the largest int64 from an ordinary base", `"2000-01-01T00:00:00Z"`, "9223372036854775807", false},
		{"to at the largest int64 from the last second", `"9999-12-31T23:59:59Z"`, "9223372036854775807", false},
		// 8000 years from 2000-01-01 are 20 x 146097 days = 252455616000 seconds: the window
		// of that width ends at 9999-12-31T23:59:59, one second more does not fit.
		{"a window of exactly the 8000 years left from 2000", `"2000-01-01T00:00:00Z"`, "252455616000", true},
		{"a window one second longer", `"2000-01-01T00:00:00Z"`, "252455616001", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := specGoodDoc().withBase(c.base).with(slotWhen, window(c.to))
			_, err := edition.ParseSpec(d.yaml())
			if c.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			specWantRules(t, err, edition.RuleSpecShape)
			var v *edition.Violation
			if !errors.As(err, &v) || v.At != "slots[3].window" || v.Slot != "when" {
				t.Errorf("violation = %+v, want slot when at slots[3].window", v)
			}
		})
	}
}

// time.base may be written without quotes: yaml reads it as a timestamp, and the field
// keeps the text.
func TestParseSpec_AnUnquotedTimeBaseIsAccepted(t *testing.T) {
	spec, err := edition.ParseSpec(specGoodDoc().withBase("2000-01-01T00:00:00Z").yaml())
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if spec.Time.Base != "2000-01-01T00:00:00Z" {
		t.Errorf("time.base = %q", spec.Time.Base)
	}
}
