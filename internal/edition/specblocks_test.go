package edition_test

// ADR-0056 amendment 28, the first PR of A7-x: edition.yaml's `blocks` and `clues`, their shape
// (E1, ParseSpec) and their fit to the template (E2, Spec.CheckBlocksAndClues), and the filler of
// one value (E2, CheckQuestions: speccheck_test.go's table). One case, one defect, and the one
// violation that must name it. The renderer does not read `blocks` or `clues` yet: a render with
// them is byte for byte the render without them (render_test.go's helpers). Every word, slot and
// line is a placeholder of no meaning. The text helpers (specDoc, ...) are spec_test.go's.

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// sbDoc is specGoodDoc with one block over the five lines of when's group in sbLines (lines 2
// to 6 of log.txt) and one clue of when (pod-a, a literal word of line 2).
func sbDoc() specDoc {
	return specGoodDoc().
		withBlocks("[{file: log.txt, from: 2, to: 6}]").
		with(slotWhen, func(s *specSlot) { s.clues = "[pod-a]" })
}

// sbLines are the lines of log.txt: a literal time outside the block, and the answer and the
// four decoys of when, each line's first token its time slot.
func sbLines() []string {
	return []string{
		"begin 2000-01-01T05:00:00Z",
		"{{ctf:when}} pod-a shell",
		"{{ctf:when-d1}} pod-b shell",
		"{{ctf:when-d2}} pod-c shell",
		"{{ctf:when-d3}} pod-d shell",
		"{{ctf:when-d4}} pod-e shell",
	}
}

// sbLinesWith is sbLines with line n (1-based) replaced by text, or text added after the last
// line when n is one more than their number.
func sbLinesWith(n int, text string) []string {
	ls := sbLines()
	if n == len(ls)+1 {
		return append(ls, text)
	}
	ls[n-1] = text
	return ls
}

// sbTemplate is the template of one file log.txt of the lines, each ended by a line feed.
func sbTemplate(lines []string) []edition.BundleFile {
	return []edition.BundleFile{{Name: "log.txt", Data: []byte(strings.Join(lines, "\n") + "\n")}}
}

// sbWithTick is d with a timestamp filler tick of the window given.
func sbWithTick(d specDoc, window string) specDoc {
	d.slots = append(slices.Clone(d.slots), specSlot{name: "tick", role: "filler", format: "timestamp", window: window})
	return d
}

func sbCheck(t *testing.T, d specDoc, tmpl []edition.BundleFile) error {
	t.Helper()
	spec, err := edition.ParseSpec(d.yaml())
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	return spec.CheckBlocksAndClues(demoCID, tmpl)
}

// sbViolations is every *Violation inside err, in order.
func sbViolations(err error) []*edition.Violation {
	var out []*edition.Violation
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, x := range j.Unwrap() {
				walk(x)
			}
			return
		}
		var v *edition.Violation
		if errors.As(e, &v) {
			out = append(out, v)
		}
	}
	walk(err)
	return out
}

// sbWantOne fails unless err is exactly one violation of the rule.
func sbWantOne(t *testing.T, err error, rule string) *edition.Violation {
	t.Helper()
	vs := sbViolations(err)
	if len(vs) != 1 || vs[0].Rule != rule {
		t.Fatalf("violations = %v, want exactly one of %s", err, rule)
	}
	return vs[0]
}

func TestParseSpec_ReadsBlocksAndClues(t *testing.T) {
	spec, err := edition.ParseSpec(sbDoc().yaml())
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if len(spec.Blocks) != 1 {
		t.Fatalf("%d blocks, want 1", len(spec.Blocks))
	}
	if b := spec.Blocks[0]; b.File != "log.txt" || b.From == nil || *b.From != 2 || b.To == nil || *b.To != 6 {
		t.Errorf("block = %+v", b)
	}
	if got := spec.Slots[slotWhen].Clues; !slices.Equal(got, []string{"pod-a"}) {
		t.Errorf("when's clues = %v", got)
	}
	for _, d := range spec.ImpliedDecoys {
		if len(d.Clues) != 0 {
			t.Errorf("the implied decoy %s has clues: B17 reads its answer's", d.Name)
		}
	}
	// A file without the two keys is read as before.
	spec, err = edition.ParseSpec(specGoodDoc().yaml())
	if err != nil || len(spec.Blocks) != 0 || len(spec.Slots[slotWhen].Clues) != 0 {
		t.Errorf("a file without blocks and clues: %v, %d blocks", err, len(spec.Blocks))
	}
}

// sbManyBlocks is n one-line blocks of log.txt, on lines 1..n.
func sbManyBlocks(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("{file: log.txt, from: %d, to: %d}", i+1, i+1)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// E1: the shapes that are accepted, at their bounds.
func TestParseSpec_BlocksAndCluesAtTheirBounds(t *testing.T) {
	manyClues := func(n, size int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("%02d", i) + strings.Repeat("a", size-2)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	cases := []struct {
		name string
		doc  specDoc
	}{
		{"a one-line block", specGoodDoc().withBlocks("[{file: log.txt, from: 3, to: 3}]")},
		{"two blocks of one file that touch", specGoodDoc().withBlocks("[{file: log.txt, from: 1, to: 2}, {file: log.txt, from: 3, to: 4}]")},
		{"two blocks of two files on the same lines", specGoodDoc().withBlocks("[{file: a.txt, from: 1, to: 4}, {file: b.txt, from: 1, to: 4}]")},
		{"MaxBlocks blocks", specGoodDoc().withBlocks(sbManyBlocks(edition.MaxBlocks))},
		{"an empty list of blocks", specGoodDoc().withBlocks("[]")},
		{"MaxClues clues of MaxClueBytes bytes", specGoodDoc().with(slotWho, func(s *specSlot) { s.clues = manyClues(edition.MaxClues, edition.MaxClueBytes) })},
		{"a clue of every kind of token byte", specGoodDoc().with(slotWho, func(s *specSlot) { s.clues = `["Az09._:/-"]` })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := edition.ParseSpec(c.doc.yaml()); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// E1: one defect of `blocks` or of `clues`, one violation.
func TestParseSpec_RefusesBlocksAndClues(t *testing.T) {
	clues := func(v string) specDoc {
		return specGoodDoc().with(slotWho, func(s *specSlot) { s.clues = v })
	}
	cases := []struct {
		name string
		doc  specDoc
	}{
		// blocks
		{"a block with no file", specGoodDoc().withBlocks("[{from: 1, to: 2}]")},
		{"a block's file outside the grammar", specGoodDoc().withBlocks("[{file: Log.TXT, from: 1, to: 2}]")},
		{"a block's file with a slash", specGoodDoc().withBlocks("[{file: a/b.txt, from: 1, to: 2}]")},
		{"a block with no from", specGoodDoc().withBlocks("[{file: log.txt, to: 2}]")},
		{"a block with no to", specGoodDoc().withBlocks("[{file: log.txt, from: 1}]")},
		{"a block from line 0", specGoodDoc().withBlocks("[{file: log.txt, from: 0, to: 2}]")},
		{"a block whose from is above its to", specGoodDoc().withBlocks("[{file: log.txt, from: 3, to: 2}]")},
		{"two blocks of one file that share a line", specGoodDoc().withBlocks("[{file: log.txt, from: 1, to: 3}, {file: log.txt, from: 3, to: 5}]")},
		{"a block inside another of the same file", specGoodDoc().withBlocks("[{file: log.txt, from: 1, to: 9}, {file: log.txt, from: 3, to: 4}]")},
		{"more blocks than the limit", specGoodDoc().withBlocks(sbManyBlocks(edition.MaxBlocks + 1))},
		{"an unknown key in a block", specGoodDoc().withBlocks("[{file: log.txt, from: 1, to: 2, order: time}]")},
		{"blocks that is a mapping", specGoodDoc().withBlocks("{file: log.txt, from: 1, to: 2}")},
		{"a from that is a word", specGoodDoc().withBlocks("[{file: log.txt, from: one, to: 2}]")},

		// clues
		{"clues on a filler", specGoodDoc().with(slotOther, func(s *specSlot) { s.clues = "[pod-a]" })},
		{"an empty clue", clues(`[""]`)},
		{"a clue with a space", clues(`["pod a"]`)},
		{"a clue with a tab", clues(`["pod\ta"]`)},
		{"a clue with a control character", clues(`["pod\aa"]`)},
		{"a clue with a byte outside the token bytes", clues(`["pod=a"]`)},
		{"a clue that is not ASCII", clues(`["p` + "ö" + `d"]`)},
		{"a clue over the size limit", clues("[" + strings.Repeat("a", edition.MaxClueBytes+1) + "]")},
		{"a clue repeated", clues("[pod-a, pod-a]")},
		{"more clues than the limit", clues(specWords("c", edition.MaxClues+1))},
		{"clues that is a word", clues("pod-a")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := edition.ParseSpec(c.doc.yaml())
			sbWantOne(t, err, edition.RuleSpecShape)
		})
	}
}

// A violation of a clue names the slot and the clue's place, and never the clue.
func TestParseSpec_AClueViolationNamesItsPlaceNotTheClue(t *testing.T) {
	d := specGoodDoc().with(slotWhen, func(s *specSlot) { s.clues = "[" + sentinel + ", " + sentinel + "]" })
	_, err := edition.ParseSpec(d.yaml())
	v := sbWantOne(t, err, edition.RuleSpecShape)
	if v.Slot != "when" || v.At != "slots[3].clues[1]" {
		t.Errorf("slot %q at %q, want when at slots[3].clues[1]", v.Slot, v.At)
	}
	noSecret(t, "a repeated clue", err)

	_, err = edition.ParseSpec(specGoodDoc().withBlocks("[{file: log.txt, from: 1, to: 3}, {file: log.txt, from: 2, to: 4}]").yaml())
	v = sbWantOne(t, err, edition.RuleSpecShape)
	if v.At != "blocks[1]" || v.File != "log.txt" {
		t.Errorf("at %q file %q, want blocks[1] of log.txt", v.At, v.File)
	}
}

// E2: what fits the template is accepted.
func TestCheckBlocksAndClues_Accepts(t *testing.T) {
	cases := []struct {
		name string
		doc  specDoc
		tmpl []edition.BundleFile
	}{
		{"the example", sbDoc(), sbTemplate(sbLines())},
		{"no blocks and no clues, whatever the template", specGoodDoc(), sbTemplate([]string{"x"})},
		{"a file whose last line has no line feed", sbDoc(), []edition.BundleFile{{Name: "log.txt", Data: []byte(strings.Join(sbLines(), "\n"))}}},
		{"a literal time after the time slot", sbDoc(), sbTemplate(sbLinesWith(3, "{{ctf:when-d1}} pod-b 2000-01-01T00:00:01Z"))},
		{"the mark of a name slot, alone, before the time slot", sbDoc(), sbTemplate(sbLinesWith(3, "{{ctf:other}} {{ctf:when-d1}} pod-b shell"))},
		{"a filler time slot of the block's window", sbWithTick(sbDoc(), "{from: 0, to: 3600}"), sbTemplate(sbLinesWith(4, "{{ctf:tick}} pod-c shell"))},
		{"two blocks of one file", sbDoc().withBlocks("[{file: log.txt, from: 2, to: 3}, {file: log.txt, from: 4, to: 6}]"), sbTemplate(sbLines())},
		{"a clue in another file of the template", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[desk-x]" }),
			append(sbTemplate(sbLines()), edition.BundleFile{Name: "notes.txt", Data: []byte("seen on desk-x\n")})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := sbCheck(t, c.doc, c.tmpl); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// E2: one defect, one violation.
func TestCheckBlocksAndClues_Refusals(t *testing.T) {
	cases := []struct {
		name string
		doc  specDoc
		tmpl []edition.BundleFile
	}{
		// blocks
		{"a block names a file the template does not have", sbDoc().withBlocks("[{file: other.txt, from: 2, to: 6}]"), sbTemplate(sbLines())},
		{"a block ends one line after its file", sbDoc().withBlocks("[{file: log.txt, from: 2, to: 7}]"), sbTemplate(sbLines())},
		{"a block ends one line after a file whose last line has no line feed", sbDoc().withBlocks("[{file: log.txt, from: 2, to: 7}]"),
			[]edition.BundleFile{{Name: "log.txt", Data: []byte(strings.Join(sbLines(), "\n"))}}},
		{"a line of the block has no time slot", sbDoc(), sbTemplate(sbLinesWith(4, "pod-c shell"))},
		{"a line of the block has only the mark of a name slot", sbDoc(), sbTemplate(sbLinesWith(4, "{{ctf:other}} pod-c shell"))},
		{"a block takes in a line whose only time is literal", sbDoc().withBlocks("[{file: log.txt, from: 1, to: 6}]"), sbTemplate(sbLines())},
		{"a literal time before the time slot", sbDoc(), sbTemplate(sbLinesWith(3, "2000-01-01T00:00:01Z {{ctf:when-d1}} pod-b shell"))},
		{"the time slot glued to a token byte", sbDoc(), sbTemplate(sbLinesWith(3, "at:{{ctf:when-d1}} pod-b shell"))},
		{"a glued mark of another slot before the time slot", sbDoc(), sbTemplate(sbLinesWith(3, "x{{ctf:other}} {{ctf:when-d1}} pod-b shell"))},
		{"a time slot of another window", sbWithTick(sbDoc(), "{from: 0, to: 60}"), sbTemplate(sbLinesWith(4, "{{ctf:tick}} pod-c shell"))},
		// (no clue: a file the lexer refuses has no literal word either, which would be a second violation)
		{"the block's file has a mark outside the grammar", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "" }), sbTemplate(sbLinesWith(7, "{{ctf:Bad}}"))},

		// clues
		{"a clue that is not in the template", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[pod-z]" }), sbTemplate(sbLines())},
		{"a clue that is a part of a word", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[pod]" }), sbTemplate(sbLines())},
		{"a clue that is a slot name inside a mark", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[when-d1]" }), sbTemplate(sbLines())},
		{"a clue glued to a mark", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[pod-q]" }), sbTemplate(sbLinesWith(7, "pod-q{{ctf:other}}"))},
		{"the sentinel as a clue that is not in the template", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[" + sentinel + "]" }), sbTemplate(sbLines())},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := sbCheck(t, c.doc, c.tmpl)
			v := sbWantOne(t, err, edition.RuleSpecQuestion)
			if v.CID != demoCID {
				t.Errorf("the violation names cid %q, want %s", v.CID, demoCID)
			}
			noSecret(t, c.name, err)
		})
	}
}

// A violation of a block names the block, the file and the line; one of a clue names the slot,
// its question and the clue's place.
func TestCheckBlocksAndClues_AViolationNamesItsPlace(t *testing.T) {
	v := sbWantOne(t, sbCheck(t, sbDoc(), sbTemplate(sbLinesWith(4, "pod-c shell"))), edition.RuleSpecQuestion)
	if v.At != "blocks[0]" || v.File != "log.txt" || v.Line != 4 {
		t.Errorf("at %q file %q line %d, want blocks[0] of log.txt, line 4", v.At, v.File, v.Line)
	}
	d := sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[pod-a, pod-z]" })
	v = sbWantOne(t, sbCheck(t, d, sbTemplate(sbLines())), edition.RuleSpecQuestion)
	if v.Slot != "when" || v.QID != "q4" || v.At != "slots[3].clues[1]" {
		t.Errorf("slot %q qid %q at %q, want when, q4, slots[3].clues[1]", v.Slot, v.QID, v.At)
	}
}

// sbGroupFile is c.txt: one line per slot of when's group (the answer, then its decoys), its
// first token a literal word and its mark alone, so every line has a time slot of when's window.
func sbGroupFile(spec *edition.Spec) (edition.BundleFile, int) {
	var b strings.Builder
	n := 0
	add := func(name string) {
		fmt.Fprintf(&b, "%s={{ctf:%s}} pod-%d shell\n", name, name, n)
		n++
	}
	add("when")
	for _, d := range spec.ImpliedDecoys {
		if d.DecoyOf == "when" {
			add(d.Name)
		}
	}
	return edition.BundleFile{Name: "c.txt", Data: []byte(b.String())}, n
}

// This stage does not reorder a block: the same edition with `blocks` and `clues` renders to the
// same bundles and the same answer rows, for every seat, as without them.
func TestRender_BlocksAndCluesDoNotChangeTheOutput(t *testing.T) {
	plain := rdDoc()
	group, lines := sbGroupFile(rdSpec(t, plain))
	declared := plain.
		withBlocks(fmt.Sprintf("[{file: c.txt, from: 1, to: %d}]", lines)).
		with(slotWhen, func(s *specSlot) { s.clues = "[pod-0]" })
	if spec := rdSpec(t, declared); len(spec.Blocks) != 1 || len(spec.Slots[slotWhen].Clues) != 1 {
		t.Fatal("the declared edition has no block or no clue: the test does not test")
	}
	run := func(d specDoc) *edition.Rendered {
		t.Helper()
		spec := rdSpec(t, d)
		return rdRender(t, edition.RenderInput{
			CID: demoCID, Questions: rdQuestions(), Spec: spec, Template: append(rdTemplate(spec), group),
			Key: rdKey(t, rdKeyText), Seats: []string{"seat-a", "seat-b"}, Previous: edition.NoPreviousSeats(),
		})
	}
	a, b := run(plain), run(declared)
	if !slices.Equal(a.Rows, b.Rows) {
		t.Error("the answer rows differ with blocks and clues")
	}
	if len(a.Bundles) != len(b.Bundles) {
		t.Fatalf("%d bundles, %d with blocks and clues", len(a.Bundles), len(b.Bundles))
	}
	for i := range a.Bundles {
		fa, fb := a.Bundles[i].Files, b.Bundles[i].Files
		if a.Bundles[i].Seat != b.Bundles[i].Seat || len(fa) != len(fb) {
			t.Fatalf("bundle %d differs in its seat or its number of files", i)
		}
		for j := range fa {
			if fa[j].Name != fb[j].Name || string(fa[j].Data) != string(fb[j].Data) {
				t.Errorf("seat %s, file %s: the bytes differ with blocks and clues", a.Bundles[i].Seat, fa[j].Name)
			}
		}
	}
}

// The renderer holds the spec to E2 of `blocks` before it draws anything.
func TestRender_RefusesABlockOfAFileTheTemplateDoesNotHave(t *testing.T) {
	in := rdInput(t, "seat-a")
	in.Spec = rdSpec(t, rdDoc().withBlocks("[{file: missing.txt, from: 1, to: 1}]"))
	_, err := edition.Render(in)
	sbWantOne(t, err, edition.RuleSpecQuestion)
}

// A Spec that ParseSpec did not make is refused, not passed: a block without lines is E1.
func TestCheckBlocksAndClues_ASpecNotFromParseSpecIsRefused(t *testing.T) {
	var none *edition.Spec
	if err := none.CheckBlocksAndClues(demoCID, sbTemplate(sbLines())); err == nil {
		t.Error("a nil Spec was accepted")
	}
	hand := &edition.Spec{Blocks: []edition.Block{{File: "log.txt"}}}
	sbWantOne(t, hand.CheckBlocksAndClues(demoCID, sbTemplate(sbLines())), edition.RuleSpecShape)
}
