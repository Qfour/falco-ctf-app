package edition_test

// ADR-0056 amendment 28 (as revised), the first PR of A7-x: edition.yaml's `blocks` and `clues`,
// their shape (E1, ParseSpec), their fit to the template (E2, Spec.CheckBlocksAndClues: one group
// in a block, one shape of its lines, a time slot of its own for each line), B8 (a2)'s bound for a
// group in a block (CheckSeatSpace), and the filler of one value (E2, CheckQuestions:
// speccheck_test.go's table). One case, one defect, and the one violation that must name it. What
// the renderer and B7 do with a block (A7-x PR 2) is block_test.go's; here, only that a block
// changes nothing outside its group and its lines. Every word, slot and line is a placeholder of
// no meaning. The text helpers (specDoc, ...) are spec_test.go's, the render helpers
// render_test.go's.

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

// sbGroup is the slots of the group of an answer slot with n decoys: the answer, then d1..dn.
func sbGroup(answer string, n int) []string {
	out := []string{answer}
	for j := 1; j <= n; j++ {
		out = append(out, fmt.Sprintf("%s-d%d", answer, j))
	}
	return out
}

// sbGroupLines is one line per slot of the group, f(i, slot) for the i-th (0-based).
func sbGroupLines(answer string, n int, f func(i int, slot string) string) []string {
	var out []string
	for i, s := range sbGroup(answer, n) {
		out = append(out, f(i, s))
	}
	return out
}

const sbHead = "begin 2000-01-01T05:00:00Z"

// sbDoc is specGoodDoc with one block over when's group in sbLines (lines 2 to 6 of log.txt)
// and one clue of when (pod-a, a literal word of line 2). when is a timestamp answer: the mark of
// its group is each line's time slot.
func sbDoc() specDoc {
	return specGoodDoc().
		withBlocks("[{file: log.txt, from: 2, to: 6}]").
		with(slotWhen, func(s *specSlot) { s.clues = "[pod-a]" })
}

// sbLines are the lines of log.txt: a literal time outside the block, then when's group.
func sbLines() []string {
	return append([]string{sbHead}, sbGroupLines("when", 4, func(i int, s string) string {
		return fmt.Sprintf("{{ctf:%s}} pod-%c shell", s, 'a'+i)
	})...)
}

// sbWhereLines are the lines of log.txt for where's group (a path answer): the head, then a line
// per slot of the group, its time slot a filler of its own (tick-1..5), a name filler and a hexid
// filler in the same words of every line.
func sbWhereLines() []string {
	return append([]string{sbHead}, sbGroupLines("where", 4, func(i int, s string) string {
		return fmt.Sprintf("{{ctf:tick-%d}} {{ctf:%s}} pod-%c {{ctf:other}} {{ctf:hx}}", i+1, s, 'a'+i)
	})...)
}

// sbWithFillers is d with the fillers added.
func sbWithFillers(d specDoc, fillers ...specSlot) specDoc {
	d.slots = append(slices.Clone(d.slots), fillers...)
	return d
}

func sbTick(name, window string) specSlot {
	return specSlot{name: name, role: "filler", format: "timestamp", window: window}
}

// sbKeyed is lines with the n lines of a block from line from (1-based) put in the two-step shape
// (ADR-0056 amendment 31): each ends with a key of its own (<kp>-k<i>), and the clue line of each
// key (its clue columns editiontest.ClueTuple of the group g, the answer's first) is added after
// the last line.
func sbKeyed(lines []string, g, kp string, from, n int) []string {
	out := slices.Clone(lines)
	for i := range n {
		out[from-1+i] += fmt.Sprintf(" {{ctf:%s-k%d}}", kp, i)
	}
	for i := range n {
		w1, w2 := editiontest.ClueTuple(g, i)
		out = append(out, fmt.Sprintf("clue {{ctf:%s-k%d}} %s %s", kp, i, w1, w2))
	}
	return out
}

// sbWithKeys is d with the clues of the answer slot of index i set to editiontest.Clues(g) and
// the keys <kp>-k0 .. <kp>-k<n-1> declared (sbKeyed's), of editiontest.KeyVocab (E2 (e5)).
func sbWithKeys(d specDoc, i int, g, kp string, n int) specDoc {
	d = d.with(i, func(s *specSlot) { s.clues = editiontest.Clues(g) })
	for j := range n {
		d = sbWithFillers(d, specSlot{name: fmt.Sprintf("%s-k%d", kp, j), role: "filler", format: "name", vocab: editiontest.KeyVocab})
	}
	return d
}

// sbKeyedDoc is sbDoc in the two-step shape: when's clues and keys wk-k0 .. wk-k4.
func sbKeyedDoc() specDoc {
	return sbWithKeys(sbDoc(), slotWhen, "when", "wk", 5)
}

// sbKeyedLines is sbLines in the two-step shape (sbKeyedDoc's).
func sbKeyedLines(lines []string) []string {
	return sbKeyed(lines, "when", "wk", 2, 5)
}

// sbWhereDoc is specGoodDoc with one block over where's group in sbWhereLines and its fillers:
// tick-1..tick-6 of one window and hx, a hexid of 12.
func sbWhereDoc() specDoc {
	d := specGoodDoc().withBlocks("[{file: log.txt, from: 2, to: 6}]")
	for j := 1; j <= 6; j++ {
		d = sbWithFillers(d, sbTick(fmt.Sprintf("tick-%d", j), "{from: 0, to: 3600}"))
	}
	return sbWithFillers(d, specSlot{name: "hx", role: "filler", format: "hexid", length: "12"})
}

// sbLinesWith is lines with line n (1-based) replaced by text, or text added after the last line
// when n is one more than their number.
func sbLinesWith(lines []string, n int, text string) []string {
	ls := slices.Clone(lines)
	if n == len(ls)+1 {
		return append(ls, text)
	}
	ls[n-1] = text
	return ls
}

// sbTemplate is the template of one file log.txt of the lines, each ended by a line feed.
func sbTemplate(lines []string) []edition.BundleFile {
	return []edition.BundleFile{sbFile("log.txt", lines)}
}

func sbFile(name string, lines []string) edition.BundleFile {
	return edition.BundleFile{Name: name, Data: []byte(strings.Join(lines, "\n") + "\n")}
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

// E1: one defect of `blocks` or of `clues`, one violation. Two blocks of one file that share a
// line are refused here, so a line is in one block at most and, with one group in a block (E2),
// of one group at most ((b17-2)).
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
		{"a clue that is not ASCII", clues(`["p` + "\xc3\xb6" + `d"]`)},
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

// E2: what fits the template is accepted. Every group in a block is in the two-step shape
// (amendment 31: (e1) to (e4)), its clue lines after the lines of the file.
func TestCheckBlocksAndClues_Accepts(t *testing.T) {
	when, where := sbLines(), sbWhereLines()
	withOther := append([]string{sbHead}, sbGroupLines("when", 4, func(i int, s string) string {
		return fmt.Sprintf("{{ctf:other}} {{ctf:%s}} pod-%c shell", s, 'a'+i)
	})...)
	twoGroups := append(slices.Clone(when), where[1:]...) // when's on lines 2-6, where's on 7-11
	whereDoc := sbWithKeys(sbWhereDoc(), slotWhere, "where", "rk", 5)
	cases := []struct {
		name string
		doc  specDoc
		tmpl []edition.BundleFile
	}{
		{"when's group in a block (the group's marks are the time slots)", sbKeyedDoc(), sbTemplate(sbKeyedLines(when))},
		{"where's group in a block (each line has a time filler of its own, of one window)", whereDoc, sbTemplate(sbKeyed(where, "where", "rk", 2, 5))},
		{"no blocks and no clues, whatever the template", specGoodDoc(), sbTemplate([]string{"x"})},
		{"a file whose last line has no line feed", sbKeyedDoc(), []edition.BundleFile{{Name: "log.txt", Data: []byte(strings.Join(sbKeyedLines(when), "\n"))}}},
		{"a literal time after the time slot", sbKeyedDoc(), sbTemplate(sbKeyedLines(sbLinesWith(when, 3, "{{ctf:when-d1}} pod-b 2000-01-01T00:00:01Z")))},
		{"the mark of a name slot, alone, before the time slot in every line", sbKeyedDoc(), sbTemplate(sbKeyedLines(withOther))},
		{"two groups, each in a block of its own, in one file",
			sbWithKeys(whereDoc.withBlocks("[{file: log.txt, from: 2, to: 6}, {file: log.txt, from: 7, to: 11}]"), slotWhen, "when", "wk", 5),
			sbTemplate(sbKeyed(sbKeyed(twoGroups, "when", "wk", 2, 5), "where", "rk", 7, 5))},
		{"one group in two blocks of two files (a block for each place it is written, each line with its own clue line)",
			sbWithKeys(sbKeyedDoc().withBlocks("[{file: log.txt, from: 2, to: 6}, {file: copy.txt, from: 1, to: 5}]"), slotWhen, "when", "ck", 5),
			append(sbTemplate(sbKeyedLines(when)), sbFile("copy.txt", sbKeyed(when[1:], "when", "ck", 1, 5)))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := sbCheck(t, c.doc, c.tmpl); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// E2: one defect, one violation. A line is reported once, for the first rule it breaks.
func TestCheckBlocksAndClues_Refusals(t *testing.T) {
	when, where := sbLines(), sbWhereLines()
	noClue := sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "" })
	// then is a second timestamp answer (of q4, which E2's CheckQuestions would refuse; this check
	// does not read the questions), so that its group's lines have the shape of when's.
	withThen := sbWithFillers(sbDoc(), specSlot{name: "then", role: "answer", question: "q4", decoys: "4", window: "{from: 0, to: 3600}"})
	cases := []struct {
		name string
		doc  specDoc
		tmpl []edition.BundleFile
	}{
		// the file and the lines
		{"a block names a file the template does not have", sbDoc().withBlocks("[{file: other.txt, from: 2, to: 6}]"), sbTemplate(when)},
		{"a block ends one line after its file", sbDoc().withBlocks("[{file: log.txt, from: 2, to: 7}]"), sbTemplate(when)},
		{"a block ends one line after a file whose last line has no line feed", sbDoc().withBlocks("[{file: log.txt, from: 2, to: 7}]"),
			[]edition.BundleFile{{Name: "log.txt", Data: []byte(strings.Join(when, "\n"))}}},
		{"the block's file has a mark outside the grammar", noClue, sbTemplate(sbLinesWith(when, 7, "{{ctf:Bad}}"))},

		// one group in a block
		{"a block takes in a line of no group", sbDoc().withBlocks("[{file: log.txt, from: 1, to: 6}]"), sbTemplate(when)},
		{"a block holds the lines of two groups", withThen, sbTemplate(sbLinesWith(when, 6, "{{ctf:then}} pod-e shell"))},
		{"a slot of the group is in no line of the block", sbDoc().withBlocks("[{file: log.txt, from: 2, to: 5}]"), sbTemplate(when[:5])},
		{"a slot of the group is in two lines of the block", sbWhereDoc().withBlocks("[{file: log.txt, from: 2, to: 7}]"),
			sbTemplate(sbLinesWith(where, 7, "{{ctf:tick-6}} {{ctf:where-d4}} pod-f {{ctf:other}} {{ctf:hx}}"))},
		{"a mark of the group is on a line outside its block", sbDoc(), sbTemplate(sbLinesWith(when, 7, "{{ctf:when-d2}} pod-z shell"))},

		// the time slot of a line
		{"a line of the block has no time slot", sbWhereDoc(), sbTemplate(sbLinesWith(where, 4, "{{ctf:other}} {{ctf:where-d2}} pod-c {{ctf:other}} {{ctf:hx}}"))},
		{"a literal time before the time slot", sbDoc(), sbTemplate(sbLinesWith(when, 3, "2000-01-01T00:00:01Z {{ctf:when-d1}} pod-b shell"))},
		{"the time slot glued to a token byte", sbDoc(), sbTemplate(sbLinesWith(when, 3, "at:{{ctf:when-d1}} pod-b shell"))},
		{"a glued mark of another slot before the time slot", sbDoc(), sbTemplate(sbLinesWith(when, 3, "x{{ctf:other}} {{ctf:when-d1}} pod-b shell"))},
		{"two lines share a time slot", sbWhereDoc(), sbTemplate(sbLinesWith(where, 4, "{{ctf:tick-2}} {{ctf:where-d2}} pod-c {{ctf:other}} {{ctf:hx}}"))},

		// one shape
		{"a line with another number of words", sbDoc(), sbTemplate(sbLinesWith(when, 4, "{{ctf:when-d2}} pod-c shell extra"))},
		{"the group's mark at another word", sbWhereDoc(), sbTemplate(sbLinesWith(where, 4, "{{ctf:where-d2}} {{ctf:tick-3}} pod-c {{ctf:other}} {{ctf:hx}}"))},
		{"a mark at another word", sbWhereDoc(), sbTemplate(sbLinesWith(where, 4, "{{ctf:tick-3}} {{ctf:where-d2}} {{ctf:other}} pod-c {{ctf:hx}}"))},
		{"a filler of another vocabulary at a word", sbWithFillers(sbWhereDoc(), specSlot{name: "alt", role: "filler", format: "name", vocab: "[[n0, n9]]"}),
			sbTemplate(sbLinesWith(where, 4, "{{ctf:tick-3}} {{ctf:where-d2}} pod-c {{ctf:alt}} {{ctf:hx}}"))},
		{"a filler of another length at a word", sbWithFillers(sbWhereDoc(), specSlot{name: "hx-long", role: "filler", format: "hexid", length: "16"}),
			sbTemplate(sbLinesWith(where, 4, "{{ctf:tick-3}} {{ctf:where-d2}} pod-c {{ctf:other}} {{ctf:hx-long}}"))},
		{"a time filler of another window at a word", sbWithFillers(sbWhereDoc(), sbTick("tock", "{from: 0, to: 60}")),
			sbTemplate(sbLinesWith(where, 4, "{{ctf:tock}} {{ctf:where-d2}} pod-c {{ctf:other}} {{ctf:hx}}"))},

		// clues
		{"a clue that is not in the template", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[pod-z]" }), sbTemplate(when)},
		{"a clue that is a part of a word", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[pod]" }), sbTemplate(when)},
		{"a clue that is a slot name inside a mark", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[when-d1]" }), sbTemplate(when)},
		{"a clue glued to a mark", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[pod-q]" }), sbTemplate(sbLinesWith(when, 7, "pod-q{{ctf:other}}"))},
		{"the sentinel as a clue that is not in the template", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[" + sentinel + "]" }), sbTemplate(when)},

		// the clue lines (amendment 31; the rest of their rules: rowsymmetry_test.go)
		{"a clue in another file of the template, not on the answer's clue line (e3)", sbKeyedDoc().with(slotWhen, func(s *specSlot) { s.clues = "[desk-x]" }),
			append(sbTemplate(sbKeyedLines(when)), sbFile("notes.txt", []string{"seen on desk-x"}))},
		{"a group in a block with no clue (e1)", sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "" }), sbTemplate(when)},
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

// (b17-2): a line that holds a slot of one group and a slot of another is refused at its line (it
// would be the answer's line of one group and a decoy's of the other). Its slot of the block's
// group is then not counted, so the block also misses it: both violations are E2.
func TestCheckBlocksAndClues_ALineOfTwoGroupsIsRefused(t *testing.T) {
	lines := sbLinesWith(sbWhereLines(), 3, "{{ctf:tick-2}} {{ctf:where-d1}} pod-b {{ctf:who}} {{ctf:hx}}")
	vs := sbViolations(sbCheck(t, sbWhereDoc(), sbTemplate(lines)))
	atLine3 := false
	for _, v := range vs {
		if v.Rule != edition.RuleSpecQuestion {
			t.Errorf("a violation of rule %s: %v", v.Rule, v)
		}
		atLine3 = atLine3 || v.Line == 3
	}
	if len(vs) == 0 || !atLine3 {
		t.Errorf("violations = %v, want one at line 3", vs)
	}
}

// A violation of a block names the block, the file and the line; one of a clue names the slot,
// its question and the clue's place.
func TestCheckBlocksAndClues_AViolationNamesItsPlace(t *testing.T) {
	lines := sbLinesWith(sbLines(), 4, "2000-01-01T00:00:01Z {{ctf:when-d2}} pod-c shell")
	v := sbWantOne(t, sbCheck(t, sbDoc(), sbTemplate(lines)), edition.RuleSpecQuestion)
	if v.At != "blocks[0]" || v.File != "log.txt" || v.Line != 4 {
		t.Errorf("at %q file %q line %d, want blocks[0] of log.txt, line 4", v.At, v.File, v.Line)
	}
	d := sbDoc().with(slotWhen, func(s *specSlot) { s.clues = "[pod-a, pod-z]" })
	v = sbWantOne(t, sbCheck(t, d, sbTemplate(sbLines())), edition.RuleSpecQuestion)
	if v.Slot != "when" || v.QID != "q4" || v.At != "slots[3].clues[1]" {
		t.Errorf("slot %q qid %q at %q, want when, q4, slots[3].clues[1]", v.Slot, v.QID, v.At)
	}
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

// sbRenderTemplate is the template of rdDoc's slots with when's group in c.txt, a line per slot
// (its first token a literal word, its mark alone, so each line's time slot is its own), and
// every other slot in a.txt, one line `<slot>={{ctf:<slot>}}` each. When the spec declares the
// keys wk0 .. (sbRenderKeys), each line of c.txt ends with its own, and k.txt holds the clue line
// of each (amendment 31's two-step shape). It returns the number of lines of c.txt.
func sbRenderTemplate(spec *edition.Spec) ([]edition.BundleFile, int) {
	keyed := slices.ContainsFunc(spec.Slots, func(s edition.Slot) bool { return s.Name == "wk0" })
	var a []string
	for _, s := range spec.Slots {
		if s.Name != "when" && !strings.HasPrefix(s.Name, "wk") {
			a = append(a, fmt.Sprintf("%s={{ctf:%s}}", s.Name, s.Name))
		}
	}
	var group []string
	for _, d := range spec.ImpliedDecoys {
		if d.DecoyOf != "when" {
			a = append(a, fmt.Sprintf("%s={{ctf:%s}}", d.Name, d.Name))
		} else {
			group = append(group, d.Name)
		}
	}
	c := sbGroupLines("when", len(group), func(i int, s string) string {
		if keyed {
			return fmt.Sprintf("%s={{ctf:%s}} pod-%d shell {{ctf:wk%d}}", s, s, i, i)
		}
		return fmt.Sprintf("%s={{ctf:%s}} pod-%d shell", s, s, i)
	})
	files := []edition.BundleFile{sbFile("a.txt", a), sbFile("c.txt", c)}
	if keyed {
		var k []string
		for i := range c {
			w1, w2 := editiontest.ClueTuple("when", i)
			k = append(k, fmt.Sprintf("clue {{ctf:wk%d}} %s %s", i, w1, w2))
		}
		files = append(files, sbFile("k.txt", k))
	}
	return files, len(c)
}

// sbRenderKeys is d with the keys wk0 .. wk<n-1> of sbRenderTemplate declared, all alike (E2 holds
// the keys at one word of the lines of a block to one declaration): hexids of 16 digits, a space of
// 16^16 (E2 (e5) asks n), in which n keys drawn as they come do not meet, so the keys of the block,
// which the renderer draws apart in a seat (amendment 32), are the ones drawn without the block.
func sbRenderKeys(d specDoc, n int) specDoc {
	for j := range n {
		d = sbWithFillers(d, specSlot{name: fmt.Sprintf("wk%d", j), role: "filler", format: "hexid", length: "16"})
	}
	return d
}

// sbLineTime is the time of a line of sbRenderTemplate's c.txt (`<slot>=<time> pod-<i> shell`).
func sbLineTime(t *testing.T, line string) string {
	t.Helper()
	_, rest, ok := strings.Cut(line, "=")
	fs := strings.Fields(rest)
	if !ok || len(fs) == 0 {
		t.Fatalf("a line of c.txt is not <slot>=<time> ...")
	}
	return fs[0]
}

// A block changes its own group and its own lines only (amendment 28 as revised, A7-x PR 2; this
// test was "blocks and clues do not change the output" while the renderer did not read them). The
// same edition with `blocks` and `clues` renders, for every seat, a.txt (no block) byte for byte
// as without them, and the rows of every question but the block's (q4) alike. The first seat,
// whom no earlier seat constrains (r1), gets the same values, and its block holds the same lines,
// put in the order of their times.
func TestRender_ABlockChangesOnlyItsGroupAndItsLines(t *testing.T) {
	_, n := sbRenderTemplate(rdSpec(t, rdDoc()))
	plain := sbRenderKeys(rdDoc(), n)
	tmpl, lines := sbRenderTemplate(rdSpec(t, plain))
	declared := plain.
		withBlocks(fmt.Sprintf("[{file: c.txt, from: 1, to: %d}]", lines)).
		with(slotWhen, func(s *specSlot) { s.clues = editiontest.Clues("when") })
	if spec := rdSpec(t, declared); len(spec.Blocks) != 1 || len(spec.Slots[slotWhen].Clues) != 2 || len(tmpl) != 3 {
		t.Fatal("the declared edition has no block, no clues or no clue lines: the test does not test")
	}
	run := func(d specDoc) *edition.Rendered {
		t.Helper()
		return rdRender(t, edition.RenderInput{
			CID: demoCID, Questions: rdQuestions(), Spec: rdSpec(t, d), Template: tmpl,
			Key: rdKey(t, rdKeyText), Seats: []string{"seat-a", "seat-b"}, Previous: edition.NoPreviousSeats(),
		})
	}
	a, b := run(plain), run(declared)
	if len(a.Rows) != len(b.Rows) || len(a.Bundles) != len(b.Bundles) {
		t.Fatalf("%d rows and %d bundles, %d and %d with blocks", len(a.Rows), len(a.Bundles), len(b.Rows), len(b.Bundles))
	}
	for i := range a.Rows {
		ra, rb := a.Rows[i], b.Rows[i]
		if (ra.QID != "q4" || ra.Seat == "seat-a") && ra != rb {
			t.Errorf("row %d (seat %s, %s) differs with a block", i, ra.Seat, ra.QID)
		}
	}
	for i := range a.Bundles {
		fa, fb := a.Bundles[i].Files, b.Bundles[i].Files
		if a.Bundles[i].Seat != b.Bundles[i].Seat || len(fa) != len(fb) {
			t.Fatalf("bundle %d differs in its seat or its number of files", i)
		}
		for j := range fa {
			if fa[j].Name != fb[j].Name {
				t.Fatalf("seat %s: file %d is named otherwise with a block", a.Bundles[i].Seat, j)
			}
			if fa[j].Name == "a.txt" && string(fa[j].Data) != string(fb[j].Data) {
				t.Errorf("seat %s, a.txt (no block): the bytes differ with a block", a.Bundles[i].Seat)
			}
			if fa[j].Name != "c.txt" || a.Bundles[i].Seat != "seat-a" {
				continue
			}
			want := strings.Split(strings.TrimSuffix(string(fa[j].Data), "\n"), "\n")
			slices.SortStableFunc(want, func(x, y string) int { return strings.Compare(sbLineTime(t, x), sbLineTime(t, y)) })
			if got := strings.Join(want, "\n") + "\n"; got != string(fb[j].Data) {
				t.Error("seat-a, c.txt: the block is not the same lines in the order of their times")
			}
			if string(fa[j].Data) == string(fb[j].Data) {
				t.Log("seat-a's lines of c.txt were in the order of their times already")
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

// B8 (a2) for a group in a block (amendment 28, as revised): S >= 2 x N x (k + 1), k the group's
// decoys (6 in rdDoc, above K = 4). With q4's window at 140 seconds, when's group in a block fits
// 10 seats (2 x 10 x 7 = 140) and not 11 (154); without the block, 2 x 11 = 22 fits. who (200
// words, in no block) keeps its bound of 2 x N.
func TestCheckSeatSpace_AGroupInABlockNeedsTwiceTheSeatsTimesTheGroup(t *testing.T) {
	plain := rdDoc()
	tmpl, lines := sbRenderTemplate(rdSpec(t, plain))
	blocked := rdSpec(t, plain.withBlocks(fmt.Sprintf("[{file: c.txt, from: 1, to: %d}]", lines)))
	qs := rdQuestions()
	qs[3].Params.WindowSeconds = specI64(140)
	if err := blocked.CheckSeatSpace(demoCID, qs, tmpl, 10, edition.RuleVocabSpace); err != nil {
		t.Errorf("10 seats, 140 <= 140: %v", err)
	}
	v := sbWantOne(t, blocked.CheckSeatSpace(demoCID, qs, tmpl, 11, edition.RuleVocabSpace), edition.RuleVocabSpace)
	if v.Slot != "when" {
		t.Errorf("the violation names slot %q, want when", v.Slot)
	}
	sbWantOne(t, blocked.CheckSeatSpace(demoCID, qs, tmpl, 11, edition.RuleSpecRender), edition.RuleSpecRender)
	if err := rdSpec(t, plain).CheckSeatSpace(demoCID, qs, tmpl, 11, edition.RuleVocabSpace); err != nil {
		t.Errorf("no block, 11 seats: %v", err)
	}
	if err := blocked.CheckSeatSpace(demoCID, rdQuestions(), tmpl, 100, edition.RuleVocabSpace); err != nil {
		t.Errorf("who in no block, 100 seats (2 x 100 = 200 words): %v", err)
	}
}

// A block whose group cannot be read (here its file is not in the template; E2 refuses it) holds
// every answer slot to the block's bound (fail-closed): who's 200 words are short for 15 seats
// (2 x 15 x 7 = 210) though 2 x 15 = 30 is not.
func TestCheckSeatSpace_ABlockThatCannotBeReadHoldsEveryAnswerToTheBlocksBound(t *testing.T) {
	plain := rdDoc()
	tmpl, _ := sbRenderTemplate(rdSpec(t, plain))
	unread := rdSpec(t, plain.withBlocks("[{file: missing.txt, from: 1, to: 1}]"))
	v := sbWantOne(t, unread.CheckSeatSpace(demoCID, rdQuestions(), tmpl, 15, edition.RuleVocabSpace), edition.RuleVocabSpace)
	if v.Slot != "who" {
		t.Errorf("the violation names %q, want who", v.Slot)
	}
	if err := rdSpec(t, plain).CheckSeatSpace(demoCID, rdQuestions(), tmpl, 15, edition.RuleVocabSpace); err != nil {
		t.Errorf("no block, 15 seats: %v", err)
	}
}
