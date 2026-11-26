package edition_test

// ADR-0056 D10 B17 and B19 (amendments 27 to 31, A7-x PR 4 and 4b) and E2's clue lines ((e1) to
// (e4), amendment 31) on a synthetic edition: V111 (the lines of a group), the second half of
// (b17-1), (b17-3) (i) to (iv), V112 (3) (4) and V114 (a part of the clues leaves at least 2 x
// attempts values, in the lines of the group's shape). The edition is the two-step shape: a block
// of K + 1 lines that are the same but for their marks (time, the answer or a decoy, a key), and
// outside the blocks one clue line per key, the same but for its marks and its two clue columns.
// Every value is a placeholder.

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

const rsCID = "01-demo"

// rsQuestions is the one question of the synthetic edition: a timestamp of one attempt, so K = 4
// and B19's threshold is 2 x attempts = 2.
func rsQuestions() []catalog.Question {
	return rsQuestionsOf(1)
}

// rsQuestionsOf is the question with the given attempts.
func rsQuestionsOf(attempts int) []catalog.Question {
	w := int64(3600)
	return []catalog.Question{{ID: "q1", Format: answerformat.Timestamp, Attempts: attempts, Params: answerformat.Params{WindowSeconds: &w}}}
}

// rsOpts are the changes a case makes to the synthetic edition.yaml.
type rsOpts struct {
	noClues  bool
	noBlocks bool
	// k3 replaces the declaration of the filler k3 (the key of the third decoy's line), c2 that of
	// c2 (the time of the second decoy's clue line).
	k3 string
	c2 string
	// clues replaces the clues of when (alpha, sh).
	clues string
	// keyVocab replaces the vocabulary of every key (editiontest.KeyVocab).
	keyVocab string
}

// rsSpec is the synthetic edition.yaml: the answer `when` with 4 decoys and the clues alpha and
// sh, the keys k0..k4, the times of the clue lines c0..c4 (of another window than when's), two
// times n0 and n1 declared as when (its window), and one block over a.log.
func rsSpec(o rsOpts) string {
	var b strings.Builder
	b.WriteString("version: 1\ntime:\n  base: \"2001-01-01T00:00:00Z\"\nslots:\n")
	b.WriteString("  - name: when\n    role: answer\n    question: q1\n    decoys: 4\n    window: {from: 0, to: 3600}\n")
	switch {
	case o.clues != "":
		b.WriteString("    clues: " + o.clues + "\n")
	case !o.noClues:
		b.WriteString("    clues: [alpha, sh]\n")
	}
	keys := editiontest.KeyVocab
	if o.keyVocab != "" {
		keys = o.keyVocab
	}
	for i := range 5 {
		if i == 3 && o.k3 != "" {
			b.WriteString("  - " + o.k3 + "\n")
			continue
		}
		fmt.Fprintf(&b, "  - {name: k%d, role: filler, format: name, vocab: %s}\n", i, keys)
	}
	for i := range 5 {
		if i == 2 && o.c2 != "" {
			b.WriteString("  - " + o.c2 + "\n")
			continue
		}
		fmt.Fprintf(&b, "  - {name: c%d, role: filler, format: timestamp, window: {from: 3600, to: 7200}}\n", i)
	}
	for i := range 2 {
		fmt.Fprintf(&b, "  - {name: n%d, role: filler, format: timestamp, window: {from: 0, to: 3600}}\n", i)
	}
	if !o.noBlocks {
		b.WriteString("blocks:\n  - {file: a.log, from: 1, to: 5}\n")
	}
	return b.String()
}

// rsBlock is a.log: the block, one line for the answer and one for each decoy.
func rsBlock() string {
	var b strings.Builder
	b.WriteString("at {{ctf:when}} seen key {{ctf:k0}}\n")
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&b, "at {{ctf:when-d%d}} seen key {{ctf:k%d}}\n", i, i)
	}
	return b.String()
}

// rsClueWords are the words of the clue lines of the keys k0..k4 (the answer's first), the clue
// columns the second and the fourth word: the answer's (alpha, sh) holds both clues, line 1's the
// second, line 2's the first, line 3's neither (a square of four: every line of it shares a word of
// a clue column with two others, (b17-3) (iii) and (iv)), line 4's words of its own. Each clue
// alone leaves the answer and one decoy: 2 x attempts (B19). The decoys' clue columns hold words
// that are not declared (V111's green case).
var rsClueWords = []string{
	"container alpha proc sh",
	"container beta proc sh",
	"container alpha proc init",
	"container beta proc init",
	"container gamma proc cron",
}

// rsClues is b.log: the clue lines (one per key, with its own time) and the extra lines.
func rsClues(words []string, extra []string) string {
	var b strings.Builder
	for i, w := range words {
		fmt.Fprintf(&b, "at {{ctf:c%d}} key {{ctf:k%d}} %s\n", i, i, w)
	}
	for _, n := range extra {
		b.WriteString(n + "\n")
	}
	return b.String()
}

// rsWords is rsClueWords with line i's words replaced.
func rsWords(i int, words string) []string {
	w := slices.Clone(rsClueWords)
	w[i] = words
	return w
}

// rsRun is a parsed synthetic edition, its template, and what CheckRowRules gave for it.
type rsRun struct {
	spec *edition.Spec
	tmpl []edition.BundleFile
	rep  edition.RowReport
	err  error
}

// rsCheckOf parses the edition.yaml and applies CheckRowRules to the template a.log, b.log for the
// questions.
func rsCheckOf(t *testing.T, qs []catalog.Question, spec, block, clues string) rsRun {
	t.Helper()
	s, err := edition.ParseSpec([]byte(spec))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	r := rsRun{spec: s, tmpl: []edition.BundleFile{{Name: "a.log", Data: []byte(block)}, {Name: "b.log", Data: []byte(clues)}}}
	r.rep, r.err = s.CheckRowRules(rsCID, qs, r.tmpl)
	return r
}

// rsCheck is rsCheckOf for rsQuestions.
func rsCheck(t *testing.T, spec, block, clues string) rsRun {
	t.Helper()
	return rsCheckOf(t, rsQuestions(), spec, block, clues)
}

// rsNoValue fails if the error names a word of the template.
func rsNoValue(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, w := range []string{"alpha", "beta", "gamma", "root", "www", "seen", "init", "cron", "2001-01-01T"} {
		if strings.Contains(err.Error(), w) {
			t.Errorf("the error names a word of the template (%s): %v", w, err)
		}
	}
}

// The two-step edition is accepted by E2, B17 and B19 (V111's green case: the decoys' clue columns
// hold words that are not declared clues).
func TestRowRules_TheTwoStepEditionIsAccepted(t *testing.T) {
	r := rsCheck(t, rsSpec(rsOpts{}), rsBlock(), rsClues(rsClueWords, nil))
	if r.err != nil {
		t.Fatalf("CheckRowRules = %v; want the edition accepted", r.err)
	}
	if e2 := r.spec.CheckBlocksAndClues(rsCID, r.tmpl); e2 != nil {
		t.Fatalf("the fixture does not hold to E2: %v", e2)
	}
	if r.rep.AnswerSlots != 1 || r.rep.Blocks != 1 || r.rep.ClueSets != 2 {
		t.Errorf("report %+v; want one answer slot, one block, two subsets of the clues", r.rep)
	}
}

// E2 (e1): a group in a block with no clue is not an edition (amendment 31), so B19's "no clue,
// nothing to say" is left to a slot in no block, which B17 refuses.
func TestRowRules_ABlockGroupWithNoCluesIsRefusedByE2(t *testing.T) {
	r := rsCheck(t, rsSpec(rsOpts{noClues: true}), rsBlock(), rsClues(rsClueWords, nil))
	if !slices.Equal(rules(r.err), []string{edition.RuleRowSymmetry}) || !strings.Contains(fmt.Sprint(r.err), "does not hold to E2") {
		t.Errorf("CheckRowRules = %v; want B17 for an edition E2 refuses", r.err)
	}
	vs := sbViolations(r.spec.CheckBlocksAndClues(rsCID, r.tmpl))
	if len(vs) != 1 || vs[0].Rule != edition.RuleSpecQuestion || !strings.Contains(vs[0].Msg, "(e1)") {
		t.Errorf("E2 = %v; want one violation of (e1)", vs)
	}
}

// The one-step shape (clue words in the lines of the block) is refused by B17 (amendment 31): the
// lines of a block differ in their marks only.
func TestRowRules_TheOneStepShapeIsRefused(t *testing.T) {
	inBlock := []string{"sh", "alpha", "sh", "alpha", "sh"}
	var b strings.Builder
	b.WriteString("at {{ctf:when}} " + inBlock[0] + " key {{ctf:k0}}\n")
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&b, "at {{ctf:when-d%d}} %s key {{ctf:k%d}}\n", i, inBlock[i], i)
	}
	r := rsCheck(t, rsSpec(rsOpts{}), b.String(), rsClues(rsClueWords, nil))
	if !slices.Contains(rules(r.err), edition.RuleRowSymmetry) || !strings.Contains(fmt.Sprint(r.err), "differs from the line of the answer") {
		t.Errorf("clue words that differ between the lines of the block: %v; want B17", r.err)
	}
	rsNoValue(t, r.err)
}

// V111, (b17-1) and (b17-3): each change is refused by its rule, and names no word.
func TestRowRules_EachBrokenCopyIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		o      rsOpts
		block  func(string) string
		clues  func() string
		rule   string
		msg    string // a part of the message of the violation
		wantE2 bool   // E2 (CheckBlocksAndClues) refuses the copy too
	}{
		// V111 (1) (2)
		{name: "a fixed character of a decoy's line changed", block: func(s string) string {
			return strings.Replace(s, "{{ctf:when-d3}} seen", "{{ctf:when-d3}} seem", 1)
		}, rule: edition.RuleRowSymmetry, msg: "differs from the line of the answer"},
		{name: "the answer's mark once more on a line of no group (a block is declared)", clues: func() string {
			return rsClues(rsClueWords, []string{"late {{ctf:when}} again"})
		}, rule: edition.RuleRowSymmetry, msg: "does not hold to E2", wantE2: true},
		{name: "the group in no block", o: rsOpts{noBlocks: true}, rule: edition.RuleRowSymmetry, msg: "are in no block"},
		// V111 (3): the one-step shape
		{name: "a word of a decoy's line of the block made a declared clue", block: func(s string) string {
			return strings.Replace(s, "{{ctf:when-d3}} seen", "{{ctf:when-d3}} alpha", 1)
		}, rule: edition.RuleRowSymmetry, msg: "differs from the line of the answer"},
		// (b17-1)
		{name: "the answer line's key on one more line outside the blocks (two clue lines, E2 (e2))", clues: func() string {
			return rsClues(rsClueWords, []string{"extra {{ctf:k0}} copy"})
		}, rule: edition.RuleRowSymmetry, msg: "does not hold to E2", wantE2: true},
		{name: "a decoy's key of another length (E2's first half)", o: rsOpts{k3: "{name: k3, role: filler, format: hexid, length: 12}"},
			rule: edition.RuleRowSymmetry, msg: "does not hold to E2", wantE2: true},
		// V111 (4): (b17-3) (i), with words that are not declared
		{name: "two decoys' clue lines with one tuple of undeclared words", clues: func() string {
			return rsClues(rsWords(4, rsClueWords[3]), nil)
		}, rule: edition.RuleRowSymmetry, msg: "(b17-3) (i)"},
		// V111 (5): (b17-3) (iv), three clues (c x (2A - 1) = 3 <= K = 4); with two, (iv) follows from
		// (iii): no line shares both clue columns with the answer's ((ii)), so its sum is its count
		{name: "the answer's clue line at the most frequent word of every clue column", o: rsOpts{clues: "[alpha, sh, root]"}, clues: func() string {
			return rsClues([]string{
				"container alpha proc sh user root",
				"container alpha proc sh user www",
				"container alpha proc init user root",
				"container beta proc sh user root",
				"container alpha proc init user www",
			}, nil)
		}, rule: edition.RuleRowSymmetry, msg: "(b17-3) (iv)"},
		// V111 (6): (b17-3) (ii)
		{name: "a decoy's clue line with every declared clue, the columns swapped", clues: func() string {
			return rsClues(rsWords(3, "container sh proc alpha"), nil)
		}, rule: edition.RuleRowSymmetry, msg: "(b17-3) (ii)"},
		// (b17-3) (iii)
		{name: "the answer's clue line at the centre of a star", clues: func() string {
			return rsClues([]string{
				"container alpha proc sh",
				"container alpha proc init",
				"container beta proc sh",
				"container gamma proc cron",
				"container delta proc www",
			}, nil)
		}, rule: edition.RuleRowSymmetry, msg: "(b17-3) (iii)"},
		// V114
		{name: "a part of the clues leaves fewer than 2 x attempts values", clues: func() string {
			return rsClues(rsWords(1, "container beta proc www"), nil)
		}, rule: edition.RuleClueSpace, msg: "2 x attempts (2)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			block, clues := rsBlock(), rsClues(rsClueWords, nil)
			if c.block != nil {
				block = c.block(block)
			}
			if c.clues != nil {
				clues = c.clues()
			}
			r := rsCheck(t, rsSpec(c.o), block, clues)
			if !slices.Contains(rules(r.err), c.rule) || !strings.Contains(fmt.Sprint(r.err), c.msg) {
				t.Errorf("rules %v; want %s with %q: %v", rules(r.err), c.rule, c.msg, r.err)
			}
			if got := r.spec.CheckBlocksAndClues(rsCID, r.tmpl) != nil; got != c.wantE2 {
				t.Errorf("E2 refuses the copy: %v, want %v", got, c.wantE2)
			}
			rsNoValue(t, r.err)
		})
	}
}

// E2's clue lines (amendment 31, V112 (3) (4)) and the space of the keys ((e5), amendment 32):
// each copy is one violation of E2 that names its rule, refused by the renderer's and the
// validator's E2 alike, and so by B17 (not compared).
func TestCheckBlocksAndClues_ClueLines(t *testing.T) {
	cases := []struct {
		name  string
		o     rsOpts
		block string
		clues string
		code  string
	}{
		{"(e1) a group in a block with no clue (V112 (3))", rsOpts{noClues: true}, "", "", "(e1)"},
		{"(e2) a line of the group with no clue line", rsOpts{}, "", strings.Replace(rsClues(rsClueWords, nil), "key {{ctf:k4}}", "key none", 1), "(e2)"},
		{"(e2) two lines of the group share a key (one clue line of two lines)", rsOpts{},
			strings.Replace(rsBlock(), "{{ctf:when-d1}} seen key {{ctf:k1}}", "{{ctf:when-d1}} seen key {{ctf:k0}}", 1), "", "(e2)"},
		{"(e2) a line of the group with two clue lines", rsOpts{}, "", rsClues(rsClueWords, []string{"extra {{ctf:k0}} copy"}), "(e2)"},
		{"(e3) a declared clue that is not a word of the answer's clue line", rsOpts{clues: "[alpha, sh, cron]"}, "", "", "(e3)"},
		{"(e4) a word of a clue line that is not in a clue column changed (V112 (4))", rsOpts{}, "", rsClues(rsWords(2, "pod alpha proc init"), nil), "(e4)"},
		{"(e4) a mark in a clue column", rsOpts{}, "", rsClues(rsWords(2, "container {{ctf:n0}} proc init"), nil), "(e4)"},
		{"(e4) a mark of a clue line declared otherwise", rsOpts{c2: "{name: c2, role: filler, format: timestamp, window: {from: 7200, to: 10800}}"}, "", "", "(e4)"},
		{"(e4) a mark of a clue line that occurs once more", rsOpts{}, "", rsClues(rsClueWords, []string{"extra {{ctf:c3}} copy"}), "(e4)"},
		// (e5), amendment 32: 5 keys of a vocabulary of 4 words cannot be drawn apart in a seat.
		{"(e5) the keys of the block draw from fewer values than the block has keys", rsOpts{keyVocab: "[[ka, kb, kc, kd]]"}, "", "", "(e5)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			block, clues := c.block, c.clues
			if block == "" {
				block = rsBlock()
			}
			if clues == "" {
				clues = rsClues(rsClueWords, nil)
			}
			r := rsCheck(t, rsSpec(c.o), block, clues)
			err := r.spec.CheckBlocksAndClues(rsCID, r.tmpl)
			vs := sbViolations(err)
			if len(vs) != 1 || vs[0].Rule != edition.RuleSpecQuestion || !strings.Contains(vs[0].Msg, c.code) {
				t.Errorf("E2 = %v; want one violation of %s", err, c.code)
			}
			if !strings.Contains(fmt.Sprint(r.err), "does not hold to E2") {
				t.Errorf("CheckRowRules = %v; want B17 for an edition E2 refuses", r.err)
			}
			rsNoValue(t, err)
		})
	}
}

// B19 at its bound, 2 x attempts (amendment 31): with one attempt each clue alone leaves the answer
// and one decoy (2), and B19 is silent; with line 1's second clue gone, the second clue leaves the
// answer alone (1). With two attempts the threshold is 4, and the edition is refused.
func TestRowRules_B19AtItsBound(t *testing.T) {
	at := rsCheck(t, rsSpec(rsOpts{}), rsBlock(), rsClues(rsClueWords, nil))
	if slices.Contains(rules(at.err), edition.RuleClueSpace) || at.rep.ClueSets != 2 {
		t.Errorf("2 values for a threshold of 2: (%+v, %v); want two subsets counted and no B19", at.rep, at.err)
	}
	below := rsCheck(t, rsSpec(rsOpts{}), rsBlock(), rsClues(rsWords(1, "container beta proc www"), nil))
	if !slices.Contains(rules(below.err), edition.RuleClueSpace) || !strings.Contains(fmt.Sprint(below.err), "hold 1 values") {
		t.Errorf("1 value for a threshold of 2: %v; want B19, 1 value", below.err)
	}
	two := rsCheckOf(t, rsQuestionsOf(2), rsSpec(rsOpts{}), rsBlock(), rsClues(rsClueWords, nil))
	if !slices.Contains(rules(two.err), edition.RuleClueSpace) || !strings.Contains(fmt.Sprint(two.err), "2 x attempts (4)") {
		t.Errorf("two attempts: %v; want B19 with the threshold 4", two.err)
	}
}

// B19 counts in the lines of the group's shape only (amendment 31, security's condition): with
// line 1's second clue gone (1 value), a line of another shape that holds the clue and a mark
// declared as the answer adds nothing, nor does a line of the clue lines' shape whose words in
// the place of the marks are literal (a literal word is not counted); one of that shape with the
// mark declared as the answer at a mark's place adds one, and B19 is silent.
func TestRowRules_B19CountsOnlyTheGroupsShape(t *testing.T) {
	short := rsWords(1, "container beta proc www")
	cases := []struct {
		name    string
		extra   string
		refused bool
	}{
		{"nothing more", "", true},
		{"a noise line with the clue and a time declared as the answer", "noise {{ctf:n0}} sh", true},
		{"a line of the clue lines' shape with literal words at the marks", "at 2001-01-01T00:10:00Z key kz container delta proc sh", true},
		{"a line of the clue lines' shape with a time declared as the answer", "at {{ctf:n0}} key kz container delta proc sh", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var extra []string
			if c.extra != "" {
				extra = []string{c.extra}
			}
			r := rsCheck(t, rsSpec(rsOpts{}), rsBlock(), rsClues(short, extra))
			if got := slices.Contains(rules(r.err), edition.RuleClueSpace); got != c.refused {
				t.Errorf("B19 refuses: %v, want %v: %v", got, c.refused, r.err)
			}
		})
	}
}

// V114 (the positive side): with every clue, only the answer's clue line is left; with one clue
// fewer, two values (the threshold). The count of each subset is what B19 compared.
func TestRowRules_EveryClueSinglesOutTheAnswer(t *testing.T) {
	clues := rsClues(rsClueWords, nil)
	n := 0
	for _, ln := range strings.Split(clues, "\n") {
		if strings.Contains(ln, " alpha ") && strings.HasSuffix(ln, " sh") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d lines hold every clue, want 1 (the answer's clue line): the fixture does not test", n)
	}
	if r := rsCheck(t, rsSpec(rsOpts{}), rsBlock(), clues); r.err != nil {
		t.Errorf("CheckRowRules = %v; want it accepted", r.err)
	}
}
