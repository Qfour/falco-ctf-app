package edition_test

// ADR-0056 D10 B17 and B19 (amendments 27 and 28, A7-x PR 4) on a synthetic edition: V111 (the
// lines of a group), the second half of (b17-1) (the marks of a line occur as often as the
// answer's), (b17-3) (the combinations of clue words) and V114 (a part of the clues leaves at
// least k + 1 values). The edition is the two-step shape of the CTO's decision (2026-11-26): a
// block of K + 1 lines that are the same but for their marks (time, the answer or a decoy, a
// key), and outside the blocks one clue line per key, whose clue words tell the answer apart.
// Every value is a placeholder.

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

const rsCID = "01-demo"

// rsQuestions is the one question of the synthetic edition: a timestamp of one attempt, so K = 4
// and k + 1 = 5.
func rsQuestions() []catalog.Question {
	w := int64(3600)
	return []catalog.Question{{ID: "q1", Format: answerformat.Timestamp, Attempts: 1, Params: answerformat.Params{WindowSeconds: &w}}}
}

// rsOpts are the changes a case makes to the synthetic edition.yaml.
type rsOpts struct {
	noClues  bool
	noBlocks bool
	// k3 replaces the declaration of the filler k3 (the key of the third decoy's line).
	k3 string
	// clues replaces the clues of when (alpha, sh, root).
	clues string
}

// rsSpec is the synthetic edition.yaml: the answer `when` with 4 decoys and the clues alpha, sh and
// root, the keys k0..k4, the times of the clue lines c0..c4, and one block over a.log.
func rsSpec(o rsOpts) string {
	var b strings.Builder
	b.WriteString("version: 1\ntime:\n  base: \"2001-01-01T00:00:00Z\"\nslots:\n")
	b.WriteString("  - name: when\n    role: answer\n    question: q1\n    decoys: 4\n    window: {from: 0, to: 3600}\n")
	switch {
	case o.clues != "":
		b.WriteString("    clues: " + o.clues + "\n")
	case !o.noClues:
		b.WriteString("    clues: [alpha, sh, root]\n")
	}
	for i := range 5 {
		if i == 3 && o.k3 != "" {
			b.WriteString("  - " + o.k3 + "\n")
			continue
		}
		fmt.Fprintf(&b, "  - {name: k%d, role: filler, format: name, vocab: [[ka, kb, kc]]}\n", i)
	}
	for i := range 5 {
		fmt.Fprintf(&b, "  - {name: c%d, role: filler, format: timestamp, window: {from: 3600, to: 7200}}\n", i)
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

// rsClueWords are the words of the clue lines of the keys k0..k4: the answer's line holds the three
// clues, each decoy's another combination of them (so the answer's line shares a clue with four
// lines, and so does the line of k1).
var rsClueWords = []string{
	"container alpha proc sh user root",
	"container alpha proc sh user www",
	"container alpha proc init user root",
	"container beta proc sh user root",
	"container alpha proc init user www",
}

// rsNoise are lines outside the blocks with two of the clues and a literal time each: with one clue
// left out, the lines that hold the other two give the answer, one decoy, their two clue lines'
// times and this literal time, five values (k + 1).
var rsNoise = []string{
	"at 2001-01-01T03:00:01Z noise container alpha proc sh user www",
	"at 2001-01-01T03:00:02Z noise container alpha proc init user root",
	"at 2001-01-01T03:00:03Z noise container beta proc sh user root",
}

// rsClues is b.log: the clue lines (one per key, with its own time) and the noise.
func rsClues(words []string, noise []string) string {
	var b strings.Builder
	for i, w := range words {
		fmt.Fprintf(&b, "at {{ctf:c%d}} key {{ctf:k%d}} %s\n", i, i, w)
	}
	for _, n := range noise {
		b.WriteString(n + "\n")
	}
	return b.String()
}

// rsRun is a parsed synthetic edition, its template, and what CheckRowRules gave for it.
type rsRun struct {
	spec *edition.Spec
	tmpl []edition.BundleFile
	rep  edition.RowReport
	err  error
}

// rsCheck parses the edition.yaml and applies CheckRowRules to the template a.log, b.log.
func rsCheck(t *testing.T, spec, block, clues string) rsRun {
	t.Helper()
	s, err := edition.ParseSpec([]byte(spec))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	r := rsRun{spec: s, tmpl: []edition.BundleFile{{Name: "a.log", Data: []byte(block)}, {Name: "b.log", Data: []byte(clues)}}}
	r.rep, r.err = s.CheckRowRules(rsCID, rsQuestions(), r.tmpl)
	return r
}

// rsNoValue fails if the error names a word of the template.
func rsNoValue(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, w := range []string{"alpha", "beta", "root", "www", "seen", "2001-01-01T"} {
		if strings.Contains(err.Error(), w) {
			t.Errorf("the error names a word of the template (%s): %v", w, err)
		}
	}
}

func TestRowRules_TheTwoStepEditionIsAccepted(t *testing.T) {
	r := rsCheck(t, rsSpec(rsOpts{}), rsBlock(), rsClues(rsClueWords, rsNoise))
	if r.err != nil {
		t.Fatalf("CheckRowRules = %v; want the edition accepted", r.err)
	}
	if e2 := r.spec.CheckBlocksAndClues(rsCID, r.tmpl); e2 != nil {
		t.Fatalf("the fixture does not hold to E2: %v", e2)
	}
	if r.rep.AnswerSlots != 1 || r.rep.Blocks != 1 || r.rep.ClueSets != 3 {
		t.Errorf("report %+v; want one answer slot, one block, three subsets of the clues", r.rep)
	}
}

// B19 says nothing of a slot with no clue (the empty set has no proper subset), and B17 compares
// its block word for word.
func TestRowRules_NoCluesIsVacuousForB19(t *testing.T) {
	r := rsCheck(t, rsSpec(rsOpts{noClues: true}), rsBlock(), rsClues(rsClueWords, nil))
	if r.err != nil || r.rep.ClueSets != 0 || r.rep.Blocks != 1 {
		t.Errorf("CheckRowRules = (%+v, %v); want it accepted, one block compared, no subset counted", r.rep, r.err)
	}
}

// The clues may be in the block's lines (the one-step shape): a word where every line holds a
// clue may differ; a word that is not a clue may not.
func TestRowRules_CluesInTheBlockLines(t *testing.T) {
	inBlock := []string{"sh", "alpha", "root", "sh", "alpha"} // a clue of each line's own combination
	block := func(words []string) string {
		var b strings.Builder
		b.WriteString("at {{ctf:when}} " + words[0] + " key {{ctf:k0}}\n")
		for i := 1; i <= 4; i++ {
			fmt.Fprintf(&b, "at {{ctf:when-d%d}} %s key {{ctf:k%d}}\n", i, words[i], i)
		}
		return b.String()
	}
	if r := rsCheck(t, rsSpec(rsOpts{}), block(inBlock), rsClues(rsClueWords, rsNoise)); slices.Contains(rules(r.err), edition.RuleRowSymmetry) {
		t.Errorf("clue words that differ between the lines of the block were refused by B17: %v", r.err)
	}
	broken := slices.Clone(inBlock)
	broken[4] = "zeta"
	r := rsCheck(t, rsSpec(rsOpts{}), block(broken), rsClues(rsClueWords, rsNoise))
	if !slices.Contains(rules(r.err), edition.RuleRowSymmetry) {
		t.Errorf("a word that is not a clue and differs in one line of the block was not refused by B17: %v", r.err)
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
		// V111
		{name: "a fixed character of a decoy's line changed", block: func(s string) string {
			return strings.Replace(s, "{{ctf:when-d3}} seen", "{{ctf:when-d3}} seem", 1)
		}, rule: edition.RuleRowSymmetry, msg: "differs from the line of the answer"},
		{name: "the answer's mark once more on a line of no group (a block is declared)", clues: func() string {
			return rsClues(rsClueWords, rsNoise) + "late {{ctf:when}} again\n"
		}, rule: edition.RuleRowSymmetry, msg: "does not hold to E2", wantE2: true},
		{name: "the group in no block", o: rsOpts{noBlocks: true}, rule: edition.RuleRowSymmetry, msg: "are in no block"},
		// (b17-1)
		{name: "the answer line's key on one more line outside the blocks", clues: func() string {
			return rsClues(rsClueWords, rsNoise) + "extra {{ctf:k0}} copy\n"
		}, rule: edition.RuleRowSymmetry, msg: "another number of times"},
		{name: "a decoy's key of another length (E2's first half)", o: rsOpts{k3: "{name: k3, role: filler, format: hexid, length: 12}"},
			rule: edition.RuleRowSymmetry, msg: "does not hold to E2", wantE2: true},
		// (b17-3)
		{name: "two lines with one combination of clue words", clues: func() string {
			w := slices.Clone(rsClueWords)
			w[4] = "container alpha proc init user root"
			return rsClues(w, rsNoise)
		}, rule: edition.RuleRowSymmetry, msg: "same combination of clue words"},
		{name: "the answer's line at the centre of a star", clues: func() string {
			w := []string{rsClueWords[0], "container alpha proc init user www", "container beta proc sh user www", "container beta proc init user root", "container beta proc init user www"}
			return rsClues(w, rsNoise)
		}, rule: edition.RuleRowSymmetry, msg: "centre of the clues"},
		// V114
		{name: "a part of the clues leaves fewer than k + 1 values", clues: func() string {
			return rsClues(rsClueWords, rsNoise[1:])
		}, rule: edition.RuleClueSpace, msg: "below the decoys of the group + 1 (5)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			block, clues := rsBlock(), rsClues(rsClueWords, rsNoise)
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

// B19 at its bound (the review's R2#2): a slot of one clue has one proper subset, the empty one, so
// every line of the template is counted. With the answer and its 4 decoys and no other time, that is
// k + 1 = 5 values and B19 is silent; with one decoy's line gone (no block declares the group, so E2
// does not ask for it; B17 refuses that, and only B19 is looked at here), it is k = 4 and B19
// refuses.
func TestRowRules_B19AtItsBoundWithOneClue(t *testing.T) {
	var clueLines strings.Builder
	for i := range 5 {
		fmt.Fprintf(&clueLines, "key {{ctf:k%d}} user root\n", i)
	}
	full := rsBlock()
	short := strings.Replace(full, "at {{ctf:when-d4}} seen key {{ctf:k4}}\n", "", 1)
	if short == full {
		t.Fatal("the line of the fourth decoy was not taken out: the test does not test")
	}
	spec := rsSpec(rsOpts{noBlocks: true, clues: "[root]"})
	at := rsCheck(t, spec, full, clueLines.String())
	if slices.Contains(rules(at.err), edition.RuleClueSpace) || at.rep.ClueSets != 1 {
		t.Errorf("k + 1 values with the empty subset: (%+v, %v); want one subset counted and no B19", at.rep, at.err)
	}
	below := rsCheck(t, spec, short, clueLines.String())
	if !slices.Contains(rules(below.err), edition.RuleClueSpace) || !strings.Contains(fmt.Sprint(below.err), "hold 4 values") {
		t.Errorf("k values with the empty subset: %v; want B19, 4 values", below.err)
	}
}

// V114 (the positive side): with every clue, only the answer's clue line and its block line are
// left; with one clue fewer, five values or more. The count of each subset is what B19 compared.
func TestRowRules_EveryClueSinglesOutTheAnswer(t *testing.T) {
	clues := rsClues(rsClueWords, rsNoise)
	n := 0
	for _, ln := range strings.Split(clues, "\n") {
		if strings.Contains(ln, " alpha ") && strings.Contains(ln, " sh ") && strings.HasSuffix(ln, " root") {
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
