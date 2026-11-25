package edition_test

// ADR-0056 B17 and B19 end to end (A7-x PR 4, the review's R2#1 and R1#2): an event edition that
// declares clues, in the two-step shape (amendment 29): when's group is a block of K + 1 lines that
// are the same but for their marks (the time, the answer or a decoy, a key), and outside the blocks
// one clue line per key, whose clue words tell the answer apart, and a few lines of noise. The
// edition is editiontest's good one with when's group changed to that shape (4 decoys: K of one
// attempt, so k + 1 = 5). It goes through RenderEvent (the renderer's self check, B7's block form)
// and CheckEvent (B7's (o1) to (o3), B17, its (b17-3), B19); a clue line broken after its shape is
// refused by exactly the rule that names it. Every value is a placeholder.

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

// erClueWords are the words of the clue lines of the keys wk0..wk4 (the answer's first): the
// answer's holds the three clues, each decoy's another combination of them.
var erClueWords = []string{
	"container amber proc sh user root",
	"container amber proc sh user www",
	"container amber proc init user root",
	"container slate proc sh user root",
	"container amber proc init user www",
}

// erNoise are lines outside the blocks with two of the clues and a literal time each (after when's
// answer window, B16): with one clue left out, five values (k + 1) are left.
var erNoise = []string{
	"at 2001-01-01T05:00:01Z noise container amber proc sh user www",
	"at 2001-01-01T05:00:02Z noise container amber proc init user root",
	"at 2001-01-01T05:00:03Z noise container slate proc sh user root",
}

// erClueLine is the clue line of key j: its time, its key and its words.
func erClueLine(j int, words string) string {
	return fmt.Sprintf("clue at {{ctf:wc%d}} key {{ctf:wk%d}} %s", j, j, words)
}

// erClueSpec is editiontest's good edition.yaml with when's group of 4 decoys, its clues, the keys
// wk0..wk4 and the times of the clue lines wc0..wc4, and when's block over its 5 lines.
func erClueSpec(s string) string {
	s = strings.Replace(s, "    question: q4\n    decoys: 9\n", "    question: q4\n    decoys: 4\n    clues: [amber, sh, root]\n", 1)
	from, to := editiontest.BlockLines(editiontest.GoodDecoys, "when")
	s = strings.Replace(s, fmt.Sprintf("  - {file: %s, from: %d, to: %d}\n", editiontest.TemplateName, from, to),
		fmt.Sprintf("  - {file: %s, from: %d, to: %d}\n", editiontest.TemplateName, from, from+4), 1)
	var b strings.Builder
	for i := range 5 {
		fmt.Fprintf(&b, "  - {name: wk%d, role: filler, format: name, vocab: [[ka, kb, kc]]}\n", i)
		fmt.Fprintf(&b, "  - {name: wc%d, role: filler, format: timestamp, window: {from: 18000, to: 21600}}\n", i)
	}
	return strings.Replace(s, "blocks:\n", b.String()+"blocks:\n", 1)
}

// erClueTemplate is the template edit: when's block of 5 lines with their keys, the filler line,
// then the clue lines and the noise.
func erClueTemplate(clueLines, noise []string) func(string) string {
	return func(s string) string {
		i := strings.Index(s, "when record at {{ctf:when}}\n")
		if i < 0 {
			return s
		}
		var b strings.Builder
		b.WriteString(s[:i])
		b.WriteString("when record at {{ctf:when}} key {{ctf:wk0}}\n")
		for j := 1; j <= 4; j++ {
			fmt.Fprintf(&b, "when record at {{ctf:when-d%d}} key {{ctf:wk%d}}\n", j, j)
		}
		b.WriteString("side-note = {{ctf:other}}\n")
		for _, ln := range append(slices.Clone(clueLines), noise...) {
			b.WriteString(ln + "\n")
		}
		return b.String()
	}
}

// erGoodClueLines are the clue lines of the accepted edition.
func erGoodClueLines() []string {
	var out []string
	for j, w := range erClueWords {
		out = append(out, erClueLine(j, w))
	}
	return out
}

// erEdition is the spec and the template text of an edition with the given clue lines and noise,
// held to have been changed as meant (a replacement that missed would test nothing).
func erEdition(t *testing.T, clueLines, noise []string) (string, string) {
	t.Helper()
	spec := erClueSpec(editiontest.GoodSpec())
	tmpl := erClueTemplate(clueLines, noise)(editiontest.GoodTemplate())
	from, _ := editiontest.BlockLines(editiontest.GoodDecoys, "when")
	if !strings.Contains(spec, "clues: [amber, sh, root]") || !strings.Contains(spec, fmt.Sprintf("from: %d, to: %d}", from, from+4)) ||
		!strings.Contains(tmpl, "key {{ctf:wk4}}\nside-note") {
		t.Fatal("the edition was not changed to the two-step shape: the test does not test")
	}
	return spec, tmpl
}

// (a) RenderEvent makes the edition with clues and CheckEvent accepts its output.
func TestRenderEvent_AnEditionWithCluesGoesThroughTheSelfCheckAndTheCheck(t *testing.T) {
	spec, tmpl := erEdition(t, erGoodClueLines(), erNoise)
	f := newRfFix(t)
	f.tree.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.SpecFileName, spec)
	f.tree.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.TemplateDirName+"/"+editiontest.TemplateName, tmpl)
	ev, err := edition.RenderEvent(f.in)
	if err != nil || ev == nil {
		t.Fatalf("RenderEvent of an edition with clues = (%v, %v); want the event", ev, err)
	}
	checked, _, err := edition.CheckEvent(f.checkInput())
	if err != nil || checked == nil {
		t.Fatalf("CheckEvent of the output of an edition with clues = (%v, %v); want it accepted", checked, err)
	}
}

// (b) A clue line broken, rendered and checked: the rule that names it, and that rule alone.
func TestCheckEvent_ABrokenClueLineIsRefusedByItsRule(t *testing.T) {
	good := erGoodClueLines()
	cases := []struct {
		name  string
		lines []string
		noise []string
		rule  string
	}{
		{"accepted as it is", good, erNoise, ""},
		{"the noise of two clues taken out: fewer than k + 1 values with one clue left out", good, erNoise[1:], edition.RuleClueSpace},
		{"a decoy's clue line with the answer's clue words", func() []string {
			ls := slices.Clone(good)
			ls[1] = erClueLine(1, erClueWords[0])
			return ls
		}(), erNoise, edition.RuleRowSymmetry},
		{"a decoy's key taken off its clue line", func() []string {
			ls := slices.Clone(good)
			ls[4] = "clue at {{ctf:wc4}} key none " + erClueWords[4]
			return ls
		}(), erNoise, edition.RuleRowSymmetry},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, tmpl := erEdition(t, c.lines, c.noise)
			f := newCevFix(t, cevOpts{
				nameWords: editiontest.GoodNameWords,
				decoys:    editiontest.GoodDecoys,
				specEdit:  func(string) string { return spec },
				tmplEdit:  func(string) string { return tmpl },
			})
			if c.rule == "" {
				if ev, _, err := f.check(); err != nil || ev == nil {
					t.Fatalf("the edition with clues was refused: %v", err)
				}
				return
			}
			err, _ := f.refused(c.name)
			if got := cevRuleSet(err); !slices.Equal(got, []string{c.rule}) {
				t.Errorf("rules %v, want exactly [%s]: %v", got, c.rule, err)
			}
		})
	}
}
