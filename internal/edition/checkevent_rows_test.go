package edition_test

// ADR-0056 B17, B18 and B19 end to end (A7-x PR 4 and 4b, the review's R2#1 and R1#2): the good
// event edition (editiontest's) is in the two-step shape (amendments 29 and 31): each group is a
// block of K + 1 lines that are the same but for their marks (the time, the answer or a decoy, a
// key), and outside the blocks one clue line per key, whose clue columns tell the answer apart. It
// goes through RenderEvent (the renderer's self check: E2's (e1) to (e4), B7's block form) and
// CheckEvent (B7's (o1) to (o3), B17 and its (b17-3), B18, B19); a clue line broken after its
// shape is refused by exactly the rule that names it. Every value is a placeholder.

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

// erWithClueLine is the good template with the clue line of the j-th line of group g replaced by
// line, held to have been replaced (a replacement that missed would test nothing).
func erWithClueLine(t *testing.T, g string, j int, line string) string {
	t.Helper()
	tmpl, old := editiontest.GoodTemplate(), editiontest.ClueLine(g, j)+"\n"
	if !strings.Contains(tmpl, old) {
		t.Fatal("the good template has no such clue line: the test does not test")
	}
	return strings.Replace(tmpl, old, line+"\n", 1)
}

// (a) RenderEvent makes the edition with clues and CheckEvent accepts its output.
func TestRenderEvent_AnEditionWithCluesGoesThroughTheSelfCheckAndTheCheck(t *testing.T) {
	f := newRfFix(t)
	f.tree.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.SpecFileName, editiontest.GoodSpec())
	f.tree.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.TemplateDirName+"/"+editiontest.TemplateName, editiontest.GoodTemplate())
	ev, err := edition.RenderEvent(f.in)
	if err != nil || ev == nil {
		t.Fatalf("RenderEvent of an edition with clues = (%v, %v); want the event", ev, err)
	}
	checked, _, err := edition.CheckEvent(f.checkInput())
	if err != nil || checked == nil {
		t.Fatalf("CheckEvent of the output of an edition with clues = (%v, %v); want it accepted", checked, err)
	}
}

// (b) A clue line of when's group broken, rendered and checked: the rule that names it, and that
// rule alone. Line 1's clue line holds the second clue (when-cb), so that without the first one
// the answer and line 1 are left: 2 x attempts.
func TestCheckEvent_ABrokenClueLineIsRefusedByItsRule(t *testing.T) {
	cases := []struct {
		name string
		tmpl string
		rule string
	}{
		{"accepted as it is", editiontest.GoodTemplate(), ""},
		{"a decoy's clue line with the answer's clue words ((b17-3) (i) and (ii))",
			erWithClueLine(t, "when", 1, "when clue key {{ctf:when-k1}} by when-ca at when-cb"), edition.RuleRowSymmetry},
		{"line 1's second clue taken away: the second clue alone leaves the answer only (B19)",
			erWithClueLine(t, "when", 1, "when clue key {{ctf:when-k1}} by when-x1 at when-z1"), edition.RuleClueSpace},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCevFix(t, cevOpts{
				nameWords: editiontest.GoodNameWords,
				decoys:    editiontest.GoodDecoys,
				tmplEdit:  func(string) string { return c.tmpl },
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

// (b') A decoy's key taken off its clue line: the line of the block has no clue line, so the
// edition is not one (E2 (e2), the bijection of amendment 31). E2 is what the renderer holds an
// edition to before it draws (render.go), so this copy cannot be rendered, nor checked: it is
// refused as one violation of E2, naming (e2) and no word.
func TestCheckEvent_AKeyTakenOffItsClueLineIsE2(t *testing.T) {
	tmpl := erWithClueLine(t, "when", 4, strings.Replace(editiontest.ClueLine("when", 4), "{{ctf:when-k4}}", "none", 1))
	spec, err := edition.ParseSpec([]byte(editiontest.GoodSpec()))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if err := spec.CheckBlocksAndClues(demoCID, []edition.BundleFile{{Name: editiontest.TemplateName, Data: []byte(editiontest.GoodTemplate())}}); err != nil {
		t.Fatalf("the good edition does not hold to E2: %v", err)
	}
	err = spec.CheckBlocksAndClues(demoCID, []edition.BundleFile{{Name: editiontest.TemplateName, Data: []byte(tmpl)}})
	vs := sbViolations(err)
	if len(vs) != 1 || vs[0].Rule != edition.RuleSpecQuestion || !strings.Contains(vs[0].Msg, "(e2)") || vs[0].Slot != "when" {
		t.Errorf("E2 = %v; want one violation of (e2) at when's group", err)
	}
	rsNoValue(t, err)
}

// (c) B18 through CheckEvent (V112, A7-x PR 4b): the image's practice edition (render-golden)
// declares the clue t of q4 on its answer's line, which the event's clue words (when-ca, when-cb)
// do not hold, so the good event is accepted. With the practice's clue of q4 made when-ca (a word
// the event's answer combination holds), or the practice's edition.yaml missing, not parsing or
// declaring no clue of q4 (fail-closed), the event is refused by B18 alone.
func TestCheckEvent_B18IsWired(t *testing.T) {
	specRel := "challenges/" + demoCID + "/" + edition.EditionDirName + "/" + edition.SpecFileName
	tmplRel := "challenges/" + demoCID + "/" + edition.EditionDirName + "/" + edition.TemplateDirName + "/a.txt"
	replaced := func(f *cevFix, rel, old, repl string) {
		f.t.Helper()
		s := f.read(rel)
		if !strings.Contains(s, old) {
			f.t.Fatalf("%s does not hold %q: the test does not test", rel, old)
		}
		f.put(rel, strings.Replace(s, old, repl, 1))
	}
	cases := []struct {
		name   string
		mutate func(f *cevFix)
	}{
		{"the practice's clue of q4 is a clue word of the event's answer", func(f *cevFix) {
			replaced(f, specRel, "    clues: [t]\n", "    clues: [when-ca]\n")
			replaced(f, tmplRel, "t={{ctf:when}}\n", "t={{ctf:when}} when-ca\n")
		}},
		{"the practice's edition.yaml is missing", func(f *cevFix) {
			if err := os.Remove(f.path(specRel)); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"the practice's edition.yaml does not parse", func(f *cevFix) {
			f.put(specRel, "x: y\n")
		}},
		{"the practice declares no clue of q4", func(f *cevFix) {
			replaced(f, specRel, "    clues: [t]\n", "")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newGoodCevFix(t)
			if ev, _, err := f.check(); err != nil || ev == nil {
				t.Fatalf("the event was refused before the practice edition was changed: %v", err)
			}
			c.mutate(f)
			err, _ := f.refused(c.name)
			if got := cevRuleSet(err); !slices.Equal(got, []string{edition.RulePracticeClues}) {
				t.Errorf("rules %v, want exactly [B18]: %v", got, err)
			}
		})
	}
}
