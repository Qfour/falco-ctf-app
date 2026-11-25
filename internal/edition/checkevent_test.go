package edition_test

// ADR-0056 D20, amendment 12, D19 A4e-2: CheckEvent. V86 (each check broken one at a time: no
// *CheckedEvent, an error, and the CheckReport still returned), V75 (B10), V77 (B8 (a2)), V72
// (a scope with no investigate challenge), V87 (the output that already exists, the input that
// is a FIFO) and the digests file of an accepted event. The positive fixture is the renderer's
// own output (checkevent_helpers_test.go), so every case below changes one thing in an event
// that is otherwise accepted.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

func TestCheckEvent_AcceptsAnEventThatEveryCheckAccepts(t *testing.T) {
	f := newGoodCevFix(t)
	ev, report, err := f.check()
	if err != nil || ev == nil {
		t.Fatalf("CheckEvent = (%v, _, %v); want the event", ev, err)
	}
	if ev.RunID() != runA || ev.Seats() != 3 || ev.Challenges() != 1 {
		t.Errorf("event = run id %q, %d seats, %d challenges; want %q, 3, 1", ev.RunID(), ev.Seats(), ev.Challenges(), runA)
	}
	rows := ev.Rows()
	if len(rows) != 3 || !slices.IsSortedFunc(rows, func(a, b edition.DigestRow) int { return strings.Compare(a.Seat+"/"+a.CID, b.Seat+"/"+b.CID) }) {
		t.Errorf("rows = %v; want one per seat, in byte order", rows)
	}
	if !report.OverlapRan || report.Overlap.Output.Compared == 0 || report.Overlap.Template.Compared == 0 {
		t.Errorf("report = %+v; want B4 to have run and compared both sides", report)
	}
	if report.Overlap.Output.Rate >= edition.OverlapTheta || report.Overlap.Template.Rate >= edition.OverlapTheta {
		t.Errorf("the overlaps are %v and %v; the fixture is meant to be nothing like the practice edition", report.Overlap.Output.Rate, report.Overlap.Template.Rate)
	}
}

func TestCheckEvent_TheDigestsFileOfAnAcceptedEvent(t *testing.T) {
	f := newGoodCevFix(t)
	ev, _, err := f.check()
	if err != nil {
		t.Fatalf("CheckEvent: %v", err)
	}
	if left, err := edition.WriteDigestsFile(f.in.DigestsOut, ev); err != nil || len(left) != 0 {
		t.Fatalf("WriteDigestsFile: (%v, %v), want no name left and no error", left, err)
	}
	info, err := os.Stat(f.in.DigestsOut)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the digests file: %v, %v; want a file of mode 0600", info, err)
	}
	data := []byte(f.read("out/digests.tsv"))
	id, rows, err := edition.ParseDigests(data)
	if err != nil || id != runA || !slices.Equal(rows, ev.Rows()) {
		t.Errorf("the file reads back as (%q, %v, %v); want the event's run id and rows", id, rows, err)
	}
	// V87: the output that already exists is refused and stays as it was, and nothing is left
	// beside it.
	if _, err := edition.WriteDigestsFile(f.in.DigestsOut, ev); !errors.Is(err, edition.ErrOutputExists) || !isInputErr(err) {
		t.Errorf("a second write = %v, want an *InputError of ErrOutputExists (exit 2)", err)
	}
	if got := f.read("out/digests.tsv"); got != string(data) {
		t.Error("the existing digests file changed")
	}
	if names := listNames(t, f.path("out")); !slices.Equal(names, []string{"digests.tsv"}) {
		t.Errorf("the output directory holds %v; want the digests file only", names)
	}
	// a destination in a directory that does not exist: an error, nothing made
	if _, err := edition.WriteDigestsFile(f.path("out/missing/digests.tsv"), ev); err == nil {
		t.Error("a destination in a missing directory was written")
	}
	if _, err := edition.WriteDigestsFile(f.path("out/other.tsv"), nil); err == nil {
		t.Error("a nil event was written")
	}
	if names := listNames(t, f.path("out")); !slices.Equal(names, []string{"digests.tsv"}) {
		t.Errorf("after the refusals the output directory holds %v; want the digests file only", names)
	}
}

// V87 and V92 (ADR-0056 D20, amendment 13 as revised): the writer of --digests-out, after every
// check passed, around its commit point (the link). Before it, a failure is an
// *edition.OutputError (exit 3) and nothing is at --digests-out; a cleanup that fails too lists
// the temporary name, and the same write given again succeeds. After it, a temporary name that
// cannot be removed is a warning, and the file holds the expected bytes. The failures come from
// the seam (export_test.go), never from a permission.
func TestCheckEvent_TheWriteOfTheDigestsFileAroundItsCommitPoint(t *testing.T) {
	f := newGoodCevFix(t)
	ev, _, err := f.check()
	if err != nil {
		t.Fatalf("CheckEvent: %v", err)
	}
	var want bytes.Buffer
	if err := edition.WriteDigests(&want, ev); err != nil {
		t.Fatal(err)
	}
	outputErr := func(err error) *edition.OutputError {
		var oe *edition.OutputError
		if !errors.As(err, &oe) || isInputErr(err) {
			return nil
		}
		return oe
	}

	// the link fails: exit 3, nothing left
	edition.SetWriteFaultForTest(t, map[string]error{edition.FaultLinkForTest: syscall.EPERM})
	left, err := edition.WriteDigestsFile(f.in.DigestsOut, ev)
	if oe := outputErr(err); oe == nil || len(oe.Left) != 0 || len(left) != 0 {
		t.Errorf("the link fails: (%v, %v), want an *OutputError with no name left", left, err)
	}
	if names := listNames(t, f.path("out")); len(names) != 0 {
		t.Errorf("the link fails: the output directory holds %v, want nothing", names)
	}

	// the write fails (no space) and so does the cleanup: exit 3, the name is listed
	edition.SetWriteFaultForTest(t, map[string]error{edition.FaultWriteForTest: syscall.ENOSPC, edition.FaultRemoveForTest: syscall.EIO})
	left, err = edition.WriteDigestsFile(f.in.DigestsOut, ev)
	oe := outputErr(err)
	if oe == nil || !errors.Is(err, syscall.ENOSPC) || len(oe.Left) != 1 || len(left) != 0 {
		t.Fatalf("the write and the cleanup fail: (%v, %v), want an *OutputError of ENOSPC with one name left", left, err)
	}
	names := listNames(t, f.path("out"))
	if len(names) != 1 || !strings.Contains(oe.Left[0], names[0]) || slices.Contains(names, "digests.tsv") {
		t.Errorf("the output directory holds %v and the error lists %v; want the one temporary name and no digests file", names, oe.Left)
	}
	f.noValue("a name left", strings.Join(oe.Left, " "), err.Error())

	// the same write again: accepted, the name left does not stand in its way
	edition.SetWriteFaultForTest(t, nil)
	if left, err := edition.WriteDigestsFile(f.in.DigestsOut, ev); err != nil || len(left) != 0 {
		t.Fatalf("the same write again: (%v, %v), want it to succeed", left, err)
	}
	if got := f.read("out/digests.tsv"); got != want.String() {
		t.Errorf("the digests file holds %q, want %q", got, want.String())
	}

	// after the commit point: the temporary name cannot be removed: a warning, the file is whole
	edition.SetWriteFaultForTest(t, map[string]error{edition.FaultRemoveForTest: syscall.EIO})
	left, err = edition.WriteDigestsFile(f.path("out/second.tsv"), ev)
	if err != nil || len(left) != 1 {
		t.Fatalf("the cleanup after the link fails: (%v, %v), want no error and one name left", left, err)
	}
	if got := f.read("out/second.tsv"); got != want.String() {
		t.Errorf("the digests file holds %q, want %q", got, want.String())
	}
}

func listNames(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range list {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

// V86: each check broken alone. The event is nil, the error is a rule's (not a usage error),
// it names the rule, and no value of the render is in it. report says whether B4 ran.
func TestCheckEvent_EachCheckBrokenAloneRefusesTheEvent(t *testing.T) {
	type breakFn func(f *cevFix)
	cases := []struct {
		name       string
		opts       *cevOpts // nil: the good event
		brk        breakFn
		wantRules  []string // the rules that must be named
		onlyRules  bool     // and no other
		wantB4Ran  bool
		wantSubstr string
	}{
		{name: "E1: an unknown key in edition.yaml", brk: func(f *cevFix) {
			f.rewrite("edition-root/"+demoCID+"/"+edition.SpecFileName, func(s string) string { return s + "unknown_key: 1\n" })
		}, wantRules: []string{"E1"}, onlyRules: true},
		{name: "E2: decoys below K", brk: func(f *cevFix) {
			f.put("edition-root/"+demoCID+"/"+edition.SpecFileName, cevSpec(cevOpts{nameWords: 100, decoys: 3}))
		}, wantRules: []string{"E2"}, onlyRules: true},
		{name: "E2: a block of a file the template does not have (amendment 28)", brk: func(f *cevFix) {
			f.rewrite("edition-root/"+demoCID+"/"+edition.SpecFileName, func(s string) string {
				// blocks is the last key of the fixture's edition.yaml: the entry joins its list.
				return s + "  - {file: missing.txt, from: 1, to: 1}\n"
			})
		}, wantRules: []string{"E2"}, onlyRules: true},
		{name: "E2: a clue that is not a word of the template (amendment 28)", brk: func(f *cevFix) {
			f.rewrite("edition-root/"+demoCID+"/"+edition.SpecFileName, func(s string) string {
				// when declares its clues (amendment 31): the word joins them.
				old := "    clues: " + editiontest.Clues("when") + "\n"
				if !strings.Contains(s, old) {
					f.t.Fatal("the fixture's edition.yaml declares no clues of when: the test does not test")
				}
				return strings.Replace(s, old, "    clues: "+strings.TrimSuffix(editiontest.Clues("when"), "]")+", no-such-word]\n", 1)
			})
		}, wantRules: []string{"E2"}, onlyRules: true},
		{name: "E2: a filler of one word (amendment 28 (c))", brk: func(f *cevFix) {
			f.rewrite("edition-root/"+demoCID+"/"+edition.SpecFileName, func(s string) string {
				return strings.Replace(s, "      - [n0, n1, n2]\n", "      - [n0]\n", 1)
			})
		}, wantRules: []string{"E2"}, onlyRules: true},
		{name: "B8 (a1): a name vocabulary of 99 words", brk: func(f *cevFix) {
			f.put("edition-root/"+demoCID+"/"+edition.SpecFileName, cevSpec(cevOpts{nameWords: 99, decoys: 9}))
		}, wantRules: []string{"B8"}, onlyRules: true},
		{name: "B8 (a2): 51 seats for a space of 100", brk: func(f *cevFix) {
			f.put("seats.txt", cevSeatsText(seatsList(51)))
		}, wantRules: []string{"B8"}, onlyRules: true, wantSubstr: "(51)"},
		{name: "B11: the render record has another run id", brk: func(f *cevFix) {
			var b bytes.Buffer
			if err := edition.WriteRenderRecord(&b, "fedcba9876543210fedcba9876543210", f.key, f.scope); err != nil {
				f.t.Fatal(err)
			}
			f.put("render-record.tsv", b.String())
		}, wantRules: []string{edition.RuleRunID}, onlyRules: true},
		{name: "B12: the render record is of another scope", brk: func(f *cevFix) {
			var b bytes.Buffer
			if err := edition.WriteRenderRecord(&b, runA, f.key, []string{demoCID}); err != nil {
				f.t.Fatal(err)
			}
			f.put("render-record.tsv", b.String())
		}, wantRules: []string{edition.RuleScope}, onlyRules: true},
		{name: "T8: two seats share a per-seat value", brk: func(f *cevFix) {
			f.rewrite("answers.tsv", func(s string) string {
				return strings.Replace(s, "seat-b\t"+demoCID+"\tq1\t"+f.answers["seat-b/q1"], "seat-b\t"+demoCID+"\tq1\t"+f.answers["seat-a/q1"], 1)
			})
		}, wantRules: []string{"T8"}, onlyRules: true},
		{name: "B1: a seat has no bundle", brk: func(f *cevFix) {
			if err := os.RemoveAll(f.path("evidence/seat-c")); err != nil {
				f.t.Fatal(err)
			}
		}, wantRules: []string{"B1"}},
		{name: "B2: a file name outside the grammar", brk: func(f *cevFix) {
			f.put("evidence/seat-a/"+demoCID+"/BAD.TXT", "x\n")
		}, wantRules: []string{"B2"}},
		{name: "B3: a flag shape in a bundle", brk: func(f *cevFix) {
			f.rewrite("evidence/seat-a/"+demoCID+"/"+cevTemplateName, func(s string) string { return s + "FALCO{leak}\n" })
		}, wantRules: []string{"B3"}},
		{name: "B5: a hint in a bundle", brk: func(f *cevFix) {
			f.rewrite("evidence/seat-a/"+demoCID+"/"+cevTemplateName, func(s string) string {
				return s + "alpha bravo charlie delta echo foxtrot golf hotel india juliet\n"
			})
		}, wantRules: []string{"B5"}},
		{name: "B6: the answer is not in its seat's bundle", brk: func(f *cevFix) {
			f.rewrite("evidence/seat-a/"+demoCID+"/"+cevTemplateName, func(s string) string {
				return strings.ReplaceAll(s, f.answers["seat-a/q1"], "zzzz")
			})
		}, wantRules: []string{"B6"}},
		{name: "B9: an answer is in a public file", brk: func(f *cevFix) {
			f.put("corpus/leak.txt", "a public file that holds "+f.answers["seat-a/q1"]+"\n")
		}, wantRules: []string{"B9"}, onlyRules: true},
		// B18 too: the practice's answer lines (now the event's text in a.txt) lose their clue
		// words, and a practice answer with no clue word is held by every event (fail-closed).
		{name: "B4: the event template is the practice template", brk: func(f *cevFix) {
			f.put("challenges/"+demoCID+"/edition/template/a.txt", f.tmpl)
		}, wantRules: []string{edition.RulePracticeClues, "B4"}, onlyRules: true, wantB4Ran: true},
		{name: "B7: two seats hold the same token at a decoy's position", brk: func(f *cevFix) {
			f.copyDecoyLine()
		}, wantRules: []string{"B7"}, wantB4Ran: true},
		{name: "B8 (b): 4 decoys give 5 candidates, D3 (b) needs 10", opts: &cevOpts{nameWords: 100, decoys: 4}, wantRules: []string{"B8"}, wantB4Ran: true},
		{name: "B10: a digest of the previous render differs", brk: func(f *cevFix) {
			ev, _, err := f.check()
			if err != nil {
				f.t.Fatalf("the first check: %v", err)
			}
			rows := ev.Rows()
			rows[0].Digest = strings.Repeat("0", 64)
			var b bytes.Buffer
			if err := edition.WriteDigests(&b, edition.CheckedEventForTest("fedcba9876543210fedcba9876543210", rows)); err != nil {
				f.t.Fatal(err)
			}
			f.put("previous.tsv", b.String())
			f.in.NoPrevious, f.in.PreviousDigestsFile = false, f.path("previous.tsv")
		}, wantRules: []string{"B10"}, onlyRules: true, wantB4Ran: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := cevOpts{nameWords: 100, decoys: 9}
			if c.opts != nil {
				o = *c.opts
			}
			f := newCevFix(t, o)
			if c.brk != nil {
				c.brk(f)
			}
			err, report := f.refused(c.name)
			if isInputErr(err) {
				t.Fatalf("a rule's refusal came as a usage error: %v", err)
			}
			got := cevRuleSet(err)
			for _, rule := range c.wantRules {
				if !slices.Contains(got, rule) {
					t.Errorf("the rules named are %v, want %s among them (err: %v)", got, rule, err)
				}
			}
			if c.onlyRules && !slices.Equal(got, c.wantRules) {
				t.Errorf("the rules named are %v, want exactly %v (err: %v)", got, c.wantRules, err)
			}
			if c.wantSubstr != "" && !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("the error does not hold %q: %v", c.wantSubstr, err)
			}
			if report.OverlapRan != c.wantB4Ran {
				t.Errorf("report.OverlapRan = %v, want %v", report.OverlapRan, c.wantB4Ran)
			}
		})
	}
}

// Steps 6, 7 and 8 do not depend on each other, so an event that breaks B4, B7 and B10 at once
// gets all three rules back together (and B8 (b) is checked in the same step as B7).
func TestCheckEvent_StepsSixToEightAreAllRun(t *testing.T) {
	f := newGoodCevFix(t)
	first, _, err := f.check()
	if err != nil {
		t.Fatalf("the first check: %v", err)
	}
	// B10: a previous digest that differs
	rows := first.Rows()
	rows[0].Digest = strings.Repeat("0", 64)
	var prev bytes.Buffer
	if err := edition.WriteDigests(&prev, edition.CheckedEventForTest("fedcba9876543210fedcba9876543210", rows)); err != nil {
		t.Fatal(err)
	}
	f.put("previous.tsv", prev.String())
	f.in.NoPrevious, f.in.PreviousDigestsFile = false, f.path("previous.tsv")
	// B4: the event template is the practice template
	f.put("challenges/"+demoCID+"/edition/template/a.txt", f.tmpl)
	// B7: two seats hold the same token at a decoy's position
	f.copyDecoyLine()

	// (the practice template replaced, the practice's answer lines have no clue word: B18 too)
	err, report := f.refused("B4, B7, B10 and B18 together")
	if got := cevRuleSet(err); !slices.Equal(got, []string{"B10", "B18", "B4", "B7"}) || !report.OverlapRan {
		t.Errorf("rules %v, report %+v; want B10, B18, B4 and B7 together and B4's numbers (err: %v)", got, report, err)
	}
}

// copyDecoyLine puts, in seat-b's bundle, a line of the block of who's group of seat-a's bundle at
// the same place: a line where neither seat has its answer of q1 (so B6 still holds), so the two
// seats hold the same value in the column of the group (B7's block form (2)).
func (f *cevFix) copyDecoyLine() {
	f.t.Helper()
	aName := "evidence/seat-a/" + demoCID + "/" + cevTemplateName
	bName := "evidence/seat-b/" + demoCID + "/" + cevTemplateName
	a, b := strings.Split(f.read(aName), "\n"), strings.Split(f.read(bName), "\n")
	from, to := editiontest.BlockLines(editiontest.GoodDecoys, "who")
	for i := from - 1; i < to; i++ {
		if !strings.HasSuffix(a[i], " "+f.answers["seat-a/q1"]) && !strings.HasSuffix(b[i], " "+f.answers["seat-b/q1"]) {
			b[i] = a[i]
			f.put(bName, strings.Join(b, "\n"))
			return
		}
	}
	f.t.Fatal("no line of who's block holds a decoy in both seat-a's and seat-b's bundles")
}

// A mark outside the grammar in the event template is E3 (the renderer's lexer, V69), and the
// validator's name for the rule is the renderer's.
func TestCheckEvent_ABadMarkInTheTemplateIsE3(t *testing.T) {
	if edition.RuleTemplateMark != edition.RuleSpecRender {
		t.Fatalf("RuleTemplateMark = %q, RuleSpecRender = %q; they are one rule", edition.RuleTemplateMark, edition.RuleSpecRender)
	}
	f := newGoodCevFix(t)
	// A file of its own: the fixture's template file holds the blocks, and E2 cannot read a block
	// of a file the lexer refuses (that is E2's to name, besides E3).
	f.put("edition-root/"+demoCID+"/"+edition.TemplateDirName+"/broken.txt", "broken {{ctf: mark\n")
	err, report := f.refused("a mark outside the grammar")
	if isInputErr(err) || !slices.Equal(cevRuleSet(err), []string{"E3"}) || report.OverlapRan {
		t.Errorf("rules %v, report %+v, err %v; want E3 only, before B4", cevRuleSet(err), report, err)
	}
}

// Amendment 28 (A7-x PR 1, PR 2) and B17 (PR 4): the good event's edition puts every group in a
// block (B17 asks for it), so its bundles are the renderer's output of an edition with blocks (each
// block's lines ordered by their times, the group's columns apart between the seats), accepted end
// to end through CheckEvent. The blocks declared after the render (the bundles are the render of
// the edition without them, in the template's order) are refused by B7 alone: an edition changed
// after its render is not the edition of the bundles.
func TestCheckEvent_AcceptsBlocksAndClues(t *testing.T) {
	specPath := "edition-root/" + demoCID + "/" + edition.SpecFileName
	t.Run("the blocks of the good event", func(t *testing.T) {
		f := newGoodCevFix(t)
		if !strings.Contains(f.read(specPath), "blocks:") {
			t.Fatal("the fixture's edition.yaml declares no block: the test does not test")
		}
		// The render ordered every block in every seat (the bundles are not the template's order).
		for _, seat := range f.seats {
			lines := strings.Split(f.read("evidence/"+seat+"/"+demoCID+"/"+cevTemplateName), "\n")
			for _, g := range editiontest.Groups {
				from, to := editiontest.BlockLines(editiontest.GoodDecoys, g)
				prev := ""
				for _, ln := range lines[from-1 : to] {
					fields := strings.Fields(ln)
					if len(fields) <= editiontest.TimeField || fields[editiontest.TimeField] <= prev {
						t.Fatalf("seat %s: the block of %s of the render is not in strictly ascending time", seat, g)
					}
					prev = fields[editiontest.TimeField]
				}
			}
		}
		if ev, _, err := f.check(); err != nil || ev == nil {
			t.Fatalf("an edition with blocks and the renderer's bundles was refused: %v", err)
		}
	})
	t.Run("declared after the render", func(t *testing.T) {
		noBlocks := func(s string) string {
			i := strings.Index(s, "blocks:\n")
			if i < 0 {
				t.Fatal("the fixture's edition.yaml declares no block")
			}
			return s[:i]
		}
		f := newCevFix(t, cevOpts{nameWords: editiontest.GoodNameWords, decoys: editiontest.GoodDecoys, specEdit: noBlocks})
		f.put(specPath, editiontest.GoodSpec())
		err, _ := f.refused("the blocks declared after the render")
		if got := rules(err); !slices.Equal(got, []string{"B7"}) {
			t.Errorf("rules = %v, want [B7]: %v", got, err)
		}
	})
}

// B17 through CheckEvent (V111 (2), the event's template): the good event's template with one
// fixed word of a decoy's line changed, rendered and checked, is refused by B17 (and by it alone:
// nothing else compares the lines of a group); and a group that is in no block is refused by B17.
func TestCheckEvent_B17IsWired(t *testing.T) {
	from, _ := editiontest.BlockLines(editiontest.GoodDecoys, "who")
	whoBlock := fmt.Sprintf("  - {file: %s, from: %d, to: %d}\n", cevTemplateName, from, from+editiontest.GoodDecoys)
	if !strings.Contains(editiontest.GoodSpec(), whoBlock) {
		t.Fatal("the fixture's edition.yaml has no block of who: the test does not test")
	}
	cases := []struct {
		name string
		o    cevOpts
	}{
		{name: "a fixed word of a decoy's line changed", o: cevOpts{tmplEdit: func(s string) string {
			lines := strings.Split(s, "\n")
			lines[from] = strings.Replace(lines[from], " holds ", " keeps ", 1)
			return strings.Join(lines, "\n")
		}}},
		{name: "the group of who in no block", o: cevOpts{specEdit: func(s string) string {
			return strings.Replace(s, whoBlock, "", 1)
		}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := c.o
			o.nameWords, o.decoys = editiontest.GoodNameWords, editiontest.GoodDecoys
			f := newCevFix(t, o)
			err, _ := f.refused(c.name)
			if got := cevRuleSet(err); !slices.Equal(got, []string{edition.RuleRowSymmetry}) {
				t.Errorf("rules %v, want [B17]: %v", got, err)
			}
		})
	}
}

// V89 (A4e-2c): B5 holds the bundles to what the server shows, and the server shows the
// scenario's narrative overrides (catalog.LoadHintInputs is the one reader of both). A narrative
// override can only replace a briefing and a bridge; the briefing is free text and the bridge is
// shown to no hint check (hlscope.Assemble), so an override can take a free copy of a hint away.
// The fixture: the journey's own briefing repeats the hint, so a bundle that holds words of the
// hint is accepted (they are shown without paying). With a narrative.yaml beside the scenario
// that replaces the briefing with other words, the participant is no longer shown them for
// free, and the same bundle is refused by B5. A CheckEvent that read the journeys without the
// override would accept it, and this test would be red. The bundle's words of the hint replace
// the template's first line, token for token (five tokens for five), so the bundle keeps the
// template's layout and the later steps (B7, B8 (b)) see what they saw before.
func TestCheckEvent_B5HoldsTheBundlesToTheNarrativeOverride(t *testing.T) {
	const (
		hint      = "alpha bravo charlie delta echo foxtrot golf hotel india juliet"
		firstLine = "fixture record, placeholder text only\n"
		hintWords = "alpha bravo charlie delta echo\n"
	)
	build := func(t *testing.T, override bool) *cevFix {
		t.Helper()
		f := newGoodCevFix(t)
		f.rewrite("challenges/"+demoCID+"/journey.yaml", func(s string) string {
			const local = "briefing: plain placeholder briefing of the fixture\n"
			if !strings.Contains(s, local) {
				t.Fatalf("the fixture's journey has no briefing line %q", local)
			}
			return strings.Replace(s, local, "briefing: \""+hint+"\"\n", 1)
		})
		if override {
			f.put("scenario/narrative.yaml", "overrides:\n  "+demoCID+":\n    briefing: plain placeholder briefing of the scenario\n")
		}
		f.rewrite("evidence/seat-a/"+demoCID+"/"+cevTemplateName, func(s string) string {
			if !strings.HasPrefix(s, firstLine) {
				t.Fatalf("the bundle does not start with the template's first line %q", firstLine)
			}
			return hintWords + strings.TrimPrefix(s, firstLine)
		})
		return f
	}

	t.Run("the journey's own briefing shows the hint: accepted", func(t *testing.T) {
		f := build(t, false)
		if ev, _, err := f.check(); err != nil || ev == nil {
			t.Fatalf("CheckEvent = (%v, _, %v); want the event (the hint is shown for free by the briefing)", ev, err)
		}
	})
	t.Run("the narrative replaces the briefing: B5", func(t *testing.T) {
		f := build(t, true)
		err, report := f.refused("a hint that only the replaced briefing showed")
		if isInputErr(err) || !slices.Contains(cevRuleSet(err), edition.RuleBundleHint) || report.OverlapRan {
			t.Errorf("rules %v, report %+v, err %v; want B5 among them, before B4", cevRuleSet(err), report, err)
		}
	})
}

// V86 (the report): B4's numbers come back with a refusal that is B4's own.
func TestCheckEvent_TheReportIsReturnedWhenB4Refuses(t *testing.T) {
	f := newGoodCevFix(t)
	f.put("challenges/"+demoCID+"/edition/template/a.txt", f.tmpl)
	_, report, err := f.check()
	if err == nil || !report.OverlapRan {
		t.Fatalf("err %v, report %+v; want a refusal and the report", err, report)
	}
	if report.Overlap.Template.Rate < edition.OverlapTheta || report.Overlap.Template.Practice != demoCID || report.Overlap.Template.Event != demoCID {
		t.Errorf("the template overlap = %+v; want a rate at or above theta between the challenge's event and practice templates", report.Overlap.Template)
	}
}

// V77: every group of the fixture is in a block (B17), so its bound is 2 x N x (k + 1) with k = 9
// decoys: a space of 1000 for 51 seats (1020) is B8, the same decision as the renderer's E3; for 50
// seats (1000) it is not B8 (the seat list then fails B1, the answers table has 3 seats). where's
// space is 1000 too.
func TestCheckEvent_B8SeatSpaceAtTheBoundary(t *testing.T) {
	f := newCevFix(t, cevOpts{nameWords: 1000, decoys: 9})
	f.put("seats.txt", cevSeatsText(seatsList(51)))
	err, _ := f.refused("51 seats")
	if got := cevRuleSet(err); !slices.Equal(got, []string{"B8"}) || !strings.Contains(err.Error(), "(51)") {
		t.Errorf("51 seats for a space of 1000 in a block of 10: rules %v, err %v; want B8 naming 51 seats", got, err)
	}
	f.put("seats.txt", cevSeatsText(seatsList(50)))
	err, _ = f.refused("50 seats")
	if got := cevRuleSet(err); slices.Contains(got, "B8") || !slices.Contains(got, "B1") {
		t.Errorf("50 seats for a space of 1000 in a block of 10: rules %v; want B1 (the list is not the table's) and no B8", got)
	}
}

// V75: B10 and the two ways of saying "previous".
func TestCheckEvent_ContinuityWithThePreviousDigests(t *testing.T) {
	f := newGoodCevFix(t)
	first, _, err := f.check()
	if err != nil {
		t.Fatalf("the first check (--no-previous): %v", err)
	}
	prevID := "fedcba9876543210fedcba9876543210"
	writePrev := func(rows []edition.DigestRow) {
		var b bytes.Buffer
		if err := edition.WriteDigests(&b, edition.CheckedEventForTest(prevID, rows)); err != nil {
			t.Fatal(err)
		}
		f.put("previous.tsv", b.String())
	}
	f.in.NoPrevious, f.in.PreviousDigestsFile = false, f.path("previous.tsv")

	writePrev(first.Rows())
	if ev, _, err := f.check(); err != nil || ev == nil {
		t.Errorf("the same digests as the previous: (%v, %v), want the event", ev, err)
	}
	// a seat that was added at the end: the previous render does not have it, and that is fine
	writePrev(first.Rows()[:2])
	if ev, _, err := f.check(); err != nil || ev == nil {
		t.Errorf("a seat the previous render does not have: (%v, %v), want the event", ev, err)
	}
	// a previous file of another event (no pair in common) and one with a pair that this render
	// does not have are B10, not a pass
	other := []edition.DigestRow{{Seat: "other-seat", CID: demoCID, Digest: strings.Repeat("1", 64)}}
	writePrev(other)
	if ev, _, err := f.check(); ev != nil || err == nil || isInputErr(err) || !slices.Equal(cevRuleSet(err), []string{"B10"}) {
		t.Errorf("a previous file with no pair in common: (%v, %v), want B10 and no event", ev, err)
	}
	writePrev(append(first.Rows()[:1:1], other...))
	if ev, _, err := f.check(); ev != nil || err == nil || !slices.Equal(cevRuleSet(err), []string{"B10"}) {
		t.Errorf("a previous pair that this render does not have: (%v, %v), want B10 and no event", ev, err)
	}
	// a header alone is not a first check: it is a usage error, never read as --no-previous
	f.put("previous.tsv", "# falco-ctf evidence-digests v1 run="+prevID+"\n")
	if _, _, err := f.check(); !isInputErr(err) {
		t.Errorf("a previous file with no row: err = %v, want a usage error", err)
	}
	// and a file that is not there
	f.in.PreviousDigestsFile = f.path("no-such-previous.tsv")
	if _, _, err := f.check(); !isInputErr(err) {
		t.Errorf("a previous file that does not exist: err = %v, want a usage error", err)
	}
}

// V79's library half and V72: every input that is missing, unreadable or malformed is a usage
// error, never a rule's refusal, and no event comes back. A scope with no investigate
// challenge stops before B4.
func TestCheckEvent_UsageErrorsAndUnreadableInputs(t *testing.T) {
	cases := []struct {
		name string
		brk  func(f *cevFix)
	}{
		{"challenges is empty", func(f *cevFix) { f.in.Challenges = "" }},
		{"scenario is empty", func(f *cevFix) { f.in.ScenarioFile = "" }},
		{"flags-file is empty", func(f *cevFix) { f.in.FlagsFile = "" }},
		{"answers is empty", func(f *cevFix) { f.in.AnswersFile = "" }},
		{"render-record is empty", func(f *cevFix) { f.in.RenderRecordFile = "" }},
		{"evidence-root is empty", func(f *cevFix) { f.in.EvidenceRoot = "" }},
		{"seats is empty", func(f *cevFix) { f.in.SeatsFile = "" }},
		{"edition-root is empty", func(f *cevFix) { f.in.EditionRoot = "" }},
		{"digests-out is empty", func(f *cevFix) { f.in.DigestsOut = "" }},
		{"no corpus", func(f *cevFix) { f.in.CorpusDirs = nil }},
		{"an empty corpus argument", func(f *cevFix) { f.in.CorpusDirs = append(f.in.CorpusDirs, "") }},
		{"previous-digests and no-previous together", func(f *cevFix) { f.in.PreviousDigestsFile = f.path("previous.tsv") }},
		{"neither previous-digests nor no-previous", func(f *cevFix) { f.in.NoPrevious = false }},
		{"the digests output already exists", func(f *cevFix) { f.put("out/digests.tsv", "already here\n") }},
		{"the directory of the digests output does not exist", func(f *cevFix) { f.in.DigestsOut = f.path("out/missing/digests.tsv") }},
		{"the seats file does not exist", func(f *cevFix) { f.in.SeatsFile = f.path("no-such-seats.txt") }},
		{"the seats file is a header alone", func(f *cevFix) { f.put("seats.txt", "# falco-ctf seats v1\n") }},
		{"a seat listed twice", func(f *cevFix) { f.put("seats.txt", cevSeatsText([]string{"seat-a", "seat-b", "seat-a"})) }},
		{"a blank line in the seats", func(f *cevFix) { f.put("seats.txt", "# falco-ctf seats v1\nseat-a\n\nseat-b\n") }},
		{"a comment in the seats", func(f *cevFix) { f.put("seats.txt", "# falco-ctf seats v1\nseat-a\n# seat-b\n") }},
		{"a seat outside the grammar", func(f *cevFix) { f.put("seats.txt", cevSeatsText([]string{"seat-a", "Seat_B"})) }},
		{"the seats file has no header", func(f *cevFix) { f.put("seats.txt", "seat-a\nseat-b\n") }},
		{"the seats file has CRLF line ends", func(f *cevFix) { f.put("seats.txt", "# falco-ctf seats v1\r\nseat-a\r\n") }},
		{"the seats file has no final newline", func(f *cevFix) { f.put("seats.txt", "# falco-ctf seats v1\nseat-a") }},
		{"the scenario does not exist", func(f *cevFix) { f.in.ScenarioFile = f.path("no-such-scenario.yaml") }},
		{"the scenario has no investigate challenge", func(f *cevFix) {
			f.in.ScenarioFile = f.tree.PutScenario("evade-only", cevEvade)
		}},
		{"the answers file does not exist", func(f *cevFix) { f.in.AnswersFile = f.path("no-such-answers.tsv") }},
		{"the render record does not exist", func(f *cevFix) { f.in.RenderRecordFile = f.path("no-such-record.tsv") }},
		{"the render record is not a record", func(f *cevFix) { f.put("render-record.tsv", "not a render record\n") }},
		{"the edition root does not exist", func(f *cevFix) { f.in.EditionRoot = f.path("no-such-edition-root") }},
		{"edition.yaml of a challenge does not exist", func(f *cevFix) {
			if err := os.Remove(f.path("edition-root/" + demoCID + "/" + edition.SpecFileName)); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"the template of a challenge has no file", func(f *cevFix) {
			if err := os.Remove(f.path("edition-root/" + demoCID + "/" + edition.TemplateDirName + "/" + cevTemplateName)); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"a link in the template directory", func(f *cevFix) {
			dir := f.path("edition-root/" + demoCID + "/" + edition.TemplateDirName)
			if err := os.Symlink(filepath.Join(dir, cevTemplateName), filepath.Join(dir, "link.txt")); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"edition.yaml of a challenge is a link", func(f *cevFix) {
			spec := f.path("edition-root/" + demoCID + "/" + edition.SpecFileName)
			f.put("real-spec.yaml", f.spec)
			if err := os.Remove(spec); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink(f.path("real-spec.yaml"), spec); err != nil {
				f.t.Fatal(err)
			}
		}},
		// D20 (amendment 13's revision): an entry of the edition root named like a challenge id
		// that is not a directory is exit 2, not E2 (TestCheckEvent_TheEditionRootHoldsExactly
		// TheScope has the set's E2).
		{"a file named like a challenge id in the edition root", func(f *cevFix) { f.put("edition-root/02-other", "x\n") }},
		{"the challenge's entry of the edition root is a link to its directory", func(f *cevFix) {
			if err := os.Rename(f.path("edition-root/"+demoCID), f.path("real-edition")); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink(f.path("real-edition"), f.path("edition-root/"+demoCID)); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"the evidence root does not exist", func(f *cevFix) { f.in.EvidenceRoot = f.path("no-such-evidence") }},
		{"the corpus directory does not exist", func(f *cevFix) { f.in.CorpusDirs = []string{f.path("no-such-corpus")} }},
		{"the seats file is a link", func(f *cevFix) {
			if err := os.Remove(f.path("seats.txt")); err != nil {
				f.t.Fatal(err)
			}
			f.put("real-seats.txt", cevSeatsText(f.seats))
			if err := os.Symlink(f.path("real-seats.txt"), f.path("seats.txt")); err != nil {
				f.t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newGoodCevFix(t)
			c.brk(f)
			existing, existed := "", false
			if b, err := os.ReadFile(f.in.DigestsOut); err == nil {
				existing, existed = string(b), true
			}
			err, report := f.refused(c.name)
			if !isInputErr(err) {
				t.Errorf("err = %v; want a usage error or an unreadable input (exit 2), not a rule's refusal", err)
			}
			if report.OverlapRan {
				t.Error("B4 ran although the check could not get to it")
			}
			if existed {
				if b, rerr := os.ReadFile(f.in.DigestsOut); rerr != nil || string(b) != existing {
					t.Errorf("the digests output that was there changed: %v", rerr)
				}
			}
		})
	}
}

// A malformed or an extra edition root is a rule's refusal (E2), not a usage error: the files
// were read and the set of challenges is not the scope's.
func TestCheckEvent_TheEditionRootHoldsExactlyTheScope(t *testing.T) {
	cases := []struct {
		name string
		brk  func(f *cevFix)
	}{
		{"a directory of another challenge", func(f *cevFix) { f.put("edition-root/02-other/"+edition.SpecFileName, "x\n") }},
		{"a name that is not a challenge id", func(f *cevFix) { f.put("edition-root/Not-An-Id/x", "x\n") }},
		{"a file in the root", func(f *cevFix) { f.put("edition-root/stray.txt", "x\n") }},
		{"no directory for the challenge", func(f *cevFix) {
			if err := os.RemoveAll(f.path("edition-root/" + demoCID)); err != nil {
				f.t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newGoodCevFix(t)
			c.brk(f)
			err, _ := f.refused(c.name)
			if isInputErr(err) || !slices.Equal(cevRuleSet(err), []string{"E2"}) {
				t.Errorf("rules %v, err %v; want E2 only", cevRuleSet(err), err)
			}
		})
	}
}

// V87: a seats file that is a FIFO does not make the reader wait for a writer.
func TestCheckEvent_AFifoIsRefusedWithoutBlocking(t *testing.T) {
	f := newGoodCevFix(t)
	if err := os.Remove(f.path("seats.txt")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(f.path("seats.txt"), 0o600); err != nil {
		t.Skipf("no FIFO on this file system: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		ev, _, err := f.check()
		if ev != nil {
			err = errors.New("an event came back for a FIFO")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !isInputErr(err) {
			t.Errorf("err = %v; want a usage error", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("CheckEvent is blocked on a FIFO")
	}
}

// V15: a table with no value of the practice editions repeated, T3..T8, is LoadEventTable's;
// here the first step that is CheckEvent's own: the table's refusal comes back as a rule's.
func TestCheckEvent_ATableRuleIsARuleNotAUsageError(t *testing.T) {
	f := newGoodCevFix(t)
	f.put("answers.tsv", "# falco-ctf answers v1 run="+edition.PracticeRunID+"\n")
	err, report := f.refused("a table with the practice run id")
	if isInputErr(err) || report.OverlapRan || !slices.Contains(cevRuleSet(err), edition.RuleShape) {
		t.Errorf("err %v, report %+v; want a rule's refusal before B4, T3 among the rules", err, report)
	}
}

func TestCheckEvent_NothingIsLeftWhereTheOutputGoes(t *testing.T) {
	f := newGoodCevFix(t)
	f.put("answers.tsv", "not a table\n")
	f.refused("a table that is not one")
	if names := listNames(t, f.path("out")); len(names) != 0 {
		t.Errorf("CheckEvent left %v in the output directory", names)
	}
}
