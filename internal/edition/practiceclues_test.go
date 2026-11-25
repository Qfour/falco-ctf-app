package edition_test

// ADR-0056 D10 B18 (amendment 30, A7-x PR 4b) and V112: the clue words of an event answer do not
// hold those of the practice answer of the same question. The event is rowsymmetry_test.go's
// two-step edition (when's clues alpha and sh; B17 and B19 accept it). The practice edition
// is of the same shape with clue words of its own and, in some cases, slot names of its own (B18
// matches the answers by question, q1). Every value is a placeholder.

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// pcPractice is a practice edition of the shape of the event: its answer slot is named answer
// (its marks renamed in the template), declares clues (rsOpts's: "" is alpha and sh) and its
// clue lines hold words.
type pcPractice struct {
	answer string
	o      rsOpts
	words  []string
}

// files is the practice's edition.yaml and template.
func (p pcPractice) files() ([]byte, []edition.BundleFile) {
	spec := rsSpec(p.o)
	block, clues := rsBlock(), rsClues(p.words, nil)
	if p.answer != "when" {
		spec = strings.Replace(spec, "  - name: when\n", "  - name: "+p.answer+"\n", 1)
		block = strings.ReplaceAll(block, "{{ctf:when", "{{ctf:"+p.answer)
	}
	return []byte(spec), []edition.BundleFile{{Name: "a.log", Data: []byte(block)}, {Name: "b.log", Data: []byte(clues)}}
}

// pcCheck applies B18 to the event and the practice edition given by its edition.yaml and
// template.
func pcCheck(t *testing.T, practiceSpec []byte, practiceTemplate []edition.BundleFile) error {
	t.Helper()
	ev := rsCheck(t, rsSpec(rsOpts{}), rsBlock(), rsClues(rsClueWords, nil))
	if ev.err != nil {
		t.Fatalf("the event is not accepted by B17 and B19: %v", ev.err)
	}
	return ev.spec.CheckPracticeClues(rsCID, rsQuestions(), ev.tmpl, practiceSpec, practiceTemplate)
}

// pcWords is rsClueWords with the answer's clue line holding words.
func pcWords(words string) []string {
	w := slices.Clone(rsClueWords)
	w[0] = words
	return w
}

// pcSameSecond are clue lines whose second clue column holds one word in every line: a practice
// edition with the first column as its one clue column holds to E2 (e4) with them.
var pcSameSecond = []string{
	"container alpha proc same",
	"container beta proc same",
	"container gamma proc same",
	"container delta proc same",
	"container omega proc same",
}

// V112's two green cases: a practice combination with one word swapped (the event, which B19
// accepts, holds one of its two words), with the slots named as the event's and named otherwise.
func TestPracticeClues_Accepts(t *testing.T) {
	swapped := pcWords("container alpha proc zeta")
	cases := []struct {
		name string
		p    pcPractice
	}{
		{"one word of the practice's combination swapped", pcPractice{answer: "when", o: rsOpts{clues: "[alpha, zeta]"}, words: swapped}},
		{"the same, the practice's answer slot named otherwise", pcPractice{answer: "pwhen", o: rsOpts{clues: "[alpha, zeta]"}, words: swapped}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, tmpl := c.p.files()
			if err := pcCheck(t, spec, tmpl); err != nil {
				t.Errorf("CheckPracticeClues = %v; want it accepted", err)
			}
		})
	}
}

// V112 (1) and (2), and the comparison by question: each is refused by B18, once, at q1, and the
// violation names no word.
func TestPracticeClues_RefusesAnEventThatHoldsThePracticesClues(t *testing.T) {
	cases := []struct {
		name string
		p    pcPractice
	}{
		{"(1) the practice's combination itself", pcPractice{answer: "when", words: rsClueWords}},
		{"(1) the same, the practice's answer slot named otherwise (B18 matches by question)", pcPractice{answer: "pwhen", words: rsClueWords}},
		{"(2) the event holds the practice's combination and one word more", pcPractice{answer: "when", o: rsOpts{clues: "[alpha]"}, words: pcSameSecond}},
		// In no block (E2 (e1) asks a block's group for clues): P_c is empty, and held.
		{"a practice answer with no clue word (fail-closed: held by every event)", pcPractice{answer: "when", o: rsOpts{noClues: true, noBlocks: true}, words: rsClueWords}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, tmpl := c.p.files()
			err := pcCheck(t, spec, tmpl)
			vs := sbViolations(err)
			if len(vs) != 1 || vs[0].Rule != edition.RulePracticeClues || vs[0].QID != "q1" || vs[0].CID != rsCID {
				t.Fatalf("violations = %v, want one of B18 at %s q1", err, rsCID)
			}
			rsNoValue(t, err)
		})
	}
}

// An answer written on two lines of the practice edition (no block: E2 lets it be) has two
// combinations; the event's answer combination holds one of them, though not their union: B18
// refuses (one grep for each line).
func TestPracticeClues_OneLineOfThePracticesAnswerIsEnough(t *testing.T) {
	spec := strings.Replace(rsSpec(rsOpts{noBlocks: true, clues: "[alpha, sh, gamma, delta]"}), "  - name: when\n", "  - name: pwhen\n", 1)
	tmpl := []edition.BundleFile{{Name: "p.log", Data: []byte("first {{ctf:pwhen}} alpha sh\nsecond {{ctf:pwhen}} gamma delta\n")}}
	err := pcCheck(t, []byte(spec), tmpl)
	if vs := sbViolations(err); len(vs) != 1 || vs[0].Rule != edition.RulePracticeClues || vs[0].QID != "q1" {
		t.Errorf("violations = %v, want one of B18 at q1", err)
	}
	// No line's combination held (sh stays a word of the template, on a line of no answer, for E2):
	// accepted.
	one := strings.Replace(string(tmpl[0].Data), "first {{ctf:pwhen}} alpha sh\n", "first {{ctf:pwhen}} alpha gamma\nnote sh\n", 1)
	if err := pcCheck(t, []byte(spec), []edition.BundleFile{{Name: "p.log", Data: []byte(one)}}); err != nil {
		t.Errorf("no line's combination is held by the event's: %v; want it accepted", err)
	}
}

// Fail-closed: a practice edition B18 cannot read is one violation of B18, never a pass.
func TestPracticeClues_RefusesWhatItCannotRead(t *testing.T) {
	goodSpec, goodTmpl := pcPractice{answer: "when", o: rsOpts{clues: "[alpha, zeta]"}, words: pcWords("container alpha proc zeta")}.files()
	noClueSpec, _ := pcPractice{answer: "when", o: rsOpts{noClues: true}, words: rsClueWords}.files()
	if err := pcCheck(t, goodSpec, goodTmpl); err != nil {
		t.Fatalf("the practice edition of the cases is refused as it is: %v", err)
	}
	cases := []struct {
		name string
		spec []byte
		tmpl []edition.BundleFile
		msg  string
	}{
		{"no edition.yaml", nil, goodTmpl, "no edition.yaml that can be read"},
		{"an edition.yaml that does not parse", []byte("x: y\n"), goodTmpl, "does not parse"},
		{"no template", goodSpec, nil, "has no template"},
		{"a practice edition that does not hold to E2 (decoys below K)", []byte(strings.Replace(string(goodSpec), "    decoys: 4\n", "    decoys: 3\n", 1)), goodTmpl, "does not hold to E2"},
		{"a practice edition whose group in a block declares no clue (E2 (e1))", noClueSpec, goodTmpl, "does not hold to E2"},
		{"a practice template with a mark opener that is not a mark", goodSpec, append(slices.Clone(goodTmpl), edition.BundleFile{Name: "c.log", Data: []byte("broken {{ctf: mark\n")}), "that is not a mark"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := pcCheck(t, c.spec, c.tmpl)
			vs := sbViolations(err)
			if len(vs) != 1 || vs[0].Rule != edition.RulePracticeClues || !strings.Contains(fmt.Sprint(err), c.msg) {
				t.Errorf("violations = %v, want one of B18 that says %q", err, c.msg)
			}
			rsNoValue(t, err)
		})
	}
}
