package edition_test

// ADR-0056 D12 and D19 A4d-2: the renderer (V4, V63, and V18's length-prefix part, which
// is in render_internal_test.go). One case, one defect, and the rule that must name it.
// Every word, slot and key is a placeholder of no meaning; the name vocabulary is made of
// the sentinel, so a message that echoes a word of it shows up as a match.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// rdKeyText is the master key of these tests: a made-up string. A message, a printed
// MasterKey or a printed input that holds it is a leak.
const rdKeyText = "KEY-SENTINEL-yyyy-0123456789abcdef01" // 36 bytes: the length an event needs

// rdBase is the time.base of the example (specGoodDoc's).
var rdBase = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

func rdKey(t *testing.T, text string) edition.MasterKey {
	t.Helper()
	k, err := edition.NewMasterKey([]byte(text))
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	return k
}

// rdQuestions are specQuestions and a fixed question, with a day for the timestamp (so
// that two seats drawing one second of it is a chance of 1 in 86400).
func rdQuestions() []catalog.Question {
	qs := specQuestionsWithFixed()
	qs[3].Params.WindowSeconds = specI64(86400)
	return qs
}

// rdDoc is the example of amendment 8, with 6 decoys for each answer (K is 4), the name
// vocabulary made of the sentinel, a fixed answer and a window of a day.
func rdDoc() specDoc {
	d := specGoodDoc().withFixed(specFixedQ5)
	d = d.with(slotWho, func(s *specSlot) { s.vocab = specVocab(specWords(sentinel, 200)) })
	for _, i := range []int{slotWho, slotWhere, slotTag, slotWhen} {
		d = d.with(i, func(s *specSlot) { s.decoys = "6" })
	}
	return d.with(slotWhen, func(s *specSlot) { s.window = "{from: 0, to: 86400}" })
}

func rdSpec(t *testing.T, d specDoc) *edition.Spec {
	t.Helper()
	s, err := edition.ParseSpec(d.yaml())
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	return s
}

// rdTemplate is a template with a mark for every slot and every implied decoy, two files
// (a.txt, b.txt) alternately, one line `<slot>={{ctf:<slot>}}` each, so that a test can
// read the value of a slot back from the output.
func rdTemplate(spec *edition.Spec) []edition.BundleFile {
	var a, b strings.Builder
	n := 0
	add := func(name string) {
		w := &a
		if n%2 == 1 {
			w = &b
		}
		n++
		fmt.Fprintf(w, "%s={{ctf:%s}}\n", name, name)
	}
	for _, s := range spec.Slots {
		add(s.Name)
	}
	for _, d := range spec.ImpliedDecoys {
		add(d.Name)
	}
	return []edition.BundleFile{
		{Name: "a.txt", Data: []byte(a.String())},
		{Name: "b.txt", Data: []byte(b.String())},
	}
}

func rdInput(t *testing.T, seats ...string) edition.RenderInput {
	t.Helper()
	spec := rdSpec(t, rdDoc())
	return edition.RenderInput{
		CID: demoCID, Questions: rdQuestions(), Spec: spec, Template: rdTemplate(spec),
		Key: rdKey(t, rdKeyText), Seats: seats, Previous: edition.NoPreviousSeats(),
	}
}

func rdRender(t *testing.T, in edition.RenderInput) *edition.Rendered {
	t.Helper()
	r, err := edition.Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return r
}

// rdValues is the value of every slot in a bundle written by rdTemplate.
func rdValues(t *testing.T, b *edition.Bundle) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, f := range b.Files {
		for _, ln := range strings.Split(strings.TrimSuffix(string(f.Data), "\n"), "\n") {
			k, v, ok := strings.Cut(ln, "=")
			if !ok {
				t.Fatalf("%s of seat %s: a line without `=`", f.Name, b.Seat)
			}
			out[k] = v
		}
	}
	return out
}

func rdBundle(t *testing.T, r *edition.Rendered, seat string) *edition.Bundle {
	t.Helper()
	for _, b := range r.Bundles {
		if b.Seat == seat {
			return b
		}
	}
	t.Fatalf("no bundle for seat %s", seat)
	return nil
}

func rdRowsOf(r *edition.Rendered, seat string) []edition.AnswerRow {
	var out []edition.AnswerRow
	for _, row := range r.Rows {
		if row.Seat == seat {
			out = append(out, row)
		}
	}
	return out
}

func rdSameBundle(a, b *edition.Bundle) bool {
	if a.Seat != b.Seat || a.CID != b.CID || len(a.Files) != len(b.Files) {
		return false
	}
	for i := range a.Files {
		if a.Files[i].Name != b.Files[i].Name || !bytes.Equal(a.Files[i].Data, b.Files[i].Data) {
			return false
		}
	}
	return true
}

func rdViolations(err error) []*edition.Violation {
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

// rdNoLeak fails if the key, a word of the sentinel vocabulary or one of the values of a
// render is in err's text under the verbs an operator's code is likely to use.
func rdNoLeak(t *testing.T, what string, err error, values []string) {
	t.Helper()
	texts := []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)}
	needles := append([]string{rdKeyText, sentinel}, values...)
	for _, text := range texts {
		for _, s := range needles {
			if s != "" && strings.Contains(text, s) {
				t.Errorf("%s: an error holds a secret (%q): %q", what, s, text)
			}
		}
	}
}

// rdSecretValues are the answers of a render (the fixed one is not a secret of the run).
func rdSecretValues(r *edition.Rendered) []string {
	var out []string
	for _, row := range r.Rows {
		if row.QID != "q5" {
			out = append(out, row.Value)
		}
	}
	return out
}

// V63: the example of amendment 8 goes through the renderer, and every seat gets what D12
// promises of it.
func TestRender_RendersTheExample(t *testing.T) {
	r := rdRender(t, rdInput(t, "seat-c", "seat-a", "seat-b"))
	if len(r.Bundles) != 3 {
		t.Fatalf("%d bundles, want 3", len(r.Bundles))
	}
	// The seats are rendered, and listed, in the order of the list given (U2).
	for i, seat := range []string{"seat-c", "seat-a", "seat-b"} {
		b := r.Bundles[i]
		if b.Seat != seat || b.CID != demoCID {
			t.Errorf("bundle %d is (%s, %s), want (%s, %s): the bundles are in the order of the seat list", i, b.Seat, b.CID, seat, demoCID)
		}
		if len(b.Files) != 2 || b.Files[0].Name != "a.txt" || b.Files[1].Name != "b.txt" {
			t.Errorf("%s: the files are %v, want a.txt and b.txt in byte order", seat, b.Files)
		}
		for _, f := range b.Files {
			if !edition.ValidFileName(f.Name) || bytes.Contains(f.Data, []byte("{{ctf:")) {
				t.Errorf("%s/%s: a bad name or a mark left", seat, f.Name)
			}
		}
		// 5 slots and 4 x 6 implied decoys: one line each.
		if got := len(rdValues(t, b)); got != 5+24 {
			t.Errorf("%s: %d values, want 29", seat, got)
		}
	}
	// 4 answers and the fixed one, for every seat.
	if len(r.Rows) != 3*5 {
		t.Errorf("%d rows, want 15", len(r.Rows))
	}
}

// The answer rows are the answer slots' values, in the format of their question; an
// answer and its decoys are all different; every value is of its slot's vocabulary or
// window.
func TestRender_ValuesAreOfTheirFormatAndTheGroupsDiffer(t *testing.T) {
	seats := []string{"seat-a", "seat-b", "seat-c", "seat-d", "seat-e", "seat-f"}
	r := rdRender(t, rdInput(t, seats...))
	qs := rdQuestions()
	slotOf := map[string]string{"q1": "who", "q2": "where", "q3": "tag", "q4": "when"}
	for _, seat := range seats {
		vals := rdValues(t, rdBundle(t, r, seat))
		for _, row := range rdRowsOf(r, seat) {
			if row.CID != demoCID {
				t.Errorf("%s: a row of cid %s", seat, row.CID)
			}
			slot, ok := slotOf[row.QID]
			if !ok {
				continue // the fixed one
			}
			if vals[slot] != row.Value {
				t.Errorf("%s: the row of %s is not the value of slot %s", seat, row.QID, slot)
			}
			var q catalog.Question
			for _, c := range qs {
				if c.ID == row.QID {
					q = c
				}
			}
			if err := answerformat.Canonical(q.Format, q.Params, row.Value); err != nil {
				t.Errorf("%s: the answer of %s is not in normalised form: %v", seat, row.QID, err)
			}
		}
		for _, slot := range []string{"who", "where", "tag", "when"} {
			group := map[string]struct{}{vals[slot]: {}}
			for j := 1; j <= 6; j++ {
				v := vals[fmt.Sprintf("%s-d%d", slot, j)]
				if v == "" {
					t.Fatalf("%s: no value for %s-d%d", seat, slot, j)
				}
				group[v] = struct{}{}
			}
			if len(group) != 7 {
				t.Errorf("%s: the answer of slot %s and its 6 decoys are %d different values, want 7", seat, slot, len(group))
			}
		}
		// The vocabularies and the window.
		for _, slot := range []string{"who", "who-d1", "who-d6", "other"} {
			if v := vals[slot]; slot != "other" && !strings.HasPrefix(v, sentinel) {
				t.Errorf("%s: %s is not a word of the vocabulary", seat, slot)
			}
		}
		for _, slot := range []string{"where", "where-d3"} {
			parts := strings.Split(vals[slot], "/")
			if len(parts) != 6 || parts[0] != "" || parts[1] != "opt" || parts[2] != "x" ||
				!strings.HasPrefix(parts[3], "a") || !strings.HasPrefix(parts[4], "b") || !strings.HasPrefix(parts[5], "c") {
				t.Errorf("%s: %s is not a path of the vocabulary", seat, slot)
			}
		}
		for _, slot := range []string{"when", "when-d1", "when-d6"} {
			ts, err := time.Parse(time.RFC3339, vals[slot])
			if err != nil || ts.Before(rdBase) || !ts.Before(rdBase.Add(86400*time.Second)) {
				t.Errorf("%s: %s is not a second of the window [base, base + 86400 s)", seat, slot)
			}
		}
	}
}

// V63: a timestamp is a value of the window, and two seats do not draw one (1 in 86400).
func TestRender_TimestampAnswersDifferBySeatAndStayInTheWindow(t *testing.T) {
	r := rdRender(t, rdInput(t, "seat-a", "seat-b"))
	a := rdValues(t, rdBundle(t, r, "seat-a"))["when"]
	b := rdValues(t, rdBundle(t, r, "seat-b"))["when"]
	if a == b {
		t.Errorf("two seats drew one timestamp: %s", a)
	}
	for _, v := range []string{a, b} {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil || ts.Before(rdBase) || !ts.Before(rdBase.Add(86400*time.Second)) {
			t.Errorf("%s is not in the window", v)
		}
	}
}

// A window that does not start at base: the values are of [base + from, base + to).
func TestRender_AWindowAfterBase(t *testing.T) {
	doc := rdDoc().with(slotWhen, func(s *specSlot) { s.window = "{from: 90000, to: 176400}" })
	spec := rdSpec(t, doc)
	in := rdInput(t, "seat-a", "seat-b", "seat-c")
	in.Spec, in.Template = spec, rdTemplate(spec)
	r := rdRender(t, in)
	lo, hi := rdBase.Add(90000*time.Second), rdBase.Add(176400*time.Second)
	for _, b := range r.Bundles {
		vals := rdValues(t, b)
		for _, slot := range []string{"when", "when-d1", "when-d2", "when-d3", "when-d4", "when-d5", "when-d6"} {
			ts, err := time.Parse(time.RFC3339, vals[slot])
			if err != nil || ts.Before(lo) || !ts.Before(hi) {
				t.Errorf("%s: %s is not in [base + 90000 s, base + 176400 s)", b.Seat, slot)
			}
		}
	}
}

// V63: `fixed` is a row of every seat.
func TestRender_FixedAnswersAreInEverySeatsRows(t *testing.T) {
	seats := []string{"seat-a", "seat-b", "seat-c"}
	r := rdRender(t, rdInput(t, seats...))
	for _, seat := range seats {
		n := 0
		for _, row := range rdRowsOf(r, seat) {
			if row.QID == "q5" {
				n++
				if row.Value != "c1,c3" || row.CID != demoCID {
					t.Errorf("%s: the fixed row is %+v", seat, row)
				}
			}
		}
		if n != 1 {
			t.Errorf("%s has %d rows of the fixed question, want 1", seat, n)
		}
		if got := len(rdRowsOf(r, seat)); got != 5 {
			t.Errorf("%s has %d rows, want 5 (4 answers and the fixed one)", seat, got)
		}
	}
}

// V4: one input is one output, and the output is a function of the key and of the seats up
// to and including the seat (U2): not of the seats after it.
func TestRender_IsDeterministicAndKeyed(t *testing.T) {
	a := rdRender(t, rdInput(t, "seat-a", "seat-b"))
	b := rdRender(t, rdInput(t, "seat-a", "seat-b"))
	if !slices.Equal(a.Rows, b.Rows) {
		t.Error("the same input gave other rows")
	}
	for i := range a.Bundles {
		if !rdSameBundle(a.Bundles[i], b.Bundles[i]) {
			t.Errorf("bundle %d differs between two renders of one input", i)
		}
	}

	t.Run("a seat's output does not depend on the seats after it", func(t *testing.T) {
		ab := rdRender(t, rdInput(t, "seat-a", "seat-b"))
		ac := rdRender(t, rdInput(t, "seat-a", "seat-c"))
		if !rdSameBundle(rdBundle(t, ab, "seat-a"), rdBundle(t, ac, "seat-a")) {
			t.Error("the bundle of seat-a changed with the seat after it")
		}
		if !slices.Equal(rdRowsOf(ab, "seat-a"), rdRowsOf(ac, "seat-a")) {
			t.Error("the rows of seat-a changed with the seat after it")
		}
	})
	t.Run("another seat is another output", func(t *testing.T) {
		if rdBundle(t, a, "seat-a").Digest() == rdBundle(t, a, "seat-b").Digest() {
			t.Error("two seats got one bundle")
		}
	})
	t.Run("another key is another output", func(t *testing.T) {
		in := rdInput(t, "seat-a")
		in.Key = rdKey(t, rdKeyText+"-other")
		other := rdRender(t, in)
		if rdBundle(t, other, "seat-a").Digest() == rdBundle(t, a, "seat-a").Digest() {
			t.Error("two keys gave one bundle")
		}
		if slices.Equal(rdRowsOf(other, "seat-a"), rdRowsOf(a, "seat-a")) {
			t.Error("two keys gave one set of rows")
		}
	})
}

// The practice edition: the public key and the seat *.
func TestRenderPractice_IsOneOutputForEveryone(t *testing.T) {
	spec := rdSpec(t, rdDoc())
	tmpl := rdTemplate(spec)
	a, err := edition.RenderPractice(demoCID, spec, rdQuestions(), tmpl)
	if err != nil {
		t.Fatalf("RenderPractice: %v", err)
	}
	b, err := edition.RenderPractice(demoCID, spec, rdQuestions(), tmpl)
	if err != nil {
		t.Fatalf("RenderPractice: %v", err)
	}
	if len(a.Bundles) != 1 || a.Bundles[0].Seat != edition.AnySeat || !rdSameBundle(a.Bundles[0], b.Bundles[0]) || !slices.Equal(a.Rows, b.Rows) {
		t.Error("a practice render is not one bundle of the seat * that repeats byte for byte")
	}
	for _, row := range a.Rows {
		if row.Seat != edition.AnySeat {
			t.Errorf("a practice row of seat %s", row.Seat)
		}
	}
	// It is not the event's output of any seat under another key.
	ev := rdRender(t, rdInput(t, "seat-a"))
	if rdBundle(t, ev, "seat-a").Digest() == a.Bundles[0].Digest() {
		t.Error("the practice bundle is an event bundle")
	}
}

// The inputs that are refused. Each message holds no key and no value.
func TestRender_RefusesWhatItCannotRender(t *testing.T) {
	good := rdRender(t, rdInput(t, "seat-a"))
	values := rdSecretValues(good)
	noKey := rdInput(t, "seat-a")
	noKey.Key = edition.MasterKey{}
	practiceKey := rdInput(t, "seat-a")
	practiceKey.Key = edition.PracticeMasterKey()
	noSeat := rdInput(t, "seat-a")
	noSeat.Seats = nil
	badCID := rdInput(t, "seat-a")
	badCID.CID = "nope"
	noSpec := rdInput(t, "seat-a")
	noSpec.Spec = nil
	handSpec := rdInput(t, "seat-a")
	handSpec.Spec = &edition.Spec{Slots: []edition.Slot{{Name: "who", Role: edition.RoleFiller}}}
	// E2 holds the spec to the questions first: decoys K - 1.
	fewDecoys := rdInput(t, "seat-a")
	fewDecoys.Spec = rdSpec(t, rdDoc().with(slotWho, func(s *specSlot) { s.decoys = "3" }))
	fewDecoys.Template = rdTemplate(fewDecoys.Spec)

	cases := []struct {
		name  string
		in    edition.RenderInput
		rules []string
	}{
		{"no key", noKey, []string{"E3"}},
		{"the public practice key for an event", practiceKey, []string{"E3"}},
		{"no seat", noSeat, []string{"E3"}},
		{"the practice seat in an event", rdInput(t, "seat-a", "*"), []string{"E3"}},
		{"a seat outside the grammar", rdInput(t, "seat-a", "Seat_B"), []string{"E3"}},
		{"a seat twice", rdInput(t, "seat-a", "seat-a"), []string{"E3"}},
		{"a cid that is not a challenge id", badCID, []string{"E3"}},
		{"no spec", noSpec, []string{"E3"}},
		{"a spec that did not come from ParseSpec", handSpec, []string{"E3"}},
		{"decoys below K (E2 first)", fewDecoys, []string{"E2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := edition.Render(c.in)
			if err == nil || r != nil {
				t.Fatalf("Render = %v, %v; want a refusal and no output", r, err)
			}
			if got := rules(err); !slices.Equal(got, c.rules) {
				t.Errorf("rules = %v, want %v: %v", got, c.rules, err)
			}
			rdNoLeak(t, c.name, err, values)
		})
	}
}

// V63 and the fail rules of the template: every failure is a refusal with no output, by the
// rule E3, and names the slot or the file, never a value.
func TestRender_RefusesATemplateThatDoesNotFitTheSpec(t *testing.T) {
	good := rdRender(t, rdInput(t, "seat-a"))
	values := rdSecretValues(good)
	in0 := rdInput(t, "seat-a")

	// with is the template, changed.
	with := func(f func(files []edition.BundleFile) []edition.BundleFile) []edition.BundleFile {
		return f(slices.Clone(in0.Template))
	}
	dropLine := func(prefix string) []edition.BundleFile {
		return with(func(files []edition.BundleFile) []edition.BundleFile {
			for i := range files {
				var keep []string
				for _, ln := range strings.Split(string(files[i].Data), "\n") {
					if !strings.HasPrefix(ln, prefix) {
						keep = append(keep, ln)
					}
				}
				files[i].Data = []byte(strings.Join(keep, "\n"))
			}
			return files
		})
	}
	addToA := func(text string) []edition.BundleFile {
		return with(func(files []edition.BundleFile) []edition.BundleFile {
			files[0].Data = append(slices.Clone(files[0].Data), text...)
			return files
		})
	}
	many := func(n int) []edition.BundleFile {
		files := slices.Clone(in0.Template)
		for i := 0; len(files) < n; i++ {
			files = append(files, edition.BundleFile{Name: fmt.Sprintf("f%02d.txt", i), Data: []byte("x\n")})
		}
		return files
	}
	oversize := with(func(files []edition.BundleFile) []edition.BundleFile {
		chunk := bytes.Repeat([]byte("x"), 300<<10)
		return append(files,
			edition.BundleFile{Name: "big1.txt", Data: chunk},
			edition.BundleFile{Name: "big2.txt", Data: chunk})
	})
	renamed := func(name string) []edition.BundleFile {
		return with(func(files []edition.BundleFile) []edition.BundleFile {
			files[1].Name = name
			return files
		})
	}
	bidi := string(rune(0x202e))

	cases := []struct {
		name  string
		files []edition.BundleFile
		slot  string // a slot the violation must name ("" = none)
		file  string // a file the violation must name ("" = none)
	}{
		{"an implied decoy's mark removed", dropLine("who-d3="), "who-d3", ""},
		{"an answer slot's mark removed", dropLine("where="), "where", ""},
		{"a filler's mark removed", dropLine("other="), "other", ""},
		{"a mark of a slot that is not declared", addToA("x={{ctf:nope}}\n"), "nope", "a.txt"},
		{"a mark of a decoy that is not made (decoys is 6)", addToA("x={{ctf:who-d7}}\n"), "who-d7", "a.txt"},
		{"the mark of an answer with a byte glued to it", addToA("g=x{{ctf:who}}y\n"), "who", "a.txt"},
		{"the mark of an answer with a byte glued before it", addToA("g=x{{ctf:where}}\n"), "where", "a.txt"},
		{"the mark of a decoy with a byte glued after it", addToA("g={{ctf:tag-d1}}y\n"), "tag-d1", "a.txt"},
		{"two marks of decoys in one token", addToA("g={{ctf:tag-d1}}{{ctf:tag-d2}}\n"), "tag-d1", "a.txt"},
		{"a mark with no slot name", addToA("{{ctf:}}\n"), "", "a.txt"},
		{"a mark with a capital", addToA("{{ctf:Who}}\n"), "", "a.txt"},
		{"a mark that is not closed", addToA("{{ctf:who}\n"), "", "a.txt"},
		{"a mark cut by the end of the file", addToA("{{ctf:"), "", "a.txt"},
		{"a name of 32 characters in a mark", addToA("{{ctf:a" + strings.Repeat("0", 31) + "}}\n"), "", "a.txt"},
		{"no template file", nil, "", ""},
		{"a file name outside B2", renamed("B.txt"), "", ""},
		{"a file name that starts with a dot", renamed(".b.txt"), "", ""},
		{"a name that goes up", renamed("../b.txt"), "", ""},
		{"two files with one name", renamed("a.txt"), "", "a.txt"},
		{"65 files", many(65), "", ""},
		{"a file that is not UTF-8", addToA(string([]byte{0xff, 0xfe, '\n'})), "", "a.txt"},
		{"a file with a bidi control character", addToA("x" + bidi + "\n"), "", "a.txt"},
		{"a file over 512 KiB", append(slices.Clone(in0.Template), edition.BundleFile{Name: "big.txt", Data: bytes.Repeat([]byte("x"), 512<<10+1)}), "", "big.txt"},
		{"a bundle over 512 KiB once the files are put together", oversize, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := rdInput(t, "seat-a")
			in.Template = c.files
			r, err := edition.Render(in)
			if err == nil || r != nil {
				t.Fatalf("Render = %v, %v; want a refusal and no output", r, err)
			}
			if got := rules(err); !slices.Equal(got, []string{"E3"}) {
				t.Errorf("rules = %v, want [E3]: %v", got, err)
			}
			named := false
			for _, v := range rdViolations(err) {
				if (c.slot == "" || v.Slot == c.slot) && (c.file == "" || v.File == c.file) {
					named = true
				}
			}
			if !named {
				t.Errorf("no violation names slot %q and file %q: %v", c.slot, c.file, err)
			}
			rdNoLeak(t, c.name, err, values)
		})
	}

	// The template of the cases is the one that renders: the refusals are the change.
	if _, err := edition.Render(rdInput(t, "seat-a")); err != nil {
		t.Fatalf("the unchanged template is refused: %v", err)
	}
	// A template with a mark twice, and a file with no mark, is fine.
	twice := rdInput(t, "seat-a")
	twice.Template = append(slices.Clone(twice.Template), edition.BundleFile{Name: "c.txt", Data: []byte("again {{ctf:who}} and {{ctf:who}}\n")}, edition.BundleFile{Name: "d.txt", Data: []byte("no mark here\n")})
	rt := rdRender(t, twice)
	files := rt.Bundles[0].Files
	if len(files) != 4 || files[3].Name != "d.txt" || string(files[3].Data) != "no mark here\n" {
		t.Fatalf("a file with no mark was not kept as written: %v", files)
	}
	who := rdValues(t, &edition.Bundle{Seat: "seat-a", Files: files[:2]})["who"]
	if want := "again " + who + " and " + who + "\n"; string(files[2].Data) != want {
		t.Errorf("a mark used twice was not put in twice: %q, want %q", files[2].Data, want)
	}
}

// The key never reaches a print: a MasterKey, and an input that holds one.
func TestMasterKey_PrintsNoKey(t *testing.T) {
	k := rdKey(t, rdKeyText)
	in := rdInput(t, "seat-a")
	prints := []string{
		fmt.Sprintf("%v", k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), fmt.Sprintf("%s", k), fmt.Sprintf("%q", k), fmt.Sprintf("%x", k), fmt.Sprint(k),
		fmt.Sprintf("%v", &k), fmt.Sprintf("%+v", in.Key), fmt.Sprintf("%+v", struct{ K edition.MasterKey }{k}),
	}
	enc, err := json.Marshal(struct{ K edition.MasterKey }{k})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	prints = append(prints, string(enc))
	for _, p := range prints {
		if strings.Contains(p, rdKeyText) || strings.Contains(p, "KEY-SENTINEL") {
			t.Errorf("a print of the key holds it: %q", p)
		}
	}
	if _, err := edition.NewMasterKey(nil); err == nil {
		t.Error("an empty key was accepted")
	}
	// The key is copied: changing the bytes after the call does not change the key.
	raw := []byte(rdKeyText)
	k2, err := edition.NewMasterKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 'z'
	}
	in2 := rdInput(t, "seat-a")
	in2.Key = k2
	if !rdSameBundle(rdBundle(t, rdRender(t, in2), "seat-a"), rdBundle(t, rdRender(t, rdInput(t, "seat-a")), "seat-a")) {
		t.Error("NewMasterKey did not copy its argument")
	}
}
