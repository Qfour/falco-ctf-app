package edition_test

// ADR-0056 D10 B7 and B8 (b), D3 (b), D12, amendment 10, D19 A4d-2c (V6 (b), V69, V4): the
// two rules that read what a render made. B7 is a check per seat (U2 gives every position
// of every seat a value of its own, so the pairs follow); the hand-made bundles give its
// exact boundary (K and K - 1), the renders show it on the renderer's own output, and the
// pairs of seats are compared in render_assign_test.go. A token is a maximal run of
// [A-Za-z0-9._:/-]; the hex values below are made-up numbers.

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// rdHexQ is one per-seat question of 2 attempts: K = 4 and R x attempts = 20.
var rdHexQ = []catalog.Question{
	{ID: "hx", Format: answerformat.HexID, Params: answerformat.Params{Length: ip(12)}, Attempts: 2},
}

func rdHex(i int) string { return fmt.Sprintf("%012x", i) }

// rdHexSpec is the spec and the template that go with rdHexSeat: one answer slot `ans` of the
// question hx with 4 decoys (ans-d1 .. ans-d4), a.txt with the answer on one line and each
// decoy on a line of its own.
func rdHexSpec(t *testing.T) (*edition.Spec, []edition.BundleFile) {
	t.Helper()
	spec := rdSpec(t, specDoc{
		version: "1", fixed: "{}",
		slots: []specSlot{{name: "ans", role: "answer", question: "hx", decoys: "4"}},
	})
	var b strings.Builder
	b.WriteString("a={{ctf:ans}}\n")
	for j := 1; j <= 4; j++ {
		fmt.Fprintf(&b, "d%d={{ctf:ans-d%d}}\n", j-1, j)
	}
	return spec, []edition.BundleFile{{Name: "a.txt", Data: []byte(b.String())}}
}

// rdHexSeat is a seat's bundle of one file, a.txt, in the layout of rdHexSpec's template.
func rdHexSeat(seat, answer string, decoys ...string) edition.SpreadSeat {
	var b strings.Builder
	fmt.Fprintf(&b, "a=%s\n", answer)
	for i, d := range decoys {
		fmt.Fprintf(&b, "d%d=%s\n", i, d)
	}
	return edition.SpreadSeat{Seat: seat, Files: []edition.BundleFile{{Name: "a.txt", Data: []byte(b.String())}}}
}

// rdHexRange is the hex values from, from+1, ..., from+n-1.
func rdHexRange(from, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = rdHex(from + i)
	}
	return out
}

func rdSpreadSeats(r *edition.Rendered) []edition.SpreadSeat {
	var out []edition.SpreadSeat
	for _, b := range r.Bundles {
		out = append(out, edition.SpreadSeat{Seat: b.Seat, Files: b.Files})
	}
	return out
}

// rdWideInput is the example with `decoys` decoys for every answer slot.
func rdWideInput(t *testing.T, decoys string, seats ...string) edition.RenderInput {
	t.Helper()
	d := rdDoc()
	for _, i := range []int{slotWho, slotWhere, slotTag, slotWhen} {
		d = d.with(i, func(s *specSlot) { s.decoys = decoys })
	}
	spec := rdSpec(t, d)
	in := rdInput(t, seats...)
	in.Spec, in.Template = spec, rdTemplate(spec)
	return in
}

func rdQIDs(err error) []string {
	set := map[string]struct{}{}
	for _, v := range rdViolations(err) {
		set[v.QID] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for q := range set {
		out = append(out, q)
	}
	slices.Sort(out)
	return out
}

// B7 to the unit: K = 4 distinct decoy tokens that fit pass, 3 do not. A decoy that does not
// fit (another token, capitals, glued to other bytes), and a decoy that repeats another, is
// not a decoy the participant has to try.
func TestCheckDecoySpread_KPassesAndKMinusOneDoesNot(t *testing.T) {
	spec, tmpl := rdHexSpec(t)
	cases := []struct {
		name string
		seat edition.SpreadSeat
		want bool // accepted
		have int  // the count the message gives, when it is refused
	}{
		{"4 decoys that fit (K)", rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 4)...), true, 0},
		{"3 decoys fit, the 4th is not a hexid", rdHexSeat("seat-a", rdHex(1), rdHex(10), rdHex(11), rdHex(12), "zz"), false, 3},
		{"3 decoys fit, the 4th is in capitals", rdHexSeat("seat-a", rdHex(1), rdHex(10), rdHex(11), rdHex(12), strings.ToUpper(rdHex(0xabc))), false, 3},
		{"3 decoys fit, the 4th has a byte glued to it", rdHexSeat("seat-a", rdHex(1), rdHex(10), rdHex(11), rdHex(12), "x"+rdHex(13)+"y"), false, 3},
		{"4 decoys of which 2 are one value", rdHexSeat("seat-a", rdHex(1), rdHex(10), rdHex(10), rdHex(11), rdHex(12)), false, 3},
		{"no decoy fits", rdHexSeat("seat-a", rdHex(1), "a", "b", "c", "d"), false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := edition.CheckDecoySpread(demoCID, spec, rdHexQ, tmpl, []edition.SpreadSeat{c.seat})
			if c.want {
				if err != nil {
					t.Fatalf("CheckDecoySpread: %v", err)
				}
				return
			}
			specWantRules(t, err, "B7")
			vs := rdViolations(err)
			if len(vs) != 1 || vs[0].Seat != "seat-a" || vs[0].QID != "hx" || vs[0].CID != demoCID {
				t.Fatalf("violations = %+v, want one: seat-a, hx, %s", vs, demoCID)
			}
			if want := fmt.Sprintf("holds %d distinct decoy tokens", c.have); !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "K = 4") {
				t.Errorf("the message is %q, want it to say %q and K = 4", err.Error(), want)
			}
			for _, v := range []string{rdHex(1), rdHex(10), rdHex(11), rdHex(12)} {
				if strings.Contains(err.Error(), v) {
					t.Errorf("the message holds a value: %v", err)
				}
			}
		})
	}
}

// Each seat is checked on its own: the seat that is short is named, the other is not, and one
// seat alone is checked too (the check does not need a pair).
func TestCheckDecoySpread_EverySeatIsChecked(t *testing.T) {
	spec, tmpl := rdHexSpec(t)
	ok := rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 4)...)
	short := rdHexSeat("seat-b", rdHex(2), rdHex(20), rdHex(21), rdHex(22), "zz")
	err := edition.CheckDecoySpread(demoCID, spec, rdHexQ, tmpl, []edition.SpreadSeat{short, ok})
	if vs := rdViolations(err); len(vs) != 1 || vs[0].Seat != "seat-b" {
		t.Errorf("violations = %+v (err %v), want only seat-b", vs, err)
	}
	if err := edition.CheckDecoySpread(demoCID, spec, rdHexQ, tmpl, []edition.SpreadSeat{ok}); err != nil {
		t.Errorf("one seat that is fine: %v", err)
	}
	// Two seats that are fine: nothing is asked of the pair.
	two := rdHexSeat("seat-b", rdHex(2), rdHexRange(20, 4)...)
	if err := edition.CheckDecoySpread(demoCID, spec, rdHexQ, tmpl, []edition.SpreadSeat{ok, two}); err != nil {
		t.Errorf("two seats that are fine: %v", err)
	}
}

// A bundle that does not have the template's layout cannot be read by position: a
// violation, not a pass.
func TestCheckDecoySpread_ALayoutThatDiffersIsAViolation(t *testing.T) {
	spec, tmpl := rdHexSpec(t)
	moreTokens := rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 5)...)
	otherName := rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 4)...)
	otherName.Files[0].Name = "b.txt"
	for name, s := range map[string]edition.SpreadSeat{"another number of tokens": moreTokens, "another file name": otherName} {
		err := edition.CheckDecoySpread(demoCID, spec, rdHexQ, tmpl, []edition.SpreadSeat{s})
		specWantRules(t, err, "B7")
		if !strings.Contains(err.Error(), "layout") {
			t.Errorf("%s: the message does not say it is the layout: %v", name, err)
		}
	}
}

// What the rules cannot be run on is refused, not passed. A practice edition (the seat *, which
// is public) is not checked: the seat grammar refuses it.
func TestSpreadRules_RefuseWhatTheyCannotRunOn(t *testing.T) {
	spec, tmpl := rdHexSpec(t)
	a := rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 4)...)
	b := rdHexSeat("seat-b", rdHex(2), rdHexRange(20, 4)...)
	badSeat := rdHexSeat("Seat_B", rdHex(2), rdHexRange(20, 4)...)
	starSeat := rdHexSeat("*", rdHex(2), rdHexRange(20, 4)...)
	choiceOnly := []catalog.Question{{ID: "pick", Format: answerformat.ChoiceSet, Params: answerformat.Params{Choices: []string{"ca", "cb"}}, Attempts: 2}}
	badTemplate := []edition.BundleFile{{Name: "a.txt", Data: []byte("a={{ctf:}}\n")}}

	cases := []struct {
		name  string
		cid   string
		spec  *edition.Spec
		qs    []catalog.Question
		tmpl  []edition.BundleFile
		seats []edition.SpreadSeat
	}{
		{"no seat", demoCID, spec, rdHexQ, tmpl, nil},
		{"a cid that is not a challenge id", "nope", spec, rdHexQ, tmpl, []edition.SpreadSeat{a, b}},
		{"no question that can vary per seat", demoCID, spec, choiceOnly, tmpl, []edition.SpreadSeat{a, b}},
		{"a seat outside the grammar", demoCID, spec, rdHexQ, tmpl, []edition.SpreadSeat{a, badSeat}},
		{"the practice seat", demoCID, spec, rdHexQ, tmpl, []edition.SpreadSeat{starSeat}},
		{"a seat twice", demoCID, spec, rdHexQ, tmpl, []edition.SpreadSeat{a, a}},
	}
	for _, c := range cases {
		for rule, run := range map[string]func() error{
			"B7": func() error { return edition.CheckDecoySpread(c.cid, c.spec, c.qs, c.tmpl, c.seats) },
			"B8": func() error { return edition.CheckOutputSpace(c.cid, c.qs, c.seats) },
		} {
			err := run()
			if err == nil {
				t.Errorf("%s (%s): accepted", c.name, rule)
				continue
			}
			if got := rules(err); len(got) != 1 || got[0] != "B7" {
				t.Errorf("%s (%s): rules = %v, want [B7] (the rule that could not run)", c.name, rule, got)
			}
		}
	}
	// B7 alone: no spec, and a template with a mark outside the grammar.
	if err := edition.CheckDecoySpread(demoCID, nil, rdHexQ, tmpl, []edition.SpreadSeat{a}); err == nil {
		t.Error("a missing spec was accepted")
	}
	if err := edition.CheckDecoySpread(demoCID, spec, rdHexQ, badTemplate, []edition.SpreadSeat{a}); err == nil {
		t.Error("a template with a mark outside the grammar was accepted")
	}
}

// B8 (b) to the unit: R x attempts = 20 distinct tokens of the format pass, 19 do not. A
// token counts once, and only if it is in the question's normalised form.
func TestCheckOutputSpace_RTimesAttemptsAndOneLess(t *testing.T) {
	cases := []struct {
		name string
		seat edition.SpreadSeat
		want bool
		have int // the count the message gives, when it is refused
	}{
		{"the answer and 19 decoys: 20", rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 19)...), true, 0},
		{"the answer and 18 decoys: 19", rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 18)...), false, 19},
		{"25 lines, 19 distinct values", rdHexSeat("seat-a", rdHex(1), append(rdHexRange(10, 18), rdHexRange(10, 6)...)...), false, 19},
		{"20 values of which 2 are in capitals", rdHexSeat("seat-a", rdHex(1), append(rdHexRange(10, 17),
			strings.ToUpper(rdHex(0xa0)), strings.ToUpper(rdHex(0xa1)))...), false, 18},
		{"20 values of which 2 are of another length", rdHexSeat("seat-a", rdHex(1), append(rdHexRange(10, 17),
			rdHex(0xa0)+"0", rdHex(0xa1)[1:])...), false, 18},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := edition.CheckOutputSpace(demoCID, rdHexQ, []edition.SpreadSeat{c.seat})
			if c.want {
				if err != nil {
					t.Fatalf("CheckOutputSpace: %v", err)
				}
				return
			}
			specWantRules(t, err, "B8")
			vs := rdViolations(err)
			if len(vs) != 1 || vs[0].Seat != "seat-a" || vs[0].QID != "hx" || vs[0].CID != demoCID {
				t.Fatalf("violations = %+v, want one: seat-a, hx, %s", vs, demoCID)
			}
			if want := fmt.Sprintf("holds %d distinct tokens", c.have); !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "needs 20") {
				t.Errorf("the message is %q, want it to say %q and 'needs 20'", err.Error(), want)
			}
			if strings.Contains(err.Error(), rdHex(1)) || strings.Contains(err.Error(), rdHex(10)) {
				t.Errorf("the message holds a value: %v", err)
			}
		})
	}
	// Each seat is counted on its own: a seat that is short is named, the other is not.
	short := rdHexSeat("seat-b", rdHex(2), rdHexRange(100, 5)...)
	ok := rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 19)...)
	err := edition.CheckOutputSpace(demoCID, rdHexQ, []edition.SpreadSeat{ok, short})
	if vs := rdViolations(err); len(vs) != 1 || vs[0].Seat != "seat-b" {
		t.Errorf("violations = %+v (err %v), want only seat-b", vs, err)
	}
}

// B8 (b) on the renderer's output: with 19 decoys an answer slot gives 20 candidates, the least
// for 2 attempts; with 18 it gives 19, and the questions of a path, a hexid and a timestamp
// are short (a name has the labels and the hexids of the template to try as well, which the
// rule counts, as the attacker does).
func TestCheckOutputSpace_OnARender(t *testing.T) {
	seats := []string{"seat-a", "seat-b", "seat-c"}
	wide := rdRender(t, rdWideInput(t, "19", seats...))
	if err := edition.CheckOutputSpace(demoCID, rdQuestions(), rdSpreadSeats(wide)); err != nil {
		t.Errorf("19 decoys: %v", err)
	}
	narrow := rdRender(t, rdWideInput(t, "18", seats...))
	err := edition.CheckOutputSpace(demoCID, rdQuestions(), rdSpreadSeats(narrow))
	specWantRules(t, err, "B8")
	if got := rdQIDs(err); !slices.Equal(got, []string{"q2", "q3", "q4"}) {
		t.Errorf("the questions that are short are %v, want q2, q3 and q4", got)
	}
	if got := len(rdViolations(err)); got != 3*3 {
		t.Errorf("%d violations, want 9 (3 seats x 3 questions)", got)
	}
	rdNoLeak(t, "B8 on a render", err, rdSecretValues(narrow))
}

// B7 on the renderer's output (V4, V69): every seat has its decoys and no two seats share a token
// at a position, for 8 seats and for 1 seat (the per-seat part is checked alone, the part
// between seats is empty).
func TestCheckDecoySpread_OnARender(t *testing.T) {
	r := rdRender(t, rdInput(t, rdSeatNames(8)...))
	spec := rdSpec(t, rdDoc())
	tmpl := rdTemplate(spec)
	if err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, rdSpreadSeats(r)); err != nil {
		t.Fatalf("CheckDecoySpread on a render of 8 seats: %v", err)
	}
	one := rdRender(t, rdInput(t, "seat-a"))
	if err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, rdSpreadSeats(one)); err != nil {
		t.Errorf("one seat: %v", err)
	}
}

// V69: the validator does not trust the renderer. A template that glues a byte to the mark of
// an answer or a decoy (E3 in the renderer) cannot be located by position, so B7 is red on it
// (the bundles are the ones the unglued template renders: only the template is not trusted).
func TestCheckDecoySpread_ATemplateWithAGluedMarkIsAViolation(t *testing.T) {
	spec := rdSpec(t, rdDoc())
	tmpl := rdTemplate(spec)
	out := rdRender(t, rdInput(t, "seat-a", "seat-b"))
	for _, slot := range []string{"tag-d1", "tag"} {
		files := slices.Clone(tmpl)
		for i := range files {
			files[i].Data = []byte(strings.ReplaceAll(string(files[i].Data), "{{ctf:"+slot+"}}", "x{{ctf:"+slot+"}}y"))
		}
		err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), files, rdSpreadSeats(out))
		specWantRules(t, err, "B7")
		if !strings.Contains(err.Error(), "token of its own") {
			t.Errorf("%s glued: the message is %v", slot, err)
		}
	}
	// A filler's mark may be glued: it is not located.
	files := slices.Clone(tmpl)
	for i := range files {
		files[i].Data = []byte(strings.ReplaceAll(string(files[i].Data), "{{ctf:other}}", "x{{ctf:other}}y"))
	}
	if err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), files, rdSpreadSeats(out)); err != nil {
		t.Errorf("a glued filler mark made B7 red: %v", err)
	}
}

// V69: two seats that hold the same token at the position of a decoy, or of an answer, are a
// violation (the seat that comes second in byte order is named), while each seat alone is fine.
func TestCheckDecoySpread_TwoSeatsWithOneTokenAtAPositionAreAViolation(t *testing.T) {
	spec, tmpl := rdHexSpec(t)
	a := rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 4)...)
	for _, c := range []struct {
		name string
		b    edition.SpreadSeat
		slot string
	}{
		{"a decoy in common", rdHexSeat("seat-b", rdHex(2), rdHex(10), rdHex(21), rdHex(22), rdHex(23)), "ans-d1"},
		{"the answer in common", rdHexSeat("seat-b", rdHex(1), rdHexRange(20, 4)...), "ans"},
	} {
		err := edition.CheckDecoySpread(demoCID, spec, rdHexQ, tmpl, []edition.SpreadSeat{c.b, a})
		specWantRules(t, err, "B7")
		vs := rdViolations(err)
		if len(vs) != 1 || vs[0].Seat != "seat-b" || vs[0].QID != "hx" || vs[0].Slot != c.slot || vs[0].File != "a.txt" {
			t.Errorf("%s: violations = %+v, want one: seat-b, hx, slot %s, file a.txt", c.name, vs, c.slot)
		}
		for _, v := range []string{rdHex(1), rdHex(10)} {
			if strings.Contains(err.Error(), v) {
				t.Errorf("%s: the message holds a value: %v", c.name, err)
			}
		}
	}
	// Each of the two alone is fine, and so are two that differ everywhere.
	b := rdHexSeat("seat-b", rdHex(2), rdHexRange(20, 4)...)
	for _, seats := range [][]edition.SpreadSeat{{a}, {b}, {a, b}} {
		if err := edition.CheckDecoySpread(demoCID, spec, rdHexQ, tmpl, seats); err != nil {
			t.Errorf("%d seats that differ everywhere: %v", len(seats), err)
		}
	}
}

// rdWithValues is a seat's bundle (a render's, one `slot=value` line each) with the value of
// some slots replaced: a bundle that the renderer did not make, as the validator may be given.
func rdWithValues(b *edition.Bundle, repl map[string]string) edition.SpreadSeat {
	out := edition.SpreadSeat{Seat: b.Seat}
	for _, f := range b.Files {
		lines := strings.Split(strings.TrimSuffix(string(f.Data), "\n"), "\n")
		for i, ln := range lines {
			if k, _, ok := strings.Cut(ln, "="); ok {
				if v, hit := repl[k]; hit {
					lines[i] = k + "=" + v
				}
			}
		}
		out.Files = append(out.Files, edition.BundleFile{Name: f.Name, Data: []byte(strings.Join(lines, "\n") + "\n")})
	}
	return out
}

// rdSwapSeat is seats with the bundle of the seat replaced by s.
func rdSwapSeat(seats []edition.SpreadSeat, s edition.SpreadSeat) []edition.SpreadSeat {
	out := slices.Clone(seats)
	for i := range out {
		if out[i].Seat == s.Seat {
			out[i] = s
		}
	}
	return out
}

// V69 and V4, on the renderer's own output: 8 seats pass; then ONE change that the renderer did
// not make (a decoy or an answer that another seat holds at the position) is a B7 violation that
// names the seat, the question, the slot and the file, and no value (the vocabulary of the name
// question is the sentinel, so a value in a message shows up).
func TestCheckDecoySpread_OneSharedTokenOnARenderIsRed(t *testing.T) {
	r := rdRender(t, rdInput(t, rdSeatNames(8)...))
	spec := rdSpec(t, rdDoc())
	tmpl := rdTemplate(spec)
	seats := rdSpreadSeats(r)
	if err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, seats); err != nil {
		t.Fatalf("the render itself: %v", err)
	}
	first := rdValues(t, rdBundle(t, r, "seat-000"))
	changed := rdBundle(t, r, "seat-003")
	for _, c := range []struct{ name, slot, qid string }{
		{"a decoy of the name question", "who-d3", "q1"},
		{"the answer of the path question", "where", "q2"},
		{"a decoy of the hexid question", "tag-d5", "q3"},
		{"a decoy of the timestamp question", "when-d2", "q4"},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := rdWithValues(changed, map[string]string{c.slot: first[c.slot]})
			err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, rdSwapSeat(seats, bad))
			specWantRules(t, err, "B7")
			vs := rdViolations(err)
			if len(vs) != 1 || vs[0].Seat != "seat-003" || vs[0].QID != c.qid || vs[0].Slot != c.slot || vs[0].CID != demoCID || vs[0].File == "" {
				t.Fatalf("violations = %+v, want one: seat-003, %s, slot %s, a file", vs, c.qid, c.slot)
			}
			rdNoLeak(t, c.name, err, rdSecretValues(r))
		})
	}
}

// V69, V4: the per-seat part alone (one seat): K = 4 distinct decoys that fit pass and 3 do not,
// on a render. The decoys are made the same as one another, within the seat, so that no other
// seat is involved.
func TestCheckDecoySpread_OneSeatOnARenderKAndKMinusOne(t *testing.T) {
	r := rdRender(t, rdInput(t, "seat-000"))
	spec := rdSpec(t, rdDoc())
	tmpl := rdTemplate(spec)
	own := rdBundle(t, r, "seat-000")
	v := rdValues(t, own)
	if err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, rdSpreadSeats(r)); err != nil {
		t.Fatalf("the render of one seat: %v", err)
	}
	// 6 decoys of which 4 are different: K.
	four := rdWithValues(own, map[string]string{"who-d5": v["who-d4"], "who-d6": v["who-d4"]})
	if err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, []edition.SpreadSeat{four}); err != nil {
		t.Errorf("4 different decoys (K): %v", err)
	}
	// 6 decoys of which 3 are different: K - 1.
	three := rdWithValues(own, map[string]string{"who-d4": v["who-d3"], "who-d5": v["who-d3"], "who-d6": v["who-d3"]})
	err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, []edition.SpreadSeat{three})
	specWantRules(t, err, "B7")
	vs := rdViolations(err)
	if len(vs) != 1 || vs[0].Seat != "seat-000" || vs[0].QID != "q1" || !strings.Contains(vs[0].Msg, "holds 3 distinct decoy tokens") {
		t.Errorf("violations = %+v, want one: seat-000, q1, 3 distinct decoy tokens", vs)
	}
	rdNoLeak(t, "K - 1 on a render", err, rdSecretValues(r))
}

// V4, V68: B7 is what the assignment is for. 100 seats rendered together (S = 200 = 2N) pass; the
// same 100 seats each drawn on its own (the assignment taken away) share a token at some
// position, and B7 is red on them.
func TestCheckDecoySpread_SeatsDrawnWithoutTheAssignmentAreRed(t *testing.T) {
	seats := rdSeatNames(100)
	spec := rdSpec(t, rdDoc())
	tmpl := rdTemplate(spec)
	together := rdRender(t, rdInput(t, seats...))
	if err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, rdSpreadSeats(together)); err != nil {
		t.Fatalf("100 seats rendered together: %v", err)
	}
	var alone []edition.SpreadSeat
	for _, seat := range seats {
		one := rdRender(t, rdInput(t, seat))
		alone = append(alone, rdSpreadSeats(one)...)
	}
	err := edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, alone)
	specWantRules(t, err, "B7")
	if !strings.Contains(err.Error(), "an earlier seat holds the same token") {
		t.Errorf("the message does not say that two seats hold one token: %v", err)
	}
	rdNoLeak(t, "seats drawn alone", err, rdSecretValues(together))
}

// V69: a practice edition (the seat *, rendered with the public key) is not checked by B7 or by
// B8 (b): both refuse it (the caller, A4e, does not pass one), and neither passes it.
func TestSpreadRules_APracticeRenderIsNotChecked(t *testing.T) {
	spec := rdSpec(t, rdDoc())
	tmpl := rdTemplate(spec)
	p, err := edition.RenderPractice(demoCID, spec, rdQuestions(), tmpl)
	if err != nil {
		t.Fatalf("RenderPractice: %v", err)
	}
	seats := rdSpreadSeats(p)
	if len(seats) != 1 || seats[0].Seat != edition.AnySeat {
		t.Fatalf("a practice render is %+v, want the one seat *", seats)
	}
	for rule, run := range map[string]func() error{
		"B7":     func() error { return edition.CheckDecoySpread(demoCID, spec, rdQuestions(), tmpl, seats) },
		"B8 (b)": func() error { return edition.CheckOutputSpace(demoCID, rdQuestions(), seats) },
	} {
		err := run()
		if err == nil {
			t.Errorf("%s: a practice render was accepted", rule)
			continue
		}
		if got := rules(err); len(got) != 1 || got[0] != "B7" || !strings.Contains(err.Error(), "practice edition is not checked") {
			t.Errorf("%s: rules = %v, err = %v; want the refusal of the seat *", rule, got, err)
		}
	}
}

// The validator does not trust what it is given: a Spec made by hand (Version 1 and the slots of
// a parsed one, with no implied decoy, so nothing says where the decoys are), a mark of a slot
// that edition.yaml does not declare, and a question with no attempts (a floor of 0 passes
// anything) are refused.
func TestSpreadRules_RefuseInputsTheyCannotTrust(t *testing.T) {
	spec, tmpl := rdHexSpec(t)
	seats := []edition.SpreadSeat{rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 4)...)}

	hand := &edition.Spec{Version: edition.SpecVersion, Fixed: spec.Fixed, Slots: spec.Slots}
	err := edition.CheckDecoySpread(demoCID, hand, rdHexQ, tmpl, seats)
	specWantRules(t, err, "B7")
	if !strings.Contains(err.Error(), "ParseSpec") {
		t.Errorf("a spec made by hand: %v", err)
	}

	undeclared := []edition.BundleFile{{Name: "a.txt", Data: append(slices.Clone(tmpl[0].Data), "z={{ctf:nope}}\n"...)}}
	err = edition.CheckDecoySpread(demoCID, spec, rdHexQ, undeclared, seats)
	specWantRules(t, err, "B7")
	if !strings.Contains(err.Error(), "does not declare") {
		t.Errorf("a mark of an undeclared slot: %v", err)
	}

	noAttempts := []catalog.Question{{ID: "hx", Format: answerformat.HexID, Params: answerformat.Params{Length: ip(12)}, Attempts: 0}}
	for rule, run := range map[string]func() error{
		"B7":     func() error { return edition.CheckDecoySpread(demoCID, spec, noAttempts, tmpl, seats) },
		"B8 (b)": func() error { return edition.CheckOutputSpace(demoCID, noAttempts, seats) },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "attempts") {
			t.Errorf("%s: a question with no attempts: %v", rule, err)
		}
	}
}

// Which seat is named when two share a token does not depend on the order the caller lists
// them in: the one that comes later in byte order is.
func TestCheckDecoySpread_TheLaterSeatInByteOrderIsNamedWhateverTheListOrder(t *testing.T) {
	spec, tmpl := rdHexSpec(t)
	a := rdHexSeat("seat-a", rdHex(1), rdHexRange(10, 4)...)
	b := rdHexSeat("seat-b", rdHex(1), rdHexRange(20, 4)...)
	for _, seats := range [][]edition.SpreadSeat{{a, b}, {b, a}} {
		vs := rdViolations(edition.CheckDecoySpread(demoCID, spec, rdHexQ, tmpl, seats))
		if len(vs) != 1 || vs[0].Seat != "seat-b" {
			t.Errorf("violations = %+v, want one, of seat-b, for the order %s, %s", vs, seats[0].Seat, seats[1].Seat)
		}
	}
}
