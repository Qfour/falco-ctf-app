package edition_test

// ADR-0056 amendment 10 / D19 A4d-2a (V68, V70, V71, and V4's pairs): the assignment of
// values to seats (U2), the key, and the refusals of E3. The example is rdDoc: its smallest
// answer space is the 200 words of the name vocabulary, so 100 seats is the most it takes
// (S >= 2N). Every value and key is a placeholder.

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// rdSeatNames is n seats in the order seat-000, seat-001, ...
func rdSeatNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("seat-%03d", i)
	}
	return out
}

// rdPositionSlots are the slots that U2 assigns: an answer slot and its 6 decoys, for each
// of the four per-seat questions of rdDoc. (The filler `other` is not assigned.)
func rdPositionSlots() []string {
	var out []string
	for _, s := range []string{"who", "where", "tag", "when"} {
		out = append(out, s)
		for j := 1; j <= 6; j++ {
			out = append(out, fmt.Sprintf("%s-d%d", s, j))
		}
	}
	return out
}

// rdPositionsAreUnique reports whether every assigned slot has a value of its own in every
// seat of the rendered bundles, and says which slot is the first that has not.
func rdPositionsAreUnique(t *testing.T, bundles []*edition.Bundle) (bool, string) {
	t.Helper()
	valuesOf := make([]map[string]string, len(bundles))
	for i, b := range bundles {
		valuesOf[i] = rdValues(t, b)
	}
	for _, slot := range rdPositionSlots() {
		seen := make(map[string]struct{}, len(bundles))
		for _, vals := range valuesOf {
			if _, dup := seen[vals[slot]]; dup {
				return false, slot
			}
			seen[vals[slot]] = struct{}{}
		}
	}
	return true, ""
}

// rdTable is the rows of a render as an answers table (the helper of the package's tests).
func rdTable(rows []edition.AnswerRow) []byte {
	var out [][]string
	for _, r := range rows {
		out = append(out, []string{r.Seat, r.CID, r.QID, r.Value})
	}
	return render(runA, out)
}

// V68: with S = 200 and 100 seats (2N = S), no two seats share a value at any position of
// an answer group, and the table passes Check, T8 included. The same seats drawn without
// the assignment (each seat on its own, which is what a draw that ignores the others is)
// share values, and T8 refuses the table.
func TestRender_EveryPositionHasAValueOfItsOwnInEverySeat(t *testing.T) {
	seats := rdSeatNames(100)
	r := rdRender(t, rdInput(t, seats...))
	if ok, slot := rdPositionsAreUnique(t, r.Bundles); !ok {
		t.Fatalf("two seats share a value of slot %s", slot)
	}
	tb, err := edition.Parse(rdTable(r.Rows))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	scope := edition.Scope{demoCID: rdQuestions()}
	if err := edition.Check(tb, scope, eventOpts()); err != nil {
		t.Fatalf("Check refuses the table of 100 seats: %v", err)
	}

	// Without the assignment: every seat alone.
	var alone []*edition.Bundle
	var rows []edition.AnswerRow
	for _, seat := range seats {
		one := rdRender(t, rdInput(t, seat))
		alone = append(alone, one.Bundles...)
		rows = append(rows, one.Rows...)
	}
	if ok, _ := rdPositionsAreUnique(t, alone); ok {
		t.Error("100 seats drawn on their own share no value at any position: the test does not show what the assignment is for")
	}
	tb, err = edition.Parse(rdTable(rows))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := rules(edition.Check(tb, scope, eventOpts())); !slices.Contains(got, "T8") {
		t.Errorf("Check of the seats drawn on their own: rules = %v, want T8 among them", got)
	}
}

// V4 (pairs): for 8 seats, every pair of seats differs at every decoy of every question (so
// at K or more positions that are not the answer's), and in the answer.
func TestRender_EveryPairOfSeatsDiffersAtEveryDecoy(t *testing.T) {
	seats := rdSeatNames(8)
	r := rdRender(t, rdInput(t, seats...))
	k := edition.DecoyK(2)
	for i := range r.Bundles {
		vi := rdValues(t, r.Bundles[i])
		for j := i + 1; j < len(r.Bundles); j++ {
			vj := rdValues(t, r.Bundles[j])
			for _, s := range []string{"who", "where", "tag", "when"} {
				if vi[s] == vj[s] {
					t.Errorf("%s and %s have one answer of slot %s", seats[i], seats[j], s)
				}
				differing := 0
				for d := 1; d <= 6; d++ {
					if slot := fmt.Sprintf("%s-d%d", s, d); vi[slot] != vj[slot] {
						differing++
					}
				}
				if differing < k {
					t.Errorf("%s and %s differ at %d decoys of slot %s, want at least K = %d", seats[i], seats[j], differing, s, k)
				}
			}
		}
	}
}

// V68: a seat added at the end of the list changes no value of the others (answers, decoys
// and fillers), byte for byte.
func TestRender_AppendingASeatChangesNothingBefore(t *testing.T) {
	seats := rdSeatNames(51)
	before := rdRender(t, rdInput(t, seats[:50]...))
	after := rdRender(t, rdInput(t, seats...))
	for i := 0; i < 50; i++ {
		if !rdSameBundle(before.Bundles[i], after.Bundles[i]) {
			t.Errorf("the bundle of %s changed when a seat was added at the end", seats[i])
		}
	}
	if !slices.Equal(before.Rows, after.Rows[:len(before.Rows)]) {
		t.Error("the rows of the earlier seats changed when a seat was added at the end")
	}
}

// V68: the order of the list matters: a seat that moves behind the others gets other values
// where an earlier seat had taken its draw. With 100 seats in a space of 200, half of the
// positions of the last seat are taken, so reversing the list changes the first and the last
// seat (it would take 29 positions agreeing by chance for one of them not to).
func TestRender_ReorderingTheSeatsChangesTheLaterValues(t *testing.T) {
	seats := rdSeatNames(100)
	fwd := rdRender(t, rdInput(t, seats...))
	rev := slices.Clone(seats)
	slices.Reverse(rev)
	bwd := rdRender(t, rdInput(t, rev...))
	first, last := seats[0], seats[99]
	changed := !rdSameBundle(rdBundle(t, fwd, first), rdBundle(t, bwd, first)) ||
		!rdSameBundle(rdBundle(t, fwd, last), rdBundle(t, bwd, last))
	if !changed {
		t.Error("reversing the seat list changed no value of the first and the last seat")
	}
	// The seat that is first in a list does not depend on the others: it has the same bundle
	// whatever follows.
	if !rdSameBundle(rdBundle(t, fwd, first), rdBundle(t, rdRender(t, rdInput(t, first)), first)) {
		t.Error("the first seat of a list differs from the same seat rendered alone")
	}
}

// V68, E3: a space below 2 x the seats is refused before anything is drawn, with the slot
// named, and 2N = S is accepted (the first test above).
func TestRender_ASpaceBelowTwiceTheSeatsIsE3(t *testing.T) {
	r, err := edition.Render(rdInput(t, rdSeatNames(101)...))
	if err == nil || r != nil {
		t.Fatalf("Render of 101 seats in a space of 200 = %v, %v; want E3 and no output", r, err)
	}
	if got := rules(err); !slices.Equal(got, []string{"E3"}) {
		t.Errorf("rules = %v, want [E3]: %v", got, err)
	}
	named := map[string]bool{}
	for _, v := range rdViolations(err) {
		named[v.Slot] = true
	}
	if !named["who"] || named["where"] {
		t.Errorf("the slots named are %v, want who (the name vocabulary of 200) and not where (1000)", named)
	}
	good := rdRender(t, rdInput(t, "seat-a"))
	rdNoLeak(t, "a space below 2N", err, rdSecretValues(good))

	// S = 2N - 1: a name vocabulary of 199 words (one attempt, so 100 x attempts is met) and
	// 100 seats. The refusal is a comparison of two numbers: another key gives the same E3,
	// and the same seats with a vocabulary of 200 words render.
	qs := rdQuestions()
	qs[0].Attempts = 1
	short := rdSpec(t, rdDoc().with(slotWho, func(s *specSlot) { s.vocab = specVocab(specWords(sentinel, 199)) }))
	enough := rdSpec(t, rdDoc().with(slotWho, func(s *specSlot) { s.vocab = specVocab(specWords(sentinel, 200)) }))
	for i, key := range []string{rdKeyText, rdKeyText + "-another", strings.Repeat("z", 40)} {
		in := rdInput(t, rdSeatNames(100)...)
		in.Key = rdKey(t, key)
		in.Questions = qs
		in.Spec, in.Template = short, rdTemplate(short)
		if r, err := edition.Render(in); err == nil || r != nil || !slices.Equal(rules(err), []string{"E3"}) {
			t.Errorf("S = 199, N = 100, key %d: Render = %v, %v; want E3 and no output", i, r, err)
		}
	}
	in := rdInput(t, rdSeatNames(100)...)
	in.Questions = qs
	in.Spec, in.Template = enough, rdTemplate(enough)
	if _, err := edition.Render(in); err != nil {
		t.Errorf("S = 200, N = 100: %v", err)
	}
}

// CheckSeatSpace is the one comparison (B8 (a2)): the validator calls it with its own rule
// name and gets the same refusal as the renderer's E3.
func TestSpecCheckSeatSpace_IsOneComparisonForTheRendererAndTheValidator(t *testing.T) {
	spec := rdSpec(t, rdDoc())
	qs := rdQuestions()
	tmpl := rdTemplate(spec)
	if err := spec.CheckSeatSpace(demoCID, qs, tmpl, 100, edition.RuleVocabSpace); err != nil {
		t.Errorf("100 seats in a space of 200: %v", err)
	}
	err := spec.CheckSeatSpace(demoCID, qs, tmpl, 101, edition.RuleVocabSpace)
	if got := rules(err); !slices.Equal(got, []string{"B8"}) {
		t.Errorf("101 seats as the validator: rules = %v, want [B8]", got)
	}
	if got := rules(spec.CheckSeatSpace(demoCID, qs, tmpl, 101, edition.RuleSpecRender)); !slices.Equal(got, []string{"E3"}) {
		t.Errorf("101 seats as the renderer: rules = %v, want [E3]", got)
	}
	if len(rdViolations(err)) != 1 {
		t.Errorf("%d violations, want one per answer slot that is short (who)", len(rdViolations(err)))
	}
	rdNoLeak(t, "CheckSeatSpace", err, nil)
	if spec.CheckSeatSpace(demoCID, qs, tmpl, 0, edition.RuleSpecRender) == nil {
		t.Error("no seat was accepted")
	}
	var none *edition.Spec
	if none.CheckSeatSpace(demoCID, qs, tmpl, 1, edition.RuleSpecRender) == nil {
		t.Error("a missing spec was accepted")
	}
}

// V74: the previous seat list. It is required, the first render is NoPreviousSeats and nothing
// else (an empty list is "not given", ADR-0056 D20), and the new list must extend the
// previous one at its end; the check is before anything is drawn.
func TestRender_PreviousSeatsMustBeExtendedAtTheEnd(t *testing.T) {
	seats := []string{"seat-a", "seat-b", "seat-c", "seat-d"}
	with := func(prev edition.PreviousSeats, list ...string) edition.RenderInput {
		in := rdInput(t, list...)
		in.Previous = prev
		return in
	}
	var notGiven edition.RenderInput = rdInput(t, seats...)
	notGiven.Previous = edition.PreviousSeats{}
	cases := []struct {
		name string
		in   edition.RenderInput
		ok   bool
	}{
		{"not given (the zero value)", notGiven, false},
		{"the first render (an empty list)", with(edition.NoPreviousSeats(), seats...), true},
		{"an empty previous list is not the first render: it is not given (D20)", with(edition.PreviousSeatsOf(nil), seats...), false},
		{"an empty, non-nil previous list is not given either", with(edition.PreviousSeatsOf([]string{}), seats...), false},
		{"the same list", with(edition.PreviousSeatsOf(seats), seats...), true},
		{"a seat added at the end", with(edition.PreviousSeatsOf(seats[:3]), seats...), true},
		{"two seats swapped", with(edition.PreviousSeatsOf([]string{"seat-b", "seat-a"}), seats...), false},
		{"a seat removed (the previous list is longer)", with(edition.PreviousSeatsOf(append(slices.Clone(seats), "seat-e")), seats...), false},
		{"a seat removed from the middle", with(edition.PreviousSeatsOf(seats), "seat-a", "seat-b", "seat-d"), false},
		{"a seat inserted in the middle", with(edition.PreviousSeatsOf(seats[:3]), "seat-a", "seat-b", "seat-x", "seat-c"), false},
		{"a seat inserted at the start", with(edition.PreviousSeatsOf(seats[:3]), "seat-x", "seat-a", "seat-b", "seat-c"), false},
		{"a previous seat outside the grammar", with(edition.PreviousSeatsOf([]string{"Seat_A"}), seats...), false},
		{"a previous seat twice", with(edition.PreviousSeatsOf([]string{"seat-a", "seat-a"}), seats...), false},
	}
	good := rdRender(t, rdInput(t, "seat-a"))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := edition.Render(c.in)
			if c.ok {
				if err != nil {
					t.Fatalf("Render: %v", err)
				}
				return
			}
			if err == nil || r != nil {
				t.Fatalf("Render = %v, %v; want E3 and no output", r, err)
			}
			if got := rules(err); !slices.Equal(got, []string{"E3"}) {
				t.Errorf("rules = %v, want [E3]: %v", got, err)
			}
			rdNoLeak(t, c.name, err, rdSecretValues(good))
		})
	}

	// The previous list is copied: changing the slice afterwards changes nothing.
	prevList := slices.Clone(seats[:3])
	prev := edition.PreviousSeatsOf(prevList)
	prevList[0] = "seat-z"
	if _, err := edition.Render(with(prev, seats...)); err != nil {
		t.Errorf("the previous list was not copied: %v", err)
	}
	// A list that extends the previous one keeps the values of the earlier seats, byte for byte.
	before := rdRender(t, with(edition.NoPreviousSeats(), seats[:3]...))
	after := rdRender(t, with(edition.PreviousSeatsOf(seats[:3]), seats...))
	for i := 0; i < 3; i++ {
		if !rdSameBundle(before.Bundles[i], after.Bundles[i]) {
			t.Errorf("the bundle of %s changed when a seat was added at the end", seats[i])
		}
	}
	// The same list as the previous one (an extension by no seat: the render made again after the
	// image changed, ADR-0056 amendment 19) passes and keeps every value, byte for byte.
	same := rdRender(t, with(edition.PreviousSeatsOf(seats[:3]), seats[:3]...))
	if len(same.Bundles) != 3 {
		t.Fatalf("the render of the same list has %d bundles, want 3", len(same.Bundles))
	}
	for i := 0; i < 3; i++ {
		if !rdSameBundle(before.Bundles[i], same.Bundles[i]) {
			t.Errorf("the bundle of %s changed when the list was the previous one again", seats[i])
		}
	}
}

// V74 (E3, the marks): the mark of an answer or a decoy that has a token byte next to it is E3,
// and the mark of a filler may. (The cases that are refused are in render_test.go's table.)
func TestRender_AFillersMarkMayBeGluedAndAnAnswersMayNotBe(t *testing.T) {
	in := rdInput(t, "seat-a")
	glued := append(slices.Clone(in.Template), edition.BundleFile{Name: "c.txt", Data: []byte("f=x{{ctf:other}}y\n")})
	in.Template = glued
	r := rdRender(t, in)
	if got := string(r.Bundles[0].Files[2].Data); !strings.HasPrefix(got, "f=x") || !strings.HasSuffix(got, "y\n") {
		t.Errorf("the filler's file is %q", got)
	}
}

// V76: the key's fingerprint, and the record of a render. The same key gives the same
// fingerprint, another key another one; it is 64 lower-case hex digits; the record holds the
// run id and the fingerprint and neither the key nor a value.
func TestKeyFingerprintAndRenderRecord(t *testing.T) {
	a, b := rdKey(t, rdKeyText), rdKey(t, rdKeyText+"-other")
	if a.Fingerprint() != rdKey(t, rdKeyText).Fingerprint() {
		t.Error("one key gave two fingerprints")
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("two keys gave one fingerprint")
	}
	if !edition.ValidDigest(a.Fingerprint()) {
		t.Errorf("the fingerprint is not 64 lower-case hex digits: %q", a.Fingerprint())
	}
	if strings.Contains(a.Fingerprint(), "KEY") || strings.Contains(a.Fingerprint(), rdKeyText) {
		t.Error("the fingerprint holds the key")
	}

	var buf bytes.Buffer
	scope := []string{"00-evade", demoCID}
	if err := edition.WriteRenderRecord(&buf, runA, a, scope); err != nil {
		t.Fatalf("WriteRenderRecord: %v", err)
	}
	want := "# falco-ctf render-record v2\nrun-id\t" + runA + "\nkey-fingerprint\t" + a.Fingerprint() + "\nscope\t" + edition.ScopeDigest(scope) + "\n"
	if buf.String() != want {
		t.Errorf("the record is %q, want %q", buf.String(), want)
	}
	good := rdRender(t, rdInput(t, "seat-a", "seat-b"))
	for _, secret := range append([]string{rdKeyText, sentinel}, rdSecretValues(good)...) {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("the record holds a secret: %q", secret)
		}
	}
	// What it refuses, and writes nothing.
	for name, c := range map[string]struct {
		runID string
		key   edition.MasterKey
		scope []string
	}{
		"the practice run id":          {edition.PracticeRunID, a, scope},
		"a short run id":               {"0123", a, scope},
		"no key":                       {runA, edition.MasterKey{}, scope},
		"the practice key":             {runA, edition.PracticeMasterKey(), scope},
		"no scope":                     {runA, a, nil},
		"an id outside the grammar":    {runA, a, []string{"00-evade", "Demo"}},
		"an id with a line feed in it": {runA, a, []string{"00-evade\n01-demo"}},
	} {
		var out bytes.Buffer
		err := edition.WriteRenderRecord(&out, c.runID, c.key, c.scope)
		if err == nil || out.Len() != 0 {
			t.Errorf("%s: err = %v, %d bytes written; want a refusal and nothing", name, err, out.Len())
		}
	}
}

// V70: the key. 31 bytes and the bytes of the public key are refused (the error holds no
// byte of the key), 32 bytes are not, and no run id is an input of the render.
func TestNewMasterKey_ShortAndPublicKeysAreRefused(t *testing.T) {
	short := strings.Repeat("k", edition.MinMasterKeyBytes-1)
	if _, err := edition.NewMasterKey([]byte(short)); err == nil {
		t.Error("a key of 31 bytes was accepted")
	} else if strings.Contains(err.Error(), "kkkk") {
		t.Errorf("the error holds the key: %v", err)
	}
	if _, err := edition.NewMasterKey([]byte(short + "k")); err != nil {
		t.Errorf("a key of 32 bytes was refused: %v", err)
	}
	if edition.MinMasterKeyBytes != 32 {
		t.Errorf("MinMasterKeyBytes = %d, want 32", edition.MinMasterKeyBytes)
	}
	if _, err := edition.NewMasterKey([]byte("practice")); err == nil {
		t.Error("the bytes of the public practice key were accepted")
	}
	if _, err := edition.NewMasterKey(nil); err == nil {
		t.Error("an empty key was accepted")
	}
	// No run id in the input: the values are a function of the key and the seats alone.
	typ := reflect.TypeOf(edition.RenderInput{})
	for i := 0; i < typ.NumField(); i++ {
		if strings.Contains(strings.ToLower(typ.Field(i).Name), "run") {
			t.Errorf("RenderInput has the field %s: a run id must not be an input of the render", typ.Field(i).Name)
		}
	}
}
