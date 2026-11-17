package edition

// ADR-0056 D12 and D19 A4d-2, the parts that need the unexported pieces of the renderer:
// the random source (V4, E12: the length prefixes, the seed, the stream, the unbiased
// choice) and the scan of the marks. The key here is a made-up string of a test.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	drbgTestKey = "not-a-secret-test-key-0123456789abcdef" // 38 bytes: a key of the length an event needs
	drbgSeat    = "seat-a"
	drbgCID     = "01-demo"
)

// timeZero is the time.base of a slot that is not a timestamp: it is not read.
var timeZero time.Time

func drbgTestMasterKey(t *testing.T) MasterKey {
	t.Helper()
	k, err := NewMasterKey([]byte(drbgTestKey))
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	return k
}

// The input of a seed is the ADR's: every field as 4 bytes (big-endian) of its length and
// then its bytes.
func TestLengthPrefixed_IsTheInputOfTheADR(t *testing.T) {
	want := []byte{0, 0, 0, 2, 'a', 'b', 0, 0, 0, 1, 'c'}
	if got := lengthPrefixed("ab", "c"); !bytes.Equal(got, want) {
		t.Errorf("lengthPrefixed(ab, c) = %v, want %v", got, want)
	}
	if got := lengthPrefixed("", "x"); !bytes.Equal(got, []byte{0, 0, 0, 0, 0, 0, 0, 1, 'x'}) {
		t.Errorf("lengthPrefixed(\"\", x) = %v", got)
	}
}

// The seed is HMAC-SHA256(master, len(v) || v || len(seat) || seat || len(cid) || cid ||
// len(slot) || slot) with v the label falco-ctf/edition/v1 (20 bytes), computed here by hand
// from the ADR's text and not through lengthPrefixed.
func TestNewDRBG_SeedIsTheHMACOfTheADRsInput(t *testing.T) {
	var in []byte
	in = append(in, 0, 0, 0, 20)
	in = append(in, "falco-ctf/edition/v1"...)
	in = append(in, 0, 0, 0, 6)
	in = append(in, "seat-a"...)
	in = append(in, 0, 0, 0, 7)
	in = append(in, "01-demo"...)
	in = append(in, 0, 0, 0, 3)
	in = append(in, "who"...)
	m := hmac.New(sha256.New, []byte(drbgTestKey))
	m.Write(in)
	want := m.Sum(nil)

	d := newDRBG(drbgTestMasterKey(t), drbgSeat, drbgCID, "who")
	if !bytes.Equal(d.seed[:], want) {
		t.Errorf("the seed is not the HMAC of the length-prefixed input")
	}
}

// V70: the version label is in the input of the seed: another label is another stream and
// other values, and a label that moves a byte into the seat is another seed too.
func TestNewDRBG_TheLabelIsPartOfTheInput(t *testing.T) {
	key := drbgTestMasterKey(t)
	v1 := newDRBGLabel(editionLabel, key, drbgSeat, drbgCID, "who")
	v2 := newDRBGLabel("falco-ctf/edition/v2", key, drbgSeat, drbgCID, "who")
	if editionLabel != "falco-ctf/edition/v1" {
		t.Errorf("the label is %q", editionLabel)
	}
	if v1.seed == v2.seed {
		t.Error("two labels gave one seed")
	}
	a, _ := v1.bytes(64)
	b, _ := v2.bytes(64)
	if bytes.Equal(a, b) {
		t.Error("two labels gave one stream")
	}
	// The label is length-prefixed like the rest: moving its last byte into the seat is a
	// different input.
	x := newDRBGLabel("falco-ctf/edition/v", key, "1"+drbgSeat, drbgCID, "who")
	if x.seed == v1.seed {
		t.Error("the end of the label and the start of the seat are one input")
	}
	if newDRBG(key, drbgSeat, drbgCID, "who").seed != v1.seed {
		t.Error("newDRBG does not use editionLabel")
	}
}

// V76: the fingerprint is HMAC-SHA256(key, len || the fingerprint label), computed here by hand;
// its label is another domain than the seeds', so it is no seed and no block of a stream.
func TestKeyFingerprint_IsAnotherDomainThanTheSeeds(t *testing.T) {
	key := drbgTestMasterKey(t)
	const label = "falco-ctf/edition/key-fingerprint/v1"
	var in []byte
	in = append(in, 0, 0, 0, byte(len(label)))
	in = append(in, label...)
	m := hmac.New(sha256.New, []byte(drbgTestKey))
	m.Write(in)
	want := fmt.Sprintf("%x", m.Sum(nil))
	if got := key.Fingerprint(); got != want {
		t.Errorf("the fingerprint is not the HMAC of the length-prefixed label")
	}
	if keyFingerprintLabel == editionLabel {
		t.Error("the fingerprint label is the seeds' label")
	}
	// It is no seed, and no block of a stream, of any (seat, cid, slot) tried here.
	for _, slot := range []string{"who", "where", "tag", "when", "other"} {
		d := newDRBG(key, drbgSeat, drbgCID, slot)
		if fmt.Sprintf("%x", d.seed) == want {
			t.Errorf("the fingerprint is the seed of slot %s", slot)
		}
		blk, _ := d.bytes(96)
		for i := 0; i+32 <= len(blk); i += 32 {
			if fmt.Sprintf("%x", blk[i:i+32]) == want {
				t.Errorf("the fingerprint is a block of the stream of slot %s", slot)
			}
		}
	}
}

// E12: ("ab", "c") and ("a", "bc") are two inputs. The same bytes without the prefixes
// would be one (the first assertion of each case documents it).
func TestNewDRBG_TheBoundaryOfTwoFieldsIsPartOfTheInput(t *testing.T) {
	key := drbgTestMasterKey(t)
	for _, c := range []struct {
		name string
		a, b [3]string // seat, cid, slot
	}{
		{"seat and cid", [3]string{"ab", "c", "x"}, [3]string{"a", "bc", "x"}},
		{"cid and slot", [3]string{"s", "ab", "c"}, [3]string{"s", "a", "bc"}},
		{"seat and slot, with an empty cid", [3]string{"ab", "", "c"}, [3]string{"a", "", "bc"}},
		{"a field moved whole to the next", [3]string{"ab", "", "c"}, [3]string{"", "ab", "c"}},
	} {
		if c.a[0]+c.a[1]+c.a[2] != c.b[0]+c.b[1]+c.b[2] {
			t.Fatalf("%s: the case does not concatenate to one string", c.name)
		}
		da := newDRBG(key, c.a[0], c.a[1], c.a[2])
		db := newDRBG(key, c.b[0], c.b[1], c.b[2])
		if da.seed == db.seed {
			t.Errorf("%s: two inputs have one seed", c.name)
		}
	}
}

func TestDRBG_StreamIsDeterministicAndContinuous(t *testing.T) {
	key := drbgTestMasterKey(t)
	read := func(slot string, parts ...int) []byte {
		d := newDRBG(key, drbgSeat, drbgCID, slot)
		var out []byte
		for _, n := range parts {
			b, err := d.bytes(n)
			if err != nil {
				t.Fatalf("bytes(%d): %v", n, err)
			}
			if len(b) != n {
				t.Fatalf("bytes(%d) gave %d bytes", n, len(b))
			}
			out = append(out, b...)
		}
		return out
	}
	whole := read("who", 100)
	if !bytes.Equal(whole, read("who", 100)) {
		t.Error("the same slot gave two streams")
	}
	// Reads that cross the end of a 32-byte block give the same bytes as one read.
	if !bytes.Equal(whole, read("who", 31, 5, 1, 63)) {
		t.Error("a read in pieces is not the same stream as one read")
	}
	if bytes.Equal(whole, read("where", 100)) {
		t.Error("two slots gave one stream")
	}
	// The blocks of one stream differ from each other (a counter, not a repeat).
	if bytes.Equal(whole[:32], whole[32:64]) || bytes.Equal(whole[32:64], whole[64:96]) {
		t.Error("two blocks of a stream are equal")
	}
	// The stream is keyed by the master key.
	other, err := NewMasterKey([]byte(drbgTestKey + "-other"))
	if err != nil {
		t.Fatal(err)
	}
	d := newDRBG(other, drbgSeat, drbgCID, "who")
	b, _ := d.bytes(100)
	if bytes.Equal(whole, b) {
		t.Error("two keys gave one stream")
	}
}

// scriptedDraws is a source of 64-bit draws that the test writes down.
type scriptedDraws struct {
	vals []uint64
	used int
}

func (s *scriptedDraws) next() (uint64, error) {
	if s.used >= len(s.vals) {
		return 0, errors.New("the script is over")
	}
	v := s.vals[s.used]
	s.used++
	return v, nil
}

// Rejection sampling: a draw below 2^64 mod n is thrown away, the next one is used. With
// `r % n` alone the values 0 .. (2^64 mod n) - 1 would be drawn one time more than the rest.
func TestUniformBelow_RejectsTheDrawsThatWouldBiasTheChoice(t *testing.T) {
	const bigN = uint64(1)<<63 + 1 // 2^64 mod bigN = 2^63 - 1
	const bigT = uint64(1)<<63 - 1 // the threshold of bigN
	cases := []struct {
		name     string
		n        uint64
		draws    []uint64
		want     uint64
		consumed int
	}{
		{"n = 3: 2^64 mod 3 = 1, so 0 is rejected", 3, []uint64{0, 5}, 2, 2},
		{"n = 3: 1 is kept", 3, []uint64{1}, 1, 1},
		{"n = 3: the largest draw is kept", 3, []uint64{^uint64(0)}, (^uint64(0)) % 3, 1},
		{"n a power of two: nothing is rejected", 8, []uint64{13}, 5, 1},
		{"n = 1: the one value", 1, []uint64{7}, 0, 1},
		{"a large n: the draw below the threshold is rejected", bigN, []uint64{bigT - 1, bigT}, bigT, 2},
		{"a large n: the draw at the threshold is kept", bigN, []uint64{bigT}, bigT, 1},
	}
	for _, c := range cases {
		src := &scriptedDraws{vals: c.draws}
		got, err := uniformBelow(src, c.n)
		if err != nil || got != c.want || src.used != c.consumed {
			t.Errorf("%s: uniformBelow = %d, %v after %d draws; want %d after %d", c.name, got, err, src.used, c.want, c.consumed)
		}
	}
	if _, err := uniformBelow(&scriptedDraws{vals: []uint64{1}}, 0); !errors.Is(err, errBelowZero) {
		t.Errorf("n = 0: err = %v, want errBelowZero", err)
	}
	// A source that only ever gives a rejected draw ends in an error, not in a loop.
	rejected := make([]uint64, maxRejections+1)
	if _, err := uniformBelow(&scriptedDraws{vals: rejected}, 3); !errors.Is(err, errDrawBudget) {
		t.Errorf("endless rejections: err = %v, want errDrawBudget", err)
	}
	// A source that fails is an error.
	if _, err := uniformBelow(&scriptedDraws{}, 3); err == nil {
		t.Error("a source that fails gave a value")
	}
}

// The stream gives a choice among 3 that is close to uniform (a fixed key, so the counts
// are the same every run; the bounds are 7 standard deviations wide).
func TestDRBG_BelowIsRoughlyUniform(t *testing.T) {
	d := newDRBG(drbgTestMasterKey(t), drbgSeat, drbgCID, "who")
	var counts [3]int
	for i := 0; i < 3000; i++ {
		v, err := d.below(3)
		if err != nil {
			t.Fatalf("below: %v", err)
		}
		counts[v]++
	}
	for v, n := range counts {
		if n < 800 || n > 1200 {
			t.Errorf("value %d was drawn %d times of 3000 (counts %v)", v, n, counts)
		}
	}
}

// A group's slots are drawn to differ. In a space as small as the group the draws use
// every value once, and one more draw has no value left and is an error, not a repeat.
func TestDrawDistinct_FillsATightSpaceAndRefusesToRepeat(t *testing.T) {
	key := drbgTestMasterKey(t)
	words := []string{"a", "b", "c", "d", "e"}
	slot := &renderSlot{name: "s", format: "name", vocab: [][]string{words}, group: "s"}
	seen := map[string]struct{}{}
	for i := 0; i < len(words); i++ {
		d := newDRBG(key, drbgSeat, drbgCID, fmt.Sprintf("s-d%d", i))
		v, err := slot.drawDistinct(d, timeZero, seen, nil)
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		if _, ok := seen[v]; !ok {
			t.Errorf("draw %d: %q was not recorded", i, v)
		}
	}
	if len(seen) != len(words) {
		t.Errorf("the group holds %d distinct values of %d", len(seen), len(words))
	}
	d := newDRBG(key, drbgSeat, drbgCID, "s-d5")
	if v, err := slot.drawDistinct(d, timeZero, seen, nil); err == nil {
		t.Errorf("a sixth value of a space of five was drawn: %q", v)
	}
}

// U2: a value that an earlier seat got at the position is thrown away and the next of the
// same stream is taken; the draws of a stream are the same however the value is used, so
// the value after a rejection is the stream's next. And the draw is bounded: a position
// whose every value is taken is an error (E3 at the caller), not a loop.
func TestDrawDistinct_SkipsWhatEarlierSeatsGot(t *testing.T) {
	key := drbgTestMasterKey(t)
	words := make([]string, 20)
	for i := range words {
		words[i] = fmt.Sprintf("w%02d", i)
	}
	slot := &renderSlot{name: "s", format: "name", vocab: [][]string{words}, group: "s"}

	free, err := slot.drawDistinct(newDRBG(key, drbgSeat, drbgCID, "s"), timeZero, nil, nil)
	if err != nil {
		t.Fatalf("drawDistinct: %v", err)
	}
	// The stream's first value is taken by an earlier seat: the seat gets another one, and it
	// is the second value of the very stream (read here with a copy of the stream).
	d := newDRBG(key, drbgSeat, drbgCID, "s")
	first, _ := slot.draw(d, timeZero)
	second, _ := slot.draw(d, timeZero)
	if first != free {
		t.Fatalf("the first draw %q is not what an empty position gives %q", first, free)
	}
	before := map[string]struct{}{first: {}}
	got, err := slot.drawDistinct(newDRBG(key, drbgSeat, drbgCID, "s"), timeZero, nil, before)
	if err != nil || got == first {
		t.Fatalf("drawDistinct = %q, %v; want a value other than the taken one", got, err)
	}
	if second != first && got != second {
		t.Errorf("the value after a rejection is %q, want the stream's next, %q", got, second)
	}
	if _, ok := before[got]; !ok {
		t.Error("the value was not added to the position's set")
	}
	// A position with every value taken: an error, after a bounded number of draws.
	all := make(map[string]struct{}, len(words))
	for _, w := range words {
		all[w] = struct{}{}
	}
	if v, err := slot.drawDistinct(newDRBG(key, drbgSeat, drbgCID, "s"), timeZero, nil, all); err == nil {
		t.Errorf("a value was drawn from a position that has none left: %q", v)
	}
}

// fill puts a value in once and refuses what it cannot: no format makes a `{{ctf:`, so the
// test hands fill a value that does; a mark with no value; a bundle over the limit.
func TestFill_PutsTheValuesInAndRefusesWhatItCannot(t *testing.T) {
	ct := &compiledTemplate{files: []tmplFile{{
		name:  "a.txt",
		parts: []TemplatePart{{Lit: []byte("x="), Slot: "a"}, {Lit: []byte("\n")}},
	}}}
	got, err := ct.fill(drbgCID, drbgSeat, map[string]string{"a": "v"})
	if err != nil || len(got) != 1 || got[0].Name != "a.txt" || string(got[0].Data) != "x=v\n" {
		t.Fatalf("fill = %v, %v; want one file a.txt of x=v", got, err)
	}
	for name, values := range map[string]map[string]string{
		"a value that is a mark":  {"a": "{{ctf:b}}"},
		"a mark with no value":    {},
		"a bundle over 512 KiB":   {"a": strings.Repeat("x", MaxBundleBytes+1)},
		"a value that makes one":  {"a": "{{ctf:"},
		"a value of a lone brace": {"a": "{"},
	} {
		out, err := ct.fill(drbgCID, drbgSeat, values)
		switch name {
		case "a value of a lone brace":
			// Not a mark: a brace alone is a value no format makes, but it is not `{{ctf:`.
			if err != nil || len(out) != 1 {
				t.Errorf("%s: fill = %v, %v; want it put in", name, out, err)
			}
		default:
			if err == nil || out != nil {
				t.Errorf("%s: fill = %v, %v; want a refusal and no output", name, out, err)
			}
		}
	}
}

// LayoutOf gives the index of the token of each mark, and whether the mark is the whole token:
// the one place the renderer (E3) and the validator (B7) read positions from.
func TestLayoutOf(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		marks  []MarkPosition
		tokens int
	}{
		{"a mark of its own", "u={{ctf:who}}\n", []MarkPosition{{"who", 1, true}}, 2},
		{"two lines", "a={{ctf:x}}\nb={{ctf:y}}\n", []MarkPosition{{"x", 1, true}, {"y", 3, true}}, 4},
		{"a byte glued before and after", "x{{ctf:a}}y", []MarkPosition{{"a", 0, false}}, 1},
		{"a slash glued before", "/opt/{{ctf:a}}", []MarkPosition{{"a", 0, false}}, 1},
		{"a suffix glued after", "p={{ctf:a}}.txt", []MarkPosition{{"a", 1, false}}, 2},
		{"two marks in one token", "{{ctf:a}}{{ctf:b}}", []MarkPosition{{"a", 0, false}, {"b", 0, false}}, 1},
		{"a mark between spaces and brackets", "[ {{ctf:a}} ]", []MarkPosition{{"a", 0, true}}, 1},
		{"no mark", "plain words here\n", nil, 3},
		{"empty", "", nil, 0},
	}
	for _, c := range cases {
		got, err := LayoutOf([]byte(c.in))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got.Tokens != c.tokens || fmt.Sprint(got.Marks) != fmt.Sprint(c.marks) {
			t.Errorf("%s: LayoutOf = %v (%d tokens), want %v (%d)", c.name, got.Marks, got.Tokens, c.marks, c.tokens)
		}
	}
	if _, err := LayoutOf([]byte("a {{ctf:Who}}")); err == nil {
		t.Error("a mark outside the grammar was accepted")
	}
}

// What the template scan reads is a mark {{ctf:<slot>}} and nothing else (slotmark.go, the
// one lexer; B4 calls it too).
func TestScanMarks(t *testing.T) {
	type part struct{ lit, slot string }
	ok := []struct {
		name string
		in   string
		want []part
	}{
		{"no mark", "plain\ntext\n", []part{{"plain\ntext\n", ""}}},
		{"one mark", "u={{ctf:who}}\n", []part{{"u=", "who"}, {"\n", ""}}},
		{"two marks, adjacent", "{{ctf:a}}{{ctf:b-d1}}", []part{{"", "a"}, {"", "b-d1"}, {"", ""}}},
		{"an extra brace before", "{{{ctf:a}}", []part{{"{", "a"}, {"", ""}}},
		{"an extra brace after", "{{ctf:a}}}", []part{{"", "a"}, {"}", ""}}},
		{"the longest slot name", "{{ctf:a" + fmt.Sprintf("%030d", 0) + "}}", []part{{"", "a" + fmt.Sprintf("%030d", 0)}, {"", ""}}},
		{"a brace pair that is not a mark", "{{ ctf:a }} {{x}}", []part{{"{{ ctf:a }} {{x}}", ""}}},
		{"empty", "", []part{{"", ""}}},
	}
	for _, c := range ok {
		parts, err := ScanMarks([]byte(c.in))
		if err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
			continue
		}
		var got []part
		for _, p := range parts {
			got = append(got, part{string(p.Lit), p.Slot})
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: parts = %v, want %v", c.name, got, c.want)
		}
	}
	bad := []struct {
		name string
		in   string
		line int
	}{
		{"no slot name", "{{ctf:}}", 1},
		{"a capital in the name", "{{ctf:Who}}", 1},
		{"a digit first", "{{ctf:1x}}", 1},
		{"no closing braces", "{{ctf:who}", 1},
		{"one closing brace and the end", "{{ctf:who", 1},
		{"a space inside", "{{ctf: who}}", 1},
		{"an underscore in the name", "{{ctf:who_x}}", 1},
		{"a name of 32 characters", "{{ctf:a" + fmt.Sprintf("%031d", 0) + "}}", 1},
		{"the line of the mark", "ok\n{{ctf:Who}}\n", 2},
		{"a bad mark after a good one", "{{ctf:who}} {{ctf:", 1},
	}
	for _, c := range bad {
		parts, err := ScanMarks([]byte(c.in))
		var me *MarkError
		if err == nil || parts != nil || !errors.As(err, &me) || me.Line != c.line {
			t.Errorf("%s: ScanMarks = %v, %v; want a *MarkError at line %d", c.name, parts, err, c.line)
		}
	}
}
