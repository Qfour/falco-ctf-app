package edition

// ADR-0056 D10 B4, V3 (B4) and V19 (A4c-2). One case, one defect, and the sentence that
// names it. The texts are runs of distinct code points (ovRunes), so every 10-rune window of
// a text is distinct and an overlap can be built to an exact count; they carry no meaning.
// An event input is explicit (overlapInput): the practice editions' files and answers and the
// event templates are given by the test, as A4e will give them from CheckedTable.

import (
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// ovRunes is n distinct runes, the k-th being the code point 0x4E00+from+k. A text of n runes
// has n-9 distinct 10-rune shingles, and two texts built from the same `from` share the
// shingles of their common prefix.
func ovRunes(from, n int) string {
	r := make([]rune, n)
	for i := range r {
		r[i] = rune(0x4E00 + from + i)
	}
	return string(r)
}

func ovFile(name, data string) BundleFile { return BundleFile{Name: name, Data: []byte(data)} }

func ovBundle(seat, cid string, files ...BundleFile) *Bundle {
	return &Bundle{Seat: seat, CID: cid, Files: files}
}

func ovBundles(bs ...*Bundle) *Bundles {
	out := &Bundles{index: make(map[cell]*Bundle)}
	for _, b := range bs {
		out.list = append(out.list, b)
		out.index[cell{seat: b.Seat, cid: b.CID}] = b
	}
	return out
}

// ovBase is an input B4 accepts: nothing is shared between the event side (runes from 1000
// and from 2000) and the practice side (from 0 and from 500), and no practice answer is in
// a bundle.
func ovBaseBundles() *Bundles {
	return ovBundles(
		ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(1000, 40))),
		ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
	)
}

func ovBaseInput() overlapInput {
	return overlapInput{
		Practice: practiceFiles{
			"02-prac": {
				Evidence: []BundleFile{ovFile("notes.txt", ovRunes(0, 40))},
				Template: []BundleFile{ovFile("page.txt", ovRunes(500, 40))},
			},
		},
		Answers:   PracticeSet{"hexid": {"0badc0ffee01": {}}, "name": {"practice-who": {}}, "choice-set": {"ca,cb": {}}},
		Templates: map[string][]BundleFile{"01-demo": {ovFile("page.txt", ovRunes(2000, 40))}},
	}
}

func ovRun(bundles *Bundles, in overlapInput, theta float64) (OverlapReport, error) {
	var c collector
	rep := checkPracticeOverlap(&c, bundles, in, theta)
	return rep, c.err()
}

func ovRulesOf(err error) []string {
	var out []string
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
		var v *Violation
		if errors.As(e, &v) {
			out = append(out, v.Rule)
		}
	}
	walk(err)
	slices.Sort(out)
	return slices.Compact(out)
}

func ovApprox(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// The pins (V19): theta is 0.5, and a shingle is hintleak's 10 runes.
func TestPracticeOverlap_PinsThetaAndTheShingleSize(t *testing.T) {
	if OverlapTheta != 0.5 {
		t.Errorf("OverlapTheta = %v, want 0.5 (ADR-0056 D10 B4, CISO 2026-11-16: provisional; a change is Signpost 6's decision and changes this pin with it)", OverlapTheta)
	}
	if hintleak.GramRunes != 10 {
		t.Errorf("hintleak.GramRunes = %d: B4 is defined on the 10-rune shingles of ADR-0026 D5", hintleak.GramRunes)
	}
}

func TestPracticeOverlap_AcceptsAnEditionThatIsNotAPracticeEdition(t *testing.T) {
	rep, err := ovRun(ovBaseBundles(), ovBaseInput(), OverlapTheta)
	if err != nil {
		t.Fatalf("B4 refused an event edition that shares nothing with a practice edition: %v", err)
	}
	if rep.Output.Rate != 0 || rep.Output.Event != "" || rep.Output.Practice != "" {
		t.Errorf("Output = %+v, want rate 0 and no pair", rep.Output)
	}
	if rep.Output.Compared != 2 || rep.Template.Compared != 1 {
		t.Errorf("compared = %d outputs, %d templates; want 2 bundles x 1 edition and 1 template x 1 edition", rep.Output.Compared, rep.Template.Compared)
	}

	// what B4 does not refuse
	cases := []struct {
		name   string
		mutate func(in *overlapInput) *Bundles
	}{
		{"a practice name answer in another case (a name is case sensitive)", func(in *overlapInput) *Bundles {
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(1000, 40)+" PRACTICE-WHO")),
				ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
			)
		}},
		{"a bundle with no file (B1's)", func(in *overlapInput) *Bundles {
			return ovBundles(ovBundle("seat-a", "01-demo"), ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ovBaseInput()
			bundles := c.mutate(&in)
			if bundles == nil {
				bundles = ovBaseBundles()
			}
			if _, err := ovRun(bundles, in, OverlapTheta); err != nil {
				t.Errorf("B4 refused: %v", err)
			}
		})
	}
}

// V3 (B4): every term of B4 refuses, one defect each, as B4 and with the sentence that names it.
func TestPracticeOverlap_OneDefectNamesItsTerm(t *testing.T) {
	cases := []struct {
		name    string
		bundles func() *Bundles
		mutate  func(in *overlapInput)
		theta   float64
		want    string
	}{
		// (a) digests
		{"a file of a bundle is a file of a practice bundle", func() *Bundles {
			// x.txt is the practice file; y.txt is long, so the shingle overlap stays under theta
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("x.txt", ovRunes(0, 40)), ovFile("y.txt", ovRunes(1200, 60))),
				ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
			)
		}, nil, OverlapTheta, "the digest of the file is the digest of a file of the bundle of practice edition 02-prac"},
		{"a bundle is a practice bundle", func() *Bundles {
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(0, 40))),
				ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
			)
		}, nil, OverlapTheta, "the digest of the bundle is the digest of the bundle of practice edition 02-prac"},
		// (b) answers
		{"a practice hexid answer in capitals in a bundle", func() *Bundles {
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(1000, 40)+"\nid 0BADC0FFEE01\n")),
				ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
			)
		}, nil, OverlapTheta, "an answer of a practice edition appears in the bundle"},
		{"a practice name answer in a bundle", func() *Bundles {
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(1000, 40))),
				ovBundle("seat-b", "01-demo", ovFile("a.txt", ovRunes(1100, 40)), ovFile("b.txt", "user practice-who")),
			)
		}, nil, OverlapTheta, "an answer of a practice edition appears in the bundle"},
		// (b) answers of a format that is not per seat (reversed in A4c-2 review: the ADR does
		// not restrict the formats, so the normalised value is searched as it is)
		{"a practice choice-set answer in a bundle", func() *Bundles {
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(1000, 40)+" ca,cb")),
				ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
			)
		}, nil, OverlapTheta, "an answer of a practice edition appears in the bundle"},
		{"a practice technique answer of one character in a bundle", func() *Bundles {
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(1000, 40)+" Z")),
				ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
			)
		}, func(in *overlapInput) { in.Answers["technique"] = map[string]struct{}{"Z": {}} }, OverlapTheta, "an answer of a practice edition appears in the bundle"},
		{"an empty practice answer", nil, func(in *overlapInput) {
			in.Answers["name"] = map[string]struct{}{"": {}}
		}, OverlapTheta, "a practice answer is empty"},
		// (c) shingles: the boundary is TestPracticeOverlap_ThetaBoundary
		{"the outputs overlap", func() *Bundles {
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(0, 30))),
				ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
			)
		}, nil, OverlapTheta, "(outputs)"},
		{"the templates overlap", nil, func(in *overlapInput) {
			in.Templates = map[string][]BundleFile{"01-demo": {ovFile("page.txt", ovRunes(500, 30))}}
		}, OverlapTheta, "(templates)"},
		// theta that is not set: refused, not skipped
		{"theta is zero", nil, nil, 0, "theta is not a number in (0, 1]"},
		{"theta is negative", nil, nil, -0.5, "theta is not a number in (0, 1]"},
		{"theta is NaN", nil, nil, math.NaN(), "theta is not a number in (0, 1]"},
		{"theta is above 1", nil, nil, 1.5, "theta is not a number in (0, 1]"},
		// what was not supplied
		{"the practice files were not supplied", nil, func(in *overlapInput) { in.Practice = nil }, OverlapTheta, "files were not supplied"},
		{"the practice answers were not supplied", nil, func(in *overlapInput) { in.Answers = nil }, OverlapTheta, "practice answers were not supplied"},
		{"no event template was supplied", nil, func(in *overlapInput) { in.Templates = nil }, OverlapTheta, "no event template was supplied"},
		{"no event bundle was supplied", func() *Bundles { return nil }, nil, OverlapTheta, "no event bundle was supplied"},
		// a challenge with a bundle and no template: skipped without a word before A4c-2's review
		{"a challenge that has a bundle has no event template", func() *Bundles {
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(1000, 40))),
				ovBundle("seat-a", "02-other", ovFile("notes.txt", ovRunes(1300, 40))),
			)
		}, nil, OverlapTheta, "no event template was supplied for this challenge"},
		// nothing to compare with: not a pass (reversed in A4c-2 review: it was accepted)
		{"no practice edition at all", nil, func(in *overlapInput) { in.Practice = practiceFiles{} }, OverlapTheta, "no practice edition has a bundle"},
		{"no practice edition at all (the template side)", nil, func(in *overlapInput) { in.Practice = practiceFiles{} }, OverlapTheta, "no practice edition has a template"},
		{"practice editions with a template and no bundle", nil, func(in *overlapInput) { in.Practice["02-prac"].Evidence = nil }, OverlapTheta, "no practice edition has a bundle"},
		{"practice editions with a bundle and no template", nil, func(in *overlapInput) { in.Practice["02-prac"].Template = nil }, OverlapTheta, "no practice edition has a template"},
		// a set with no shingle: 0 / 0 is not a rate
		{"a bundle whose files have no 10-rune sequence", func() *Bundles {
			return ovBundles(
				ovBundle("seat-a", "01-demo", ovFile("a.txt", "abcde fgh"), ovFile("b.txt", "ijk lmnop")),
				ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
			)
		}, nil, OverlapTheta, "the bundle has no 10-rune sequence"},
		{"a template that is only slot marks", nil, func(in *overlapInput) {
			in.Templates = map[string][]BundleFile{"01-demo": {ovFile("page.txt", "{{ctf:alpha}} {{ctf:beta-d1}}")}}
		}, OverlapTheta, "no 10-rune sequence outside its slot marks"},
		{"an event template with no file", nil, func(in *overlapInput) {
			in.Templates = map[string][]BundleFile{"01-demo": nil}
		}, OverlapTheta, "has no file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ovBaseInput()
			if c.mutate != nil {
				c.mutate(&in)
			}
			bundles := ovBaseBundles()
			if c.bundles != nil {
				bundles = c.bundles()
			}
			_, err := ovRun(bundles, in, c.theta)
			if err == nil {
				t.Fatal("B4 accepted the defect")
			}
			if got := ovRulesOf(err); !slices.Equal(got, []string{RuleBundlePractice}) {
				t.Errorf("rules = %v, want only [B4]: %v", got, err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error does not hold %q: %v", c.want, err)
			}
			// no content, no answer value
			for _, bad := range []string{ovRunes(0, 10), ovRunes(1000, 10), ovRunes(500, 10), ovRunes(2000, 10), "0badc0ffee01", "0BADC0FFEE01", "practice-who"} {
				if strings.Contains(err.Error(), bad) {
					t.Errorf("the error carries %q: %v", bad, err)
				}
			}
		})
	}
}

// A violation names where it is: the seat and the challenge of the bundle, the file of a
// digest, the challenge of a template.
func TestPracticeOverlap_ViolationsNameTheirPlace(t *testing.T) {
	in := ovBaseInput()
	bundles := ovBundles(
		ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(1000, 40))),
		ovBundle("seat-b", "01-demo", ovFile("x.txt", ovRunes(0, 40)), ovFile("y.txt", ovRunes(1200, 60))),
	)
	_, err := ovRun(bundles, in, OverlapTheta)
	var v *Violation
	if !errors.As(err, &v) {
		t.Fatalf("err = %v, want a violation", err)
	}
	if v.Rule != RuleBundlePractice || v.Seat != "seat-b" || v.CID != "01-demo" || v.File != "x.txt" {
		t.Errorf("violation = %+v, want B4 at seat-b, 01-demo, file x.txt", *v)
	}

	in.Templates = map[string][]BundleFile{"01-demo": {ovFile("page.txt", ovRunes(500, 30))}}
	_, err = ovRun(ovBaseBundles(), in, OverlapTheta)
	if !errors.As(err, &v) || v.Rule != RuleBundlePractice || v.CID != "01-demo" || v.Seat != "" {
		t.Errorf("violation = %+v (%v), want B4 at challenge 01-demo with no seat", v, err)
	}
}

// V19: the boundary of theta, in both comparisons. n shingles of the event side and m of the
// practice side share the shingles of their common prefix, so the rate is exact. "At or
// above theta" is a refusal: 0.5 itself is refused, and so is a rate a little above it.
func TestPracticeOverlap_ThetaBoundary(t *testing.T) {
	cases := []struct {
		name            string
		event, practice int // runes of the two texts, both from code point 0 (they share a prefix)
		practiceFrom    int // where the practice text starts (0 = shares the prefix)
		reject          bool
		rate            float64
	}{
		{"exactly theta (10 of 20)", 29, 19, 0, true, 0.5},
		{"a little above theta (11 of 21)", 30, 20, 0, true, 11.0 / 21.0},
		{"a little below theta (10 of 21)", 30, 19, 0, false, 10.0 / 21.0},
		{"well below theta (9 of 20)", 29, 18, 0, false, 9.0 / 20.0},
		{"a copy (20 of 20)", 29, 29, 0, true, 1},
		{"nothing in common", 29, 29, 3000, false, 0},
	}
	for _, c := range cases {
		for _, term := range []string{"outputs", "templates"} {
			t.Run(c.name+" / "+term, func(t *testing.T) {
				in := ovBaseInput()
				bundles := ovBaseBundles()
				event, practice := ovRunes(0, c.event), ovRunes(c.practiceFrom, c.practice)
				if term == "outputs" {
					bundles = ovBundles(
						ovBundle("seat-a", "01-demo", ovFile("notes.txt", event)),
						ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
					)
					in.Practice["02-prac"].Evidence = []BundleFile{ovFile("notes.txt", practice)}
				} else {
					in.Templates = map[string][]BundleFile{"01-demo": {ovFile("page.txt", event)}}
					in.Practice["02-prac"].Template = []BundleFile{ovFile("page.txt", practice)}
				}
				rep, err := ovRun(bundles, in, OverlapTheta)
				pair := rep.Output
				if term == "templates" {
					pair = rep.Template
				}
				if !ovApprox(pair.Rate, c.rate) {
					t.Errorf("rate = %v, want %v", pair.Rate, c.rate)
				}
				if c.reject != (err != nil) {
					t.Fatalf("refused = %v, want %v (rate %v, theta %v): %v", err != nil, c.reject, pair.Rate, OverlapTheta, err)
				}
				if c.reject {
					if !strings.Contains(err.Error(), "("+term+")") {
						t.Errorf("the error does not name the term (%s): %v", term, err)
					}
					if pair.Practice != "02-prac" {
						t.Errorf("the pair names practice edition %q, want 02-prac", pair.Practice)
					}
				}
			})
		}
	}

	// theta is the parameter, not a literal: the same overlap passes under a larger theta,
	// and the exact boundary is refused at theta = 0.5 only because 0.5 >= 0.5.
	in := ovBaseInput()
	in.Practice["02-prac"].Evidence = []BundleFile{ovFile("notes.txt", ovRunes(0, 19))}
	bundles := ovBundles(
		ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(0, 29))),
		ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
	)
	if _, err := ovRun(bundles, in, 0.51); err != nil {
		t.Errorf("a rate of 0.5 was refused under theta 0.51: %v", err)
	}
	if _, err := ovRun(bundles, in, 0.5); err == nil {
		t.Error("a rate of 0.5 was accepted under theta 0.5")
	}
	// theta = 1 is a threshold that is set: only a full copy is refused.
	if _, err := ovRun(bundles, in, 1); err != nil {
		t.Errorf("a rate of 0.5 was refused under theta 1: %v", err)
	}
}

// V19: a public template used again with only the fillers changed. The outputs of the two
// editions differ in the filler runs, so the overlap of (1) stays under theta; the templates
// are the same text once the slot marks are out, so (2) is a copy. (1) passes and (2) is
// red, and only (2) is named. The marks carry other slot names in the event template, which
// the comparison does not see.
func TestPracticeOverlap_AReusedTemplateIsCaughtByTheTemplateComparison(t *testing.T) {
	a, b, c := ovRunes(0, 20), ovRunes(100, 20), ovRunes(200, 20)
	practiceTemplate := a + "{{ctf:slot-a}}" + b + "{{ctf:slot-b}}" + c
	practiceOutput := a + ovRunes(300, 12) + b + ovRunes(400, 12) + c
	eventTemplate := a + "{{ctf:other-a}}" + b + "{{ctf:other-b}}" + c
	eventOutput := a + ovRunes(600, 12) + b + ovRunes(700, 12) + c

	in := ovBaseInput()
	in.Practice = practiceFiles{"02-prac": {
		Evidence: []BundleFile{ovFile("notes.txt", practiceOutput)},
		Template: []BundleFile{ovFile("page.txt", practiceTemplate)},
	}}
	in.Templates = map[string][]BundleFile{"01-demo": {ovFile("page.txt", eventTemplate)}}
	bundles := ovBundles(
		ovBundle("seat-a", "01-demo", ovFile("notes.txt", eventOutput)),
		ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(1100, 40))),
	)

	rep, err := ovRun(bundles, in, OverlapTheta)
	if err == nil {
		t.Fatal("B4 accepted a template that is a practice template with other fillers")
	}
	if !strings.Contains(err.Error(), "(templates)") || strings.Contains(err.Error(), "(outputs)") {
		t.Errorf("B4 names the wrong term: %v", err)
	}
	// 3 runs of 20 runes share 11 shingles each (33), of the 75 shingles of the 84-rune output
	if want := 33.0 / 75.0; !ovApprox(rep.Output.Rate, want) || rep.Output.Rate >= OverlapTheta {
		t.Errorf("outputs rate = %v, want %v (under theta: the outputs of a reused template differ)", rep.Output.Rate, want)
	}
	if !ovApprox(rep.Template.Rate, 1) || rep.Template.Event != "01-demo" || rep.Template.Practice != "02-prac" {
		t.Errorf("template pair = %+v, want rate 1 of 01-demo and 02-prac (the marks are removed before the comparison)", rep.Template)
	}
}

// The report names the pair of the largest rate: the practice edition that overlaps most,
// and the bundle that overlaps most. Nothing in it is a content.
func TestPracticeOverlap_TheReportHoldsTheLargestPair(t *testing.T) {
	in := ovBaseInput()
	in.Practice = practiceFiles{
		"02-prac": {Evidence: []BundleFile{ovFile("notes.txt", ovRunes(0, 19))}, Template: []BundleFile{ovFile("page.txt", ovRunes(500, 40))}},
		"03-prac": {Evidence: []BundleFile{ovFile("notes.txt", ovRunes(0, 26))}},
		"04-prac": {Evidence: []BundleFile{ovFile("notes.txt", ovRunes(3000, 40))}},
	}
	bundles := ovBundles(
		ovBundle("seat-a", "01-demo", ovFile("notes.txt", ovRunes(1000, 40))),
		ovBundle("seat-b", "01-demo", ovFile("notes.txt", ovRunes(0, 29))),
	)
	rep, err := ovRun(bundles, in, OverlapTheta)
	if err == nil {
		t.Fatal("B4 accepted a bundle that overlaps a practice bundle by 17 of 20")
	}
	// 03-prac holds the first 26 runes: 17 shingles of the 20 of seat-b's bundle
	if !ovApprox(rep.Output.Rate, 17.0/20.0) || rep.Output.Event != "seat-b/01-demo" || rep.Output.Practice != "03-prac" {
		t.Errorf("Output = %+v, want 0.85 of seat-b/01-demo and 03-prac", rep.Output)
	}
	if rep.Output.Compared != 6 {
		t.Errorf("Output.Compared = %d, want 2 bundles x 3 editions", rep.Output.Compared)
	}
	var v *Violation
	if !errors.As(err, &v) || v.Seat != "seat-b" || !strings.Contains(v.Msg, "03-prac") || strings.Contains(err.Error(), "02-prac") {
		t.Errorf("the violation does not name seat-b and the practice edition 03-prac only: %v", err)
	}
}

// The windows are hintleak's: the whitespace is not a rune of a run, a file is cut by
// itself, and a text of fewer than GramRunes runes has no shingle.
func TestShingleSet_IsHintleaksWindowOverTheNormalisedRunes(t *testing.T) {
	n := hintleak.GramRunes
	text := ovRunes(0, n+5)
	spaced := ""
	for i, r := range []rune(text) {
		spaced += string(r)
		if i%3 == 0 {
			spaced += " \t\n"
		}
	}
	for name, files := range map[string][]BundleFile{
		"plain":      {ovFile("a", text)},
		"whitespace": {ovFile("a", spaced)},
	} {
		if got := len(shingleSet(files, false)); got != 6 {
			t.Errorf("%s: %d shingles of %d runes, want 6", name, got, n+5)
		}
	}
	// two files of GramRunes-1 runes: a run is not made of two files
	short := ovRunes(0, n-1)
	if got := len(shingleSet([]BundleFile{ovFile("a", short), ovFile("b", short)}, false)); got != 0 {
		t.Errorf("two short files gave %d shingles, want 0 (a window is cut from one file)", got)
	}
	// the same file twice is the same shingles
	if got := len(shingleSet([]BundleFile{ovFile("a", text), ovFile("b", text)}, false)); got != 6 {
		t.Errorf("a file twice gave %d shingles, want 6 (a set)", got)
	}
	// marks: removed only when asked, and the text on both sides is joined
	marked := ovRunes(0, 6) + "{{ctf:slot}}" + ovRunes(6, 6)
	if got := len(shingleSet([]BundleFile{ovFile("a", marked)}, true)); got != 3 {
		t.Errorf("a marked template gave %d shingles with the marks out, want 3 (12 runes)", got)
	}
	if got := len(shingleSet([]BundleFile{ovFile("a", marked)}, false)); got <= 3 {
		t.Errorf("the marks were removed when they were not to be: %d shingles", got)
	}
}
