package api

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode"

	"gopkg.in/yaml.v3"
)

// app#377: a board thread subject is participant-written text rendered INLINE
// next to the author ("subject — author"), so validBoardSubject refuses the same
// invisible characters (Cc, Cf) a display name refuses (app#331), with the same
// ZWJ-between-emoji exception, and none of the metacharacters (a subject is
// prose: "can't", "a & b"). The rule is displayNameHasForbidden's, read from
// testdata/display-name-parity/rule.yaml; nothing here restates the class.

// TestBoardSubject_SweepEveryCodePoint: for EVERY code point c, validBoardSubject
// of "a"+c+"b" rejects exactly what the rule's Cc / Cf categories name (the rule's
// metacharacters are accepted: that is the difference from a display name), except
// U+200D, which is only accepted between two emoji and must be refused between
// letters. So "subject == rule" over all of Unicode, as "display name == rule".
func TestBoardSubject_SweepEveryCodePoint(t *testing.T) {
	rule := loadNameRule(t)
	var disagree []string
	var refused int
	for cp := 0; cp <= unicode.MaxRune; cp++ {
		if cp >= 0xD800 && cp <= 0xDFFF { // surrogates are not code points
			continue
		}
		r := rune(cp)
		_, err := validBoardSubject("a" + string(r) + "b")
		got := err != nil
		if cp == rule.Exempt {
			if !got {
				disagree = append(disagree, fmt.Sprintf("U+%04X between letters is accepted", cp))
			}
			continue
		}
		if got {
			refused++
		}
		if want := rule.forbiddenInvisible(r); got != want {
			disagree = append(disagree, fmt.Sprintf("U+%04X subject-rejects=%v rule=%v", cp, got, want))
		}
	}
	if len(disagree) > 0 {
		t.Fatalf("validBoardSubject and the rule disagree (unicode.Version %s): %v", unicode.Version, disagree)
	}
	if refused < 200 {
		t.Fatalf("the sweep refused only %d code points; the rule is not being applied", refused)
	}
	// The metacharacters stay legal in a subject.
	for _, c := range rule.Meta {
		if _, err := validBoardSubject("a" + string(c) + "b"); err != nil {
			t.Errorf("metacharacter %q refused in a subject: %v", c, err)
		}
	}
}

// TestBoardSubject_AgreesWithDisplayNameTable: on every row of the display-name
// table (cases.yaml, the shared case list) the subject predicate answers as the
// display-name predicate does once each metacharacter is REPLACED by a neutral
// letter "x". Replaced, not deleted: deleting one would join its neighbours (a
// ZWJ that sat next to a metacharacter could end up between two emoji). The
// premise is that "x" is neither an emoji nor a Cc / Cf character, so it changes
// nothing about the rest of the row. This is the "reuse" half: one table, no
// second list of inputs.
func TestBoardSubject_AgreesWithDisplayNameTable(t *testing.T) {
	rule := loadNameRule(t)
	neutral := strings.NewReplacer(metaToX(rule.Meta)...)
	for _, c := range loadNameParityCases(t) {
		in := c.input()
		t.Run(c.Note, func(t *testing.T) {
			if got, want := inlineTextHasForbidden(in), displayNameHasForbidden(neutral.Replace(in)); got != want {
				t.Fatalf("inlineTextHasForbidden(%+q) = %v, displayNameHasForbidden(metacharacters replaced) = %v", in, got, want)
			}
		})
	}
}

// metaToX is the argument list of a Replacer that turns each character of chars into "x".
func metaToX(chars string) []string {
	var out []string
	for _, c := range chars {
		out = append(out, string(c), "x")
	}
	return out
}

// boardSubjectCase is one row of testdata/board-subject/cases.yaml, shared with the
// portal's form test (view/portal_subjectproblem_test.go).
type boardSubjectCase struct {
	Name   string  `yaml:"name"`
	Repeat int     `yaml:"repeat"`
	Server string  `yaml:"server"`
	Error  string  `yaml:"error"`
	Client string  `yaml:"client"`
	Stored *string `yaml:"stored"`
	Note   string  `yaml:"note"`
}

func (c boardSubjectCase) input() string {
	if c.Repeat > 0 {
		return strings.Repeat(c.Name, c.Repeat)
	}
	return c.Name
}

func loadBoardSubjectCases(t *testing.T) []boardSubjectCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/board-subject/cases.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []boardSubjectCase `yaml:"cases"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("board-subject/cases.yaml: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("board-subject/cases.yaml: no cases")
	}
	for i, c := range f.Cases {
		if (c.Server != "accept" && c.Server != "reject") || (c.Client != "accept" && c.Client != "reject") {
			t.Fatalf("board-subject/cases.yaml row %d (%s): server/client must be accept|reject, got %q/%q", i, c.Note, c.Server, c.Client)
		}
		if (c.Server == "reject") != (c.Error != "") {
			t.Fatalf("board-subject/cases.yaml row %d (%s): `error` is exactly the reject rows' sentence", i, c.Note)
		}
		if c.Stored != nil && c.Server != "accept" {
			t.Fatalf("board-subject/cases.yaml row %d (%s): stored only makes sense on a server: accept row", i, c.Note)
		}
	}
	return f.Cases
}

// TestBoardSubject_Table: the subject accept / reject rows (the shared display-name
// table has no board rows; the portal form's test reads the same file), and the 400
// sentence being fixed.
func TestBoardSubject_Table(t *testing.T) {
	if maxBoardSubjectRunes != 120 {
		t.Fatalf("maxBoardSubjectRunes = %d: the length rows of board-subject/cases.yaml and the form's MAX_SUBJECT_RUNES say 120; change them together", maxBoardSubjectRunes)
	}
	for _, c := range loadBoardSubjectCases(t) {
		in := c.input()
		t.Run(c.Note, func(t *testing.T) {
			got, err := validBoardSubject(in)
			if c.Server == "accept" {
				if err != nil {
					t.Fatalf("validBoardSubject(%+q) = error %v, want accept", in, err)
				}
				want := in
				if c.Stored != nil {
					want = *c.Stored
				}
				if got != want {
					t.Fatalf("validBoardSubject(%+q) stored %+q, want %+q", in, got, want)
				}
				return
			}
			if err == nil {
				t.Fatalf("validBoardSubject(%+q) = %q, nil; want %q", in, got, c.Error)
			}
			if err.Error() != c.Error {
				t.Fatalf("validBoardSubject(%+q) error = %q, want %q", in, err, c.Error)
			}
		})
	}
}

// TestBoardSubject_ClientIsNeverStricter: the table never records a form that refuses a
// subject the server accepts, and the one documented difference (form accepts, server
// refuses) is only ever on a row holding U+200D, and still exists. The "client-only reject = 0"
// half of the contract (as TestDisplayNameParity_ClientIsNeverStricter); the view test checks
// that the form really answers the table.
func TestBoardSubject_ClientIsNeverStricter(t *testing.T) {
	var clientOnlyReject, serverOnlyReject int
	for _, c := range loadBoardSubjectCases(t) {
		switch {
		case c.Client == "reject" && c.Server == "accept":
			clientOnlyReject++
			t.Errorf("%s: the form refuses a subject the server accepts (%+q)", c.Note, c.input())
		case c.Client == "accept" && c.Server == "reject":
			serverOnlyReject++
			if !strings.ContainsRune(c.input(), zeroWidthJoiner) {
				t.Errorf("%s: only a ZWJ may be accepted by the form and refused by the server (%+q)", c.Note, c.input())
			}
		}
	}
	if clientOnlyReject != 0 {
		t.Fatalf("client-only rejects = %d, want 0", clientOnlyReject)
	}
	if serverOnlyReject == 0 {
		t.Fatal("the table has no ZWJ row the server refuses and the form lets through; the documented difference is gone")
	}
}
