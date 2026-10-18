package api

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode"

	"gopkg.in/yaml.v3"
)

// app#331: validDisplayName rejects Unicode Cf (format: bidi controls,
// zero-width characters) and C1 (U+0080-009F) characters on top of the old
// ASCII metachar / C0 / DEL set. A ZWJ between two emoji is the one allowed Cf.
// This is not an anti-impersonation test: blank-looking characters outside Cf
// (U+3164, U+2800, ...) and duplicate names still pass.

// Parity table for the display-name rule (app#331, app#343), the SERVER half.
//
// testdata/display-name-parity/cases.yaml is read by two tests: this one runs
// validDisplayName (the authority) on every row; internal/scoreboard/view/
// portal_nameproblem_test.go runs the Profile form's JS (pane-me.tmpl) on the
// same rows. The contract between them: the form is never stricter than the
// server, so a row may never be `client: reject` with `server: accept`; the only
// allowed difference is `client: accept, server: reject` on a U+200D (ZWJ),
// whose emoji-adjacency rule the form leaves to the server, or on a flag SHAPE
// (flagShapePattern, app#402), a pattern rule the form leaves to the server too.
//
// The view test carries its own copy of the row struct and loader: the two
// packages share the file, not code (a shared test-only package would be one more
// import edge for a table this small).

// reasonFlagShape is the `reason` of a row the server refuses for its flag SHAPE.
const reasonFlagShape = "flag-shape"

type nameParityCase struct {
	Name   string  `yaml:"name"`
	Repeat int     `yaml:"repeat"`
	Server string  `yaml:"server"`
	Client string  `yaml:"client"`
	Stored *string `yaml:"stored"`
	Reason string  `yaml:"reason"`
	Note   string  `yaml:"note"`
}

func (c nameParityCase) input() string {
	if c.Repeat > 0 {
		return strings.Repeat(c.Name, c.Repeat)
	}
	return c.Name
}

func loadNameParityCases(t *testing.T) []nameParityCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/display-name-parity/cases.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []nameParityCase `yaml:"cases"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("cases.yaml: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("cases.yaml: no cases")
	}
	for i, c := range f.Cases {
		if (c.Server != "accept" && c.Server != "reject") || (c.Client != "accept" && c.Client != "reject") {
			t.Fatalf("cases.yaml row %d (%s): server/client must be accept|reject, got %q/%q", i, c.Note, c.Server, c.Client)
		}
		if c.Stored != nil && c.Server != "accept" {
			t.Fatalf("cases.yaml row %d (%s): stored only makes sense on a server: accept row", i, c.Note)
		}
		if c.Reason != "" && (c.Reason != reasonFlagShape || c.Server != "reject" || c.Client != "accept") {
			t.Fatalf("cases.yaml row %d (%s): reason is only `%s`, on a server: reject, client: accept row", i, c.Note, reasonFlagShape)
		}
	}
	return f.Cases
}

// TestDisplayNameParity_ServerMatchesTable: validDisplayName answers every row
// of the shared table as the table says, and stores the trimmed name it lists.
func TestDisplayNameParity_ServerMatchesTable(t *testing.T) {
	for _, c := range loadNameParityCases(t) {
		in := c.input()
		t.Run(c.Note, func(t *testing.T) {
			got, err := validDisplayName(in)
			if c.Server == "reject" {
				if err == nil {
					t.Fatalf("validDisplayName(%+q) = %q, nil; the table says reject", in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validDisplayName(%+q) = error %v; the table says accept", in, err)
			}
			want := in
			if c.Stored != nil {
				want = *c.Stored
			}
			if got != want {
				t.Fatalf("validDisplayName(%+q) stored %+q; the table says %+q", in, got, want)
			}
		})
	}
}

// TestDisplayNameParity_ClientIsNeverStricter: the table itself never records a
// form that refuses what the server accepts, and the one documented difference
// (form accepts, server refuses) is only ever on a ZWJ or a flag shape. This is the
// "client-only reject = 0" half of the contract; the view test checks that the
// form really answers the table.
func TestDisplayNameParity_ClientIsNeverStricter(t *testing.T) {
	var clientOnlyReject, zwjOnly, flagShapeOnly int
	for _, c := range loadNameParityCases(t) {
		switch {
		case c.Client == "reject" && c.Server == "accept":
			clientOnlyReject++
			t.Errorf("%s: the form refuses a name the server accepts (%+q)", c.Note, c.input())
		case c.Client == "accept" && c.Server == "reject":
			if c.Reason == reasonFlagShape {
				// The form leaves the flag shape to the server, and the refusal must BE
				// the flag-shape one: the input passed the length and character checks.
				flagShapeOnly++
				if _, err := validDisplayName(c.input()); err == nil || err.Error() != errMsgDisplayNameFlagShape {
					t.Errorf("%s: a reason: %s row must be refused with %q, got %v (%+q)", c.Note, reasonFlagShape, errMsgDisplayNameFlagShape, err, c.input())
				}
				continue
			}
			zwjOnly++
			if !strings.ContainsRune(c.input(), zeroWidthJoiner) {
				t.Errorf("%s: a server-only reject needs either a ZWJ or `reason: %s` (%+q)", c.Note, reasonFlagShape, c.input())
			}
		}
	}
	if clientOnlyReject != 0 {
		t.Fatalf("client-only rejects = %d, want 0", clientOnlyReject)
	}
	// Each documented difference keeps its own floor, so deleting one family cannot hide behind the other.
	if zwjOnly == 0 {
		t.Fatal("the table has no ZWJ row the server refuses and the form lets through; the documented difference is gone")
	}
	if flagShapeOnly < minFlagShapeRows {
		t.Fatalf("the table has %d flag-shape rows (reason: %s), want at least %d", flagShapeOnly, reasonFlagShape, minFlagShapeRows)
	}
}

// minFlagShapeRows is the floor of `reason: flag-shape` rows in cases.yaml.
const minFlagShapeRows = 10

// nameRule is testdata/display-name-parity/rule.yaml: the character class both
// sweeps (this package's and the form's, in internal/scoreboard/view) compare to.
type nameRule struct {
	Meta       string   `yaml:"meta"`
	Categories []string `yaml:"categories"`
	Exempt     int      `yaml:"exempt"`
}

func loadNameRule(t *testing.T) nameRule {
	t.Helper()
	raw, err := os.ReadFile("testdata/display-name-parity/rule.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var r nameRule
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("rule.yaml: %v", err)
	}
	if r.Meta == "" || len(r.Categories) == 0 || r.Exempt == 0 {
		t.Fatalf("rule.yaml: incomplete rule %+v", r)
	}
	for _, c := range r.Categories {
		if unicode.Categories[c] == nil {
			t.Fatalf("rule.yaml: unknown Unicode category %q", c)
		}
	}
	return r
}

// forbidden is the rule for one code point (the exempt one is not asked).
func (r nameRule) forbidden(c rune) bool {
	return strings.ContainsRune(r.Meta, c) || r.forbiddenInvisible(c)
}

// forbiddenInvisible is the rule without the metacharacters: the Cc / Cf half,
// which inline prose (a board subject, app#377) shares with a display name.
func (r nameRule) forbiddenInvisible(c rune) bool {
	for _, cat := range r.Categories {
		if unicode.Is(unicode.Categories[cat], c) {
			return true
		}
	}
	return false
}

// TestDisplayNameParity_SweepEveryCodePoint: for EVERY code point c,
// displayNameHasForbidden("a"+c+"b") agrees with the rule (meta | Cc | Cf), except
// U+200D, which is only accepted between two emoji (the table pins that; here it
// must be refused between letters). With the form's sweep doing the same against
// the same rule, "form == rule" and "server == rule" hold over all of Unicode, so
// the form is never stricter than the server for any single code point.
func TestDisplayNameParity_SweepEveryCodePoint(t *testing.T) {
	rule := loadNameRule(t)
	var disagree []string
	var refused int
	for cp := 0; cp <= unicode.MaxRune; cp++ {
		if cp >= 0xD800 && cp <= 0xDFFF { // surrogates are not code points
			continue
		}
		if cp == rule.Exempt {
			if !displayNameHasForbidden("a" + string(rune(cp)) + "b") {
				disagree = append(disagree, fmt.Sprintf("U+%04X between letters is accepted", cp))
			}
			continue
		}
		r := rune(cp)
		got := displayNameHasForbidden("a" + string(r) + "b")
		if got {
			refused++
		}
		if want := rule.forbidden(r); got != want {
			disagree = append(disagree, fmt.Sprintf("U+%04X server=%v rule=%v", cp, got, want))
		}
	}
	if len(disagree) > 0 {
		t.Fatalf("the server and the rule disagree (unicode.Version %s): %v", unicode.Version, disagree)
	}
	if refused < 200 {
		t.Fatalf("the sweep refused only %d code points; the rule is not being applied", refused)
	}
}
