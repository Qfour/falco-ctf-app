package api

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Parity table for the display-name rule (app#331, app#343), the SERVER half.
//
// testdata/display-name-parity/cases.yaml is read by two tests: this one runs
// validDisplayName (the authority) on every row; internal/scoreboard/view/
// portal_nameproblem_test.go runs the Profile form's JS (pane-me.tmpl) on the
// same rows. The contract between them: the form is never stricter than the
// server, so a row may never be `client: reject` with `server: accept`; the only
// allowed difference is `client: accept, server: reject` on a U+200D (ZWJ),
// whose emoji-adjacency rule the form leaves to the server.
//
// The view test carries its own copy of the row struct and loader: the two
// packages share the file, not code (a shared test-only package would be one more
// import edge for a table this small).

type nameParityCase struct {
	Name   string  `yaml:"name"`
	Repeat int     `yaml:"repeat"`
	Server string  `yaml:"server"`
	Client string  `yaml:"client"`
	Stored *string `yaml:"stored"`
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
// (form accepts, server refuses) is only ever on a ZWJ. This is the
// "client-only reject = 0" half of the contract; the view test checks that the
// form really answers the table.
func TestDisplayNameParity_ClientIsNeverStricter(t *testing.T) {
	var clientOnlyReject, serverOnlyReject int
	for _, c := range loadNameParityCases(t) {
		switch {
		case c.Client == "reject" && c.Server == "accept":
			clientOnlyReject++
			t.Errorf("%s: the form refuses a name the server accepts (%+q)", c.Note, c.input())
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
