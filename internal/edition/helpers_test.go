package edition_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// Every value in these tests is synthetic. sentinel is in the value of every
// per-seat name answer, so any message that echoes a value shows up as a match.
const (
	sentinel = "SENTINEL-zzzz"
	runA     = "0123456789abcdef0123456789abcdef"
	demoCID  = "01-demo"
)

// secrets are the table values of baseRows: none may appear in any error or in
// any formatted Table / Judge.
var secrets = []string{sentinel, "aaaaaaaaaaaa", "bbbbbbbbbbbb", "ca,cb"}

func ip(i int) *int { return &i }

// scoredOf is the catalog.Scored of a scope cat over the tree at dir, as
// catalog.LoadScored hands it to edition.Load (ADR-0056 A4a-3): Catalog is the scope,
// FullCatalog is the whole tree (catalog.Load(dir), the repository defaults) and
// ChallengesDir is dir. A challenge of cat that the tree at dir does not hold (a
// synthetic catalog built elsewhere) is added to the full catalog, so that the value
// is one Load's consistency check (checkScored) accepts, as LoadScored's always is.
func scoredOf(t *testing.T, cat catalog.Catalog, dir string) catalog.Scored {
	t.Helper()
	full, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("catalog.Load(%s): %v", dir, err)
	}
	for id, ch := range cat {
		if _, ok := full[id]; !ok {
			full[id] = ch
		}
	}
	return catalog.Scored{Catalog: cat, FullCatalog: full, ChallengesDir: dir}
}

// demoScope: one challenge with a per-seat name, a per-seat hexid and a choice-set
// that is the same for every seat.
var demoScope = edition.Scope{
	demoCID: {
		{ID: "who", Format: answerformat.Name, Attempts: 5},
		{ID: "hx", Format: answerformat.HexID, Params: answerformat.Params{Length: ip(12)}, Attempts: 5},
		{ID: "pick", Format: answerformat.ChoiceSet, Params: answerformat.Params{Choices: []string{"ca", "cb", "cc"}}, Attempts: 5},
	},
}

// baseRows is a table that Check accepts in the event mode.
func baseRows() [][]string {
	return [][]string{
		{"seat-a", demoCID, "who", sentinel + "-a"},
		{"seat-a", demoCID, "hx", "aaaaaaaaaaaa"},
		{"seat-a", demoCID, "pick", "ca,cb"},
		{"seat-b", demoCID, "who", sentinel + "-b"},
		{"seat-b", demoCID, "hx", "bbbbbbbbbbbb"},
		{"seat-b", demoCID, "pick", "ca,cb"},
	}
}

func render(runID string, rows [][]string) []byte {
	var b strings.Builder
	b.WriteString("# falco-ctf answers v1 run=" + runID + "\n")
	for _, r := range rows {
		b.WriteString(strings.Join(r, "\t") + "\n")
	}
	return []byte(b.String())
}

// set returns a copy of rows with rows[i][col] = v.
func set(rows [][]string, i, col int, v string) [][]string {
	out := make([][]string, len(rows))
	for k, r := range rows {
		out[k] = slices.Clone(r)
	}
	out[i][col] = v
	return out
}

// without returns a copy of rows minus rows[i].
func without(rows [][]string, i int) [][]string {
	return slices.Delete(slices.Clone(rows), i, i+1)
}

// rename returns a copy of rows with every seat `from` renamed `to`.
func rename(rows [][]string, from, to string) [][]string {
	out := make([][]string, len(rows))
	for k, r := range rows {
		out[k] = slices.Clone(r)
		if out[k][0] == from {
			out[k][0] = to
		}
	}
	return out
}

func mustParse(t *testing.T, data []byte) *edition.Table {
	t.Helper()
	tb, err := edition.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return tb
}

func eventOpts() edition.Options {
	return edition.Options{EventMode: true, Practice: edition.PracticeSet{}}
}

// rules is the sorted distinct rules of the violations inside err (Check returns
// an errors.Join).
func rules(err error) []string {
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
		var v *edition.Violation
		if errors.As(e, &v) {
			out = append(out, v.Rule)
		}
	}
	walk(err)
	slices.Sort(out)
	return slices.Compact(out)
}

// noSecret fails if any secret is in err's text under the verbs an operator's code
// is likely to use.
func noSecret(t *testing.T, what string, err error) {
	t.Helper()
	noSecretIn(t, what, err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err))
}

func noSecretIn(t *testing.T, what string, texts ...string) {
	t.Helper()
	for _, text := range texts {
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Errorf("%s: output contains a table value (%q): %q", what, s, text)
			}
		}
	}
}
