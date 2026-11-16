package edition_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// ADR-0056 D19 A4a-1 / V34: edition.Load reads the practice answers of EVERY
// challenge of the Scored's tree (scoredOf: the tree at dir) and hands them to T6. The trees are synthetic and
// written under t.TempDir(); every value is a made-up one.

const (
	otherCID = "02-other"

	// practiceSecret is in the value of every practice `who` row below: a message that
	// echoes a practice value shows up as a match.
	practiceSecret = "PRACTICE-zzzz"
)

// otherCID is a second investigate challenge with the same questions as demoCID (the
// tree writes it with loadFixtureYAML): the one that is outside the scope in some of
// the tests. evadeYAML is a challenge of another type, for the edition/ that is refused.
const evadeYAML = "type: evade\nexpectedFlag: FALCO{dev-practice}\nforbiddenRules: [r]\n"

func practicePath(cid string) string { return cid + "/edition/practice/answers.tsv" }

// practiceFile is the practice table of one challenge, as the tree's file map wants it.
func practiceFile(rows [][]string) string { return string(render(edition.PracticeRunID, rows)) }

// writeTree writes the two investigate challenges of the fixture and then extra
// (slash path -> content; a path that has a deeper path under it becomes a directory
// by MkdirAll, an extra entry replaces a base one).
func writeTree(t *testing.T, extra map[string]string) string {
	t.Helper()
	files := map[string]string{
		demoCID + "/falco-rule.yaml":  loadFixtureYAML,
		otherCID + "/falco-rule.yaml": loadFixtureYAML,
	}
	for k, v := range extra {
		files[k] = v
	}
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// scopeOf is the catalog of dir restricted to ids: the scope the scoreboard scores,
// smaller than the tree.
func scopeOf(t *testing.T, dir string, ids ...string) catalog.Catalog {
	t.Helper()
	full, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	out := catalog.Catalog{}
	for _, id := range ids {
		ch, ok := full[id]
		if !ok {
			t.Fatalf("%s is not in the fixture tree", id)
		}
		out[id] = ch
	}
	return out
}

func eventTable(t *testing.T) string { return writeTable(t, render(runA, loadRows())) }

// V3 (T6) at start-up: the event table is refused when a value is a practice answer
// of the same format, whichever challenge the practice answer belongs to; a practice
// answer of another format, or no practice answer at all, is no obstacle.
func TestLoad_T6_UsesThePracticeAnswersOfTheImage(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		scope []string
		rules []string // nil = accepted
	}{
		{"a practice answer of the same challenge, same format", map[string]string{
			practicePath(demoCID): practiceFile([][]string{{"*", demoCID, "hx", "aaaaaaaaaaaa"}}),
		}, []string{demoCID}, []string{"T6"}},
		{"a practice answer of a challenge OUTSIDE the scope (the whole tree is read)", map[string]string{
			practicePath(otherCID): practiceFile([][]string{{"*", otherCID, "hx", "bbbbbbbbbbbb"}}),
		}, []string{demoCID}, []string{"T6"}},
		{"a practice name equal to an event name", map[string]string{
			practicePath(otherCID): practiceFile([][]string{{"*", otherCID, "who", sentinel + "-a"}}),
		}, []string{demoCID}, []string{"T6"}},
		{"practice values that differ from the event's", map[string]string{
			practicePath(demoCID):  practiceFile([][]string{{"*", demoCID, "who", practiceSecret}, {"*", demoCID, "hx", "cccccccccccc"}}),
			practicePath(otherCID): practiceFile([][]string{{"*", otherCID, "hx", "dddddddddddd"}}),
		}, []string{demoCID}, nil},
		{"the same text under another format (a name that reads like the hexid)", map[string]string{
			practicePath(otherCID): practiceFile([][]string{{"*", otherCID, "who", "aaaaaaaaaaaa"}}),
		}, []string{demoCID}, nil},
		{"no edition directory at all: the empty set", map[string]string{}, []string{demoCID}, nil},
		{"edition/ without practice/, practice/ without answers.tsv: nothing to add", map[string]string{
			demoCID + "/edition/edition.yaml":     "x: y\n",
			otherCID + "/edition/practice/README": "no table here\n",
		}, []string{demoCID}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeTree(t, c.files)
			j, runID, err := edition.Load(scoredOf(t, scopeOf(t, dir, c.scope...), dir), eventTable(t), true)
			if c.rules == nil {
				if err != nil || j == nil || runID != runA {
					t.Fatalf("Load = %v, %q, %v; want a judge and run id %s", j, runID, err, runA)
				}
				return
			}
			if err == nil {
				t.Fatal("Load accepted an event table that repeats a practice answer")
			}
			if j != nil || runID != "" {
				t.Errorf("a judge or a run id came back with the error: %v, %q", j, runID)
			}
			if got := rules(errors.Unwrap(err)); !slices.Equal(got, c.rules) {
				t.Errorf("rules = %v, want %v (err: %v)", got, c.rules, err)
			}
			noSecret(t, c.name, err)
		})
	}
}

// A practice edition that is not well formed stops the start-up (fail-closed): a
// T6 that ran on part of the practice answers would pass what it should refuse. The
// error names the challenge and a rule, and carries no practice value.
func TestLoad_RefusesABrokenPracticeEdition(t *testing.T) {
	row := func(seat, cid, qid, value string) [][]string { return [][]string{{seat, cid, qid, value}} }
	const header = "# falco-ctf answers v1 run=" + edition.PracticeRunID + "\n"
	cases := []struct {
		name     string
		files    map[string]string
		scope    []string
		rule     string // the *Violation's rule, "" = not a violation
		is       error
		contains string
	}{
		{"not a table (no header)", map[string]string{practicePath(demoCID): "*\t" + demoCID + "\twho\t" + practiceSecret + "\n"}, []string{demoCID}, "T3", nil, ""},
		{"a row of five columns", map[string]string{practicePath(demoCID): header + "*\t" + demoCID + "\twho\t" + practiceSecret + "\tx\n"}, []string{demoCID}, "T3", nil, ""},
		{"no trailing newline", map[string]string{practicePath(demoCID): strings.TrimSuffix(practiceFile(row("*", demoCID, "who", practiceSecret)), "\n")}, []string{demoCID}, "T3", nil, ""},
		{"a repeated row", map[string]string{practicePath(demoCID): practiceFile(append(row("*", demoCID, "who", practiceSecret), row("*", demoCID, "who", practiceSecret+"2")...))}, []string{demoCID}, "T4", nil, ""},
		{"an event run id", map[string]string{practicePath(demoCID): string(render(runA, row("*", demoCID, "who", practiceSecret)))}, []string{demoCID}, "T3", nil, ""},
		{"a seat that is not *", map[string]string{practicePath(demoCID): practiceFile(row("seat-a", demoCID, "who", practiceSecret))}, []string{demoCID}, "T4", nil, ""},
		{"a cid that is not in the catalog", map[string]string{practicePath(demoCID): practiceFile(row("*", "99-none", "who", practiceSecret))}, []string{demoCID}, "T4", nil, ""},
		{"the cid of another challenge", map[string]string{practicePath(demoCID): practiceFile(row("*", otherCID, "who", practiceSecret))}, []string{demoCID}, "T4", nil, ""},
		{"a qid that is not a question of the challenge", map[string]string{practicePath(demoCID): practiceFile(row("*", demoCID, "nope", practiceSecret))}, []string{demoCID}, "T4", nil, ""},
		{"a value that normalisation would change (V34)", map[string]string{practicePath(demoCID): practiceFile(row("*", demoCID, "hx", "AAAAAAAAAAAA"))}, []string{demoCID}, "T5", answerformat.ErrNotCanonical, ""},
		{"a value outside its format", map[string]string{practicePath(demoCID): practiceFile(row("*", demoCID, "hx", "not-hex"))}, []string{demoCID}, "T5", answerformat.ErrFormat, ""},
		{"a broken edition of a challenge outside the scope", map[string]string{practicePath(otherCID): practiceFile(row("*", otherCID, "hx", "AAAAAAAAAAAA"))}, []string{demoCID}, "T5", answerformat.ErrNotCanonical, otherCID},
		{"an edition/ under a challenge that is not an investigate one", map[string]string{
			"03-ev/falco-rule.yaml": evadeYAML,
			practicePath("03-ev"):   practiceFile(row("*", "03-ev", "who", practiceSecret)),
		}, []string{demoCID}, "", nil, "investigate"},
		{"answers.tsv is a directory", map[string]string{practicePath(demoCID) + "/keep": "x"}, []string{demoCID}, "", nil, "not a regular file"},
		{"practice/ is a file", map[string]string{demoCID + "/edition/practice": "x"}, []string{demoCID}, "", nil, "not a directory"},
		{"edition/ is a file", map[string]string{demoCID + "/edition": "x"}, []string{demoCID}, "", nil, "not a directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeTree(t, c.files)
			j, runID, err := edition.Load(scoredOf(t, scopeOf(t, dir, c.scope...), dir), eventTable(t), true)
			if err == nil {
				t.Fatal("Load accepted a broken practice edition")
			}
			if j != nil || runID != "" {
				t.Errorf("a judge or a run id came back with the error: %v, %q", j, runID)
			}
			if !strings.Contains(err.Error(), "practice answers") {
				t.Errorf("the error does not say it is about the practice answers: %v", err)
			}
			var v *edition.Violation
			switch {
			case c.rule != "":
				if !errors.As(err, &v) || v.Rule != c.rule {
					t.Errorf("err = %v, want a %s violation", err, c.rule)
				}
			case errors.As(err, &v):
				t.Errorf("err = %v, want a file problem, not a rule violation", err)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Errorf("err = %v, want it to wrap %v", err, c.is)
			}
			if c.contains != "" && !strings.Contains(err.Error(), c.contains) {
				t.Errorf("err = %v, want it to contain %q", err, c.contains)
			}
			for _, leak := range []string{practiceSecret, "AAAAAAAAAAAA", "not-hex"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("the error carries a practice value (%q): %v", leak, err)
				}
			}
		})
	}
}

// A link is never followed: answers.tsv that is a symlink to a good table is refused.
func TestLoad_RefusesALinkedPracticeTable(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"real.tsv": practiceFile([][]string{{"*", demoCID, "who", practiceSecret}}),
	})
	link := filepath.Join(dir, filepath.FromSlash(practicePath(demoCID)))
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real.tsv"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, _, err := edition.Load(scoredOf(t, scopeOf(t, dir, demoCID), dir), eventTable(t), true)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a symlinked answers.tsv: err = %v, want a refusal (not a regular file)", err)
	}
}

// Without a table, the practice edition is read only when an investigate challenge
// is in scope (the practice mode, ADR-0056 D8 (iv)). With none in scope there is
// nothing to judge, so a broken edition elsewhere in the tree changes nothing and the
// answer is (nil, "", nil): every environment today starts as before. With one in
// scope the same broken edition is a refusal (a T3 here, the file is not a table).
func TestLoad_WithoutATableThePracticeEditionIsReadOnlyForAnInvestigateScope(t *testing.T) {
	dir := writeTree(t, map[string]string{practicePath(demoCID): "not a table\n"})
	evadeOnly := catalog.Catalog{"03-ev": {ID: "03-ev", Type: "evade", ExpectedFlag: plainFlag}}
	for _, event := range []bool{false, true} {
		j, runID, err := edition.Load(scoredOf(t, evadeOnly, dir), "", event)
		if err != nil || j != nil || runID != "" {
			t.Errorf("no investigate challenge in scope (event mode %v): Load = %v, %q, %v; want nil, \"\", nil", event, j, runID, err)
		}
	}
	j, runID, err := edition.Load(scoredOf(t, scopeOf(t, dir, demoCID), dir), "", false)
	var v *edition.Violation
	if err == nil || j != nil || runID != "" || !errors.As(err, &v) || v.Rule != "T3" {
		t.Errorf("an investigate challenge in scope, a broken practice edition: Load = %v, %q, %v; want a T3 refusal", j, runID, err)
	}
}
