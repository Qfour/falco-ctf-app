package edition

// ADR-0056 D20 and D19 A4e-1: LoadEventTable, the validator's door to the answers table. It reads
// and checks the file through the function that Load shares (loadChecked), so the two accept the
// same tables and refuse the same ones, in the same words; it carries the practice set and the
// files of the practice editions, which the start-up never opens; and it refuses a link, which the
// start-up follows. The tests are internal because they look at what a CheckedTable carries.
// Every value is a placeholder.

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const evRun = "0123456789abcdef0123456789abcdef"

// evRows are the event's rows for the tree of practiceFixtureYAML (who: a name, hx: a hexid of
// 12), for two seats; no value is a practice answer (practiceGoodRows) and no two seats share one.
func evRows() [][]string {
	return [][]string{
		{"seat-a", "01-demo", "who", "ev-alpha"},
		{"seat-a", "01-demo", "hx", "cccccccccccc"},
		{"seat-b", "01-demo", "who", "ev-beta"},
		{"seat-b", "01-demo", "hx", "dddddddddddd"},
	}
}

func evTable(runID string, rows [][]string) string {
	var b strings.Builder
	b.WriteString("# falco-ctf answers v1 run=" + runID + "\n")
	for _, r := range rows {
		b.WriteString(strings.Join(r, "\t") + "\n")
	}
	return b.String()
}

// evFile writes an answers file and gives its path.
func evFile(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "table.tsv")
	filesWrite(t, p, text)
	return p
}

// evTree is a tree with the challenge 01-demo and a practice edition that has a bundle and a
// template, plus the files of extra (path under the challenge directory -> content).
func evTree(t *testing.T, extra map[string]string) string {
	t.Helper()
	files := map[string]string{
		"edition/practice/answers.tsv":        practiceGoodRows,
		"edition/practice/evidence/notes.txt": "bundle notes",
		"edition/template/page.txt":           "template page",
	}
	for k, v := range extra {
		files[k] = v
	}
	return filesTree(t, map[string]map[string]string{"01-demo": files})
}

func TestLoadEventTable_CarriesTheTableThePracticeSetAndTheFiles(t *testing.T) {
	dir := evTree(t, nil)
	answers := evFile(t, evTable(evRun, evRows()))
	ct, runID, err := LoadEventTable(treeScored(t, dir), answers)
	if err != nil {
		t.Fatalf("LoadEventTable: %v", err)
	}
	if ct == nil || ct.table == nil || runID != evRun || ct.table.RunID() != evRun {
		t.Fatalf("LoadEventTable = (%v, %q), want a CheckedTable of the table and its run id %q", ct, runID, evRun)
	}
	if got := ct.table.Seats(); !slices.Equal(got, []string{"seat-a", "seat-b"}) {
		t.Errorf("the table's seats are %v", got)
	}
	// The practice set T6 compared with: the values of the practice answers, by format.
	if !ct.practice.Has("name", "practice-who") || !ct.practice.Has("hexid", "aaaaaaaaaaaa") {
		t.Errorf("the practice set is %v, want the two practice answers of 01-demo", ct.practice)
	}
	// The files of the practice edition, which only this path reads.
	demo := ct.files["01-demo"]
	if len(ct.files) != 1 || demo == nil {
		t.Fatalf("the practice files are %v, want 01-demo's", ct.files)
	}
	if got := fileNames(demo.Evidence); !slices.Equal(got, []string{"notes.txt"}) || string(demo.Evidence[0].Data) != "bundle notes" {
		t.Errorf("the practice bundle is %v", got)
	}
	if got := fileNames(demo.Template); !slices.Equal(got, []string{"page.txt"}) || string(demo.Template[0].Data) != "template page" {
		t.Errorf("the practice template is %v", got)
	}
	// The same file is the scoreboard's table in the event mode.
	j, id, err := Load(treeScored(t, dir), answers, true)
	if err != nil || j == nil || id != evRun {
		t.Errorf("Load of the same table = (%v, %q, %v), want the judge and the run id", j, id, err)
	}
	// The value of a CheckedTable prints as a fixed string: it holds the plaintext values.
	for _, s := range []string{ct.String(), ct.GoString()} {
		if strings.Contains(s, "ev-alpha") || !strings.Contains(s, "redacted") {
			t.Errorf("a CheckedTable prints as %q, want the fixed redacted string", s)
		}
	}
}

// The start-up opens no bundle and no template: a practice edition whose files are broken does
// not stop a scoreboard that loads the same table, and does stop the validator (B2).
func TestLoadEventTable_ReadsThePracticeFilesAndLoadDoesNot(t *testing.T) {
	dir := evTree(t, map[string]string{
		"edition/practice/evidence/Bad Name.txt": contentSentinel,
		"edition/template/raw.bin":               "\xff\xfe" + contentSentinel,
	})
	answers := evFile(t, evTable(evRun, evRows()))
	if j, id, err := Load(treeScored(t, dir), answers, true); err != nil || j == nil || id != evRun {
		t.Fatalf("Load = (%v, %q, %v), want the judge: the start-up reads no bundle and no template", j, id, err)
	}
	ct, runID, err := LoadEventTable(treeScored(t, dir), answers)
	var v *Violation
	if err == nil || ct != nil || runID != "" || !errors.As(err, &v) || v.Rule != RuleBundleShape {
		t.Fatalf("LoadEventTable = (%v, %q, %v), want a B2 violation and nothing else", ct, runID, err)
	}
	if !strings.Contains(err.Error(), "01-demo") || strings.Contains(err.Error(), contentSentinel) {
		t.Errorf("the error does not name 01-demo, or carries a content: %v", err)
	}
}

// One Check for both: a table that Load refuses is refused by LoadEventTable with the same
// error, word for word, and the value of a defect is in neither.
func TestLoadEventTable_RefusesWhatLoadRefusesInTheSameWords(t *testing.T) {
	dir := evTree(t, nil)
	set := func(rows [][]string, i, col int, v string) [][]string {
		out := make([][]string, len(rows))
		for k, r := range rows {
			out[k] = slices.Clone(r)
		}
		out[i][col] = v
		return out
	}
	cases := []struct {
		name string
		text string
		rule string
	}{
		{"the practice run id (T3)", evTable(PracticeRunID, evRows()), RuleShape},
		{"a row missing (T4)", evTable(evRun, evRows()[:3]), RuleComplete},
		{"a value outside its format (T5)", evTable(evRun, set(evRows(), 1, 3, "not-hex")), RuleFormat},
		{"a practice answer reused (T6)", evTable(evRun, set(evRows(), 0, 3, "practice-who")), RulePractice},
		{"two seats share a value (T8)", evTable(evRun, set(evRows(), 3, 3, "cccccccccccc")), RulePerSeat},
		{"a header that is not v1", strings.Replace(evTable(evRun, evRows()), "answers v1", "answers v2", 1), RuleShape},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			answers := evFile(t, c.text)
			_, _, loadErr := Load(treeScored(t, dir), answers, true)
			ct, _, validatorErr := LoadEventTable(treeScored(t, dir), answers)
			if loadErr == nil || validatorErr == nil || ct != nil {
				t.Fatalf("Load: %v, LoadEventTable: %v (table %v); want both to refuse", loadErr, validatorErr, ct)
			}
			if loadErr.Error() != validatorErr.Error() {
				t.Errorf("the two doors refuse in different words:\n Load:           %v\n LoadEventTable: %v", loadErr, validatorErr)
			}
			if !strings.Contains(validatorErr.Error(), c.rule+":") {
				t.Errorf("the error does not name the rule %s: %v", c.rule, validatorErr)
			}
			for _, secret := range []string{"ev-alpha", "ev-beta", "cccccccccccc", "dddddddddddd", "practice-who"} {
				if strings.Contains(validatorErr.Error(), secret) {
					t.Errorf("the error carries the value %q: %v", secret, validatorErr)
				}
			}
		})
	}
}

// The file's own problems, and the one place the two doors differ: a link. The scoreboard's
// answers Secret is a directory volume whose file is a link, so the start-up follows it; the
// validator's input is a tree of the operator's own and a link in it is refused (V57).
func TestLoadEventTable_FileProblemsAndLinks(t *testing.T) {
	dir := evTree(t, nil)
	if ct, id, err := LoadEventTable(treeScored(t, dir), ""); !errors.Is(err, ErrTableMissing) || ct != nil || id != "" {
		t.Errorf("no answers file: (%v, %q, %v), want ErrTableMissing", ct, id, err)
	}
	if ct, _, err := LoadEventTable(treeScored(t, dir), filepath.Join(t.TempDir(), "missing.tsv")); err == nil || ct != nil || errors.Is(err, ErrTableMissing) {
		t.Errorf("a missing file: (%v, %v), want a read error", ct, err)
	}
	if ct, _, err := LoadEventTable(treeScored(t, dir), t.TempDir()); err == nil || ct != nil {
		t.Errorf("a directory: (%v, %v), want a refusal", ct, err)
	}

	target := evFile(t, evTable(evRun, evRows()))
	link := filepath.Join(t.TempDir(), "answers-link.tsv")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if ct, _, err := LoadEventTable(treeScored(t, dir), link); err == nil || ct != nil {
		t.Errorf("a link as the answers file: (%v, %v), want a refusal", ct, err)
	}
	if j, id, err := Load(treeScored(t, dir), link, true); err != nil || j == nil || id != evRun {
		t.Errorf("Load of a link (the Secret volume's shape) = (%v, %q, %v), want the judge: the start-up follows it", j, id, err)
	}
}
