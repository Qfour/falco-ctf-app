package edition_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// ADR-0056 stage A2b: edition.Load, the one door to the answers table. The catalog
// is made by catalog.Load from a falco-rule.yaml under t.TempDir() (the production
// call), the table is a file under t.TempDir(); every value is synthetic.

// loadFixtureYAML is an investigate challenge with a per-seat name and a per-seat
// hexid (the same question ids and formats as baseRows, minus the choice-set, which
// would be too small a space for catalog.Load).
const loadFixtureYAML = `type: investigate
investigate:
  evidence: {mountDir: /opt/ctf/evidence}
  questions:
    - id: who
      format: name
    - id: hx
      format: hexid
      params: {length: 12}
`

// plainFlag is an event flag value that is not shaped like a flag, so only the
// FlagValues wiring (not catalog.MentionsFlag) can catch it in a table value.
const plainFlag = "plainflagvalue99"

func loadCatalog(t *testing.T) catalog.Catalog {
	t.Helper()
	dir := t.TempDir()
	cdir := filepath.Join(dir, demoCID)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "falco-rule.yaml"), []byte(loadFixtureYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	if !edition.ScopeOf(cat).HasInvestigate() {
		t.Fatal("the fixture catalog has no investigate challenge")
	}
	return cat
}

// loadRows is baseRows without the choice-set question.
func loadRows() [][]string {
	var out [][]string
	for _, r := range baseRows() {
		if r[2] != "pick" {
			out = append(out, r)
		}
	}
	return out
}

func writeTable(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "answers.tsv")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_AcceptsAnEventTable(t *testing.T) {
	cat := loadCatalog(t)
	j, runID, err := edition.Load(cat, t.TempDir(), writeTable(t, render(runA, loadRows())), true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if runID != runA {
		t.Errorf("run id = %q, want %q", runID, runA)
	}
	if j == nil {
		t.Fatal("no judge")
	}
	if ok, known := j.Match("seat-a", demoCID, "who", sentinel+"-a"); !ok || !known {
		t.Errorf("Match(seat-a, who, its own value) = %v, %v; want true, true", ok, known)
	}
	if ok, _ := j.Match("seat-b", demoCID, "who", sentinel+"-a"); ok {
		t.Error("seat-b's answer was accepted with seat-a's value")
	}
}

// No table and none needed: nothing to judge (an event with no investigate
// challenge), or not the event mode. Nothing is returned and nothing fails; this is
// every environment today.
func TestLoad_NoTableNoNeed(t *testing.T) {
	noInvestigate := catalog.Catalog{"02-ev": {ID: "02-ev", Type: "evade", ExpectedFlag: plainFlag}}
	cases := []struct {
		name  string
		cat   catalog.Catalog
		event bool
	}{
		{"event mode, nothing to judge", noInvestigate, true},
		{"not the event mode, nothing to judge", noInvestigate, false},
		{"not the event mode, investigate in scope", loadCatalog(t), false},
		{"empty catalog, event mode", catalog.Catalog{}, true},
		{"nil catalog, not the event mode", nil, false},
	}
	for _, c := range cases {
		j, runID, err := edition.Load(c.cat, t.TempDir(), "", c.event)
		if err != nil || j != nil || runID != "" {
			t.Errorf("%s: Load = %v, %q, %v; want nil, \"\", nil", c.name, j, runID, err)
		}
	}
}

// D8 (i) and (ii): the two ModeCheck refusals, through the door.
func TestLoad_RefusesTheModeMismatch(t *testing.T) {
	cat := loadCatalog(t)
	table := writeTable(t, render(runA, loadRows()))

	if _, _, err := edition.Load(cat, t.TempDir(), "", true); !errors.Is(err, edition.ErrTableMissing) {
		t.Errorf("event mode, investigate in scope, no ANSWERS_FILE: err = %v, want ErrTableMissing", err)
	}
	// D8 (ii): the table, without the event mode. The file is not even read: a missing
	// path must give the same answer.
	paths := []string{table, filepath.Join(t.TempDir(), "nope")}
	for _, path := range paths {
		j, runID, err := edition.Load(cat, t.TempDir(), path, false)
		if !errors.Is(err, edition.ErrTableOutsideEventMode) || j != nil || runID != "" {
			t.Errorf("no event mode, ANSWERS_FILE %q: Load = %v, %q, %v; want ErrTableOutsideEventMode and nothing else", filepath.Base(path), j, runID, err)
		}
	}
}

// One defect per case: each is refused, by the named rule, and no error carries a
// table value (V1, V3).
func TestLoad_RefusesADefectiveTable(t *testing.T) {
	cat := loadCatalog(t)
	withFlag := loadCatalog(t)
	withFlag["02-ev"] = catalog.Challenge{ID: "02-ev", Type: "evade", ExpectedFlag: plainFlag}

	cases := []struct {
		name  string
		cat   catalog.Catalog
		table []byte
		rules []string
	}{
		{"header is not v1", cat, bytes.Replace(render(runA, loadRows()), []byte("answers v1"), []byte("answers v2"), 1), []string{"T3"}},
		{"a row with five columns", cat, render(runA, append(loadRows(), []string{"seat-c", demoCID, "who", "x", "y"})), []string{"T3"}},
		{"a carriage return", cat, bytes.Replace(render(runA, loadRows()), []byte("\n"), []byte("\r\n"), 1), []string{"T3"}},
		{"a double quote", cat, render(runA, set(loadRows(), 0, 3, `"`+sentinel+`"`)), []string{"T3"}},
		{"no trailing newline", cat, bytes.TrimSuffix(render(runA, loadRows()), []byte("\n")), []string{"T3"}},
		{"the practice run id in the event mode (V15)", cat, render(edition.PracticeRunID, loadRows()), []string{"T3"}},
		{"a row missing (seat-b has no hx)", cat, render(runA, without(loadRows(), 3)), []string{"T4"}},
		{"a question that is not in the scope", cat, render(runA, set(loadRows(), 0, 2, "nope")), []string{"T4"}},
		{"seat * in an event table", cat, render(runA, rename(loadRows(), "seat-a", "*")), []string{"T4"}},
		{"a value outside its format (hexid)", cat, render(runA, set(loadRows(), 1, 3, "not-hex")), []string{"T5"}},
		{"a value holding an event flag value", withFlag, render(runA, set(loadRows(), 0, 3, sentinel+"-"+plainFlag)), []string{"T7"}},
		{"two seats share a per-seat value", cat, render(runA, set(loadRows(), 2, 3, sentinel+"-a")), []string{"T8"}},
		{"a table of rows and no investigate challenge", catalog.Catalog{"02-ev": {ID: "02-ev", Type: "evade"}}, render(runA, loadRows()), []string{"T4"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j, runID, err := edition.Load(c.cat, t.TempDir(), writeTable(t, c.table), true)
			if err == nil {
				t.Fatal("Load accepted it")
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

// The flag value of the event is not echoed by the error that refuses a value
// holding it (noSecret above covers the table values only).
func TestLoad_ErrorDoesNotEchoAnEventFlagValue(t *testing.T) {
	withFlag := loadCatalog(t)
	withFlag["02-ev"] = catalog.Challenge{ID: "02-ev", Type: "evade", ExpectedFlag: plainFlag}
	_, _, err := edition.Load(withFlag, t.TempDir(), writeTable(t, render(runA, set(loadRows(), 0, 3, sentinel+"-"+plainFlag))), true)
	if err == nil {
		t.Fatal("Load accepted a value that holds an event flag value")
	}
	if bytes.Contains([]byte(err.Error()), []byte(plainFlag)) {
		t.Errorf("the error echoes the flag value: %v", err)
	}
}

// The read is bounded and is of a regular file.
func TestLoad_FileProblems(t *testing.T) {
	cat := loadCatalog(t)

	_, _, err := edition.Load(cat, t.TempDir(), filepath.Join(t.TempDir(), "missing.tsv"), true)
	if err == nil || errors.Is(err, edition.ErrTableMissing) {
		t.Errorf("a missing file: err = %v, want a read error (not ErrTableMissing)", err)
	}
	if _, _, err := edition.Load(cat, t.TempDir(), t.TempDir(), true); err == nil {
		t.Error("a directory was accepted as the answers file")
	}
	if _, _, err := edition.Load(cat, t.TempDir(), writeTable(t, nil), true); err == nil {
		t.Error("an empty file was accepted")
	}

	// One byte over MaxTableBytes is refused as a size (the read stops there, so a
	// larger file is never held in memory).
	big := bytes.Repeat([]byte("a"), edition.MaxTableBytes+1)
	_, _, err = edition.Load(cat, t.TempDir(), writeTable(t, big), true)
	var v *edition.Violation
	if !errors.As(err, &v) || v.Rule != "T3" || v.Msg != "table is larger than the size limit" {
		t.Errorf("MaxTableBytes+1 bytes: err = %v, want the T3 size violation", err)
	}
}
