package edition_test

// ADR-0056 V66 (Go side, A5c-2): the practice edition's reader ParsePracticeDigests, and the
// two readers of a digests file holding their doors apart. ParseDigests (the event's) refuses
// the run id of all zeros and the seat *; ParsePracticeDigests refuses every other run id and
// every other seat. Each reader is run over the other's input, so a copy of one reader that
// accepts the other's file is red here. The rest of the grammar is one reader for both
// (parseDigestsFile), so each refusal of ParseDigests that is not about the run id or the
// seat is also a refusal of ParsePracticeDigests, at the same line.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// practiceGoldenDir is the practice/ of the golden fixture challenge (render_golden_test.go
// holds it equal to the renderer's output, V67).
var practiceGoldenDir = filepath.Join("testdata", "render-golden", demoCID, edition.EditionDirName, edition.PracticeDirName)

const practiceDigestsHeader = "# falco-ctf evidence-digests v1 run=" + edition.PracticeRunID

// practiceGoldenBundleDigest is BundleDigest of the golden practice/evidence/.
func practiceGoldenBundleDigest(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(practiceGoldenDir, edition.PracticeEvidenceDirName)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []edition.BundleFile
	for _, e := range ents {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, edition.BundleFile{Name: e.Name(), Data: data})
	}
	if len(files) == 0 {
		t.Fatalf("%s holds no file: the golden practice bundle is missing", dir)
	}
	return edition.BundleDigest(files)
}

// The committed practice digests file of the golden fixture is read, to the one row of its
// own challenge with the digest of its own evidence/ (the bytes deploy-user.sh's practice path
// holds the same file to: scripts/check-deploy-user-evidence.sh runs it over this tree).
func TestParsePracticeDigests_ReadsTheGoldenFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(practiceGoldenDir, edition.PracticeDigestsFileName))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := edition.ParsePracticeDigests(data)
	if err != nil {
		t.Fatalf("ParsePracticeDigests refuses the golden practice digests file: %v", err)
	}
	want := []edition.DigestRow{{Seat: edition.AnySeat, CID: demoCID, Digest: practiceGoldenBundleDigest(t)}}
	if !slices.Equal(rows, want) {
		t.Errorf("rows = %v, want %v", rows, want)
	}
	if _, _, err := edition.ParseDigests(data); err == nil {
		t.Error("ParseDigests (event) read the golden practice digests file")
	}
}

// What WritePracticeDigests writes, ParsePracticeDigests reads back (rows in the file's order,
// which is the writer's: byte order of the cid).
func TestParsePracticeDigests_ReadsWhatWritePracticeDigestsWrites(t *testing.T) {
	d1, d2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	in := []edition.DigestRow{
		{Seat: edition.AnySeat, CID: "02-other", Digest: d2},
		{Seat: edition.AnySeat, CID: demoCID, Digest: d1},
	}
	var buf bytes.Buffer
	if err := edition.WritePracticeDigests(&buf, edition.PracticeRunID, in); err != nil {
		t.Fatalf("WritePracticeDigests: %v", err)
	}
	rows, err := edition.ParsePracticeDigests(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePracticeDigests: %v", err)
	}
	want := []edition.DigestRow{in[1], in[0]}
	if !slices.Equal(rows, want) {
		t.Errorf("rows = %v, want %v", rows, want)
	}
}

func TestParsePracticeDigests_Refuses(t *testing.T) {
	good := []string{"*", demoCID, dig1}
	text := func(rows ...[]string) []byte { return digestsText(practiceDigestsHeader, rows...) }
	cases := []struct {
		name string
		data []byte
		line int // 0 = no line
	}{
		// the two rules of the door
		{"an event run id", digestsText("# falco-ctf evidence-digests v1 run="+runA, good), 1},
		{"31 zeros and a one", digestsText("# falco-ctf evidence-digests v1 run="+strings.Repeat("0", 31)+"1", good), 1},
		{"a seat of the seat grammar", text([]string{"seat-a", demoCID, dig1}), 2},
		{"a seat of the grammar after a good row", text(good, []string{"seat-a", "02-other", dig2}), 3},
		{"a seat of two stars", text([]string{"**", demoCID, dig1}), 2},
		{"an empty seat", text([]string{"", demoCID, dig1}), 2},
		// the grammar it shares with ParseDigests
		{"empty", nil, 0},
		{"no row", text(), 0},
		{"no header", digestsText("*\t"+demoCID+"\t"+dig1, good), 1},
		{"another version", digestsText("# falco-ctf evidence-digests v2 run="+edition.PracticeRunID, good), 1},
		{"the answers table's header", digestsText("# falco-ctf answers v1 run="+edition.PracticeRunID, good), 1},
		{"no run id", digestsText("# falco-ctf evidence-digests v1 run=", good), 1},
		{"33 zeros", digestsText("# falco-ctf evidence-digests v1 run="+edition.PracticeRunID+"0", good), 1},
		{"no final newline", []byte(strings.TrimSuffix(string(text(good)), "\n")), 2},
		{"a carriage return", []byte(strings.Replace(string(text(good)), "\n", "\r\n", 1)), 1},
		{"a double quote", text([]string{"*", demoCID, "\"" + dig1[1:]}), 2},
		{"a zero-width space", text([]string{"*", demoCID + "\xe2\x80\x8b", dig1}), 2},
		{"not UTF-8", append(text(good), 0xff, '\n'), 0},
		{"two columns", text([]string{"*", demoCID}), 2},
		{"four columns", text([]string{"*", demoCID, dig1, "x"}), 2},
		{"an empty cid", text([]string{"*", "", dig1}), 2},
		{"a cid outside the grammar", text([]string{"*", "demo", dig1}), 2},
		{"a short digest", text([]string{"*", demoCID, dig1[:63]}), 2},
		{"an upper-case digest", text([]string{"*", demoCID, strings.ToUpper(dig1[:60]) + "ABCD"}), 2},
		{"a cid twice", text(good, []string{"*", demoCID, dig2}), 3},
		{"too large", bytes.Repeat([]byte("x"), edition.MaxTableBytes+1), 0},
	}
	for _, c := range cases {
		rows, err := edition.ParsePracticeDigests(c.data)
		var v *edition.Violation
		if !errors.As(err, &v) || v.Rule != edition.RuleDigests {
			t.Errorf("%s: err = %v, want a D9 violation", c.name, err)
			continue
		}
		if rows != nil {
			t.Errorf("%s: %d rows were returned with the refusal", c.name, len(rows))
		}
		if v.Line != c.line {
			t.Errorf("%s: line = %d, want %d (%v)", c.name, v.Line, c.line, err)
		}
	}
}

// V66's last item: neither reader accepts the other's file. The inputs are the real files of
// each door (the two goldens) and what each door's writer writes, and the near misses that
// differ from a good file of one door in the run id alone or in the seat alone.
func TestDigestReaders_NeitherAcceptsTheOthersInput(t *testing.T) {
	practiceGolden, err := os.ReadFile(filepath.Join(practiceGoldenDir, edition.PracticeDigestsFileName))
	if err != nil {
		t.Fatal(err)
	}
	eventGolden, err := os.ReadFile(goldenDigestsPath)
	if err != nil {
		t.Fatal(err)
	}
	var practiceWritten, eventWritten bytes.Buffer
	if err := edition.WritePracticeDigests(&practiceWritten, edition.PracticeRunID, []edition.DigestRow{{Seat: edition.AnySeat, CID: demoCID, Digest: dig1}}); err != nil {
		t.Fatalf("WritePracticeDigests: %v", err)
	}
	if err := edition.WriteDigests(&eventWritten, edition.CheckedEventForTest(runA, []edition.DigestRow{{Seat: "seat-a", CID: demoCID, Digest: dig1}})); err != nil {
		t.Fatalf("WriteDigests: %v", err)
	}
	eventHeader := "# falco-ctf evidence-digests v1 run=" + runA
	type file struct {
		name string
		data []byte
	}
	practiceGood := []file{
		{"the golden practice file", practiceGolden},
		{"WritePracticeDigests' output", practiceWritten.Bytes()},
		{"a practice file of two challenges", digestsText(practiceDigestsHeader, []string{"*", demoCID, dig1}, []string{"*", "02-other", dig2})},
	}
	eventGood := []file{
		{"the golden event file", eventGolden},
		{"WriteDigests' output", eventWritten.Bytes()},
		{"an event file of two seats", digestsText(eventHeader, []string{"seat-a", demoCID, dig1}, []string{"seat-b", demoCID, dig2})},
	}
	// Of neither door: one of the two rules of the other door in a file of one door.
	neither := []file{
		{"the practice run id and a seat", digestsText(practiceDigestsHeader, []string{"seat-a", demoCID, dig1})},
		{"an event run id and the seat *", digestsText(eventHeader, []string{"*", demoCID, dig1})},
		{"a practice file with one row of a seat", digestsText(practiceDigestsHeader, []string{"*", demoCID, dig1}, []string{"seat-a", "02-other", dig2})},
		{"an event file with one row of the seat *", digestsText(eventHeader, []string{"seat-a", demoCID, dig1}, []string{"*", "02-other", dig2})},
	}
	for _, f := range practiceGood {
		if _, err := edition.ParsePracticeDigests(f.data); err != nil {
			t.Errorf("ParsePracticeDigests refuses %s: %v", f.name, err)
		}
		if _, _, err := edition.ParseDigests(f.data); err == nil {
			t.Errorf("ParseDigests (event) read %s", f.name)
		}
	}
	for _, f := range eventGood {
		if _, _, err := edition.ParseDigests(f.data); err != nil {
			t.Errorf("ParseDigests refuses %s: %v", f.name, err)
		}
		if _, err := edition.ParsePracticeDigests(f.data); err == nil {
			t.Errorf("ParsePracticeDigests read %s", f.name)
		}
	}
	for _, f := range neither {
		if _, err := edition.ParsePracticeDigests(f.data); err == nil {
			t.Errorf("ParsePracticeDigests read %s", f.name)
		}
		if _, _, err := edition.ParseDigests(f.data); err == nil {
			t.Errorf("ParseDigests read %s", f.name)
		}
	}
}
