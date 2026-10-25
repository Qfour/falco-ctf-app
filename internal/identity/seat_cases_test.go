package identity

// app#480 (ADR-0034 D2): the seat grammar has ONE definition (SeatPattern) and
// copies of it in other languages. The cases live in ONE file,
// testdata/seat-cases.tsv, and every implementation reads it: this is the Go
// side (ValidSeat); scripts/check-seat-grammar.sh runs the same rows through
// charts/ctf-user/deploy-user.sh; platform's roster tooling (a private repo)
// reads the same rows in its paired PR. A row is never dropped to make a side
// pass: the side that disagrees is the bug.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type seatCase struct {
	line   int
	input  string
	accept bool
}

// minSeatCases keeps the table from being emptied (or the reader from misparsing
// it into nothing) and still reading as green.
const minSeatCases = 40

// seatPlaceholders are the characters the table cannot spell literally; every
// reader decodes the same set (the table's header lists them).
var seatPlaceholders = strings.NewReplacer(
	"{LF}", "\n",
	"{U+202E}", "\u202e",
	"{U+00FC}", "\u00fc",
	"{U+00EF}", "\u00ef",
)

// parseSeatCases reads the table text. It fails on any line that is not
// `input<TAB>accept|reject`, so a malformed row is red, not skipped.
func parseSeatCases(name, raw string) ([]seatCase, error) {
	var rows []seatCase
	for i, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// First tab only: input may be empty (the line starts with a tab).
		in, verdict, ok := strings.Cut(line, "\t")
		if !ok || (verdict != "accept" && verdict != "reject") {
			return nil, fmt.Errorf("%s:%d: want exactly `input<TAB>accept|reject`, got %q", name, i+1, line)
		}
		if strings.ContainsAny(in, "\n\r") {
			return nil, fmt.Errorf("%s:%d: input spells a line break literally; use {LF}", name, i+1)
		}
		decoded := seatPlaceholders.Replace(in)
		// The placeholder set is closed (the table's header). A brace left after
		// decoding is an unknown placeholder: fail the reader instead of testing
		// the literal text, which a reject row would pass without trying the
		// input it stands for.
		if strings.ContainsAny(decoded, "{}") {
			return nil, fmt.Errorf("%s:%d: %q still contains a brace after decoding: an unknown placeholder", name, i+1, in)
		}
		rows = append(rows, seatCase{line: i + 1, input: decoded, accept: verdict == "accept"})
	}
	return rows, nil
}

func readSeatCases(t *testing.T) []seatCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "seat-cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := parseSeatCases("seat-cases.tsv", string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestValidSeat_SharedCaseTable(t *testing.T) {
	rows := readSeatCases(t)
	if len(rows) < minSeatCases {
		t.Fatalf("seat-cases.tsv has %d rows, want at least %d: the table was truncated or misread", len(rows), minSeatCases)
	}
	accepted, rejected := 0, 0
	for _, r := range rows {
		if r.accept {
			accepted++
		} else {
			rejected++
		}
		if got := ValidSeat(r.input); got != r.accept {
			t.Errorf("seat-cases.tsv:%d: ValidSeat(%q) = %v, want %v", r.line, r.input, got, r.accept)
		}
	}
	// Both verdicts present: a table of one kind cannot catch a grammar that
	// accepts everything (or nothing).
	if accepted < 10 || rejected < 20 {
		t.Fatalf("seat-cases.tsv has %d accept / %d reject rows: too few of one kind to hold the grammar", accepted, rejected)
	}
}

// seatPatternHeader is the first line of the table: `# pattern: ` and the regex.
// Platform's parity test reads the grammar from it, so it is the canonical
// literal of the grammar for every reader outside this repo.
const seatPatternHeader = "# pattern: "

func TestSeatCaseTable_HeaderIsTheGoPattern(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "seat-cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(raw), "\n")
	got, ok := strings.CutPrefix(first, seatPatternHeader)
	if !ok {
		t.Fatalf("seat-cases.tsv line 1 must be %q followed by the regex, got %q", seatPatternHeader, first)
	}
	if got != SeatPattern {
		t.Errorf("seat-cases.tsv header pattern = %q, want identity.SeatPattern %q", got, SeatPattern)
	}
	// The header is a comment to the row reader, and no row is lost to it.
	if _, err := parseSeatCases("x", first+"\nuser1\taccept\n"); err != nil {
		t.Errorf("the header line is not read as a comment: %v", err)
	}
	if rows, _ := parseSeatCases("x", first+"\nuser1\taccept\n"); len(rows) != 1 {
		t.Errorf("header + one row read as %d rows, want 1", len(rows))
	}
}

func TestSeatCaseTable_ReaderFailsOnAMalformedRow(t *testing.T) {
	for _, bad := range []string{"user1", "user1\tmaybe", "user1\taccept\textra", "user1\t", "user1\r\taccept",
		"user{U+2028}\treject", "{LF\treject", "user}\treject", "{lf}user1\treject"} {
		if _, err := parseSeatCases("x", bad+"\n"); err == nil {
			t.Errorf("%q was read as a valid row", bad)
		}
	}
	rows, err := parseSeatCases("x", "# c\n\n\treject\nuser1{LF}\treject\nuser{U+202E}\treject\nuser1\taccept\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || rows[0].input != "" || rows[1].input != "user1\n" || rows[2].input != "user\u202e" || !rows[3].accept {
		t.Fatalf("placeholders or the empty first column were misread: %+v", rows)
	}
}

// The shell copy of the grammar in deploy-user.sh must be the Go pattern, byte
// for byte: the shared table checks its behaviour, this pins the text so a
// widened or narrowed copy is red even for an input no row covers.
var shellSeatPattern = regexp.MustCompile(`(?m)^SEAT_PATTERN='([^'\n]*)'$`)

func shellSeatPatternOf(src string) (string, bool) {
	m := shellSeatPattern.FindAllStringSubmatch(src, -1)
	if len(m) != 1 {
		return "", false
	}
	return m[0][1], true
}

func TestDeployUserShellPatternIsTheGoPattern(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "charts", "ctf-user", "deploy-user.sh"))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := shellSeatPatternOf(string(src))
	if !ok {
		t.Fatal("deploy-user.sh must define SEAT_PATTERN='...' exactly once on its own line")
	}
	if got != SeatPattern {
		t.Errorf("deploy-user.sh SEAT_PATTERN = %q, want identity.SeatPattern %q", got, SeatPattern)
	}
}

func TestShellPatternCheck_CatchesADriftedOrMissingCopy(t *testing.T) {
	ok1 := "x\nSEAT_PATTERN='" + SeatPattern + "'\ny\n"
	if got, ok := shellSeatPatternOf(ok1); !ok || got != SeatPattern {
		t.Fatalf("a faithful copy was not read back: %q, %v", got, ok)
	}
	drifted := strings.Replace(ok1, "{0,", "{0,9", 1)
	if got, ok := shellSeatPatternOf(drifted); !ok || got == SeatPattern {
		t.Fatalf("a drifted copy was not distinguished: %q, %v", got, ok)
	}
	for name, src := range map[string]string{
		"missing":   "x\n",
		"twice":     ok1 + ok1,
		"indented":  "  SEAT_PATTERN='" + SeatPattern + "'\n",
		"unquoted":  "SEAT_PATTERN=" + SeatPattern + "\n",
		"in a line": "echo SEAT_PATTERN='" + SeatPattern + "'\n",
	} {
		if _, ok := shellSeatPatternOf(src); ok {
			t.Errorf("%s: read as a single definition", name)
		}
	}
}
