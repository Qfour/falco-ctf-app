package identity

// app#480 (ADR-0034 D2): the seat grammar has ONE definition (SeatPattern) and
// copies of it in other languages. The cases live in ONE file,
// testdata/seat-cases.tsv, and every implementation reads it: this is the Go
// side (ValidSeat); scripts/check-seat-grammar.sh runs the same rows through
// charts/ctf-user/deploy-user.sh; platform's roster tooling (a private repo)
// reads the same rows in its paired PR. A row is never dropped to make a side
// pass: the side that disagrees is the bug.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/casetable"
)

// minSeatCases keeps the table from being emptied (or the reader from misparsing
// it into nothing) and still reading as green.
const minSeatCases = 40

func readSeatCases(t *testing.T) []casetable.Row {
	t.Helper()
	rows, err := casetable.Read(filepath.Join("testdata", "seat-cases.tsv"))
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
		if r.Accept {
			accepted++
		} else {
			rejected++
		}
		if got := ValidSeat(r.Input); got != r.Accept {
			t.Errorf("seat-cases.tsv:%d: ValidSeat(%q) = %v, want %v", r.Line, r.Input, got, r.Accept)
		}
	}
	// Both verdicts present: a table of one kind cannot catch a grammar that
	// accepts everything (or nothing).
	if accepted < 10 || rejected < 20 {
		t.Fatalf("seat-cases.tsv has %d accept / %d reject rows: too few of one kind to hold the grammar", accepted, rejected)
	}
}

// Line 1 of the table is `# pattern: ` and the regex. Platform's parity test reads
// the grammar from it, so it is the canonical literal of the grammar for every
// reader outside this repo. (The row reader, internal/casetable, reads it as a
// comment and fails on a malformed row; its own tests hold that.)
func TestSeatCaseTable_HeaderIsTheGoPattern(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "seat-cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := casetable.Header(string(raw))
	if !ok {
		first, _, _ := strings.Cut(string(raw), "\n")
		t.Fatalf("seat-cases.tsv line 1 must be %q followed by the regex, got %q", casetable.HeaderPrefix, first)
	}
	if got != SeatPattern {
		t.Errorf("seat-cases.tsv header pattern = %q, want identity.SeatPattern %q", got, SeatPattern)
	}
}

// The shell copy of the grammar in deploy-user.sh must be the Go pattern, byte
// for byte: the shared table checks its behaviour, this pins the text so a
// widened or narrowed copy is red even for an input no row covers.
func TestDeployUserShellPatternIsTheGoPattern(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "charts", "ctf-user", "deploy-user.sh"))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := casetable.ShellAssign(string(src), "SEAT_PATTERN")
	if !ok {
		t.Fatal("deploy-user.sh must define SEAT_PATTERN='...' exactly once on its own line")
	}
	if got != SeatPattern {
		t.Errorf("deploy-user.sh SEAT_PATTERN = %q, want identity.SeatPattern %q", got, SeatPattern)
	}
}
