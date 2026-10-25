package challengeid

// app#494 (ADR-0041): the challenge id grammar has ONE definition (Pattern) and a
// shell copy in charts/ctf-user/deploy-user.sh (CHALLENGE_ID_PATTERN, the single
// challenge mode: the id reaches `helm --set-string` and a path). The cases live in
// ONE file, testdata/challenge-id-cases.tsv, and every registered implementation
// reads it: this is the Go side; scripts/check-deploy-user-ids.sh runs the same rows
// through deploy-user.sh. A row is never dropped to make a side pass: the side that
// disagrees is the bug.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/casetable"
)

// minCases keeps the table from being emptied (or the reader from misparsing it
// into nothing) and still reading as green.
const minCases = 50

func TestValid_SharedCaseTable(t *testing.T) {
	rows, err := casetable.Read(filepath.Join("testdata", "challenge-id-cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < minCases {
		t.Fatalf("challenge-id-cases.tsv has %d rows, want at least %d: the table was truncated or misread", len(rows), minCases)
	}
	accepted, rejected := 0, 0
	for _, r := range rows {
		if r.Accept {
			accepted++
		} else {
			rejected++
		}
		if got := Valid(r.Input); got != r.Accept {
			t.Errorf("challenge-id-cases.tsv:%d: Valid(%q) = %v, want %v", r.Line, r.Input, got, r.Accept)
		}
	}
	// Both verdicts present: a table of one kind cannot catch a grammar that
	// accepts everything (or nothing).
	if accepted < 10 || rejected < 40 {
		t.Fatalf("challenge-id-cases.tsv has %d accept / %d reject rows: too few of one kind to hold the grammar", accepted, rejected)
	}
}

func TestCaseTable_HeaderIsThePattern(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "challenge-id-cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := casetable.Header(string(raw))
	if !ok {
		t.Fatalf("challenge-id-cases.tsv line 1 must be %q followed by the regex", casetable.HeaderPrefix)
	}
	if got != Pattern {
		t.Errorf("challenge-id-cases.tsv header pattern = %q, want challengeid.Pattern %q", got, Pattern)
	}
}

// The shell copy of the grammar in deploy-user.sh must be Pattern, byte for byte:
// the shared table checks its behaviour, this pins the text so a widened or
// narrowed copy is red even for an input no row covers.
func TestDeployUserShellPatternIsThePattern(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "charts", "ctf-user", "deploy-user.sh"))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := casetable.ShellAssign(string(src), "CHALLENGE_ID_PATTERN")
	if !ok {
		t.Fatal("deploy-user.sh must define CHALLENGE_ID_PATTERN='...' exactly once on its own line")
	}
	if got != Pattern {
		t.Errorf("deploy-user.sh CHALLENGE_ID_PATTERN = %q, want challengeid.Pattern %q", got, Pattern)
	}
}
