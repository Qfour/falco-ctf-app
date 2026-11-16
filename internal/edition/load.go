package edition

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// Load is the ONE way the scoreboard obtains an answers table (ADR-0056 D8 (iii),
// D19 A2b): it reads the file, Parses it, runs ModeCheck and Check, and hands back
// a Judge. Parse and NewJudge are called from here and nowhere else in the
// program, and Load is called from cmd/scoreboard once (load_source_test.go fixes
// both by reading the sources, the way ADR-0033 D6 does for the flags file). The
// plaintext Table never leaves this function: the caller gets the Judge (HMACs of
// the values under a per-process key) and the run id (D9), nothing else.
//
// cat is the catalog the scoreboard scores (catalog.Scored.Catalog); its
// investigate challenges are the scope the table must answer, and its evade
// challenges' ExpectedFlag are the flag values of this event (T7: they were
// already read, by catalog.LoadScored; this function does not read the flags file).
// answersFile is ANSWERS_FILE ("" = not set). eventMode is "FLAGS_FILE is not
// empty" (D8): the caller derives it, this function does not read the
// environment.
//
// Results:
//   - (nil, "", nil): no table, and none is needed (not the event mode, or nothing
//     to judge). The practice answers of the image are not read here.
//   - (judge, runID, nil): a table that every rule accepted.
//   - an error: D8 (i) or (ii) (ErrTableMissing / ErrTableOutsideEventMode), an
//     unreadable file, or a table a rule refused (a *Violation, or an errors.Join of
//     them). An error names a rule, a line and a seat / cid / qid, never a value.
//
// The set of practice answers (T6) is not loaded yet: it is the practice editions'
// (A4 / A7). Check refuses to run T6 in the event mode when the set is nil, so the
// empty set is passed explicitly: "there are none", not "not supplied".
func Load(cat catalog.Catalog, answersFile string, eventMode bool) (*Judge, string, error) {
	scope := ScopeOf(cat)
	if err := ModeCheck(eventMode, scope.HasInvestigate(), answersFile != ""); err != nil {
		return nil, "", err
	}
	if answersFile == "" {
		return nil, "", nil
	}
	data, err := readTable(answersFile)
	if err != nil {
		return nil, "", err
	}
	t, err := Parse(data)
	if err != nil {
		return nil, "", fmt.Errorf("edition: answers table: %w", err)
	}
	opts := Options{
		EventMode: eventMode,
		// The practice answers are loaded by A4 / A7. Until then there are none, and the
		// empty set (not nil) says so; see the doc comment above.
		Practice:   PracticeSet{},
		FlagValues: flagValues(cat),
	}
	if err := Check(t, scope, opts); err != nil {
		return nil, "", fmt.Errorf("edition: answers table: %w", err)
	}
	j, err := NewJudge(t)
	if err != nil {
		return nil, "", fmt.Errorf("edition: answers table: %w", err)
	}
	return j, t.RunID(), nil
}

// readTable reads the answers file, at most MaxTableBytes+1 bytes (so that an
// unbounded file is never loaded; Parse refuses the one byte over). The error
// names the path and the operating system's reason, not the file's content.
func readTable(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("edition: answers file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("edition: answers file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("edition: answers file is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxTableBytes+1))
	if err != nil {
		return nil, fmt.Errorf("edition: answers file: %w", err)
	}
	return data, nil
}

// flagValues are the flag values of the scored catalog (T7's FlagValues).
func flagValues(cat catalog.Catalog) []string {
	var out []string
	for _, ch := range cat {
		if ch.ExpectedFlag != "" {
			out = append(out, ch.ExpectedFlag)
		}
	}
	return out
}
