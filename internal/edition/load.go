package edition

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

// Load is the ONE way the scoreboard obtains an answers table (ADR-0056 D8 (iii),
// D19 A2b, A4a-1): it reads the file, Parses it, runs ModeCheck and Check, and hands
// back a Judge. Parse and NewJudge are called from here and nowhere else in the
// program (Parse also from loadPractice below, which only Load calls), and Load is
// called from cmd/scoreboard once (load_source_test.go fixes all of it by reading
// the sources, the way ADR-0033 D6 does for the flags file). The plaintext Table
// never leaves this function: the caller gets the Judge (HMACs of the values under a
// per-process key) and the run id (D9), nothing else.
//
// cat is the catalog the scoreboard scores (catalog.Scored.Catalog); its
// investigate challenges are the scope the table must answer, and its evade
// challenges' ExpectedFlag are the flag values of this event (T7: they were
// already read, by catalog.LoadScored; this function does not read the flags file).
// challengesDir is CHALLENGES_DIR: the practice answers of EVERY challenge under it
// (not only the scope's) are read for T6, because the event table must differ from
// whatever the image publishes. answersFile is ANSWERS_FILE ("" = not set).
// eventMode is "FLAGS_FILE is not empty" (D8): the caller derives it, this function
// does not read the environment.
//
// Results:
//   - (nil, "", nil): no table, and none is needed (not the event mode, or nothing
//     to judge). The practice answers of the image are not read here (the practice
//     mode's own Judge is A4a-2).
//   - (judge, runID, nil): a table that every rule accepted, T6 included.
//   - an error: D8 (i) or (ii) (ErrTableMissing / ErrTableOutsideEventMode), an
//     unreadable file, a practice edition that is broken (loadPractice), or a table
//     a rule refused (a *Violation, or an errors.Join of them). An error names a
//     rule, a line and a seat / cid / qid, never a value.
//
// The practice answers are read only when a table is, and a table only reaches
// that point in the event mode (ModeCheck refuses it otherwise). They are used for
// T6 and for nothing else: no Judge is made from them (D8 (iii)). Check refuses to
// run T6 in the event mode when the set is nil; loadPractice returns the empty set
// (not nil) when the image has no practice edition: "there are none", not "not
// supplied".
func Load(cat catalog.Catalog, challengesDir, answersFile string, eventMode bool) (*Judge, string, error) {
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
	practice, err := loadPractice(challengesDir)
	if err != nil {
		return nil, "", err
	}
	opts := Options{
		EventMode:  eventMode,
		Practice:   practice,
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

// Where a practice edition lives under a challenge (ADR-0056 D8):
// <challengesDir>/<id>/edition/practice/answers.tsv.
const (
	editionDirName  = "edition"
	practiceDirName = "practice"
	practiceTable   = "answers.tsv"
)

// loadPractice is the practice answers of the image, as the set T6 compares an
// event table with (ADR-0056 D8 (iii), D10 T6, D19 A4a-1). It is called by Load and
// by nothing else (load_source_test.go), which is what lets it call Parse.
//
// It reads EVERY challenge under challengesDir, not the scoreboard's scope: the
// event table must differ from every practice edition the image carries. For each
// challenge that has an edition/ directory:
//   - the challenge must be an investigate one (an edition/ under any other type is
//     refused, not skipped);
//   - edition/, edition/practice/ and answers.tsv are what they should be (a
//     directory, a directory, a regular file: a link is refused, Lstat does not
//     follow it); an absent practice/ or answers.tsv adds nothing (a practice
//     edition that is missing from the scope is A4a-2's refusal, not this one's);
//   - answers.tsv is an answers table (Parse, the same shape and size limit) with the
//     practice run id (32 zeros), only the seat *, only rows of this challenge's own
//     cid and of its declared questions, and every value already normalised for its
//     question's format (answerformat.Canonical: a value that normalisation would
//     change could never equal a normalised event value, so T6 would pass it).
//
// Only normalised values are added to the set, keyed by the question's format. The
// first defect is returned, wrapped with the challenge id; like every error of this
// package it names a rule, a line and a seat / cid / qid, never a value. No file but
// answers.tsv is opened, and no Judge is made from what is read.
//
// The result is never nil: no practice edition at all is the empty set.
func loadPractice(challengesDir string) (PracticeSet, error) {
	full, err := catalog.Load(challengesDir)
	if err != nil {
		return nil, fmt.Errorf("edition: practice answers: %w", err)
	}
	set := make(PracticeSet)
	for _, id := range full.IDs() {
		ch := full[id]
		editionDir := filepath.Join(challengesDir, ch.Dir(), editionDirName)
		ok, err := practiceEntry(editionDir, true)
		if err != nil {
			return nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		}
		if !ok {
			continue
		}
		if ch.Type != catalog.TypeInvestigate {
			return nil, fmt.Errorf("edition: practice answers of %s: an %s/ directory belongs to an investigate challenge only, not to type %q", id, editionDirName, ch.Type)
		}
		practiceDir := filepath.Join(editionDir, practiceDirName)
		if ok, err = practiceEntry(practiceDir, true); err != nil {
			return nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		} else if !ok {
			continue
		}
		path := filepath.Join(practiceDir, practiceTable)
		if ok, err = practiceEntry(path, false); err != nil {
			return nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		} else if !ok {
			continue
		}
		data, err := readTable(path)
		if err != nil {
			return nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		}
		t, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		}
		if err := addPractice(set, id, ch, t); err != nil {
			return nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		}
	}
	return set, nil
}

// practiceEntry reports whether path exists, and refuses what is not a directory
// (wantDir) or not a regular file (!wantDir). It does not follow a link.
func practiceEntry(path string, wantDir bool) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if wantDir && !info.IsDir() {
		return false, fmt.Errorf("%s is not a directory", filepath.Base(path))
	}
	if !wantDir && !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	return true, nil
}

// addPractice checks one practice table of challenge id against the rules of
// loadPractice and adds its (already normalised) values to set.
func addPractice(set PracticeSet, id string, ch catalog.Challenge, t *Table) error {
	if t.runID != PracticeRunID {
		return newViolation(RuleShape, "a practice table must carry the practice run id (all zeros)", 1, cell{}, nil)
	}
	for _, r := range t.rows {
		if r.c.seat != AnySeat {
			return newViolation(RuleComplete, "a practice table has only the seat *", r.line, r.c, nil)
		}
		if r.c.cid != id {
			return newViolation(RuleComplete, "cid is not the challenge of this practice table", r.line, r.c, nil)
		}
		q, ok := findQuestion(ch.Investigate.Questions, r.c.qid)
		if !ok {
			return newViolation(RuleComplete, "qid is not a question of that challenge", r.line, r.c, nil)
		}
		if err := answerformat.Canonical(q.Format, q.Params, r.value); err != nil {
			return newViolation(RuleFormat, "practice value does not fit the format of its question or is not normalised", r.line, r.c, err)
		}
		set.Add(q.Format, r.value)
	}
	return nil
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
