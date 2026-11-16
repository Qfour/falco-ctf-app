package edition

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

// Load is the ONE way the scoreboard obtains an answers table (ADR-0056 D8 (iii)
// and (iv), D19 A2b, A4a-1, A4a-2): it reads the file, Parses it, runs ModeCheck and
// Check, and hands back a Judge. Parse and NewJudge are called from here and nowhere
// else in the program (Parse also from loadPractice below, NewJudge also from
// practiceJudge below; Load is the only caller of practiceJudge, and calls it only
// when eventMode is false), and Load is called from cmd/scoreboard once
// (load_source_test.go fixes all of it by reading the sources, the way ADR-0033 D6
// does for the flags file). The plaintext Table never leaves this function: the
// caller gets the Judge (HMACs of the values under a per-process key) and the run id
// (D9), nothing else.
//
// scored is what catalog.LoadScored returned, and the ONLY input about the catalog
// and the tree (ADR-0056 D19 A4a-3; there is no separate challenges directory
// argument, so the scope and the tree the practice answers come from cannot be two
// different trees, review #628 R4#2). scored.Catalog is the catalog the scoreboard
// scores: its investigate challenges are the scope the table must answer, and its
// evade challenges' ExpectedFlag are the flag values of this event (T7: they were
// already read, by catalog.LoadScored; this function does not read the flags file).
// scored.FullCatalog and scored.ChallengesDir are the whole tree: the practice
// answers of EVERY challenge under it (not only the scope's) are read, because the
// event table must differ from whatever the image publishes (T6), and because the
// practice mode's Judge is made from them. answersFile is ANSWERS_FILE ("" = not
// set). eventMode is "FLAGS_FILE is not empty" (D8): the caller derives it, this
// function does not read the environment.
//
// Results:
//   - (nil, "", nil): no table, and none is needed: nothing to judge (no
//     investigate challenge in the scope; the practice answers are not read).
//   - (judge, runID, nil): a table that every rule accepted, T6 included (the event
//     mode); or, with no ANSWERS_FILE, outside the event mode and with an
//     investigate challenge in scope, the Judge of the practice answers of the
//     scope's challenges, run id PracticeRunID (D8 (iv), practiceJudge).
//   - an error: D8 (i) or (ii) (ErrTableMissing / ErrTableOutsideEventMode), an
//     unreadable file, a practice edition that is broken (loadPractice), a scope
//     challenge that has no practice edition (the practice mode), or a table a rule
//     refused (a *Violation, or an errors.Join of them). An error names a rule, a
//     line and a seat / cid / qid, never a value.
//
// In the event mode the practice answers are read only when a table is, and they
// are used for T6 and for nothing else: no Judge is made from them (D8 (iii)); the
// one Judge made from them is practiceJudge's, reached only from the branch of Load
// where eventMode is false. Check refuses to run T6 in the event mode when the set
// is nil; loadPractice returns the empty set (not nil) when the image has no
// practice edition: "there are none", not "not supplied".
func Load(scored catalog.Scored, answersFile string, eventMode bool) (*Judge, string, error) {
	cat := scored.Catalog
	scope := ScopeOf(cat)
	if err := ModeCheck(eventMode, scope.HasInvestigate(), answersFile != ""); err != nil {
		return nil, "", err
	}
	if answersFile == "" {
		if !eventMode && scope.HasInvestigate() {
			return practiceJudge(scored)
		}
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
	practice, _, _, err := loadPractice(scored)
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

// practiceJudge is the practice mode's Judge (ADR-0056 D8 (iv), D19 A4a-2): the
// answers the image publishes for the investigate challenges of the scope, as ONE
// table (scopePracticeTable) that goes through Check (EventMode false: run id all
// zeros, seat * only, a row for every question of the scope) and NewJudge, like an
// event table does. It is called by Load and by nothing else, and Load calls it only
// when eventMode is false (D8 (iii): in the event mode no Judge is made from the
// practice answers; load_source_test.go reads the source for that). It does not take
// eventMode: the branch of Load is the guard, and a caller outside it is the thing
// the source check refuses.
//
// A challenge of the scope that has no practice edition, or one that is broken (the
// readers' own checks, loadPractice), is a refusal (T4): a scoreboard that cannot
// grade a challenge in its scope does not start. Check lists the questions that have
// no row. The result carries PracticeRunID, so the boot record (5) says all zeros.
func practiceJudge(scored catalog.Scored) (*Judge, string, error) {
	cat := scored.Catalog
	scope := ScopeOf(cat)
	_, tables, _, err := loadPractice(scored)
	if err != nil {
		return nil, "", err
	}
	t, err := scopePracticeTable(scope, tables)
	if err != nil {
		return nil, "", fmt.Errorf("edition: practice answers: %w", err)
	}
	// FlagValues: a practice answer must not hold this instance's flag either (T7).
	// Practice is nil: T6 is the event table's rule.
	if err := Check(t, scope, Options{EventMode: false, FlagValues: flagValues(cat)}); err != nil {
		return nil, "", fmt.Errorf("edition: practice answers: %w", err)
	}
	j, err := NewJudge(t)
	if err != nil {
		return nil, "", fmt.Errorf("edition: practice answers: %w", err)
	}
	return j, t.RunID(), nil
}

// scopePracticeTable picks the practice tables of the scope's challenges (cid -> the
// table loadPractice read), in the order of the sorted cids, and joins them into one
// table (joinPractice, in table.go: it makes no Table itself). A challenge of the
// scope that has no table is a T4 violation (all of them are listed, bounded like
// Check's). Tables of challenges outside the scope are not in the result: the Judge
// answers for the scope only.
func scopePracticeTable(scope Scope, tables map[string]*Table) (*Table, error) {
	cids := make([]string, 0, len(scope))
	for cid := range scope {
		cids = append(cids, cid)
	}
	sort.Strings(cids)
	var picked []*Table
	var missing collector
	for _, cid := range cids {
		src, ok := tables[cid]
		if !ok {
			missing.add(newViolation(RuleComplete, "an investigate challenge of the scope has no practice answers (edition/practice/answers.tsv)", 0, cell{cid: cid}, nil))
			continue
		}
		picked = append(picked, src)
	}
	if err := missing.err(); err != nil {
		return nil, err
	}
	return joinPractice(picked)
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

// loadPractice is the practice answers of the image: the set T6 compares an event
// table with (ADR-0056 D8 (iii), D10 T6, D19 A4a-1) and the parsed table of each
// challenge that has one, keyed by challenge id (the practice mode's Judge is made
// from those, D8 (iv), A4a-2). It is called by Load and by practiceJudge and by
// nothing else (load_source_test.go), which is what lets it call Parse. The tables
// hold plaintext values: the callers keep them only as long as they Check and, in
// practiceJudge, build a Judge, and the event path discards them.
//
// It reads EVERY challenge of scored.FullCatalog, not the scoreboard's scope: the
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
// answers.tsv is opened, and loadPractice itself makes no Judge: practiceJudge does,
// from the tables it returns, and Load calls practiceJudge only when eventMode is false.
//
// The third result is where the practice editions are, not what is in them (A4c-2, M2):
// the edition/ directory of every challenge that has one, once it passed the checks above
// (a directory, of an investigate challenge), whether or not it holds an answers.tsv.
// loadPractice is the one function that reads Scored.FullCatalog, so it is the one that
// knows which challenges have a practice edition and where; reading the practice bundle
// and the template files from there is readPracticeFiles's (practicefiles.go), which only
// the validator's path calls. The start-up path (Load) discards it, opens nothing under it
// and so refuses nothing about it: a bundle or a template that is missing or broken does
// not stop a scoreboard, which has no use for them.
//
// No result is nil on success: no practice edition at all is the empty set, no table and
// no directory.
func loadPractice(scored catalog.Scored) (PracticeSet, map[string]*Table, practiceDirs, error) {
	// Fail-closed on the input itself (review #631 R1#1): a Scored without its tree
	// would give the EMPTY practice set, and T6 would then compare nothing and pass.
	if err := checkScored(scored); err != nil {
		return nil, nil, nil, err
	}
	// The whole tree, from the same value as the scope (A4a-3): scored.FullCatalog was
	// read from scored.ChallengesDir by catalog.LoadScored.
	full, challengesDir := scored.FullCatalog, scored.ChallengesDir
	set := make(PracticeSet)
	tables := make(map[string]*Table)
	dirs := make(practiceDirs)
	for _, id := range full.IDs() {
		ch := full[id]
		editionDir := filepath.Join(challengesDir, ch.Dir(), editionDirName)
		ok, err := practiceEntry(editionDir, true)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		}
		if !ok {
			continue
		}
		if ch.Type != catalog.TypeInvestigate {
			return nil, nil, nil, fmt.Errorf("edition: practice answers of %s: an %s/ directory belongs to an investigate challenge only, not to type %q", id, editionDirName, ch.Type)
		}
		dirs[id] = editionDir
		practiceDir := filepath.Join(editionDir, practiceDirName)
		if ok, err = practiceEntry(practiceDir, true); err != nil {
			return nil, nil, nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		} else if !ok {
			continue
		}
		path := filepath.Join(practiceDir, practiceTable)
		if ok, err = practiceEntry(path, false); err != nil {
			return nil, nil, nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		} else if !ok {
			continue
		}
		data, err := readTable(path)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		}
		t, err := Parse(data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		}
		if err := addPractice(set, id, ch, t); err != nil {
			return nil, nil, nil, fmt.Errorf("edition: practice answers of %s: %w", id, err)
		}
		tables[id] = t
	}
	return set, tables, dirs, nil
}

// checkScored refuses a catalog.Scored that cannot be what catalog.LoadScored returns
// (ADR-0056 A4a-3, review #631): no FullCatalog or no ChallengesDir (a zero value, or
// a literal built by hand), or a challenge of the scope that the tree does not have
// with the same type and directory. It is loadPractice's first step, so it runs on
// every path that reads the practice answers (the event table's T6, and the practice
// mode's Judge) and on no other: a start-up with nothing to judge (no investigate
// challenge in scope, no table) reads no tree and is not asked for one. The error
// names challenge ids only.
func checkScored(s catalog.Scored) error {
	switch {
	case s.FullCatalog == nil:
		return fmt.Errorf("%w: no full catalog", ErrInconsistentScored)
	case s.ChallengesDir == "":
		return fmt.Errorf("%w: no challenges directory", ErrInconsistentScored)
	}
	for _, id := range s.Catalog.IDs() {
		got, want := s.Catalog[id], s.FullCatalog[id]
		switch _, ok := s.FullCatalog[id]; {
		case !ok:
			return fmt.Errorf("%w: challenge %s of the scope is not in the full catalog", ErrInconsistentScored, id)
		case got.Type != want.Type:
			return fmt.Errorf("%w: challenge %s has another type in the full catalog", ErrInconsistentScored, id)
		case got.Dir() != want.Dir():
			return fmt.Errorf("%w: challenge %s has another directory in the full catalog", ErrInconsistentScored, id)
		}
	}
	return nil
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
