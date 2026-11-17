package edition

// practicefiles.go reads the FILES of the image's practice editions (ADR-0056 D8, D10 B4,
// D19 A4c-2): for every practice edition, its bundle (edition/practice/evidence/<file>) and
// its template (edition/template/<file>). They are what B4 compares an event edition with
// (practiceoverlap.go). They are read by the validator's path only (A4e, through
// CheckedTable, M2) and never by the scoreboard's start-up: Load does not call this, so a
// bundle or a template that is missing or broken does not stop a scoreboard, which has no
// use for it. Where a practice edition is comes from loadPractice (practiceDirs), the one
// function that reads Scored.FullCatalog; this file reads what is under those directories
// and never the catalog.
//
// The reader is the bundle reader's: readBundleDir applies B2 (regular files only, B2's file
// name, at most MaxBundleFiles and MaxBundleBytes, UTF-8, no invisible character) to a flat
// directory, and a violation of it is an error, because B4's input must be a practice
// edition that is itself what it should be. Nothing here names a byte of a file's content.

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
)

// The names of edition/practice/evidence/ (the practice bundle, the only part of practice/
// that a seat ever receives) and of edition/template/ (a flat directory of template files)
// are practicelayout.go's (D8, addendum 9).

// practiceDirs is where the practice editions of the image are: challenge id -> its
// edition/ directory, for every challenge that has one (loadPractice makes it).
type practiceDirs map[string]string

// practiceEdition is the files of one practice edition, in byte order of their names. A
// directory that does not exist is no file (nil): a practice edition with a template and
// no bundle, or the reverse, is B4's to compare as far as it goes, and whether a practice
// edition is complete is A4a-2's and V67's.
type practiceEdition struct {
	Evidence []BundleFile
	Template []BundleFile
}

// practiceFiles is the files of every practice edition of the image, by challenge id.
type practiceFiles map[string]*practiceEdition

// readPracticeFiles reads the bundle and the template of every directory of dirs. The
// result is not nil on success (no practice edition at all is the empty map: "there are
// none", which B4 accepts, and not "not supplied", which it refuses). The first defect is
// returned, wrapped with the challenge id and which of the two it is; it names a rule
// (B2), a challenge and a file name, never a content. A directory that is a link or not a
// directory is refused, at every level under the edition/ directory (practiceEntry does
// not follow a link).
func readPracticeFiles(dirs practiceDirs) (practiceFiles, error) {
	out := make(practiceFiles, len(dirs))
	for _, id := range slices.Sorted(maps.Keys(dirs)) {
		editionDir := dirs[id]
		ev, err := readFlatDir(id, filepath.Join(editionDir, PracticeDirName), PracticeEvidenceDirName)
		if err != nil {
			return nil, fmt.Errorf("edition: practice evidence of %s: %w", id, err)
		}
		tpl, err := readFlatDir(id, editionDir, TemplateDirName)
		if err != nil {
			return nil, fmt.Errorf("edition: practice template of %s: %w", id, err)
		}
		out[id] = &practiceEdition{Evidence: ev, Template: tpl}
	}
	return out, nil
}

// readFlatDir is the files of <parent>/<name>/, read as a bundle is (B2). A parent or a
// directory that does not exist is no file; one that is not a directory (a link or a
// file) is an error.
func readFlatDir(id, parent, name string) ([]BundleFile, error) {
	for _, d := range []string{parent, filepath.Join(parent, name)} {
		ok, err := practiceEntry(d, true)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
	}
	var c collector
	b := readBundleDir(filepath.Join(parent, name), AnySeat, id, &seatBudget{}, &c)
	if err := c.err(); err != nil {
		return nil, err
	}
	return b.Files, nil
}
