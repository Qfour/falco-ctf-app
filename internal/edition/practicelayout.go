package edition

// practicelayout.go is the ONE definition of the names of an edition's directory (ADR-0056 D8,
// amendment 9, D20, D19 A4e-1):
//
//	challenges/<cid>/edition/
//	    edition.yaml                    SpecFileName
//	    template/<file>                 TemplateDirName
//	    practice/                       PracticeDirName
//	        answers.tsv                 PracticeAnswersFileName
//	        digests.tsv                 PracticeDigestsFileName
//	        evidence/<file>             PracticeEvidenceDirName
//
// No other non-test Go file of this package spells one of these names as a string literal
// (layout_source_test.go reads the sources for that: a comment is not a spelling), so a rename
// is one edit here, and the test that holds the shell scripts of the platform and of the chart
// to this layout (ADR-0056 V85, A4e-4 / A5c-2 / A5d) has one place to read it from.
//
// The three Practice* names are the names of the files INSIDE the practice directory of an
// image's edition. The files that `edition render` writes under an event's `--out` (D20:
// answers.tsv, evidence/<seat>/<cid>/<file>, render-record.tsv) happen to be spelled the same
// way for the first two, but these constants are not their definition: whether A4e-3 uses the
// same constants for the event's output or defines its own is A4e-3's decision, and the
// "Practice" in the names is why it must decide, not assume.
//
// The names are exported so that the tests that check the committed practice editions (the
// golden of V67, which is an external test) use the definition and not a copy of it. They are
// constants and carry no behaviour.

const (
	// EditionDirName is the directory of a challenge that holds its edition (a challenge
	// of type investigate only).
	EditionDirName = "edition"
	// SpecFileName is the edition's spec, edition/edition.yaml (ParseSpec).
	SpecFileName = "edition.yaml"
	// TemplateDirName is edition/template/, a flat directory of template files.
	TemplateDirName = "template"
	// PracticeDirName is edition/practice/: what the image publishes of the practice edition.
	PracticeDirName = "practice"
	// PracticeEvidenceDirName is edition/practice/evidence/: the practice bundle, the only
	// part of practice/ that a seat ever receives.
	PracticeEvidenceDirName = "evidence"
	// PracticeAnswersFileName is edition/practice/answers.tsv: the practice answers table.
	PracticeAnswersFileName = "answers.tsv"
	// PracticeDigestsFileName is edition/practice/digests.tsv: the digest of the practice
	// bundle (WritePracticeDigests).
	PracticeDigestsFileName = "digests.tsv"
)
