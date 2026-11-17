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
// to this layout (ADR-0056 V85, A4e-4 / A5c-2 / A5d) has one place to read it from. The same
// names are the layout of the files a render writes for an event (D20: answers.tsv and
// evidence/ under the output directory), which is the other reason there is one definition.
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
