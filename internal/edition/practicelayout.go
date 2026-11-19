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
// image's edition. The files that `edition render` writes under an event's `--out` are another
// contract (D20) and have constants of their own, the Event* ones (A4e-3a):
//
//	<--out>/
//	    answers.tsv                     EventAnswersFileName
//	    evidence/<seat>/<cid>/<file>    EventEvidenceDirName (the --evidence-root of `edition check`)
//	    render-record.tsv               EventRenderRecordFileName
//
// Two of them are spelled as two Practice* names are, and are not those constants: a rename of
// one layout is not a rename of the other.
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

// The names under an event's `--out` (D20 `edition render`, the event's). No digests file is
// among them: the event's digests are written by `edition check` (--digests-out) only.
const (
	// EventAnswersFileName is <--out>/answers.tsv: the answers table of the render (WriteAnswers).
	EventAnswersFileName = "answers.tsv"
	// EventEvidenceDirName is <--out>/evidence/: the bundles, <seat>/<cid>/<file> under it.
	EventEvidenceDirName = "evidence"
	// EventRenderRecordFileName is <--out>/render-record.tsv: the record of the render
	// (WriteRenderRecord): the run id, the key's fingerprint and the digest of the scope,
	// no key and no value.
	EventRenderRecordFileName = "render-record.tsv"
)
