package edition

// practiceedition.go is `scoreboard edition render --practice` as a function (ADR-0056 D20, D19
// A4e-3b): it renders the practice edition of one investigate challenge of the image's tree from
// its edition.yaml and its template, and puts the result at the challenge's practice/ in place
// of what is there. The command (cmd/scoreboard) only reads its two arguments, calls
// RenderPracticeEdition and prints; it opens and writes no file.
//
// The steps:
//
//	(0) the arguments: the challenges tree and a challenge id of its grammar;
//	1.  catalog.Load of the tree, and the challenge: it is there and is of type investigate;
//	2.  <challenges>/<cid>/edition/{edition.yaml, template/<file>} (readEditionFiles, the reader
//	    of an event edition's directory too), then ParseSpec (E1);
//	3.  RenderPractice (the public key `practice` and the one seat *: CheckQuestions and the
//	    rest of E2 / E3 are its own) and PracticeOutput (the three parts of practice/);
//	4.  the self check of the output: the answers table is within MaxTableBytes. (That it also
//	    passes Parse and Check with the event mode off is held by the tests, which reach the door
//	    of the table: this file is not one of its callers, load_source_test.go);
//	5.  the tree practice/{answers.tsv, digests.tsv, evidence/<file>} (the Practice* names of
//	    practicelayout.go), written as a temporary sibling of practice/ and put in its place
//	    (replaceTreeAtomic: the earlier practice/ is moved aside, the new one renamed to
//	    practice/, which is the commit point, and the earlier one removed; a failure before the
//	    commit point moves it back, so practice/ is unchanged). Directories are 0755 and files
//	    0644, whatever the umask: practice/ is committed to the public repository.
//
// The output is deterministic: the same edition.yaml, template and questions give the same bytes
// (no clock, no random draw: the key is the public one), which is what the golden of V67
// compares. Nothing of the guard of an event's --out applies (D20): a practice edition is public
// and its place is the repository.
//
// The errors are the kinds the command turns into exit codes: a *Violation (E1, E2, E3, or the
// size of the table) is a rule's refusal (exit 1), an *InputError a usage error or an input that
// cannot be read (exit 2), and the *OutputError of step 5 a failure of the output's environment
// after every check passed (exit 3). left, on success only, is the name of the earlier practice/
// that was moved aside and could not be removed after the commit point (exit 0, a warning).
//
// Reach (D9, D13, V78): this file is the second of the two non-test files outside the render files
// that refer to what they declare (render_reach_test.go's renderCallers: eventrender.go and this
// one), and RenderPracticeEdition is called by the command's runEditionRenderPractice and by
// nothing else (load_source_test.go). It is not named render*.go because it reads and writes
// files, which the render files do not.

import (
	"path/filepath"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
)

// RenderPracticeEdition renders the practice edition of the challenge cid of the image's tree at
// challenges (`--challenges`, `--cid`) and puts it at <challenges>/<cid>/edition/practice/, in
// place of the practice/ that is there, as the header says. It returns no error only when the
// new practice/ is in place; otherwise the practice/ that was there is as it was (or, if it could
// not be moved back, its name is in the *OutputError's Left).
func RenderPracticeEdition(challenges, cid string) (left []string, err error) {
	// (0) The arguments.
	if challenges == "" {
		return nil, inputErr("the argument challenges is missing or empty (every argument is required)")
	}
	if !challengeid.Valid(cid) {
		return nil, inputErr("the argument cid is not a challenge id (" + challengeid.Pattern + ")")
	}

	// 1. The challenge.
	cat, err := catalog.Load(challenges)
	if err != nil {
		return nil, &InputError{Msg: "the challenges tree (--challenges) cannot be loaded", Err: err}
	}
	ch, ok := cat[cid]
	switch {
	case !ok:
		return nil, inputErr("the challenges tree (--challenges) has no challenge " + cid)
	case ch.Type != catalog.TypeInvestigate || ch.Investigate == nil:
		return nil, inputErr("the challenge " + cid + " is not an investigate challenge: only one of those has a practice edition")
	}
	dir := filepath.Join(challenges, ch.Dir(), EditionDirName)

	// 2. Its edition.
	ed, err := readEditionFiles(cid, dir)
	if err != nil {
		return nil, classify("the edition of "+cid+" cannot be read", err)
	}
	spec, err := ParseSpec(ed.specData)
	if err != nil {
		return nil, err
	}

	// 3. The render.
	r, err := RenderPractice(cid, spec, ch.Investigate.Questions, ed.template)
	if err != nil {
		return nil, err
	}
	pf, err := PracticeOutput(r)
	if err != nil {
		return nil, err
	}

	// 4. The self check.
	if len(pf.Answers) > MaxTableBytes {
		return nil, newViolation(RuleShape, "the answers table of the practice render is larger than the size limit", 0, cell{cid: cid}, nil)
	}

	// 5. The output, as one tree put in place of practice/.
	files := []outputFile{
		{Path: PracticeAnswersFileName, Data: pf.Answers},
		{Path: PracticeDigestsFileName, Data: pf.Digests},
	}
	for _, f := range pf.Evidence {
		files = append(files, outputFile{Path: PracticeEvidenceDirName + "/" + f.Name, Data: f.Data})
	}
	return replaceTreeAtomic(filepath.Join(dir, PracticeDirName), files)
}
