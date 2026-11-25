package edition

// checkevent.go is `scoreboard edition check` as a function (ADR-0056 D20 and amendment 12, D19
// A4e-2): every check the validator makes of an event edition, in the order D20 gives, and the
// ONE place that makes a *CheckedEvent. WriteDigests takes a *CheckedEvent and nothing weaker,
// so a digests file exists only for an event that every one of these checks accepted. The
// command (cmd/scoreboard) only reads its arguments, calls CheckEvent and prints; it opens and
// writes no file.
//
// The order (D20 `edition check`, the numbers are D20's):
//
//	(0) the arguments, the seat list and the previous digests: the usage errors that are
//	    looked at first, before any rule. A defect of any other input (the render record, the
//	    edition root, the evidence root, the corpus) comes out in the step that reads that
//	    input, so a rule's refusal in an earlier step can come before it;
//	1.  catalog.LoadScored; a scope with no investigate challenge is a usage error and B4 is not
//	    called (V72);
//	1b. the render record (read here, once; a form error is a usage error) and B12: its scope
//	    digest is ScopeDigest of the scope of step 1 (amendment 19);
//	2.  LoadEventTable: T3 to T8, T6 against the practice answers, the practice files;
//	3.  B11: the run id of the render record (of step 1b) is the table's;
//	4.  the set of the challenge directories of the edition root (E2; an entry named like a
//	    challenge id that is not a directory, or is a link, is a usage error), then per
//	    challenge: E1 (ParseSpec), E2 and B8 (a1) (CheckQuestions), B8 (a2) (CheckSeatSpace,
//	    on the seats given), and the template read and run through the lexer of the marks;
//	5.  CheckBundles (B1, B2, B3, B5, B6, B9); B5's Hints and Free are hlscope.Assemble's;
//	6.  B4 (checkPracticeOverlap, OverlapTheta);
//	7.  B7 (CheckDecoySpread) and B8 (b) (CheckOutputSpace);
//	7b. B13 to B16, the rules between the investigate challenges of the scope
//	    (CheckCrossChallenge, ADR-0056 amendment 26, A7-x PR 3);
//	7c. B17 and B19, the lines of an answer's group in the event's template (CheckRowRules,
//	    amendments 27 and 28, A7-x PR 4);
//	8.  B10, the continuity with the previous digests.
//
// A step that cannot be run (an input is missing, unreadable or malformed) stops the check
// (fail-closed): no later step is skipped silently. A step that finds violations stops it
// when the later steps need what it checks (1 to 5); steps 6, 7, 7b, 7c and 8 do not depend on
// each other, so all five are run and their violations listed together, and the overlap numbers
// of B4 are in the CheckReport whether the event is accepted or not.
//
// The errors are of two kinds, which the command turns into two exit codes (D20):
//
//   - an *InputError is a usage error or an input that cannot be read or is not in its form
//     (exit 2): nothing was decided about the event;
//   - a refusal of a rule of D10 is a *Violation or an errors.Join of them (exit 1): the input
//     was read and a rule refused it. Every rule's refusal here is one (the readers' collector
//     holds *Violation only, and an error of another kind is classify's *InputError).
//
// The command gives any other error exit 2 too (amendment 13 as revised: an error that is not
// classified is not taken for a rule's refusal), and the failure to write the digests file of
// an accepted event, WriteDigestsFile's *OutputError, exit 3.
//
// Nothing here names a value, a key, a word of a vocabulary or a byte of a bundle: a violation
// names a rule, a seat, a challenge, a question, a slot, a file and a position's number.

import (
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
	hlscope "github.com/Qfour/falco-ctf-app/internal/hintleak/scope"
)

// RuleContinuity is D10 B10: the continuity with the previous render.
const RuleContinuity = "B10"

// RuleRunID is D10 B11 (amendment 13): the run id of the render record is the answers table's,
// so the table and the bundles are of one render. It is the validator's only (D20 step 3). A
// render record whose form is wrong is an *InputError, not B11, and T3, the form of a table
// (which the scoreboard's start-up applies too), is not used for this comparison.
const RuleRunID = "B11"

// RuleScope is D10 B12 (amendment 19, A4e-6): the scope digest of the render record is the
// digest of the check's own scope (ScopeDigest of the ids catalog.LoadScored returned, in their
// order), so the render and the check were given one scope. It is the validator's only (D20 step
// 1b, before the table is read). A render record whose form is wrong is an *InputError, not B12.
const RuleScope = "B12"

// RuleTemplateMark is D10 E3 as the validator names it: a template with a mark outside the
// grammar (V69: the validator refuses with the renderer's own lexer, ScanMarks). It is the value
// of RuleSpecRender, which is declared in a render file that no validator file may name
// (render_reach_test.go); checkevent_test.go holds the two equal.
const RuleTemplateMark = "E3"

// InputError is a refusal of the kind D20 puts under exit 2: the invocation is not usable (an
// argument is missing, repeated or in conflict with another), or an input cannot be read (it
// is missing, is not a regular file, is a link), or is not in its form (a seat file, a previous
// digests file, a key), or the scope has nothing to check. It is not a rule of D10 refusing a
// thing that was read. Err is the cause, when there is one; Msg never holds an input's content.
type InputError struct {
	Msg string
	Err error
}

func (e *InputError) Error() string {
	if e.Err == nil {
		return e.Msg
	}
	return e.Msg + ": " + e.Err.Error()
}

func (e *InputError) Unwrap() error { return e.Err }

// inputErr is an *InputError with no cause.
func inputErr(msg string) error { return &InputError{Msg: msg} }

// classify gives err its kind: an *InputError and a rule's violation are what they are, and
// anything else (an operating system's error, a loader's error) is an input that could not be
// read, so it is an *InputError with msg for the context.
func classify(msg string, err error) error {
	var in *InputError
	var v *Violation
	switch {
	case err == nil:
		return nil
	case errors.As(err, &in), errors.As(err, &v):
		return err
	}
	return &InputError{Msg: msg, Err: err}
}

// CheckInput is what `edition check` is given: the paths of its arguments (D20). Every one is
// required, except that exactly one of ScenarioFile and AllChallenges, and exactly one of
// PreviousDigestsFile and NoPrevious, is given. The files are opened by this package's readers
// (safeopen.go), never by the caller.
type CheckInput struct {
	// Challenges (`--challenges`), ScenarioFile and FlagsFile are catalog.LoadScored's inputs,
	// and nothing else uses the challenges path: after LoadScored the tree is the one the
	// catalog.Scored carries. The flags are this event's (T7, B3).
	Challenges   string
	ScenarioFile string
	FlagsFile    string
	// AllChallenges says the scope is every challenge of the tree (`--all-challenges`, ADR-0056
	// amendment 18, A4e-5): catalog.LoadScored with no scenario, the scope of a scoreboard whose
	// SCENARIO_FILE is empty. It and ScenarioFile are one of the two and not both, so that an
	// empty scenario path is never read as "every challenge".
	AllChallenges bool
	// AnswersFile is the answers table (`--answers`), RenderRecordFile the record of the render
	// that made it and the bundles (`--render-record`), EvidenceRoot the tree
	// <seat>/<cid>/<file> of the bundles (`--evidence-root`), SeatsFile the ordered list of the
	// seats (`--seats`) and EditionRoot the tree <cid>/{edition.yaml, template/<file>} of the
	// event edition (`--edition-root`).
	AnswersFile      string
	RenderRecordFile string
	EvidenceRoot     string
	SeatsFile        string
	EditionRoot      string
	// PreviousDigestsFile is the digests file of the last check of this event
	// (`--previous-digests`), NoPrevious says this is the first one (`--no-previous`): one of
	// the two and not both, so that a previous file that was lost is never read as a first
	// check. The file holds at least one row.
	PreviousDigestsFile string
	NoPrevious          bool
	// CorpusDirs are the directories of the image's challenges and scenarios (`--corpus`, B9),
	// at least one.
	CorpusDirs []string
	// DigestsOut is where the digests file will be written (`--digests-out`): it must not exist
	// yet, and its directory must. CheckEvent only checks that; the file is written by
	// WriteDigestsFile, for the event CheckEvent returns.
	DigestsOut string
}

// validate is the usage errors that need no file: an argument that is empty, the scope and the
// two previous arguments that are not exactly one each, no corpus, and an output that is already
// there or has no directory.
func (in CheckInput) validate() error {
	if err := scopeArgsErr(in.ScenarioFile, in.AllChallenges); err != nil {
		return err
	}
	for _, a := range []struct{ name, val string }{
		{"challenges", in.Challenges},
		{"flags-file", in.FlagsFile},
		{"answers", in.AnswersFile},
		{"render-record", in.RenderRecordFile},
		{"evidence-root", in.EvidenceRoot},
		{"seats", in.SeatsFile},
		{"edition-root", in.EditionRoot},
		{"digests-out", in.DigestsOut},
	} {
		if a.val == "" {
			return inputErr("the argument " + a.name + " is missing or empty (every argument is required)")
		}
	}
	if in.NoPrevious == (in.PreviousDigestsFile != "") {
		return inputErr("exactly one of previous-digests and no-previous is required (a previous file that was lost must not read as a first check)")
	}
	if len(in.CorpusDirs) == 0 {
		return inputErr("the argument corpus is missing (B9 needs the image's challenges and scenarios)")
	}
	if slices.Contains(in.CorpusDirs, "") {
		return inputErr("an argument corpus is empty")
	}
	if err := refuseExisting(in.DigestsOut); err != nil {
		return &InputError{Msg: "the digests output", Err: err}
	}
	if info, err := os.Stat(filepath.Dir(in.DigestsOut)); err != nil || !info.IsDir() {
		return inputErr("the directory of the digests output does not exist")
	}
	return nil
}

// scopeArgsErr is the usage error of the scope of `edition check` and `edition render` (ADR-0056
// D20, amendment 18): exactly one of a scenario file and every challenge. Neither (an empty
// scenario path included: it is not "every challenge") and both are an *InputError.
func scopeArgsErr(scenarioFile string, allChallenges bool) error {
	if (scenarioFile != "") == allChallenges {
		return inputErr("exactly one of scenario and all-challenges is required (an empty scenario is not every challenge)")
	}
	return nil
}

// CheckReport is what CheckEvent measured on the way, for the caller to print: it is filled
// whether the event is accepted or not, as far as the check got.
type CheckReport struct {
	// OverlapRan says B4 ran (the check got to step 6). It is false when an earlier step
	// refused or could not run, and Overlap is then the zero value.
	OverlapRan bool
	// Overlap is B4's largest overlaps, the numbers and the ids of the pair (never a byte of a
	// file).
	Overlap OverlapReport
}

// CheckedEvent is an event edition that every check of D20 accepted (ADR-0056 amendment 12): E1,
// E2, E3, B8 (a1) and (a2), B1 to B10, B11 (the run id of the render record), B12 (its scope
// digest), B13 to B16 (between the challenges of the scope) and B17 and B19 (the lines of an
// answer's group). It carries what the digests file and the command's one line need: the run id of the
// answers table, the digest of
// every bundle, and how many seats and challenges were checked. It is made by CheckEvent and by
// nothing else (its fields are unexported, and validator_door_source_test.go fixes that no other
// non-test file builds one), and WriteDigests takes it and nothing weaker.
type CheckedEvent struct {
	runID      string
	rows       []DigestRow
	seats      int
	challenges int
}

// RunID is the run id of the answers table the event was checked against.
func (ev *CheckedEvent) RunID() string { return ev.runID }

// Rows is a copy of the digest of every bundle, in byte order of (seat, cid).
func (ev *CheckedEvent) Rows() []DigestRow { return slices.Clone(ev.rows) }

// Seats is how many seats were checked.
func (ev *CheckedEvent) Seats() int { return ev.seats }

// Challenges is how many investigate challenges were checked.
func (ev *CheckedEvent) Challenges() int { return ev.challenges }

// CheckEvent runs every check of D20's `edition check` on in, in the order of the header, and
// returns the *CheckedEvent only when every one passed; otherwise it returns no event and an
// error (see the two kinds in the header). The CheckReport is returned either way.
func CheckEvent(in CheckInput) (*CheckedEvent, CheckReport, error) {
	var report CheckReport
	if err := in.validate(); err != nil {
		return nil, report, err
	}

	// (0) The inputs whose defect is a usage error.
	seats, err := readSeatsFile(in.SeatsFile)
	if err != nil {
		return nil, report, err
	}
	var previous []DigestRow
	if !in.NoPrevious {
		if previous, err = readPreviousDigests(in.PreviousDigestsFile); err != nil {
			return nil, report, err
		}
	}

	// 1. The catalog, and a scope that has something to check.
	scored, err := catalog.LoadScored(in.Challenges, in.ScenarioFile, in.FlagsFile)
	if err != nil {
		return nil, report, &InputError{Msg: "the challenges, the scenario or the flags file cannot be loaded", Err: err}
	}
	scope := ScopeOf(scored.Catalog)
	if !scope.HasInvestigate() {
		return nil, report, inputErr("the scenario has no investigate challenge, so there is no edition to check (B4 is not called)")
	}

	// 1b. The render record, read once, and the scope it was rendered for is this check's
	// (B12). It is before the table is read, so a scope that differs is named by its cause and not
	// by its symptoms in the table (an unknown challenge, a missing row).
	record, err := readRenderRecord(in.RenderRecordFile)
	if err != nil {
		return nil, report, err
	}
	if record.scope != ScopeDigest(scored.Order) {
		// D10 B12 (ADR-0056 amendment 19, A4e-6).
		return nil, report, newViolation(RuleScope, "the scope digest of the render record is not the digest of this check's scope (the render and the check were given two scopes: other challenges, or the same in another order)", 0, cell{}, nil)
	}

	// 2. The answers table.
	table, runID, err := LoadEventTable(scored, in.AnswersFile)
	if err != nil {
		return nil, report, classify("the answers table cannot be loaded", err)
	}

	// 3. The render record (read in step 1b) is the table's.
	if record.runID != runID {
		// D10 B11 (ADR-0056 amendment 13; A4e-2c gave it its name, which was T3 before).
		return nil, report, newViolation(RuleRunID, "the run id of the render record is not the answers table's (the table and the record are of two renders)", 0, cell{}, nil)
	}

	// 4. The event edition of every challenge of the scope.
	editions, err := readEditions(in.EditionRoot, scope)
	if err != nil {
		return nil, report, classify("the edition root cannot be read", err)
	}
	if err := checkEditions(scope, editions, len(seats)); err != nil {
		return nil, report, err
	}

	// 5. The bundles.
	hints, free, err := hintInputs(in.ScenarioFile, scored)
	if err != nil {
		return nil, report, classify("the hints of the scope cannot be assembled", err)
	}
	corpus, err := ReadCorpus(in.CorpusDirs...)
	if err != nil {
		return nil, report, &InputError{Msg: "the corpus cannot be read", Err: err}
	}
	bundles, err := CheckBundles(in.EvidenceRoot, table, BundleInput{
		Scope:          scope,
		Seats:          seats,
		FlagValues:     flagValues(scored.Catalog),
		FlagChallenges: CountFlagChallenges(scored.Catalog),
		Hints:          hints,
		Free:           free,
		Corpus:         corpus,
	})
	if err != nil {
		return nil, report, classify("the evidence root cannot be read", err)
	}

	// 6, 7, 7b, 7c and 8 do not need each other's result: all five run, and what they found is
	// listed together.
	var refusals []error
	var b4 collector
	report.OverlapRan = true
	report.Overlap = checkPracticeOverlap(&b4, bundles.bundles, overlapInput{
		Practice:  table.files,
		Answers:   table.practice,
		Templates: templatesOf(editions),
	}, OverlapTheta)
	refusals = append(refusals, b4.err())
	refusals = append(refusals, checkSpreads(scope, editions, bundles.bundles, table))
	refusals = append(refusals, checkCrossChallenges(scope, scored.Catalog, editions, bundles.bundles, table))
	refusals = append(refusals, checkRowRules(scope, editions))
	refusals = append(refusals, checkContinuity(bundles.rows, previous, !in.NoPrevious))
	if err := errors.Join(refusals...); err != nil {
		return nil, report, err
	}

	// Every check passed: the one place that makes a CheckedEvent.
	return &CheckedEvent{runID: bundles.runID, rows: slices.Clone(bundles.rows), seats: len(seats), challenges: len(scope)}, report, nil
}

// checkEditions is step 4 for every challenge of the scope, in the order of the challenge ids:
// E1 (ParseSpec) and, when the file parsed, E2 and B8 (a1) (CheckQuestions), E2 of `blocks` and
// `clues` against the template (CheckBlocksAndClues, amendment 28) and B8 (a2)
// (CheckSeatSpace for the number of seats given, the rule being B8 and not the renderer's E3),
// and the template run through the lexer of the marks. The parsed spec is kept for B7. It
// lists what every challenge has; a challenge whose file did not parse has nothing more checked.
func checkEditions(scope Scope, editions map[string]*eventEdition, seats int) error {
	var errs []error
	for _, cid := range scope.sortedCIDs() {
		ed := editions[cid]
		spec, err := ParseSpec(ed.specData)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ed.spec = spec
		errs = append(errs,
			spec.CheckQuestions(cid, scope[cid]),
			spec.CheckBlocksAndClues(cid, ed.template),
			spec.CheckSeatSpace(cid, scope[cid], ed.template, seats, RuleVocabSpace),
			checkTemplateMarks(cid, ed.template))
	}
	return errors.Join(errs...)
}

// checkTemplateMarks reads every file of a template with the lexer of the marks (ScanMarks, the
// one definition) and refuses a file with a mark outside the grammar: the positions of the
// decoys cannot be located in it, which B7 needs. The rule is E3 (V69: the same lexer as the
// renderer's), so it is the rule a mark that is not one gets in both commands.
func checkTemplateMarks(cid string, template []BundleFile) error {
	var c collector
	for _, f := range template {
		if _, err := ScanMarks(f.Data); err != nil {
			v := newBundleViolation(RuleTemplateMark, "the template has a mark outside the grammar, so its positions cannot be located", cell{cid: cid}, f.Name)
			var me *MarkError
			if errors.As(err, &me) {
				v.Line = me.Line
			}
			c.add(v)
		}
	}
	return c.err()
}

// hintInputs is B5's Hints and Free for the scope: catalog.LoadHintInputs, the one reader of the
// journeys, the scenario's narrative overrides and the rule excerpts that cmd/scoreboard's
// start-up shows (ADR-0056 A4e-2c, V89), and then hlscope.Assemble, the one definition of what
// is a hint and what is shown without paying. The targets are not given here: B5 holds the files
// of the bundles to these inputs (CheckBundles). The count of the question prompts among the
// free texts is checked, as the tests of internal/hintleak check it (V24). A failure of the
// reader is a *catalog.HintInputsError, which names its step ("journeys: ...", "narrative: ...",
// "narrative overrides: ...", "rule excerpts: ...").
func hintInputs(scenarioFile string, scored catalog.Scored) (hints, free []hintleak.Item, err error) {
	scopeCat := scored.Catalog
	// The tree is the one LoadScored read (Scored.ChallengesDir): there is no second path.
	shown, err := catalog.LoadHintInputs(scored.ChallengesDir, scenarioFile, scopeCat)
	if err != nil {
		return nil, nil, err
	}
	built, wantPrompts := hlscope.Assemble(scored.Order, scopeCat, shown.Journeys, shown.Excerpts, nil)
	if err := hlscope.PromptCountProblem("event", built.Free, wantPrompts); err != nil {
		return nil, nil, newViolation(RuleBundleHint, "the question prompts of the scope are not all among the texts shown without paying, so B5 cannot run", 0, cell{}, err)
	}
	return built.Hints, built.Free, nil
}

// templatesOf is the template files of every challenge, by challenge id (B4's input (2)).
func templatesOf(editions map[string]*eventEdition) map[string][]BundleFile {
	out := make(map[string][]BundleFile, len(editions))
	for cid, ed := range editions {
		out[cid] = ed.template
	}
	return out
}

// checkSpreads is step 7: for every challenge, B7 (CheckDecoySpread, which reads the template
// and the spec of the event edition) and B8 (b) (CheckOutputSpace) on the bundles of all the
// seats of that challenge. B7 reads the answers table (a group in a block needs the seat's answer,
// spreadblock.go). It lists what every challenge has.
func checkSpreads(scope Scope, editions map[string]*eventEdition, read *Bundles, table *CheckedTable) error {
	var errs []error
	for _, cid := range scope.sortedCIDs() {
		var ofChallenge []*Bundle
		for _, b := range read.All() {
			if b.CID == cid {
				ofChallenge = append(ofChallenge, b)
			}
		}
		ed := editions[cid]
		errs = append(errs,
			CheckDecoySpread(cid, ed.spec, scope[cid], ed.template, ofChallenge, seatAnswersOf(table.table, cid)),
			CheckOutputSpace(cid, scope[cid], ofChallenge))
	}
	return errors.Join(errs...)
}

// checkCrossChallenges is step 7b: B13 to B16 (CheckCrossChallenge, ADR-0056 amendment 26) over
// the investigate challenges of the scope, with the catalog's declarations of what they share
// (cat is the scope's catalog, catalog.Scored.Catalog), the event's templates and edition.yaml
// (step 4 parsed every one, or the check stopped there), the bundles CheckBundles accepted and the
// answers table.
func checkCrossChallenges(scope Scope, cat catalog.Catalog, editions map[string]*eventEdition, read *Bundles, table *CheckedTable) error {
	chs := make(map[string]*CrossChallenge, len(scope))
	for _, cid := range scope.sortedCIDs() {
		ed := editions[cid]
		ch := &CrossChallenge{Questions: scope[cid], Spec: ed.spec, Template: ed.template, Answers: seatAnswersOf(table.table, cid)}
		if inv := cat[cid].Investigate; inv != nil {
			ch.Evidence = inv.Evidence
		}
		for _, b := range read.All() {
			if b.CID == cid {
				ch.Bundles = append(ch.Bundles, b)
			}
		}
		chs[cid] = ch
	}
	_, err := CheckCrossChallenge(chs)
	return err
}

// checkRowRules is step 7c: B17 and B19 (CheckRowRules, ADR-0056 amendments 27 and 28) on the
// event edition of every challenge of the scope, in the order of the challenge ids (step 4 parsed
// every edition.yaml and held it to E2, or the check stopped there). It lists what every challenge
// has.
func checkRowRules(scope Scope, editions map[string]*eventEdition) error {
	var errs []error
	for _, cid := range scope.sortedCIDs() {
		ed := editions[cid]
		_, err := ed.spec.CheckRowRules(cid, scope[cid], ed.template)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// seatAnswersOf is the rows of challenge cid in the answers table, in the form B7 reads them.
func seatAnswersOf(tb *Table, cid string) SeatAnswers {
	out := SeatAnswers{}
	for _, r := range tb.rows {
		if r.c.cid != cid {
			continue
		}
		if out[r.c.seat] == nil {
			out[r.c.seat] = map[string]string{}
		}
		out[r.c.seat][r.c.qid] = r.value
	}
	return out
}

// checkContinuity is D10 B10 (step 8): the (seat, cid) pairs of the previous digests are a subset
// of the current ones, and each has the same digest. The seat list only grows and the scope's
// investigate challenges do not change within an event, so every pair of the previous render is
// in this one: a pair that only the previous digests have is a violation (it also refuses a
// previous file of another event, which shares no pair with this one, so nothing is compared and
// nothing passes). With the same key and a seat list that only grew, the bundle of a pair that
// was there before is byte for byte the same, so a digest that differs is a bundle rendered
// again with another key, another edition or another list. A pair that only the current digests
// have (a seat added at the end of the list) is not compared. havePrevious is false for a first
// check (`--no-previous`): nothing is compared. A previous file that holds no row is refused too
// (its reader refuses it already). The messages name the seat and the challenge, never a value.
func checkContinuity(current, previous []DigestRow, havePrevious bool) error {
	if !havePrevious {
		return nil
	}
	var c collector
	if len(previous) == 0 {
		c.add(newViolation(RuleContinuity, "the previous digests hold no row, so the continuity would compare nothing (the first check is --no-previous)", 0, cell{}, nil))
		return c.err()
	}
	now := make(map[cell]string, len(current))
	for _, r := range current {
		now[cell{seat: r.Seat, cid: r.CID}] = r.Digest
	}
	for _, r := range previous {
		k := cell{seat: r.Seat, cid: r.CID}
		d, ok := now[k]
		switch {
		case !ok:
			c.add(newViolation(RuleContinuity, "the previous digests have this seat and challenge and this render does not (the seat list only grows and the scope does not change within an event; a previous file of another event is refused here)", 0, k, nil))
		case d != r.Digest:
			c.add(newViolation(RuleContinuity, "the bundle of this seat and challenge is not the one of the previous render (the digest differs: same key and a seat list that only grew give the same bundle)", 0, k, nil))
		}
	}
	return c.err()
}
