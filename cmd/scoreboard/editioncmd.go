package main

// editioncmd.go is `scoreboard edition ...` (ADR-0056 D20, D19 A4e-2 and A4e-3): the arguments
// of `edition check` and `edition render`, the call of edition.CheckEvent and of
// edition.RenderEvent, the exit code and what is printed. main() reaches it only when
// os.Args[1] is `edition`, before anything of the server is built, so a subcommand never starts
// the server and the server's path never reaches this file (editioncmd_source_test.go fixes
// both by reading the sources).
//
// Layers (D20): this file reads no file and writes none (it imports no `os`): the readers and
// the writers are internal/edition's, the guard of `--out` included, and it is given the two
// output streams. It prints identifiers only: a rule, a seat, a challenge, a question, a file
// name, a position's number, a line number, B4's overlap numbers, a temporary name that was
// left (cut short by the library) and, on the one line of success, the run id and the key's
// fingerprint. No value, key, vocabulary or bundle content is in any error the library returns,
// and nothing here adds one.
//
// Exit codes (D20, amendment 13 as revised; editionExitCode): 0 = accepted (the output is
// written; a temporary name that could not be removed after the commit point is printed and is
// not a failure), 1 = a rule of D10 refused what was read (every leaf of the error is a
// *Violation; nothing is written), 2 = a usage error, an input that cannot be read or is not in
// its form, an output that already exists, an error of no kind the library gives, or a mix of
// kinds (nothing is written), 3 = every check passed and the output could not be put in place
// (the output's environment; nothing is at the output, and the same input can be given again).
// `edition render --practice` (A4e-3b) has the same codes: 0 = the challenge's practice/ is the
// new render (an earlier practice/ moved aside that could not be removed is printed), 1 and 2 as
// above, 3 = practice/ was not replaced and is as it was (or the name that holds it is printed).

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// The exit codes of D20.
const (
	exitAccepted    = 0
	exitRefused     = 1
	exitUsage       = 2
	exitWriteFailed = 3
)

// maxListedViolations is how many violations are printed; the rest are counted (D20).
const maxListedViolations = 20

// The words of `scoreboard edition ...` that the contract table quotes (ADR-0056 D16 and D20,
// A4e-4 and A4e-5): the two subcommands, the argument of `edition check` that may be repeated,
// and the arguments that take no value. The lists of the arguments that take one value are
// checkFlags, renderFlags and practiceFlags below, and those of the arguments that take none
// checkSwitches, renderSwitches and practiceSwitches. internal/contracttable/editionrow_test.go
// reads these names, the lists and the exit codes from this file's source and holds the contract
// table's row to them (V82).
const (
	subcommandCheck   = "check"
	subcommandRender  = "render"
	corpusFlag        = "--corpus"
	noPreviousFlag    = "--no-previous"
	allChallengesFlag = "--all-challenges"
)

// scenarioFlag is the scope of a scenario file; exactly one of it and allChallengesFlag (every
// challenge: catalog.LoadScored with no scenario, as a scoreboard whose SCENARIO_FILE is empty)
// is given to `edition check` and `edition render` (ADR-0056 amendment 18, A4e-5).
const scenarioFlag = "--scenario"

// checkSwitches and renderSwitches are the arguments of `edition check` and of `edition render`
// that take no value, practiceSwitches that of `edition render --practice`.
var (
	checkSwitches    = []string{noPreviousFlag, allChallengesFlag}
	renderSwitches   = []string{noPreviousFlag, allChallengesFlag}
	practiceSwitches = []string{practiceFlag}
)

// runEdition is `scoreboard edition <subcommand> ...`; args are what follows `edition`. It
// returns the exit code and starts nothing.
func runEdition(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: scoreboard edition check|render ... (every argument is required; see ADR-0056 D20)")
		return exitUsage
	}
	switch args[0] {
	case subcommandCheck:
		return runEditionCheck(args[1:], stdout, stderr)
	case subcommandRender:
		return runEditionRender(args[1:], stdout, stderr)
	}
	fmt.Fprintln(stderr, "unknown subcommand of edition (want check or render)")
	return exitUsage
}

// checkFlags are the arguments of `edition check` that take one value; --corpus takes a
// value and may be given again, checkSwitches take none.
var checkFlags = []string{
	"--challenges", scenarioFlag, "--flags-file", "--answers", "--render-record",
	"--evidence-root", "--seats", "--edition-root", "--previous-digests", "--digests-out",
}

// editionArgs are the words of a subcommand's arguments as readEditionArgs read them: the value
// of each argument that takes one, the values of the one argument that may be given again, and
// which of the arguments that take no value were given.
type editionArgs struct {
	values   map[string]string
	repeated []string
	flags    map[string]bool
}

// readEditionArgs reads `--name value` and `--name=value` words: valued are the names that take
// one value once, repeated is the name that takes one value and may be given again ("" for
// none), flags are the names that take no value. An unknown name, a repeated one (other than
// repeated), a value that is missing or empty, a flag with a value or given twice and a
// positional word are errors. Nothing is opened: this only reads the words.
func readEditionArgs(args, valued []string, repeated string, flags []string) (editionArgs, error) {
	w := editionArgs{values: map[string]string{}, flags: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		switch {
		case !strings.HasPrefix(name, "--"):
			return w, errors.New("a positional argument is not allowed (every argument is a --name)")
		case isArgName(name, flags):
			if hasVal {
				return w, errors.New(name + " takes no value")
			}
			if w.flags[name] {
				return w, errors.New(name + " is given twice")
			}
			w.flags[name] = true
			continue
		case name != repeated && !isArgName(name, valued):
			return w, errors.New("an unknown argument " + shownArg(name))
		}
		if !hasVal {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return w, errors.New(name + " needs a value")
			}
			i++
			val = args[i]
		}
		if val == "" {
			return w, errors.New(name + " has an empty value")
		}
		if name == repeated {
			w.repeated = append(w.repeated, val)
			continue
		}
		if _, dup := w.values[name]; dup {
			return w, errors.New(name + " is given twice")
		}
		w.values[name] = val
	}
	return w, nil
}

// isArgName reports whether name is one of names.
func isArgName(name string, names []string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// scopeArgErr is the usage error of the scope (ADR-0056 amendment 18): exactly one of
// --scenario <file> and --all-challenges. An empty --scenario is refused before, by
// readEditionArgs (an empty value is never "every challenge").
func scopeArgErr(w editionArgs) error {
	if _, hasScenario := w.values[scenarioFlag]; hasScenario == w.flags[allChallengesFlag] {
		return errors.New("exactly one of " + scenarioFlag + " and " + allChallengesFlag + " is required")
	}
	return nil
}

// parseCheckArgs reads the arguments of `edition check` into a CheckInput. A missing argument,
// a repeated one, an unknown one, a value that is missing, a positional argument,
// `--scenario` with `--all-challenges` (or neither), `--previous-digests` with `--no-previous`
// (or neither) and no `--corpus` are errors.
func parseCheckArgs(args []string) (edition.CheckInput, error) {
	var in edition.CheckInput
	w, err := readEditionArgs(args, checkFlags, corpusFlag, checkSwitches)
	if err != nil {
		return in, err
	}
	in.NoPrevious = w.flags[noPreviousFlag]
	in.AllChallenges = w.flags[allChallengesFlag]
	in.CorpusDirs = w.repeated
	for _, name := range checkFlags {
		if _, ok := w.values[name]; !ok && name != "--previous-digests" && name != scenarioFlag {
			return in, errors.New(name + " is required")
		}
	}
	if err := scopeArgErr(w); err != nil {
		return in, err
	}
	if len(in.CorpusDirs) == 0 {
		return in, errors.New("--corpus is required (at least one directory)")
	}
	_, hasPrevious := w.values["--previous-digests"]
	if hasPrevious == in.NoPrevious {
		return in, errors.New("exactly one of --previous-digests and --no-previous is required")
	}
	in.Challenges = w.values["--challenges"]
	in.ScenarioFile = w.values[scenarioFlag]
	in.FlagsFile = w.values["--flags-file"]
	in.AnswersFile = w.values["--answers"]
	in.RenderRecordFile = w.values["--render-record"]
	in.EvidenceRoot = w.values["--evidence-root"]
	in.SeatsFile = w.values["--seats"]
	in.EditionRoot = w.values["--edition-root"]
	in.PreviousDigestsFile = w.values["--previous-digests"]
	in.DigestsOut = w.values["--digests-out"]
	return in, nil
}

// shownArg is an unknown argument's name as a message shows it: cut short and quoted, so that
// nothing odd reaches the terminal.
func shownArg(s string) string {
	if len(s) > 32 {
		s = s[:32] + "..."
	}
	return fmt.Sprintf("%q", s)
}

// runEditionCheck is `scoreboard edition check`: it reads the arguments, calls CheckEvent and,
// only for the event it accepted, writes the digests file and prints the one line of success.
func runEditionCheck(args []string, stdout, stderr io.Writer) int {
	in, err := parseCheckArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "edition check: "+err.Error())
		return exitUsage
	}
	ev, report, err := edition.CheckEvent(in)
	printOverlap(stderr, report)
	if err != nil {
		return finishRefusal(stderr, err)
	}
	left, err := edition.WriteDigestsFile(in.DigestsOut, ev)
	if err != nil {
		fmt.Fprintln(stderr, "edition check: the digests file was not written")
		return finishRefusal(stderr, err)
	}
	printLeftWarning(stderr, "edition check", left)
	fmt.Fprintf(stdout, "ok run=%s seats=%d challenges=%d\n", ev.RunID(), ev.Seats(), ev.Challenges())
	return exitAccepted
}

// finishRefusal prints err (printRefusal), the temporary names its *edition.OutputError could
// not remove (to be removed) and the names that hold an earlier output it could not move back (to
// be moved back, never removed), and returns its exit code.
func finishRefusal(w io.Writer, err error) int {
	printRefusal(w, err)
	for _, name := range leftNamesOf(err) {
		fmt.Fprintln(w, "a temporary name could not be removed and is left beside the output (remove it): "+name)
	}
	for _, name := range restoreNamesOf(err) {
		fmt.Fprintln(w, restoreLine+name)
	}
	return editionExitCode(err)
}

// restoreLine is the start of the line that names an earlier output that could not be moved back.
const restoreLine = "the earlier output was moved aside and could not be moved back: it is this name beside the output (move it back in place of the output; do NOT remove it): "

// printLeftWarning prints the temporary names that the writer could not remove AFTER the output
// was put in place (the commit point): the output is whole, the exit code is 0, and the
// operator removes the name.
func printLeftWarning(w io.Writer, cmd string, left []string) {
	for _, name := range left {
		fmt.Fprintln(w, cmd+": the output is in place; a temporary name beside it could not be removed (remove it): "+name)
	}
}

// editionExitCode is the exit code of an error of internal/edition (D20, amendment 13 as
// revised): 1 when every leaf of it is a rule's refusal (an *edition.Violation, or the count that
// closes a bounded list of them, an *edition.MoreViolations); 3 when every leaf is an
// *edition.OutputError (every check passed and the output could not be put in place); 2
// otherwise: an *edition.InputError, an error of no kind the library gives (an error that is
// not classified is never taken for a rule's refusal), and any mix of kinds (a join of a rule's
// refusal with a usage error says that not every check ran, so its list is not whole).
func editionExitCode(err error) int {
	if err == nil {
		return exitAccepted
	}
	var k leafKinds
	k.count(err)
	switch {
	case k.other == 0 && k.output == 0 && k.violation > 0:
		return exitRefused
	case k.other == 0 && k.violation == 0 && k.output > 0:
		return exitWriteFailed
	}
	return exitUsage
}

// leafKinds counts the leaves of an error by kind.
type leafKinds struct{ violation, output, other int }

// count walks err: the three kinds of the library are leaves (whatever they wrap), a join is its
// parts, a single wrap is what it wraps, and anything else is a leaf of no kind.
func (k *leafKinds) count(err error) {
	switch err.(type) {
	case *edition.Violation, *edition.MoreViolations:
		k.violation++
		return
	case *edition.OutputError:
		k.output++
		return
	case *edition.InputError:
		k.other++
		return
	}
	if m, ok := err.(interface{ Unwrap() []error }); ok {
		parts := m.Unwrap()
		if len(parts) == 0 {
			k.other++
		}
		for _, e := range parts {
			if e != nil {
				k.count(e)
			}
		}
		return
	}
	if inner := errors.Unwrap(err); inner != nil {
		k.count(inner)
		return
	}
	k.other++
}

// leftNamesOf is the temporary names that every *edition.OutputError among the leaves of err
// lists as left behind.
func leftNamesOf(err error) []string {
	var leaves []error
	collectLeaves(err, &leaves)
	var out []string
	for _, e := range leaves {
		var oe *edition.OutputError
		if errors.As(e, &oe) {
			out = append(out, oe.Left...)
		}
	}
	return out
}

// restoreNamesOf is the names that every *edition.OutputError among the leaves of err lists as
// holding an earlier output that could not be moved back (its Restore).
func restoreNamesOf(err error) []string {
	var leaves []error
	collectLeaves(err, &leaves)
	var out []string
	for _, e := range leaves {
		var oe *edition.OutputError
		if errors.As(e, &oe) {
			out = append(out, oe.Restore...)
		}
	}
	return out
}

// printOverlap prints B4's two largest overlaps, whether the event was accepted or not (D20):
// the number and the ids of the pair, never a byte of a file. Nothing is printed when B4 did
// not run.
func printOverlap(w io.Writer, report edition.CheckReport) {
	if !report.OverlapRan {
		return
	}
	line := func(what string, p edition.OverlapPair) {
		fmt.Fprintf(w, "B4 overlap (%s): rate=%.3f event=%s practice=%s compared=%d\n", what, p.Rate, orDash(p.Event), orDash(p.Practice), p.Compared)
	}
	line("outputs", report.Overlap.Output)
	line("templates", report.Overlap.Template)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// printRefusal prints the first maxListedViolations entries of err, one per line, and the
// count of the rest (D20). The entries are the leaves of err (an errors.Join is flattened, and
// so is a single wrap of one); the notes that close a bounded list (edition.MoreViolations) are
// not entries but counts, and are added to the count of what is not printed.
func printRefusal(w io.Writer, err error) {
	var leaves []error
	collectLeaves(err, &leaves)
	more := 0
	var entries []error
	for _, e := range leaves {
		var note *edition.MoreViolations
		if errors.As(e, &note) {
			more += note.N
			continue
		}
		entries = append(entries, e)
	}
	if len(entries) > maxListedViolations {
		more += len(entries) - maxListedViolations
		entries = entries[:maxListedViolations]
	}
	for _, e := range entries {
		fmt.Fprintln(w, e.Error())
	}
	if more > 0 {
		fmt.Fprintf(w, "%d further violations are not listed\n", more)
	}
}

// collectLeaves flattens err: an errors.Join (anything with `Unwrap() []error`) into its
// parts, and a plain single wrap whose inner error is one of those (the prefix of a wrap such
// as "edition: answers table: ..." says nothing the violations do not) into the parts of the
// inner error. A *edition.Violation, an *edition.InputError and an *edition.OutputError are
// never flattened away, whatever their cause is: the rule's name, the usage error's message and
// the failed write's message are what is printed. Any other error is one leaf, with its whole
// message.
func collectLeaves(err error, out *[]error) {
	if err == nil {
		return
	}
	switch err.(type) {
	case *edition.Violation, *edition.InputError, *edition.OutputError:
		*out = append(*out, err)
		return
	}
	if m, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range m.Unwrap() {
			collectLeaves(e, out)
		}
		return
	}
	if inner := errors.Unwrap(err); inner != nil && holdsJoin(inner) {
		collectLeaves(inner, out)
		return
	}
	*out = append(*out, err)
}

// holdsJoin reports whether err, or an error it wraps once at a time, is an errors.Join.
func holdsJoin(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if _, ok := e.(interface{ Unwrap() []error }); ok {
			return true
		}
	}
	return false
}

// ---- edition render (the event's; ADR-0056 D20, D19 A4e-3a) ----

// renderFlags are the arguments of `edition render` that take one value; renderSwitches take
// none. Every one is required, but exactly one of --scenario and --all-challenges, and exactly
// one of --previous-seats and --no-previous. The key is given as a file and only as a file
// (--key-file): no argument and no environment variable carries its value.
var renderFlags = []string{
	"--challenges", scenarioFlag, "--flags-file", "--edition-root", "--seats",
	"--previous-seats", "--key-file", "--out",
}

// parseRenderArgs reads the arguments of `edition render` into a RenderEventInput. A missing
// argument, a repeated one, an unknown one, a value that is missing, a positional argument,
// `--scenario` with `--all-challenges` (or neither) and `--previous-seats` with `--no-previous`
// (or neither) are errors.
func parseRenderArgs(args []string) (edition.RenderEventInput, error) {
	var in edition.RenderEventInput
	w, err := readEditionArgs(args, renderFlags, "", renderSwitches)
	if err != nil {
		return in, err
	}
	for _, name := range renderFlags {
		if _, ok := w.values[name]; !ok && name != "--previous-seats" && name != scenarioFlag {
			return in, errors.New(name + " is required")
		}
	}
	if err := scopeArgErr(w); err != nil {
		return in, err
	}
	_, hasPrevious := w.values["--previous-seats"]
	if hasPrevious == w.flags[noPreviousFlag] {
		return in, errors.New("exactly one of --previous-seats and --no-previous is required")
	}
	in.Challenges = w.values["--challenges"]
	in.ScenarioFile = w.values[scenarioFlag]
	in.AllChallenges = w.flags[allChallengesFlag]
	in.FlagsFile = w.values["--flags-file"]
	in.EditionRoot = w.values["--edition-root"]
	in.SeatsFile = w.values["--seats"]
	in.PreviousSeatsFile = w.values["--previous-seats"]
	in.NoPrevious = w.flags[noPreviousFlag]
	in.KeyFile = w.values["--key-file"]
	in.Out = w.values["--out"]
	return in, nil
}

// runEditionRender is `scoreboard edition render` (the event's): it reads the arguments, calls
// RenderEvent (which checks the output path, renders, checks its own output and writes --out)
// and, when the output is in place, prints the one line of success. Its error goes to
// finishRefusal (the exit code, and the temporary names an *edition.OutputError lists as left:
// the commit point of a tree is its rename, so a render leaves no name after it and has no
// warning of its own). With `--practice` among the arguments it is the practice edition's
// command instead (runEditionRenderPractice), whose arguments are its own.
func runEditionRender(args []string, stdout, stderr io.Writer) int {
	if hasPracticeArg(args) {
		return runEditionRenderPractice(args, stdout, stderr)
	}
	in, err := parseRenderArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "edition render: "+err.Error())
		return exitUsage
	}
	ev, err := edition.RenderEvent(in)
	if err != nil {
		fmt.Fprintln(stderr, "edition render: nothing was put at --out")
		return finishRefusal(stderr, err)
	}
	fmt.Fprintf(stdout, "ok run=%s seats=%d challenges=%d key-fingerprint=%s\n", ev.RunID(), ev.Seats(), ev.Challenges(), ev.KeyFingerprint())
	return exitAccepted
}

// ---- edition render --practice (the practice edition's; ADR-0056 D20, D19 A4e-3b) ----

// practiceFlag is the argument that makes `edition render` the practice edition's command. It
// takes no value.
const practiceFlag = "--practice"

// The line of exit 3 of `edition render --practice` (printed before finishRefusal's lines).
const practiceNotReplacedLine = "edition render --practice: every check passed and practice/ was not replaced (the output's environment failed): practice/ is as it was, unless a name is listed below to move back"

// practiceFlags are the arguments of `edition render --practice` that take one value. Both are
// required, and nothing else is taken: the practice edition is the same for every seat, so it
// has no key, no seats, no previous list and no --out (D20).
var practiceFlags = []string{"--challenges", "--cid"}

// hasPracticeArg reports whether a word of args is --practice (with a value or not: a value is
// refused by parsePracticeArgs).
func hasPracticeArg(args []string) bool {
	for _, a := range args {
		if name, _, _ := strings.Cut(a, "="); name == practiceFlag {
			return true
		}
	}
	return false
}

// parsePracticeArgs reads the arguments of `edition render --practice`: the challenges tree and
// the challenge id. An argument of the event's render (a key, the seats, the previous seats or
// --no-previous, the event edition, the scenario, the flags or --out) is refused by name, and so
// is anything readEditionArgs refuses (a missing, repeated or unknown argument, a value that is
// missing, --practice with a value or twice, a positional word).
func parsePracticeArgs(args []string) (challenges, cid string, err error) {
	for _, a := range args {
		name, _, _ := strings.Cut(a, "=")
		if !isArgName(name, practiceFlags) && (name == noPreviousFlag || isArgName(name, renderFlags)) {
			return "", "", errors.New(name + " is an argument of the event's render: with --practice only --challenges and --cid are taken (the practice edition is the same for every seat: no key, no seats, no previous list, no --out)")
		}
	}
	w, err := readEditionArgs(args, practiceFlags, "", practiceSwitches)
	if err != nil {
		return "", "", err
	}
	if !w.flags[practiceFlag] {
		return "", "", errors.New(practiceFlag + " is required")
	}
	for _, name := range practiceFlags {
		if _, ok := w.values[name]; !ok {
			return "", "", errors.New(name + " is required")
		}
	}
	return w.values["--challenges"], w.values["--cid"], nil
}

// runEditionRenderPractice is `scoreboard edition render --practice`: it reads the arguments,
// calls RenderPracticeEdition (which renders the practice edition of the challenge and puts it
// in place of its practice/) and, when the new practice/ is in place, prints the name that could
// not be removed after the commit point (the earlier practice/, moved aside), if any, and the one
// line of success. Its error goes to finishRefusal (the exit code, and the names an
// *edition.OutputError lists as left or to restore); when every check passed and the output's
// environment failed (exit 3), a line before it says that practice/ was not replaced.
func runEditionRenderPractice(args []string, stdout, stderr io.Writer) int {
	challenges, cid, err := parsePracticeArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "edition render --practice: "+err.Error())
		return exitUsage
	}
	left, err := edition.RenderPracticeEdition(challenges, cid)
	if err != nil {
		if editionExitCode(err) == exitWriteFailed {
			fmt.Fprintln(stderr, practiceNotReplacedLine)
		}
		return finishRefusal(stderr, err)
	}
	printLeftWarning(stderr, "edition render --practice", left)
	fmt.Fprintf(stdout, "ok practice cid=%s\n", cid)
	return exitAccepted
}
