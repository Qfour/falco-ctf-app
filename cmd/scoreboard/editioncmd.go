package main

// editioncmd.go is `scoreboard edition ...` (ADR-0056 D20, D19 A4e-2 and A4e-3): the arguments
// of `edition check`, the call of edition.CheckEvent, the exit code and what is printed
// (`edition render` is not in this build: a usage error). main() reaches it only when
// os.Args[1] is `edition`, before anything of the server is built, so a subcommand never starts
// the server and the server's path never reaches this file (editioncmd_source_test.go fixes
// both by reading the sources).
//
// Layers (D20): this file reads no file and writes none (it imports no `os`): the readers and
// the writers are internal/edition's, and it is given the two
// output streams. It prints identifiers only: a rule, a seat, a challenge, a question, a file
// name, a position's number, a line number, B4's overlap numbers, a temporary name that was
// left (cut short by the library) and, on the one line of success, the run id. No value, key,
// vocabulary or bundle content is in any error the library returns,
// and nothing here adds one.
//
// Exit codes (D20, amendment 13 as revised; editionExitCode): 0 = accepted (the output is
// written; a temporary name that could not be removed after the commit point is printed and is
// not a failure), 1 = a rule of D10 refused what was read (every leaf of the error is a
// *Violation; nothing is written), 2 = a usage error, an input that cannot be read or is not in
// its form, an output that already exists, an error of no kind the library gives, or a mix of
// kinds (nothing is written), 3 = every check passed and the output could not be put in place
// (the output's environment; nothing is at the output, and the same input can be given again).
// `edition render` (the event's and --practice) is the next change: until it lands it is a usage
// error.

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

// runEdition is `scoreboard edition <subcommand> ...`; args are what follows `edition`. It
// returns the exit code and starts nothing.
func runEdition(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: scoreboard edition check|render ... (every argument is required; see ADR-0056 D20)")
		return exitUsage
	}
	switch args[0] {
	case "check":
		return runEditionCheck(args[1:], stdout, stderr)
	case "render":
		fmt.Fprintln(stderr, "edition render is the next stage (ADR-0056 D19 A4e-3) and is not in this build")
		return exitUsage
	}
	fmt.Fprintln(stderr, "unknown subcommand of edition (want check or render)")
	return exitUsage
}

// checkFlags are the arguments of `edition check` that take one value; --corpus takes a
// value and may be given again, --no-previous takes none.
var checkFlags = []string{
	"--challenges", "--scenario", "--flags-file", "--answers", "--render-record",
	"--evidence-root", "--seats", "--edition-root", "--previous-digests", "--digests-out",
}

// editionArgs are the words of a subcommand's arguments as readEditionArgs read them: the value
// of each argument that takes one, the values of the one argument that may be given again, and
// whether the one argument that takes no value was given.
type editionArgs struct {
	values   map[string]string
	repeated []string
	flag     bool
}

// readEditionArgs reads `--name value` and `--name=value` words: valued are the names that take
// one value once, repeated is the name that takes one value and may be given again ("" for
// none), flag is the name that takes no value. An unknown name, a repeated one (other than
// repeated), a value that is missing or empty, a flag with a value or given twice and a
// positional word are errors. Nothing is opened: this only reads the words.
func readEditionArgs(args, valued []string, repeated, flag string) (editionArgs, error) {
	w := editionArgs{values: map[string]string{}}
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		switch {
		case !strings.HasPrefix(name, "--"):
			return w, errors.New("a positional argument is not allowed (every argument is a --name)")
		case name == flag:
			if hasVal {
				return w, errors.New(flag + " takes no value")
			}
			if w.flag {
				return w, errors.New(flag + " is given twice")
			}
			w.flag = true
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

// parseCheckArgs reads the arguments of `edition check` into a CheckInput. A missing argument,
// a repeated one, an unknown one, a value that is missing, a positional argument,
// `--previous-digests` with `--no-previous` (or neither) and no `--corpus` are errors.
func parseCheckArgs(args []string) (edition.CheckInput, error) {
	var in edition.CheckInput
	w, err := readEditionArgs(args, checkFlags, "--corpus", "--no-previous")
	if err != nil {
		return in, err
	}
	in.NoPrevious = w.flag
	in.CorpusDirs = w.repeated
	for _, name := range checkFlags {
		if _, ok := w.values[name]; !ok && name != "--previous-digests" {
			return in, errors.New(name + " is required")
		}
	}
	if len(in.CorpusDirs) == 0 {
		return in, errors.New("--corpus is required (at least one directory)")
	}
	_, hasPrevious := w.values["--previous-digests"]
	if hasPrevious == in.NoPrevious {
		return in, errors.New("exactly one of --previous-digests and --no-previous is required")
	}
	in.Challenges = w.values["--challenges"]
	in.ScenarioFile = w.values["--scenario"]
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

// finishRefusal prints err (printRefusal) and the temporary names its *edition.OutputError
// could not remove, and returns its exit code.
func finishRefusal(w io.Writer, err error) int {
	printRefusal(w, err)
	for _, name := range leftNamesOf(err) {
		fmt.Fprintln(w, "a temporary name could not be removed and is left beside the output (remove it): "+name)
	}
	return editionExitCode(err)
}

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
