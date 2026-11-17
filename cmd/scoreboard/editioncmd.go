package main

// editioncmd.go is `scoreboard edition ...` (ADR-0056 D20, D19 A4e-2): the arguments of
// `edition check`, the call of edition.CheckEvent, the exit code and what is printed. main()
// reaches it only when os.Args[1] is `edition`, before anything of the server is built, so a
// subcommand never starts the server and the server's path never reaches this file
// (editioncmd_source_test.go fixes both by reading the sources).
//
// Layers (D20): this file reads no file and writes none (it imports no `os`): the readers and
// the writers are internal/edition's, and it is given the two output streams. It prints
// identifiers only: a rule, a seat, a challenge, a question, a file name, a position's number, a
// line number and B4's overlap numbers. No value, key, vocabulary or bundle content is in any
// error the library returns, and nothing here adds one.
//
// Exit codes: 0 = accepted (the digests file is written), 1 = a rule of D10 refused what was
// read (nothing is written), 2 = a usage error or an input that cannot be read (nothing is
// written). `edition render` is A4e-3: until it lands it is a usage error.

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// The exit codes of D20.
const (
	exitAccepted = 0
	exitRefused  = 1
	exitUsage    = 2
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

// parseCheckArgs reads the arguments of `edition check` (`--name value` or `--name=value`) into
// a CheckInput. A missing argument, a repeated one, an unknown one, a value that is missing, a
// positional argument, `--previous-digests` with `--no-previous` (or neither) and no `--corpus`
// are errors. Nothing is opened: this only reads the words.
func parseCheckArgs(args []string) (edition.CheckInput, error) {
	var in edition.CheckInput
	values := map[string]string{}
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		switch {
		case !strings.HasPrefix(name, "--"):
			return in, errors.New("a positional argument is not allowed (every argument is a --name)")
		case name == "--no-previous":
			if hasVal {
				return in, errors.New("--no-previous takes no value")
			}
			if in.NoPrevious {
				return in, errors.New("--no-previous is given twice")
			}
			in.NoPrevious = true
			continue
		case name != "--corpus" && !isCheckFlag(name):
			return in, errors.New("an unknown argument " + shownArg(name))
		}
		if !hasVal {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return in, errors.New(name + " needs a value")
			}
			i++
			val = args[i]
		}
		if val == "" {
			return in, errors.New(name + " has an empty value")
		}
		if name == "--corpus" {
			in.CorpusDirs = append(in.CorpusDirs, val)
			continue
		}
		if _, dup := values[name]; dup {
			return in, errors.New(name + " is given twice")
		}
		values[name] = val
	}
	for _, name := range checkFlags {
		if _, ok := values[name]; !ok && name != "--previous-digests" {
			return in, errors.New(name + " is required")
		}
	}
	if len(in.CorpusDirs) == 0 {
		return in, errors.New("--corpus is required (at least one directory)")
	}
	_, hasPrevious := values["--previous-digests"]
	if hasPrevious == in.NoPrevious {
		return in, errors.New("exactly one of --previous-digests and --no-previous is required")
	}
	in.Challenges = values["--challenges"]
	in.ScenarioFile = values["--scenario"]
	in.FlagsFile = values["--flags-file"]
	in.AnswersFile = values["--answers"]
	in.RenderRecordFile = values["--render-record"]
	in.EvidenceRoot = values["--evidence-root"]
	in.SeatsFile = values["--seats"]
	in.EditionRoot = values["--edition-root"]
	in.PreviousDigestsFile = values["--previous-digests"]
	in.DigestsOut = values["--digests-out"]
	return in, nil
}

func isCheckFlag(name string) bool {
	for _, f := range checkFlags {
		if f == name {
			return true
		}
	}
	return false
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
		printRefusal(stderr, err)
		var input *edition.InputError
		if errors.As(err, &input) {
			return exitUsage
		}
		return exitRefused
	}
	if err := edition.WriteDigestsFile(in.DigestsOut, ev); err != nil {
		fmt.Fprintln(stderr, "edition check: the digests file was not written: "+err.Error())
		return exitUsage
	}
	fmt.Fprintf(stdout, "ok run=%s seats=%d challenges=%d\n", ev.RunID(), ev.Seats(), ev.Challenges())
	return exitAccepted
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
// inner error. A *edition.Violation and an *edition.InputError are never flattened away, whatever
// their cause is: the rule's name and the usage error's message are what is printed. Any other
// error is one leaf, with its whole message.
func collectLeaves(err error, out *[]error) {
	if err == nil {
		return
	}
	switch err.(type) {
	case *edition.Violation, *edition.InputError:
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
