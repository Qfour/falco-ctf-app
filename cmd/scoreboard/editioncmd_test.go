package main

// ADR-0056 D20, D19 A4e-2: `scoreboard edition check` as a command (V79): the arguments, the
// exit codes, what is printed, and that a refusal writes nothing. The rules themselves are
// internal/edition's (checkevent_test.go breaks each one); here a few of them are broken to see
// how the command reports them. The positive fixture is the renderer's own output, run in the
// test over the practice edition of internal/edition/testdata/render-golden and an event edition
// of its own (a key that is plainly a test key; every value a placeholder with no meaning). The
// tree it is laid out in is internal/edition/editiontest's (ADR-0056 A4e-2d, V91), which
// internal/edition's checkevent tests share and which never calls the renderer: the call of the
// renderer stays in this file.

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

const (
	ecRunID  = "0123456789abcdef0123456789abcdef"
	ecCID    = editiontest.CID
	ecEvade  = editiontest.Evade
	ecGolden = "../../internal/edition/testdata/render-golden/" + ecCID
	ecTmpl   = editiontest.TemplateName
)

// ecSpec and ecTemplate are the event edition: 9 decoys per answer slot (B8 (b) needs 10
// candidates of each question), a vocabulary, a time base and a fixed answer of their own.
func ecSpec() string { return editiontest.GoodSpec() }

func ecTemplate() string { return editiontest.GoodTemplate() }

// ecScope is the scope digest of the fixture's scenario (the evade challenge, then the
// investigate one: the order of the scenario file).
func ecScope() string { return edition.ScopeDigest([]string{ecEvade, ecCID}) }

// ecRecord is a render record of the second form (v2) with the run id run and the scope digest
// scope, and a fingerprint that is a placeholder.
func ecRecord(run, scope string) string {
	return "# falco-ctf render-record v2\nrun-id\t" + run + "\nkey-fingerprint\t" + strings.Repeat("ab", 32) + "\nscope\t" + scope + "\n"
}

// ecFix is one event on disk: its tree, and the answers the renderer drew (none may be
// printed).
type ecFix struct {
	t      *testing.T
	tree   *editiontest.Tree
	values []string
}

func (f *ecFix) path(rel string) string { return f.tree.Path(rel) }

func (f *ecFix) put(rel, content string) {
	f.t.Helper()
	f.tree.Put(rel, content)
}

func newEcFix(t *testing.T) *ecFix {
	t.Helper()
	f := &ecFix{t: t, tree: editiontest.NewTree(t)}
	seats := editiontest.Seats()

	// the image's tree (an evade challenge, and the investigate challenge with its practice
	// edition), the event edition, the seats and the output directory
	f.tree.PlaceInputs(editiontest.Inputs{Golden: ecGolden, Spec: ecSpec(), Template: ecTemplate(), Seats: seats})

	// the renderer's output
	key, err := edition.NewMasterKey(editiontest.KeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	p := f.tree.Paths()
	scored, err := catalog.LoadScored(p.Challenges, p.Scenario, p.Flags)
	if err != nil {
		t.Fatalf("catalog.LoadScored: %v", err)
	}
	spec, err := edition.ParseSpec([]byte(ecSpec()))
	if err != nil {
		t.Fatal(err)
	}
	r, err := edition.Render(edition.RenderInput{
		CID:       ecCID,
		Questions: edition.ScopeOf(scored.Catalog)[ecCID],
		Spec:      spec,
		Template:  []edition.BundleFile{{Name: ecTmpl, Data: []byte(ecTemplate())}},
		Key:       key,
		Seats:     seats,
		Previous:  edition.NoPreviousSeats(),
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var table, record bytes.Buffer
	if err := edition.WriteAnswers(&table, ecRunID, r.Rows); err != nil {
		t.Fatal(err)
	}
	if err := edition.WriteRenderRecord(&record, ecRunID, key, scored.Order); err != nil {
		t.Fatal(err)
	}
	f.tree.PlaceAnswers(table.String(), record.String())
	for _, b := range r.Bundles {
		for _, file := range b.Files {
			f.tree.PlaceBundleFile(b.Seat, b.CID, file.Name, file.Data)
		}
	}
	for _, row := range r.Rows {
		f.values = append(f.values, row.Value)
	}
	return f
}

// args are the arguments of a good `edition check` (the first check: --no-previous).
func (f *ecFix) args() []string {
	p := f.tree.Paths()
	return []string{
		"--challenges", p.Challenges,
		"--scenario", p.Scenario,
		"--flags-file", p.Flags,
		"--answers", p.Answers,
		"--render-record", p.RenderRecord,
		"--evidence-root", p.Evidence,
		"--seats", p.Seats,
		"--edition-root", p.EditionRoot,
		"--no-previous",
		"--corpus", p.Corpus,
		"--digests-out", p.DigestsOut,
	}
}

// runEd runs `edition <args>` and returns the exit code and the two streams.
func runEd(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = runEdition(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func (f *ecFix) noValue(what string, texts ...string) {
	f.t.Helper()
	for _, text := range texts {
		for _, v := range f.values {
			if strings.Contains(text, v) {
				f.t.Errorf("%s: the output holds a value of the render (%q)", what, v)
			}
		}
	}
}

func (f *ecFix) digestsOutExists() bool {
	_, err := os.Lstat(f.path("out/digests.tsv"))
	return !errors.Is(err, fs.ErrNotExist)
}

// without is args with the flag name (and its value, unless it is --no-previous) removed.
func without(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == name {
			if name != "--no-previous" {
				i++
			}
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func TestEditionCheck_Accepts(t *testing.T) {
	f := newEcFix(t)
	code, stdout, stderr := runEd(append([]string{"check"}, f.args()...)...)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q; want 0", code, stderr)
	}
	if want := "ok run=" + ecRunID + " seats=3 challenges=1\n"; stdout != want {
		t.Errorf("stdout = %q, want exactly %q", stdout, want)
	}
	if !strings.Contains(stderr, "B4 overlap (outputs): rate=") || !strings.Contains(stderr, "B4 overlap (templates): rate=") {
		t.Errorf("stderr = %q; want B4's two overlap lines even for an accepted event (D20)", stderr)
	}
	f.noValue("an accepted event", stdout, stderr)
	data, err := os.ReadFile(f.path("out/digests.tsv"))
	if err != nil {
		t.Fatalf("the digests file: %v", err)
	}
	id, rows, err := edition.ParseDigests(data)
	if err != nil || id != ecRunID || len(rows) != 3 {
		t.Errorf("the digests file reads back as (%q, %d rows, %v); want the run id and one row per seat", id, len(rows), err)
	}
	if info, err := os.Stat(f.path("out/digests.tsv")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the digests file: %v, %v; want mode 0600", info, err)
	}
	if names := dirNamesOf(t, f.path("out")); !slices.Equal(names, []string{"digests.tsv"}) {
		t.Errorf("the output directory holds %v; want the digests file only", names)
	}
}

func dirNamesOf(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range list {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

// An event that every check accepted, whose digests file cannot be written: exit 3 (ADR-0056 D20,
// amendment 13: the failure of the output's environment after every check passed; V87 and V92
// changed it from 2), no `ok` line, nothing left in the output directory. The failure does not
// depend on a permission (a test may run as root, for which chmod fails to refuse a write): the
// name of the output is 250 bytes, so the output itself can be named (the check of the path
// passes) but the temporary name beside it (a dot, the name, `.tmp-` and 16 hex digits: 272
// bytes) is over the 255 bytes of a file name, and the write fails when the temporary is made,
// after CheckEvent accepted the event.
func TestEditionCheck_AnAcceptedEventWhoseDigestsCannotBeWrittenIsExit3(t *testing.T) {
	f := newEcFix(t)
	out := f.path("out/" + strings.Repeat("d", 250))
	args := append(without(f.args(), "--digests-out"), "--digests-out", out)
	code, stdout, stderr := runEd(append([]string{"check"}, args...)...)
	if code != exitWriteFailed {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit 3", code, stdout, stderr)
	}
	if strings.Contains(stdout, "ok run=") || stdout != "" {
		t.Errorf("stdout = %q; want no `ok` line for a digests file that was not written", stdout)
	}
	if !strings.Contains(stderr, "the digests file was not written") {
		t.Errorf("stderr = %q; want it to say that the digests file was not written", stderr)
	}
	if !strings.Contains(stderr, "B4 overlap (outputs)") {
		t.Errorf("stderr = %q; want B4's numbers: the event was checked and accepted", stderr)
	}
	if names := dirNamesOf(t, f.path("out")); len(names) != 0 {
		t.Errorf("the output directory holds %v; want nothing (no digests file, no temporary)", names)
	}
	f.noValue("a failed write", stdout, stderr)
}

// The first check writes the digests; a second check of the same event, with those digests as
// the previous ones (`--previous-digests`), is accepted.
func TestEditionCheck_APreviousDigestsFileInsteadOfNoPrevious(t *testing.T) {
	f := newEcFix(t)
	if code, _, stderr := runEd(append([]string{"check"}, f.args()...)...); code != 0 {
		t.Fatalf("the first check: exit %d, %q", code, stderr)
	}
	second := append(without(f.args(), "--no-previous"), "--previous-digests", f.path("out/digests.tsv"))
	second = slices.Concat(without(second, "--digests-out"), []string{"--digests-out", f.path("out/second.tsv")})
	code, stdout, stderr := runEd(append([]string{"check"}, second...)...)
	if code != 0 || !strings.HasPrefix(stdout, "ok run=") {
		t.Errorf("exit %d, stdout %q, stderr %q; want an accepted event", code, stdout, stderr)
	}
}

// V79: every usage error is exit 2 with nothing on stdout, nothing written, and a message that
// names the argument. None of them opens a file (the paths are those of a good event, but the
// arguments are wrong before any file is read: the digests output is the check).
func TestEditionCheck_UsageErrorsAreExit2(t *testing.T) {
	f := newEcFix(t)
	good := f.args()
	required := []string{"--challenges", "--scenario", "--flags-file", "--answers", "--render-record", "--evidence-root", "--seats", "--edition-root", "--corpus", "--digests-out"}
	type tc struct {
		name string
		args []string
		want string // a word the message holds
	}
	var cases []tc
	for _, name := range required {
		cases = append(cases, tc{"without " + name, without(good, name), name})
	}
	cases = append(cases,
		tc{"neither --previous-digests nor --no-previous", without(good, "--no-previous"), "exactly one"},
		tc{"both --previous-digests and --no-previous", append(slices.Clone(good), "--previous-digests", f.path("out/digests.tsv")), "exactly one"},
		tc{"an unknown argument", append(slices.Clone(good), "--surprise", "x"), "unknown"},
		tc{"a positional argument", append(slices.Clone(good), "stray"), "positional"},
		tc{"a repeated argument", append(slices.Clone(good), "--seats", f.path("seats.txt")), "twice"},
		tc{"--no-previous twice", append(slices.Clone(good), "--no-previous"), "twice"},
		tc{"--no-previous with a value", append(without(good, "--no-previous"), "--no-previous=yes"), "no value"},
		tc{"a value that is missing at the end", append(slices.Clone(good), "--corpus"), "needs a value"},
		tc{"a value that is the next flag", append(without(good, "--seats"), "--seats", "--corpus"), "needs a value"},
		tc{"an empty value", append(without(good, "--seats"), "--seats="), "empty"},
		tc{"no arguments", nil, "required"},
	)
	for _, c := range cases {
		code, stdout, stderr := runEd(append([]string{"check"}, c.args...)...)
		if code != exitUsage || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 2, no stdout and %q in the message", c.name, code, stdout, stderr, c.want)
		}
		if f.digestsOutExists() {
			t.Fatalf("%s: a digests file was written", c.name)
		}
	}
	// the other words of the command line
	for name, args := range map[string][]string{
		"no subcommand":      nil,
		"an unknown one":     {"explode"},
		"render (too short)": {"render", "--challenges", "x"},
	} {
		if code, stdout, stderr := runEd(args...); code != exitUsage || stdout != "" || stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 2 and a message", name, code, stdout, stderr)
		}
	}
}

// `--name=value` is the same as `--name value`.
func TestParseCheckArgs_EqualsForm(t *testing.T) {
	args := []string{
		"--challenges=a=b", "--scenario=s", "--flags-file=f", "--answers=an", "--render-record=r",
		"--evidence-root=e", "--seats=se", "--edition-root=er", "--previous-digests=p",
		"--corpus=c1", "--corpus", "c2", "--digests-out=o",
	}
	in, err := parseCheckArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	if in.Challenges != "a=b" || in.PreviousDigestsFile != "p" || in.NoPrevious || !slices.Equal(in.CorpusDirs, []string{"c1", "c2"}) || in.DigestsOut != "o" {
		t.Errorf("parsed %+v", in)
	}
}

// An output that already exists is exit 2, and it is left as it was.
func TestEditionCheck_AnExistingDigestsOutIsExit2(t *testing.T) {
	f := newEcFix(t)
	f.put("out/digests.tsv", "already here\n")
	code, stdout, stderr := runEd(append([]string{"check"}, f.args()...)...)
	if code != exitUsage || stdout != "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit 2", code, stdout, stderr)
	}
	if b, err := os.ReadFile(f.path("out/digests.tsv")); err != nil || string(b) != "already here\n" {
		t.Errorf("the existing output is now (%q, %v)", b, err)
	}
	f.noValue("an existing output", stderr)
}

// V72: a catalog with no investigate challenge is exit 2 and B4 is not called (nothing about it
// is printed).
func TestEditionCheck_NoInvestigateChallengeIsExit2AndB4IsNotCalled(t *testing.T) {
	f := newEcFix(t)
	args := append(without(f.args(), "--scenario"), "--scenario", f.tree.PutScenario("evade-only", ecEvade))
	code, stdout, stderr := runEd(append([]string{"check"}, args...)...)
	if code != exitUsage || stdout != "" || strings.Contains(stderr, "B4 overlap") {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 and nothing of B4", code, stdout, stderr)
	}
	if f.digestsOutExists() {
		t.Error("a digests file was written")
	}
}

// V79: a rule broken in the event is exit 1; the message names the rule; no value of the render
// is printed; nothing is written, and the overlap numbers are still printed.
func TestEditionCheck_ARuleOfD10IsExit1(t *testing.T) {
	cases := []struct {
		name    string
		brk     func(f *ecFix)
		rule    string
		notRule string // a rule name that must not be in stderr ("" for none)
	}{
		{"B3: a flag shape in a bundle", func(f *ecFix) {
			p := f.path("evidence/seat-a/" + ecCID + "/" + ecTmpl)
			b, err := os.ReadFile(p)
			if err != nil {
				f.t.Fatal(err)
			}
			if err := os.WriteFile(p, append(b, "FALCO{leak}\n"...), 0o644); err != nil {
				f.t.Fatal(err)
			}
		}, "B3:", ""},
		{"B1: a seat has no bundle", func(f *ecFix) {
			if err := os.RemoveAll(f.path("evidence/seat-c")); err != nil {
				f.t.Fatal(err)
			}
		}, "B1:", ""},
		// V90: the run id of the render record that is not the table's is B11 (amendment 13),
		// not T3 (the form of a table, which the scoreboard's start-up applies too).
		{"B11: the render record is of another run", func(f *ecFix) {
			f.put("render-record.tsv", ecRecord("fedcba9876543210fedcba9876543210", ecScope()))
		}, "B11:", "T3:"},
		// V98: the scope digest of the render record that is not the check's scope is B12, before
		// the table is read (so not B11, and not a rule of the table).
		{"B12: the render record is of another scope", func(f *ecFix) {
			f.put("render-record.tsv", ecRecord(ecRunID, edition.ScopeDigest([]string{ecCID})))
		}, "B12:", "B11:"},
		{"E2: decoys below K", func(f *ecFix) {
			f.put("edition-root/"+ecCID+"/edition.yaml", strings.ReplaceAll(ecSpec(), "decoys: 9", "decoys: 3"))
		}, "E2:", ""},
		// V90: the set of the challenge directories of --edition-root is E2, both ways.
		{"E2: an extra challenge directory in the edition root", func(f *ecFix) {
			f.put("edition-root/02-other/edition.yaml", "x\n")
		}, "E2:", ""},
		{"E2: no directory for the challenge in the edition root", func(f *ecFix) {
			if err := os.RemoveAll(f.path("edition-root/" + ecCID)); err != nil {
				f.t.Fatal(err)
			}
		}, "E2:", ""},
		// V90: a failure of the lexer of the marks in the event template is E3. It is in a file of
		// its own: the fixture's template file holds the blocks (B17), and a block of a file the lexer
		// refuses is E2's to name too.
		{"E3: a mark outside the grammar in the template", func(f *ecFix) {
			f.put("edition-root/"+ecCID+"/template/broken.txt", "broken {{ctf: mark\n")
		}, "E3:", "E2:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newEcFix(t)
			c.brk(f)
			code, stdout, stderr := runEd(append([]string{"check"}, f.args()...)...)
			if code != exitRefused || stdout != "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 1 and no stdout", code, stdout, stderr)
			}
			if !strings.Contains(stderr, c.rule) {
				t.Errorf("stderr = %q; want the rule %s named", stderr, c.rule)
			}
			if c.notRule != "" && strings.Contains(stderr, c.notRule) {
				t.Errorf("stderr = %q; the rule %s must not be named", stderr, c.notRule)
			}
			f.noValue(c.name, stderr)
			if f.digestsOutExists() {
				t.Error("a digests file was written for a refused event")
			}
		})
	}
}

// The form of an input file that is wrong is exit 2 (D20: "the form of a file"), not a rule's
// refusal: a render record that is not a record, a template directory with a link in it.
func TestEditionCheck_ABadFormOfAnInputFileIsExit2(t *testing.T) {
	cases := []struct {
		name string
		brk  func(f *ecFix)
	}{
		{"a render record that is not a record", func(f *ecFix) { f.put("render-record.tsv", "not a render record\n") }},
		{"a render record with a run id of all zeros", func(f *ecFix) {
			f.put("render-record.tsv", ecRecord(edition.PracticeRunID, ecScope()))
		}},
		// V98: a record of the first form, and a v2 record with no scope line, are exit 2 (not B12).
		{"a render record of the first form (v1)", func(f *ecFix) {
			f.put("render-record.tsv", "# falco-ctf render-record v1\nrun-id\t"+ecRunID+"\nkey-fingerprint\t"+strings.Repeat("ab", 32)+"\n")
		}},
		{"a v2 render record with no scope line", func(f *ecFix) {
			f.put("render-record.tsv", strings.TrimSuffix(ecRecord(ecRunID, ecScope()), "scope\t"+ecScope()+"\n"))
		}},
		{"a link in the template directory", func(f *ecFix) {
			dir := f.path("edition-root/" + ecCID + "/template")
			if err := os.Symlink(filepath.Join(dir, ecTmpl), filepath.Join(dir, "link.txt")); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"a seats file with a repeated seat", func(f *ecFix) { f.put("seats.txt", "# falco-ctf seats v1\nseat-a\nseat-a\n") }},
		// V90: an entry of --edition-root named like a challenge id that is a file or a link is
		// exit 2, not E2 (D20 as amendment 13 revised it).
		{"a file named like a challenge id in the edition root", func(f *ecFix) { f.put("edition-root/02-other", "x\n") }},
		{"the challenge's entry of the edition root is a link to its directory", func(f *ecFix) {
			if err := os.Rename(f.path("edition-root/"+ecCID), f.path("real-edition")); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink(f.path("real-edition"), f.path("edition-root/"+ecCID)); err != nil {
				f.t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newEcFix(t)
			c.brk(f)
			code, stdout, stderr := runEd(append([]string{"check"}, f.args()...)...)
			if code != exitUsage || stdout != "" || stderr == "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 and a message", code, stdout, stderr)
			}
			f.noValue(c.name, stderr)
			if f.digestsOutExists() {
				t.Error("a digests file was written")
			}
		})
	}
}

// B10: a previous digests file that has a pair this render does not have (here: a file of
// another event, with no pair in common) is exit 1 and names B10, the seat and the challenge.
func TestEditionCheck_APreviousFileOfAnotherEventIsExit1(t *testing.T) {
	f := newEcFix(t)
	f.put("previous.tsv", "# falco-ctf evidence-digests v1 run=fedcba9876543210fedcba9876543210\nother-seat\t"+ecCID+"\t"+strings.Repeat("1", 64)+"\n")
	args := append(without(f.args(), "--no-previous"), "--previous-digests", f.path("previous.tsv"))
	code, stdout, stderr := runEd(append([]string{"check"}, args...)...)
	if code != exitRefused || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 1 and no stdout", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "B10: ") || !strings.Contains(stderr, "seat=other-seat") || !strings.Contains(stderr, "cid="+ecCID) {
		t.Errorf("stderr = %q; want B10 naming the seat and the challenge", stderr)
	}
	if !strings.Contains(stderr, "B4 overlap (outputs)") {
		t.Errorf("stderr = %q; want B4's numbers with a B10 refusal too", stderr)
	}
	f.noValue("B10", stderr)
	if f.digestsOutExists() {
		t.Error("a digests file was written for a refused event")
	}
}

// V79: B4's numbers are printed when B4 itself refuses.
func TestEditionCheck_TheOverlapIsPrintedWhenB4Refuses(t *testing.T) {
	f := newEcFix(t)
	f.put("challenges/"+ecCID+"/edition/template/a.txt", ecTemplate())
	code, stdout, stderr := runEd(append([]string{"check"}, f.args()...)...)
	if code != exitRefused || stdout != "" || !strings.Contains(stderr, "B4:") {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 1 and B4", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "B4 overlap (templates): rate=1.000 event="+ecCID+" practice="+ecCID) {
		t.Errorf("stderr = %q; want the template overlap line with the ids of the pair", stderr)
	}
	f.noValue("B4", stderr)
}

// V79: 21 or more violations print the first 20 and the count of the rest. 25 files with a
// name outside the grammar are 25 B2 violations: the library lists 20 and says 5 more.
func TestEditionCheck_MoreThanTwentyViolationsAreCounted(t *testing.T) {
	f := newEcFix(t)
	for i := 0; i < 25; i++ {
		f.put(fmt.Sprintf("evidence/seat-a/%s/BAD%02d.TXT", ecCID, i), "x\n")
	}
	code, stdout, stderr := runEd(append([]string{"check"}, f.args()...)...)
	if code != exitRefused || stdout != "" {
		t.Fatalf("exit %d, stdout %q; want exit 1", code, stdout)
	}
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	b2 := 0
	for _, ln := range lines {
		if strings.HasPrefix(ln, "B2: ") {
			b2++
		}
	}
	if b2 != maxListedViolations || lines[len(lines)-1] != "5 further violations are not listed" {
		t.Errorf("%d B2 lines and the last line %q; want %d and the count 5 (stderr %q)", b2, lines[len(lines)-1], maxListedViolations, stderr)
	}
}

// The printing on its own: the first 20 leaves, the notes of bounded lists added to the count,
// a wrap of a join flattened, and any other error one entry.
func TestPrintRefusal(t *testing.T) {
	leaf := func(i int) error { return fmt.Errorf("leaf %02d", i) }
	var many []error
	for i := 0; i < 30; i++ {
		many = append(many, leaf(i))
	}
	many = append(many, &edition.MoreViolations{N: 4})
	var out bytes.Buffer
	printRefusal(&out, fmt.Errorf("edition: answers table: %w", errors.Join(many...)))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != maxListedViolations+1 || lines[0] != "leaf 00" || lines[maxListedViolations-1] != "leaf 19" || lines[maxListedViolations] != "14 further violations are not listed" {
		t.Errorf("printed %q; want leaves 00 to 19 and 14 further (10 leaves and the note's 4)", out.String())
	}
	// an *InputError whose cause is a Join is printed as itself (its message), alone and inside a
	// plain wrap (the case in which the flattening used to drop it and print the cause only); a
	// *Violation inside a plain wrap is printed with its rule's name
	cause := errors.Join(leaf(1), leaf(2))
	for name, err := range map[string]error{
		"alone":         &edition.InputError{Msg: "the previous digests file", Err: cause},
		"inside a wrap": fmt.Errorf("wrapped: %w", &edition.InputError{Msg: "the previous digests file", Err: cause}),
	} {
		out.Reset()
		printRefusal(&out, err)
		if got := out.String(); !strings.HasPrefix(got, "the previous digests file: ") || strings.Count(got, "leaf") != 2 {
			t.Errorf("an input error with a join as its cause, %s, printed %q; want its message", name, got)
		}
	}
	out.Reset()
	printRefusal(&out, fmt.Errorf("wrapped: %w", errors.Join(&edition.Violation{Rule: "B7", Msg: "a rule"}, leaf(3))))
	if got := out.String(); got != "B7: a rule\nleaf 03\n" {
		t.Errorf("a violation inside a wrapped join printed %q; want its rule and the other leaf", got)
	}
	out.Reset()
	printRefusal(&out, errors.Join(leaf(1), leaf(2)))
	if got := out.String(); got != "leaf 01\nleaf 02\n" {
		t.Errorf("two leaves printed %q", got)
	}
	out.Reset()
	printRefusal(&out, &edition.InputError{Msg: "the seats file cannot be read", Err: errors.New("open x: no such file or directory")})
	if got := out.String(); got != "the seats file cannot be read: open x: no such file or directory\n" {
		t.Errorf("an input error printed %q", got)
	}
}

// V92 (ADR-0056 D20, amendment 13 as revised): the exit code of each kind of error the library
// gives, and of their mixes. A rule's refusal is 1 only when every leaf is one; an error of no
// kind (the stub errors.New) is 2, never taken for a rule's refusal; a failure of the output's
// environment after every check is 3; a mix of kinds is 2.
func TestEditionExitCode(t *testing.T) {
	v := &edition.Violation{Rule: "B7", Msg: "a rule"}
	in := &edition.InputError{Msg: "an input"}
	out := &edition.OutputError{Err: errors.New("no space left on the device")}
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"no error", nil, exitAccepted},
		{"a violation", v, exitRefused},
		{"a join of violations and the count of the rest", errors.Join(v, &edition.Violation{Rule: "B8", Msg: "another"}, &edition.MoreViolations{N: 3}), exitRefused},
		{"a wrapped join of violations", fmt.Errorf("edition: answers table: %w", errors.Join(v, v)), exitRefused},
		{"a join of joins of violations", errors.Join(errors.Join(v), errors.Join(v, v)), exitRefused},
		{"an input error", in, exitUsage},
		{"an input error whose cause is a violation", &edition.InputError{Msg: "the previous digests file", Err: v}, exitUsage},
		{"an error of no kind (a stub)", errors.New("something no reader classified"), exitUsage},
		{"a wrapped error of no kind", fmt.Errorf("edition: practice answers of 01-demo: %w", errors.New("x")), exitUsage},
		{"a violation joined with an input error", errors.Join(v, in), exitUsage},
		{"a violation joined with an error of no kind", errors.Join(v, errors.New("x")), exitUsage},
		{"an output error", out, exitWriteFailed},
		{"a wrapped output error", fmt.Errorf("w: %w", out), exitWriteFailed},
		{"an output error joined with an input error (an existing output and a name left)", errors.Join(in, out), exitUsage},
		{"an output error joined with a violation", errors.Join(v, out), exitUsage},
	}
	for _, c := range cases {
		if got := editionExitCode(c.err); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

// The command's report of a refusal: the leaves, the temporary names an *edition.OutputError
// lists as left (V92: exit 3 with the name on stderr; the library gives the name cut short and
// quoted), and the code. The cases of the library that make the names (the seam writeFault of
// internal/edition: a write that fails and a cleanup that fails, a link that succeeds and a
// cleanup that fails) are atomicwrite_internal_test.go's: this package cannot reach the seam, so
// the command's part is held here with the errors the library gives.
func TestFinishRefusal_PrintsTheNamesLeftAndGivesTheCode(t *testing.T) {
	const name = `".digests.tsv.tmp-0123456789abcdef"`
	var b bytes.Buffer
	code := finishRefusal(&b, &edition.OutputError{Err: errors.New("no space left on the device"), Left: []string{name}})
	if code != exitWriteFailed || !strings.Contains(b.String(), "no space left on the device") || !strings.Contains(b.String(), "left beside the output (remove it): "+name+"\n") {
		t.Errorf("exit %d, printed %q; want exit 3, the cause and the name left", code, b.String())
	}
	b.Reset()
	joined := errors.Join(&edition.InputError{Msg: "the output", Err: edition.ErrOutputExists}, &edition.OutputError{Err: errors.New("x"), Left: []string{name}})
	if code := finishRefusal(&b, joined); code != exitUsage || !strings.Contains(b.String(), "the output: ") || !strings.Contains(b.String(), name) {
		t.Errorf("an existing output and a name left: exit %d, printed %q; want exit 2 and the name", code, b.String())
	}
	b.Reset()
	if code := finishRefusal(&b, &edition.Violation{Rule: "B7", Msg: "a rule"}); code != exitRefused || b.String() != "B7: a rule\n" {
		t.Errorf("a violation: exit %d, printed %q", code, b.String())
	}
}

// After the commit point a name left is a warning: one line per name, and nothing else.
func TestPrintLeftWarning(t *testing.T) {
	var b bytes.Buffer
	printLeftWarning(&b, "edition check", nil)
	if b.Len() != 0 {
		t.Errorf("no name printed %q", b.String())
	}
	printLeftWarning(&b, "edition check", []string{`"a"`, `"b"`})
	want := "edition check: the output is in place; a temporary name beside it could not be removed (remove it): \"a\"\n" +
		"edition check: the output is in place; a temporary name beside it could not be removed (remove it): \"b\"\n"
	if b.String() != want {
		t.Errorf("printed %q, want %q", b.String(), want)
	}
}
