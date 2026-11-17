package main

// ADR-0056 D20, D19 A4e-3a: `scoreboard edition render` (the event's) as a command (V80, V92):
// the arguments, the exit codes, what is printed, that a refusal writes nothing at --out, and the
// round trip: what the render writes is what `edition check` accepts. The render is the
// command's own (edition.RenderEvent): nothing here calls the renderer. The tree is
// internal/edition/editiontest's; every value is a placeholder with no meaning.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

// erFix is one event laid out for `edition render`.
type erFix struct {
	t    *testing.T
	tree *editiontest.Tree
}

func newErFix(t *testing.T) *erFix {
	t.Helper()
	f := &erFix{t: t, tree: editiontest.NewTree(t)}
	f.tree.PlaceInputs(editiontest.Inputs{Golden: ecGolden, Spec: ecSpec(), Template: ecTemplate(), Seats: editiontest.Seats()})
	f.tree.PlaceKey(editiontest.KeyRel, editiontest.KeyText(), 0o600)
	return f
}

// args are the arguments of a good first render (--no-previous) to out.
func (f *erFix) args(out string) []string {
	p := f.tree.RenderPaths()
	return []string{
		"--challenges", p.Challenges,
		"--scenario", p.Scenario,
		"--flags-file", p.Flags,
		"--edition-root", p.EditionRoot,
		"--seats", p.Seats,
		"--no-previous",
		"--key-file", p.Key,
		"--out", out,
	}
}

// out is the --out of a good render.
func (f *erFix) out() string { return f.tree.RenderPaths().Out }

// checkArgs are the arguments of `edition check` of the render at out with the seats file
// seats (the first check, the digests to digestsOut).
func (f *erFix) checkArgs(out, seats, digestsOut string) []string {
	p := f.tree.Paths()
	return []string{
		"--challenges", p.Challenges,
		"--scenario", p.Scenario,
		"--flags-file", p.Flags,
		"--answers", filepath.Join(out, edition.EventAnswersFileName),
		"--render-record", filepath.Join(out, edition.EventRenderRecordFileName),
		"--evidence-root", filepath.Join(out, edition.EventEvidenceDirName),
		"--seats", seats,
		"--edition-root", p.EditionRoot,
		"--no-previous",
		"--corpus", p.Corpus,
		"--digests-out", digestsOut,
	}
}

// noSecret fails if a text holds the key (as its hex) or a value of the answers table at out.
func (f *erFix) noSecret(what, out string, texts ...string) {
	f.t.Helper()
	secrets := []string{strings.TrimSuffix(editiontest.KeyText(), "\n")}
	if data, err := os.ReadFile(filepath.Join(out, edition.EventAnswersFileName)); err == nil {
		for _, ln := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")[1:] {
			if cols := strings.Split(ln, "\t"); len(cols) == 4 {
				secrets = append(secrets, cols[3])
			}
		}
	}
	for _, text := range texts {
		for _, s := range secrets {
			if strings.Contains(text, s) {
				f.t.Errorf("%s: the output holds a secret of the render (%q)", what, s)
			}
		}
	}
}

// nothingAt fails unless out does not exist and the fixture's output directory holds nothing.
func (f *erFix) nothingAt(what, out string) {
	f.t.Helper()
	if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
		f.t.Errorf("%s: --out is there (%v)", what, err)
	}
	if names := dirNamesOf(f.t, f.tree.Path(editiontest.OutRel)); len(names) != 0 {
		f.t.Errorf("%s: the output directory holds %v, want nothing", what, names)
	}
}

// renderOK is the one line of a render of the fixture (a human's line, not a contract: D20).
var renderOK = regexp.MustCompile(`^ok run=([0-9a-f]{32}) seats=3 challenges=1 key-fingerprint=([0-9a-f]{64})\n$`)

// V80: the round trip. The render exits 0 with its one line and writes no digests file; `edition
// check` of its output exits 0 and writes the digests; a second render with a seat added and the
// first seat list as --previous-seats keeps the bundles of the earlier seats byte for byte, and
// `edition check` of it with the first digests as --previous-digests (B10) exits 0.
func TestEditionRender_TheRoundTripThroughEditionCheck(t *testing.T) {
	f := newErFix(t)
	out := f.out()
	code, stdout, stderr := runEd(append([]string{"render"}, f.args(out)...)...)
	m := renderOK.FindStringSubmatch(stdout)
	if code != exitAccepted || m == nil {
		t.Fatalf("render: exit %d, stdout %q, stderr %q; want exit 0 and the one line", code, stdout, stderr)
	}
	record := f.tree.Read(editiontest.RenderOutRel + "/" + edition.EventRenderRecordFileName)
	if !strings.Contains(record, "run-id\t"+m[1]+"\n") || !strings.Contains(record, "key-fingerprint\t"+m[2]+"\n") {
		t.Errorf("the line says run %s and fingerprint %s; the render record is %q", m[1], m[2], record)
	}
	f.noSecret("render", out, stdout, stderr)
	if names := dirNamesOf(t, out); !slices.Equal(names, []string{edition.EventAnswersFileName, edition.EventEvidenceDirName, edition.EventRenderRecordFileName}) {
		t.Errorf("--out holds %v; want the answers table, the evidence and the render record, and no digests file", names)
	}

	digests := f.tree.Path(editiontest.DigestsRel)
	code, stdout, stderr = runEd(append([]string{"check"}, f.checkArgs(out, f.tree.Path(editiontest.SeatsRel), digests)...)...)
	if code != exitAccepted || stdout != "ok run="+m[1]+" seats=3 challenges=1\n" {
		t.Fatalf("check of the render: exit %d, stdout %q, stderr %q; want exit 0 and the render's run id", code, stdout, stderr)
	}
	if _, err := os.Stat(digests); err != nil {
		t.Fatalf("the digests file of the check: %v", err)
	}

	// the second render: a seat more, the first list as the previous one
	f.tree.Put(editiontest.PreviousSeatsRel, f.tree.Read(editiontest.SeatsRel))
	f.tree.Put("seats-more.txt", editiontest.SeatsText(append(editiontest.Seats(), "seat-d")))
	out2 := f.tree.Path(editiontest.OutRel + "/second")
	args := without(without(f.args(out2), "--no-previous"), "--seats")
	args = append(args, "--seats", f.tree.Path("seats-more.txt"), "--previous-seats", f.tree.Path(editiontest.PreviousSeatsRel))
	code, stdout, stderr = runEd(append([]string{"render"}, args...)...)
	if code != exitAccepted || !strings.Contains(stdout, " seats=4 ") {
		t.Fatalf("the second render: exit %d, stdout %q, stderr %q; want exit 0 and 4 seats", code, stdout, stderr)
	}
	for _, seat := range editiontest.Seats() {
		rel := edition.EventEvidenceDirName + "/" + seat + "/" + ecCID + "/" + ecTmpl
		a, errA := os.ReadFile(filepath.Join(out, rel))
		b, errB := os.ReadFile(filepath.Join(out2, rel))
		if errA != nil || errB != nil || string(a) != string(b) {
			t.Errorf("the bundle of %s differs between the two renders (%v, %v)", seat, errA, errB)
		}
	}
	check2 := without(f.checkArgs(out2, f.tree.Path("seats-more.txt"), f.tree.Path(editiontest.OutRel+"/digests-2.tsv")), "--no-previous")
	check2 = append(check2, "--previous-digests", digests)
	if code, stdout, stderr := runEd(append([]string{"check"}, check2...)...); code != exitAccepted {
		t.Errorf("check of the second render with the first digests: exit %d, stdout %q, stderr %q; want exit 0", code, stdout, stderr)
	}
}

// V80: every usage error is exit 2, prints nothing on stdout and writes nothing: each argument
// missing, the two previous arguments both or neither, an unknown or repeated one, --practice
// (the next stage, A4e-3b).
func TestEditionRender_UsageErrorsAreExit2(t *testing.T) {
	f := newErFix(t)
	good := f.args(f.out())
	type tc struct {
		name, want string
		args       []string
	}
	var cases []tc
	for _, name := range []string{"--challenges", "--scenario", "--flags-file", "--edition-root", "--seats", "--key-file", "--out"} {
		cases = append(cases, tc{"without " + name, name, without(good, name)})
	}
	cases = append(cases,
		tc{"neither --previous-seats nor --no-previous", "exactly one", without(good, "--no-previous")},
		tc{"both --previous-seats and --no-previous", "exactly one", append(slices.Clone(good), "--previous-seats", f.tree.Path(editiontest.SeatsRel))},
		tc{"an unknown argument", "unknown", append(slices.Clone(good), "--key", "x")},
		tc{"a repeated argument", "twice", append(slices.Clone(good), "--seats", f.tree.Path(editiontest.SeatsRel))},
		tc{"--practice (the next stage)", "next stage", append(slices.Clone(good), "--practice")},
		tc{"--practice with a value", "next stage", []string{"--practice=yes"}},
		tc{"no argument", "required", nil},
	)
	for _, c := range cases {
		code, stdout, stderr := runEd(append([]string{"render"}, c.args...)...)
		if code != exitUsage || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 2, no stdout and %q", c.name, code, stdout, stderr, c.want)
		}
		f.nothingAt(c.name, f.out())
	}
}

// V80: an input that cannot be read or is not in its form, and the guard of --out, are exit 2
// and write nothing; a rule's refusal (E2, E3, the self check's B8 (b)) is exit 1, names the rule
// and writes nothing. No secret is printed.
func TestEditionRender_RefusalsWriteNothing(t *testing.T) {
	hexKey := strings.TrimSuffix(editiontest.KeyText(), "\n")
	tmplRel := editiontest.EditionRootRel + "/" + ecCID + "/" + edition.TemplateDirName + "/" + ecTmpl
	cases := []struct {
		name string
		brk  func(f *erFix) (out string)
		code int
		rule string
	}{
		{"a key of 63 hex digits", func(f *erFix) string {
			f.tree.PlaceKey(editiontest.KeyRel, hexKey[:63]+"\n", 0o600)
			return f.out()
		}, exitUsage, ""},
		{"a key that is not hex", func(f *erFix) string {
			f.tree.PlaceKey(editiontest.KeyRel, strings.Repeat("xy", 40)+"\n", 0o600)
			return f.out()
		}, exitUsage, ""},
		{"a key of mode 0644", func(f *erFix) string {
			f.tree.PlaceKey(editiontest.KeyRel, hexKey+"\n", 0o644)
			return f.out()
		}, exitUsage, ""},
		{"a key that is a link", func(f *erFix) string {
			if err := os.Rename(f.tree.Path(editiontest.KeyRel), f.tree.Path("real.key")); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink(f.tree.Path("real.key"), f.tree.Path(editiontest.KeyRel)); err != nil {
				f.t.Fatal(err)
			}
			return f.out()
		}, exitUsage, ""},
		{"an --out in a git worktree", func(f *erFix) string {
			f.tree.Put(".git", "gitdir: elsewhere\n")
			return f.out()
		}, exitUsage, ""},
		{"an --out inside the challenges tree", func(f *erFix) string {
			return f.tree.Path(editiontest.ChallengesRel + "/render")
		}, exitUsage, ""},
		{"a file named like a challenge id in the edition root", func(f *erFix) string {
			f.tree.Put(editiontest.EditionRootRel+"/02-other", "x\n")
			return f.out()
		}, exitUsage, ""},
		{"E2: an extra challenge directory in the edition root", func(f *erFix) string {
			f.tree.Put(editiontest.EditionRootRel+"/02-other/edition.yaml", "x\n")
			return f.out()
		}, exitRefused, "E2:"},
		{"E3: a mark of a slot that edition.yaml does not declare", func(f *erFix) string {
			f.tree.Put(tmplRel, ecTemplate()+"extra = {{ctf:undeclared}}\n")
			return f.out()
		}, exitRefused, "E3:"},
		{"the self check, B8 (b): 4 decoys give 5 candidates", func(f *erFix) string {
			f.tree.Put(editiontest.EditionRootRel+"/"+ecCID+"/"+edition.SpecFileName, editiontest.SpecText(editiontest.GoodNameWords, 4))
			f.tree.Put(tmplRel, editiontest.TemplateText(4))
			return f.out()
		}, exitRefused, "B8:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newErFix(t)
			out := c.brk(f)
			code, stdout, stderr := runEd(append([]string{"render"}, f.args(out)...)...)
			if code != c.code || stdout != "" || stderr == "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit %d, no stdout and a message", code, stdout, stderr, c.code)
			}
			if c.rule != "" && !strings.Contains(stderr, c.rule) {
				t.Errorf("stderr = %q; want the rule %s named", stderr, c.rule)
			}
			f.noSecret(c.name, out, stdout, stderr)
			f.nothingAt(c.name, out)
		})
	}
}

// V80 and V92: an --out that is there is exit 2 and is left as it was.
func TestEditionRender_AnExistingOutIsExit2(t *testing.T) {
	f := newErFix(t)
	f.tree.Put(editiontest.RenderOutRel+"/earlier.txt", "an earlier output\n")
	code, stdout, stderr := runEd(append([]string{"render"}, f.args(f.out())...)...)
	if code != exitUsage || stdout != "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit 2", code, stdout, stderr)
	}
	if names := dirNamesOf(t, f.out()); !slices.Equal(names, []string{"earlier.txt"}) {
		t.Errorf("the existing --out holds %v; want it as it was", names)
	}
	if names := dirNamesOf(t, f.tree.Path(editiontest.OutRel)); !slices.Equal(names, []string{filepath.Base(f.out())}) {
		t.Errorf("the output directory holds %v; want the existing --out only", names)
	}
}

// V92: every check passed and the output cannot be put in place: exit 3, no `ok` line, nothing
// at --out and nothing beside it. As for `edition check`, the failure does not depend on a
// permission: the name of --out is 250 bytes, which can be named, but the temporary tree beside
// it (a dot, the name, `.tmp-` and 16 hex digits) is over the 255 bytes of a file name, so the
// write fails when the temporary is made, after the render and its self check. (The cases of
// the seam of internal/edition, a write, a rename and a cleanup that fail, are
// internal/edition's eventrender_test.go: this package cannot reach the seam.)
func TestEditionRender_AnOutputThatCannotBePutInPlaceIsExit3(t *testing.T) {
	f := newErFix(t)
	out := f.tree.Path(editiontest.OutRel + "/" + strings.Repeat("r", 250))
	code, stdout, stderr := runEd(append([]string{"render"}, f.args(out)...)...)
	if code != exitWriteFailed || stdout != "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit 3 and no stdout", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "nothing was put at --out") {
		t.Errorf("stderr = %q; want it to say that nothing is at --out", stderr)
	}
	f.nothingAt("a temporary that cannot be made", out)
	f.noSecret("exit 3", out, stdout, stderr)
}
