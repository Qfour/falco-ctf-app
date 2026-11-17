package main

// ADR-0056 D20, D19 A4e-3b: `scoreboard edition render --practice` as a command (V81, V92): the
// arguments, the exit codes, what is printed, and that practice/ is the golden after it and as it
// was after a refusal. The render is the command's own (edition.RenderPracticeEdition): nothing
// here calls the renderer. The tree is internal/edition/editiontest's, with the practice edition
// of internal/edition/testdata/render-golden (its committed practice/ is the golden, V67). The
// failures of the output's environment (exit 3) are caused through internal/edition's seam, which
// this package cannot reach: they are internal/edition's practiceedition_test.go, and the wiring of
// the error to the exit code is editioncmd_source_test.go's.

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

// epFix is the image's tree of the fixture, with the committed practice/ of the golden.
type epFix struct {
	t    *testing.T
	tree *editiontest.Tree
}

func newEpFix(t *testing.T) *epFix {
	t.Helper()
	f := &epFix{t: t, tree: editiontest.NewTree(t)}
	f.tree.PlaceInputs(editiontest.Inputs{Golden: ecGolden, Spec: ecSpec(), Template: ecTemplate(), Seats: editiontest.Seats()})
	return f
}

// args are the arguments of a good `edition render --practice` of the fixture's challenge.
func (f *epFix) args() []string {
	return []string{"render", "--practice", "--challenges", f.tree.Path(editiontest.ChallengesRel), "--cid", ecCID}
}

// rel is the slash path of the challenge's edition/ in the tree, and of what is under it.
func (f *epFix) rel(parts ...string) string {
	return strings.Join(append([]string{editiontest.ChallengesRel, ecCID, edition.EditionDirName}, parts...), "/")
}

// editionFiles is every file under the challenge's edition/ (slash-relative) with its bytes.
func (f *epFix) editionFiles() map[string]string { return epTree(f.t, f.tree.Path(f.rel())) }

// golden is the committed practice/ of the fixture.
func (f *epFix) golden() map[string]string {
	return epTree(f.t, filepath.Join(ecGolden, edition.EditionDirName, edition.PracticeDirName))
}

// practice is the practice/ of the fixture's challenge.
func (f *epFix) practice() map[string]string {
	return epTree(f.t, f.tree.Path(f.rel(edition.PracticeDirName)))
}

// epTree is every regular file under root (slash-relative) with its bytes.
func epTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// V81 / V67: the command's practice/ is the golden, byte for byte, it replaces a practice/ that
// is not (a hand-edited file, a file the render does not make), and a second run gives the same
// bytes. The one line of success is printed, nothing is left beside practice/, and nothing is
// printed on stderr.
func TestEditionRenderPractice_IsTheGoldenAndReplacesWhatIsThere(t *testing.T) {
	f := newEpFix(t)
	f.tree.Put(f.rel(edition.PracticeDirName, edition.PracticeAnswersFileName), "not a table\n")
	f.tree.Put(f.rel(edition.PracticeDirName, edition.PracticeEvidenceDirName, "stale.txt"), "stale\n")
	want := f.golden()
	if len(want) < 3 {
		t.Fatalf("the golden practice/ has %d files, want answers.tsv, digests.tsv and the evidence", len(want))
	}
	for run := 1; run <= 2; run++ {
		code, stdout, stderr := runEd(f.args()...)
		if code != exitAccepted || stdout != "ok practice cid="+ecCID+"\n" || stderr != "" {
			t.Fatalf("run %d: exit %d, stdout %q, stderr %q; want exit 0, the one line and no stderr", run, code, stdout, stderr)
		}
		if got := f.practice(); !maps.Equal(got, want) {
			t.Errorf("run %d: practice/ is not the golden (%d files, want %d)", run, len(got), len(want))
		}
		if names := dirNamesOf(t, f.tree.Path(f.rel())); !slices.Equal(names, []string{edition.SpecFileName, edition.PracticeDirName, edition.TemplateDirName}) {
			t.Errorf("run %d: edition/ holds %v; want edition.yaml, practice and template only", run, names)
		}
	}
}

// V81: the practice edition takes --challenges and --cid only. Each argument of the event's
// render beside --practice (a key, the seats, the previous seats or --no-previous, --out, the
// event edition, the scenario, the flags), a missing or repeated argument, an unknown one and
// --practice with a value are exit 2, print nothing on stdout and leave edition/ as it was.
func TestEditionRenderPractice_UsageErrorsAreExit2(t *testing.T) {
	f := newEpFix(t)
	good := f.args()
	type tc struct {
		name, want string
		args       []string
	}
	var cases []tc
	for _, a := range [][]string{
		{"--key-file", f.tree.Path("key.hex")},
		{"--seats", f.tree.Path(editiontest.SeatsRel)},
		{"--previous-seats", f.tree.Path(editiontest.SeatsRel)},
		{"--no-previous"},
		{"--out", f.tree.Path(editiontest.RenderOutRel)},
		{"--edition-root", f.tree.Path(editiontest.EditionRootRel)},
		{"--scenario", f.tree.Path(editiontest.ScenarioRel)},
		{"--flags-file", f.tree.Path(editiontest.FlagsRel)},
	} {
		cases = append(cases, tc{"with " + a[0], "an argument of the event's render", append(slices.Clone(good), a...)})
	}
	cases = append(cases,
		tc{"with --out=<path>", "an argument of the event's render", append(slices.Clone(good), "--out="+f.tree.Path(editiontest.RenderOutRel))},
		tc{"without --cid", "--cid is required", without(good, "--cid")},
		tc{"without --challenges", "--challenges is required", without(good, "--challenges")},
		tc{"a repeated --cid", "twice", append(slices.Clone(good), "--cid", ecCID)},
		tc{"--practice twice", "twice", append(slices.Clone(good), "--practice")},
		tc{"--practice with a value", "takes no value", []string{"render", "--practice=yes", "--challenges", f.tree.Path(editiontest.ChallengesRel), "--cid", ecCID}},
		tc{"an unknown argument", "unknown", append(slices.Clone(good), "--seat", "x")},
		tc{"a positional word", "positional", append(slices.Clone(good), "extra")},
	)
	before := f.editionFiles()
	for _, c := range cases {
		code, stdout, stderr := runEd(c.args...)
		if code != exitUsage || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 2, no stdout and %q", c.name, code, stdout, stderr, c.want)
		}
		if got := f.editionFiles(); !maps.Equal(got, before) {
			t.Errorf("%s: edition/ changed", c.name)
		}
	}
}

// V81: a rule of the edition is exit 1 and names the rule (E1: an edition.yaml that does not
// parse); a challenge that is not there, not an investigate challenge or outside the grammar of
// an id, and an edition.yaml that is missing, are exit 2. Either way practice/ is byte for byte
// what it was and nothing is printed on stdout.
func TestEditionRenderPractice_RefusalsLeavePracticeAsItWas(t *testing.T) {
	cases := []struct {
		name string
		brk  func(f *epFix) []string
		code int
		rule string
	}{
		{"E1: an edition.yaml that does not parse", func(f *epFix) []string {
			f.tree.Put(f.rel(edition.SpecFileName), "version: [\n")
			return f.args()
		}, exitRefused, "E1:"},
		{"no edition.yaml", func(f *epFix) []string {
			if err := os.Remove(f.tree.Path(f.rel(edition.SpecFileName))); err != nil {
				f.t.Fatal(err)
			}
			return f.args()
		}, exitUsage, ""},
		{"a challenge that is not in the tree", func(f *epFix) []string {
			return append(without(f.args(), "--cid"), "--cid", "02-missing")
		}, exitUsage, ""},
		{"a challenge that is not of type investigate", func(f *epFix) []string {
			return append(without(f.args(), "--cid"), "--cid", ecEvade)
		}, exitUsage, ""},
		{"a challenge id outside the grammar", func(f *epFix) []string {
			return append(without(f.args(), "--cid"), "--cid", "demo")
		}, exitUsage, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newEpFix(t)
			args := c.brk(f)
			before := f.practice()
			code, stdout, stderr := runEd(args...)
			if code != c.code || stdout != "" || stderr == "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit %d, no stdout and a message", code, stdout, stderr, c.code)
			}
			if c.rule != "" && !strings.Contains(stderr, c.rule) {
				t.Errorf("stderr = %q; want the rule %s named", stderr, c.rule)
			}
			if got := f.practice(); !maps.Equal(got, before) {
				t.Error("practice/ changed after a refusal")
			}
			if names := dirNamesOf(t, f.tree.Path(f.rel())); !slices.Equal(names, []string{edition.SpecFileName, edition.PracticeDirName, edition.TemplateDirName}) && c.name != "no edition.yaml" {
				t.Errorf("edition/ holds %v; want nothing left beside practice/", names)
			}
		})
	}
}
