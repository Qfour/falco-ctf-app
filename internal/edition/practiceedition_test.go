package edition_test

// ADR-0056 D20, D19 A4e-3b: RenderPracticeEdition, the function of `edition render --practice`
// (V81, V92, V67). The image's tree of the fixture is internal/edition/editiontest's, with the
// practice edition of internal/edition/testdata/render-golden/01-demo: the committed practice/
// of that fixture is the golden (V67), so a render of its edition.yaml and template must give
// it back byte for byte. The failures of the replacement are caused through atomicwrite.go's
// seam (no permission: a test may run as root). Every value is a placeholder with no meaning.

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

// pfFix is the image's tree of the fixture, with its committed practice/.
type pfFix struct {
	t    *testing.T
	tree *editiontest.Tree
}

func newPfFix(t *testing.T) *pfFix {
	t.Helper()
	tree := editiontest.NewTree(t)
	tree.PlaceInputs(editiontest.Inputs{Golden: cevGold, Spec: editiontest.GoodSpec(), Template: editiontest.GoodTemplate(), Seats: editiontest.Seats()})
	return &pfFix{t: t, tree: tree}
}

// challenges is the image's tree (--challenges).
func (f *pfFix) challenges() string { return f.tree.Path(editiontest.ChallengesRel) }

// editionDir is the challenge's edition/ in the tree, practiceDir its practice/.
func (f *pfFix) editionDir() string {
	return f.tree.Path(editiontest.ChallengesRel + "/" + editiontest.CID + "/" + edition.EditionDirName)
}

func (f *pfFix) practiceDir() string { return filepath.Join(f.editionDir(), edition.PracticeDirName) }

// golden is the committed practice/ of the fixture.
func (f *pfFix) golden() map[string]string {
	f.t.Helper()
	return treeOf(f.t, filepath.Join(cevGold, edition.EditionDirName, edition.PracticeDirName))
}

// render runs RenderPracticeEdition on the fixture's challenge.
func (f *pfFix) render() ([]string, error) {
	return edition.RenderPracticeEdition(f.challenges(), editiontest.CID)
}

// editionNames is what the challenge's edition/ holds (no temporary and nothing moved aside is
// left when it is edition.yaml, practice and template).
func (f *pfFix) editionNames() []string { return listNames(f.t, f.editionDir()) }

var wantEditionNames = []string{edition.SpecFileName, edition.PracticeDirName, edition.TemplateDirName}

// V81 / V67: the render is the committed practice/, byte for byte; a second render gives the same
// bytes (no clock, no random draw); nothing is left beside practice/.
func TestRenderPracticeEdition_IsTheGoldenAndTheSameTwice(t *testing.T) {
	f := newPfFix(t)
	want := f.golden()
	if len(want) < 3 {
		t.Fatalf("the golden practice/ has %d files, want answers.tsv, digests.tsv and the evidence", len(want))
	}
	for run := 1; run <= 2; run++ {
		left, err := f.render()
		if err != nil || len(left) != 0 {
			t.Fatalf("render %d: (%v, %v); want no error and no name left", run, left, err)
		}
		if got := treeOf(t, f.practiceDir()); !maps.Equal(got, want) {
			t.Errorf("render %d: practice/ is not the golden (%d files, want %d)", run, len(got), len(want))
		}
		if names := f.editionNames(); !slices.Equal(names, wantEditionNames) {
			t.Errorf("render %d: edition/ holds %v, want %v (no temporary, nothing moved aside)", run, names, wantEditionNames)
		}
	}
}

// V81: the practice/ that is there is replaced as a whole: a changed file, a file the render
// does not make and a practice/ that is missing all give the golden.
func TestRenderPracticeEdition_ReplacesWhatIsThere(t *testing.T) {
	cases := map[string]func(f *pfFix){
		"a hand-edited answers table": func(f *pfFix) {
			f.tree.Put(editiontest.ChallengesRel+"/"+editiontest.CID+"/"+edition.EditionDirName+"/"+edition.PracticeDirName+"/"+edition.PracticeAnswersFileName, "not a table\n")
		},
		"an evidence file the render does not make": func(f *pfFix) {
			f.tree.Put(editiontest.ChallengesRel+"/"+editiontest.CID+"/"+edition.EditionDirName+"/"+edition.PracticeDirName+"/"+edition.PracticeEvidenceDirName+"/stale.txt", "stale\n")
		},
		"no practice/ at all": func(f *pfFix) {
			if err := os.RemoveAll(f.practiceDir()); err != nil {
				f.t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPfFix(t)
			change(f)
			if left, err := f.render(); err != nil || len(left) != 0 {
				t.Fatalf("(%v, %v); want no error and no name left", left, err)
			}
			if got := treeOf(t, f.practiceDir()); !maps.Equal(got, f.golden()) {
				t.Errorf("practice/ is not the golden: %d files", len(got))
			}
			if names := f.editionNames(); !slices.Equal(names, wantEditionNames) {
				t.Errorf("edition/ holds %v, want %v", names, wantEditionNames)
			}
		})
	}
}

// D20: practice/ is the public repository's: every directory 0755 and every file 0644, under the
// umask 022 and the umask 077 (the modes are set, not left to the umask).
func TestRenderPracticeEdition_TheModesArePublic(t *testing.T) {
	for _, mask := range []int{0o022, 0o077} {
		f := newPfFix(t)
		old := syscall.Umask(mask)
		_, err := f.render()
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("umask %#o: %v", mask, err)
		}
		n := 0
		err = filepath.WalkDir(f.practiceDir(), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := os.Lstat(p)
			if err != nil {
				return err
			}
			want := fs.FileMode(0o644)
			if info.IsDir() {
				want = 0o755
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				t.Errorf("umask %#o: %s is neither a directory nor a regular file", mask, p)
			}
			if info.Mode().Perm() != want {
				t.Errorf("umask %#o: %s has mode %#o, want %#o", mask, p, info.Mode().Perm(), want)
			}
			n++
			return nil
		})
		if err != nil || n < 5 {
			t.Errorf("umask %#o: walked %d entries (%v), want practice/, evidence/ and the files", mask, n, err)
		}
	}
}

// D20 (#643's LOW) and the start-up: the answers table of the render passes Parse, Check with
// the event mode off and MaxTableBytes, and the scoreboard's practice mode (Load with no
// ANSWERS_FILE and the event mode off) accepts the practice edition it wrote.
func TestRenderPracticeEdition_TheOutputIsWhatThePracticeModeLoads(t *testing.T) {
	f := newPfFix(t)
	// The earlier practice/ is changed first, so that what is loaded is the render's.
	f.tree.Put(editiontest.ChallengesRel+"/"+editiontest.CID+"/"+edition.EditionDirName+"/"+edition.PracticeDirName+"/"+edition.PracticeAnswersFileName, "not a table\n")
	if _, err := f.render(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(f.practiceDir(), edition.PracticeAnswersFileName))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > edition.MaxTableBytes {
		t.Errorf("the answers table is %d bytes, over MaxTableBytes", len(data))
	}
	table, err := edition.Parse(data)
	if err != nil {
		t.Fatalf("Parse of the answers table: %v", err)
	}
	cat, err := catalog.Load(f.challenges())
	if err != nil {
		t.Fatal(err)
	}
	scope := edition.Scope{editiontest.CID: cat[editiontest.CID].Investigate.Questions}
	if err := edition.Check(table, scope, edition.Options{}); err != nil {
		t.Errorf("Check (the event mode off) of the answers table: %v", err)
	}
	only := catalog.Catalog{editiontest.CID: cat[editiontest.CID]}
	j, runID, err := edition.Load(scoredOf(t, only, f.challenges()), "", false)
	if err != nil || j == nil || runID != edition.PracticeRunID {
		t.Errorf("the practice mode's Load = (%v, %q, %v); want a judge and the practice run id", j, runID, err)
	}
}

// V81 / V92: a failure after the earlier practice/ is moved aside and before the new one is put
// in its place (the rename, the commit point), and a failure of the move aside itself, are an
// *OutputError (exit 3), and practice/ is byte for byte what it was; nothing is left beside it.
// A write that fails before either is the same.
func TestRenderPracticeEdition_AFailureBeforeTheCommitPointLeavesPracticeAsItWas(t *testing.T) {
	for _, c := range []struct {
		step string
		err  error
	}{
		{edition.FaultRenameForTest, syscall.EXDEV},
		{edition.FaultBackupForTest, syscall.EIO},
		{edition.FaultWriteForTest, syscall.ENOSPC},
	} {
		t.Run(c.step, func(t *testing.T) {
			f := newPfFix(t)
			// An earlier practice/ that is not the render's, so that "as it was" is seen.
			f.tree.Put(editiontest.ChallengesRel+"/"+editiontest.CID+"/"+edition.EditionDirName+"/"+edition.PracticeDirName+"/"+edition.PracticeEvidenceDirName+"/stale.txt", "stale\n")
			before := treeOf(t, f.practiceDir())
			edition.SetWriteFaultForTest(t, map[string]error{c.step: c.err})
			left, err := f.render()
			var oe *edition.OutputError
			if len(left) != 0 || !errors.As(err, &oe) || isInputErr(err) || !errors.Is(err, c.err) || len(oe.Left) != 0 {
				t.Fatalf("(%v, %v); want an *OutputError of %v and no name left", left, err, c.err)
			}
			if got := treeOf(t, f.practiceDir()); !maps.Equal(got, before) {
				t.Error("practice/ changed after a failure before the commit point")
			}
			if names := f.editionNames(); !slices.Equal(names, wantEditionNames) {
				t.Errorf("edition/ holds %v, want %v (no temporary, nothing moved aside)", names, wantEditionNames)
			}
			edition.SetWriteFaultForTest(t, nil)
			if _, err := f.render(); err != nil {
				t.Fatalf("the same render again: %v", err)
			}
			if got := treeOf(t, f.practiceDir()); !maps.Equal(got, f.golden()) {
				t.Error("the render after the failure is not the golden")
			}
		})
	}
}

// The commit point fails and the earlier practice/ cannot be moved back either: still exit 3,
// and the name that holds the earlier practice/ is listed as the one to RESTORE (Restore), not as
// a temporary to remove (Left: the new tree, which was removed, leaves nothing there): practice/
// is not there, and that name holds its bytes. A write that fails with a cleanup that fails lists
// the temporary tree in Left, nothing in Restore, and practice/ is as it was.
func TestRenderPracticeEdition_TheNamesLeftBeforeTheCommitPointAreListed(t *testing.T) {
	f := newPfFix(t)
	before := treeOf(t, f.practiceDir())
	edition.SetWriteFaultForTest(t, map[string]error{edition.FaultRenameForTest: syscall.EXDEV, edition.FaultRestoreForTest: syscall.EIO})
	_, err := f.render()
	var oe *edition.OutputError
	if !errors.As(err, &oe) || isInputErr(err) || len(oe.Left) != 0 || len(oe.Restore) != 1 || !strings.Contains(oe.Restore[0], ".practice.old-") {
		t.Fatalf("err = %v; want an *OutputError whose Restore is the name moved aside and whose Left is empty", err)
	}
	if _, err := os.Lstat(f.practiceDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("practice/ is there (%v), but it could not be moved back", err)
	}
	var aside []string
	for _, n := range f.editionNames() {
		if strings.HasPrefix(n, ".practice.old-") {
			aside = append(aside, n)
		} else if !slices.Contains(wantEditionNames, n) {
			t.Errorf("edition/ holds %s, which is neither the edition nor the name moved aside", n)
		}
	}
	if len(aside) != 1 || !strings.Contains(oe.Restore[0], aside[0]) {
		t.Fatalf("edition/ holds %v moved aside and the error lists %v to restore; want the one name", aside, oe.Restore)
	}
	if got := treeOf(t, filepath.Join(f.editionDir(), aside[0])); !maps.Equal(got, before) {
		t.Error("the name moved aside does not hold the earlier practice/")
	}

	g := newPfFix(t)
	before = treeOf(t, g.practiceDir())
	edition.SetWriteFaultForTest(t, map[string]error{edition.FaultWriteForTest: syscall.ENOSPC, edition.FaultRemoveAllForTest: syscall.EIO})
	_, err = g.render()
	if !errors.As(err, &oe) || isInputErr(err) || len(oe.Left) != 1 || !strings.Contains(oe.Left[0], ".practice.tmp-") || len(oe.Restore) != 0 {
		t.Fatalf("err = %v; want an *OutputError that lists the temporary tree in Left and nothing to restore", err)
	}
	if got := treeOf(t, g.practiceDir()); !maps.Equal(got, before) {
		t.Error("practice/ changed after a failure before the commit point")
	}
}

// V92: after the commit point, the earlier practice/ (moved aside) that cannot be removed is a
// warning: no error, practice/ is the new render, and the name is given back.
func TestRenderPracticeEdition_ANameLeftAfterTheCommitPointIsAWarning(t *testing.T) {
	f := newPfFix(t)
	f.tree.Put(editiontest.ChallengesRel+"/"+editiontest.CID+"/"+edition.EditionDirName+"/"+edition.PracticeDirName+"/"+edition.PracticeEvidenceDirName+"/stale.txt", "stale\n")
	edition.SetWriteFaultForTest(t, map[string]error{edition.FaultRemoveAllForTest: syscall.EIO})
	left, err := f.render()
	if err != nil || len(left) != 1 || !strings.Contains(left[0], ".practice.old-") {
		t.Fatalf("(%v, %v); want no error and the name moved aside", left, err)
	}
	if got := treeOf(t, f.practiceDir()); !maps.Equal(got, f.golden()) {
		t.Error("practice/ is not the new render")
	}
	found := false
	for _, n := range f.editionNames() {
		if strings.HasPrefix(n, ".practice.old-") && strings.Contains(left[0], n) {
			found = true
		}
	}
	if !found {
		t.Errorf("edition/ holds %v; want the name of the warning %v", f.editionNames(), left)
	}
}

// The refusals before anything is written: a rule of the edition (E1: edition.yaml that does not
// parse; E3: a template mark that edition.yaml does not declare) is a *Violation (exit 1), and a
// usage error or an input that cannot be read is an *InputError (exit 2). practice/ is as it was
// and nothing is left beside it.
func TestRenderPracticeEdition_RefusalsLeavePracticeAsItWas(t *testing.T) {
	specRel := editiontest.ChallengesRel + "/" + editiontest.CID + "/" + edition.EditionDirName + "/" + edition.SpecFileName
	cases := []struct {
		name  string
		brk   func(f *pfFix) (challenges, cid string)
		input bool
		rule  string
	}{
		{"E1: edition.yaml that does not parse", func(f *pfFix) (string, string) {
			f.tree.Put(specRel, "version: [\n")
			return f.challenges(), editiontest.CID
		}, false, "E1"},
		{"E3: a mark that edition.yaml does not declare", func(f *pfFix) (string, string) {
			dir := filepath.Join(f.editionDir(), edition.TemplateDirName)
			names := listNames(f.t, dir)
			data, err := os.ReadFile(filepath.Join(dir, names[0]))
			if err != nil {
				f.t.Fatal(err)
			}
			f.tree.Put(editiontest.ChallengesRel+"/"+editiontest.CID+"/"+edition.EditionDirName+"/"+edition.TemplateDirName+"/"+names[0], string(data)+"extra = {{ctf:undeclared}}\n")
			return f.challenges(), editiontest.CID
		}, false, "E3"},
		{"no edition.yaml", func(f *pfFix) (string, string) {
			if err := os.Remove(f.tree.Path(specRel)); err != nil {
				f.t.Fatal(err)
			}
			return f.challenges(), editiontest.CID
		}, true, ""},
		{"a challenge id outside the grammar", func(f *pfFix) (string, string) { return f.challenges(), "demo" }, true, ""},
		{"a challenge that is not in the tree", func(f *pfFix) (string, string) { return f.challenges(), "02-missing" }, true, ""},
		{"a challenge that is not of type investigate", func(f *pfFix) (string, string) { return f.challenges(), editiontest.Evade }, true, ""},
		{"no challenges tree", func(f *pfFix) (string, string) { return "", editiontest.CID }, true, ""},
		{"a practice/ that is a link", func(f *pfFix) (string, string) {
			moved := filepath.Join(f.editionDir(), "elsewhere")
			if err := os.Rename(f.practiceDir(), moved); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink(moved, f.practiceDir()); err != nil {
				f.t.Fatal(err)
			}
			return f.challenges(), editiontest.CID
		}, true, ""},
		{"a practice that is a regular file", func(f *pfFix) (string, string) {
			if err := os.RemoveAll(f.practiceDir()); err != nil {
				f.t.Fatal(err)
			}
			f.tree.Put(editiontest.ChallengesRel+"/"+editiontest.CID+"/"+edition.EditionDirName+"/"+edition.PracticeDirName, "not a directory\n")
			return f.challenges(), editiontest.CID
		}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newPfFix(t)
			challenges, cid := c.brk(f)
			beforeNames := f.editionNames()
			before := pfSnapshot(t, f.editionDir())
			left, err := edition.RenderPracticeEdition(challenges, cid)
			if err == nil || len(left) != 0 {
				t.Fatalf("(%v, %v); want a refusal", left, err)
			}
			var v *edition.Violation
			var oe *edition.OutputError
			switch {
			case c.input && !isInputErr(err):
				t.Errorf("err = %v; want an *InputError (exit 2)", err)
			case !c.input && (isInputErr(err) || !errors.As(err, &v)):
				t.Errorf("err = %v; want a rule's *Violation (exit 1)", err)
			case errors.As(err, &oe):
				t.Errorf("err = %v; a refusal before anything is written is not an *OutputError", err)
			}
			if c.rule != "" && !strings.Contains(err.Error(), c.rule) {
				t.Errorf("err = %v; want the rule %s named", err, c.rule)
			}
			if got := f.editionNames(); !slices.Equal(got, beforeNames) {
				t.Errorf("edition/ holds %v, want %v as it was", got, beforeNames)
			}
			if got := pfSnapshot(t, f.editionDir()); !maps.Equal(got, before) {
				t.Error("edition/ changed after a refusal")
			}
		})
	}
}

// pfSnapshot is every entry under root (slash-relative): a file with its mode and bytes, a
// directory with its mode, and a link with its target (a link is not followed).
func pfSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out[filepath.ToSlash(rel)] = "link " + target
		case info.IsDir():
			out[filepath.ToSlash(rel)] = "dir " + info.Mode().Perm().String()
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[filepath.ToSlash(rel)] = "file " + info.Mode().Perm().String() + " " + string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
