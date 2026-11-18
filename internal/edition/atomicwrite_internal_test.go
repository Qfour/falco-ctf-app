package edition

// ADR-0056 D20 and D19 A4e-1: the atomic writer (atomicwrite.go). All of an output or none of
// it; a directory 0700 and a file 0600 whatever the umask; an existing destination is refused;
// nothing is left beside the destination when anything fails. The umask is the process's, so
// the tests that set it run in sequence (no test of this package runs in parallel) and put it
// back. Every value is a placeholder.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// withUmask runs f with the process's umask set to mask, and puts the old one back.
func withUmask(t *testing.T, mask int, f func()) {
	t.Helper()
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	f()
}

// dirNames is the names in dir, sorted.
func dirNames(t *testing.T, dir string) []string {
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

// walkModes is every path under root (root excluded), slash-relative, with its permission bits.
func walkModes(t *testing.T, root string) map[string]fs.FileMode {
	t.Helper()
	out := map[string]fs.FileMode{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = info.Mode().Perm()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWriteFileAtomic_WritesTheFileWithModeAndLeavesNothing(t *testing.T) {
	for _, mask := range []int{0o022, 0o077, 0o000} {
		withUmask(t, mask, func() {
			dir := t.TempDir()
			dest := filepath.Join(dir, "digests.tsv")
			if left, err := writeFileAtomic(dest, []byte("one line\n")); err != nil || len(left) != 0 {
				t.Fatalf("umask %#o: writeFileAtomic: (%v, %v), want no name left and no error", mask, left, err)
			}
			if got, err := os.ReadFile(dest); err != nil || string(got) != "one line\n" {
				t.Errorf("umask %#o: the file holds (%q, %v)", mask, got, err)
			}
			info, err := os.Lstat(dest)
			if err != nil {
				t.Fatal(err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Errorf("umask %#o: the file has mode %v, want a regular file of 0600", mask, info.Mode())
			}
			if got := dirNames(t, dir); !slices.Equal(got, []string{"digests.tsv"}) {
				t.Errorf("umask %#o: the directory holds %v, want the output only (no temporary left)", mask, got)
			}
		})
	}
}

func TestWriteFileAtomic_RefusesWhatExistsAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	filesWrite(t, filepath.Join(dir, "file.tsv"), "an earlier output")
	if err := os.Mkdir(filepath.Join(dir, "dir.tsv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling.tsv")); err != nil {
		t.Fatal(err)
	}
	before := dirNames(t, dir)
	for _, name := range []string{"file.tsv", "dir.tsv", "dangling.tsv"} {
		_, err := writeFileAtomic(filepath.Join(dir, name), []byte("new"))
		if !errors.Is(err, ErrOutputExists) || !isInput(err) {
			t.Errorf("%s: err = %v, want an *InputError of ErrOutputExists (exit 2)", name, err)
		}
	}
	if got := dirNames(t, dir); !slices.Equal(got, before) {
		t.Errorf("the directory holds %v after the refusals, want %v (nothing made, nothing left)", got, before)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "file.tsv")); string(got) != "an earlier output" {
		t.Errorf("the earlier output was changed: %q", got)
	}
}

// withBeforeLink sets the seam of writeFileAtomic for the length of the test.
func withBeforeLink(t *testing.T, hook func(dest string)) {
	t.Helper()
	beforeLink = hook
	t.Cleanup(func() { beforeLink = nil })
}

// A destination that another process creates AFTER the check and before the output is put in
// place is refused, never replaced (os.Link fails with EEXIST), and the temporary is removed.
func TestWriteFileAtomic_RefusesADestinationCreatedAfterTheCheck(t *testing.T) {
	cases := []struct {
		name   string
		create func(t *testing.T, dest string)
		check  func(t *testing.T, dest string)
	}{
		{
			"a file",
			func(t *testing.T, dest string) { filesWrite(t, dest, "made by another process") },
			func(t *testing.T, dest string) {
				if got, err := os.ReadFile(dest); err != nil || string(got) != "made by another process" {
					t.Errorf("the file made by the other process holds (%q, %v), want it unchanged", got, err)
				}
			},
		},
		{
			"a directory",
			func(t *testing.T, dest string) {
				if err := os.Mkdir(dest, 0o755); err != nil {
					t.Error(err)
				}
			},
			func(t *testing.T, dest string) {
				if info, err := os.Lstat(dest); err != nil || !info.IsDir() {
					t.Errorf("the directory made by the other process is (%v, %v), want it unchanged", info, err)
				}
			},
		},
		{
			"a dangling link",
			func(t *testing.T, dest string) {
				if err := os.Symlink(filepath.Join(filepath.Dir(dest), "nowhere"), dest); err != nil {
					t.Error(err)
				}
			},
			func(t *testing.T, dest string) {
				if info, err := os.Lstat(dest); err != nil || info.Mode()&fs.ModeSymlink == 0 {
					t.Errorf("the link made by the other process is (%v, %v), want it unchanged", info, err)
				}
			},
		},
	}
	for _, c := range cases {
		dir := t.TempDir()
		dest := filepath.Join(dir, "digests.tsv")
		calls := 0
		withBeforeLink(t, func(path string) {
			calls++
			c.create(t, path)
		})
		_, err := writeFileAtomic(dest, []byte("new output"))
		if calls != 1 {
			t.Fatalf("%s: the seam was called %d times, want once (after the check, before the put-in-place)", c.name, calls)
		}
		// V92: the EEXIST of the put-in-place itself is exit 2 (an *InputError), not 3.
		if !errors.Is(err, ErrOutputExists) || !isInput(err) || isOutput(err) {
			t.Errorf("%s: err = %v, want an *InputError of ErrOutputExists (the destination made after the check is refused, not replaced)", c.name, err)
		}
		c.check(t, dest)
		if got := dirNames(t, dir); !slices.Equal(got, []string{"digests.tsv"}) {
			t.Errorf("%s: the directory holds %v, want the other process's path only (the temporary is removed)", c.name, got)
		}
	}
}

func TestWriteFileAtomic_NoDirectoryNoOutput(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "missing-dir", "digests.tsv")
	if _, err := writeFileAtomic(dest, []byte("x")); err == nil {
		t.Fatal("a destination in a directory that does not exist was written")
	}
	if _, err := os.Lstat(filepath.Dir(dest)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the missing directory was made: %v", err)
	}
}

func TestWriteTreeAtomic_WritesTheTreeWithModesAndLeavesNothing(t *testing.T) {
	files := []outputFile{
		{Path: "answers.tsv", Data: []byte("answers")},
		{Path: "evidence/seat-a/01-demo/notes.txt", Data: []byte("notes a")},
		{Path: "evidence/seat-b/01-demo/notes.txt", Data: []byte("notes b")},
		{Path: "render-record.tsv", Data: nil},
	}
	for _, mask := range []int{0o022, 0o077, 0o000} {
		withUmask(t, mask, func() {
			parent := t.TempDir()
			dest := filepath.Join(parent, "out")
			if err := writeTreeAtomic(dest, files); err != nil {
				t.Fatalf("umask %#o: writeTreeAtomic: %v", mask, err)
			}
			if got := dirNames(t, parent); !slices.Equal(got, []string{"out"}) {
				t.Errorf("umask %#o: the parent holds %v, want the output only (no temporary left)", mask, got)
			}
			for _, f := range files {
				got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(f.Path)))
				if err != nil || string(got) != string(f.Data) {
					t.Errorf("umask %#o: %s holds (%q, %v), want %q", mask, f.Path, got, err, f.Data)
				}
			}
			info, err := os.Lstat(dest)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
				t.Errorf("umask %#o: the output is %v (%v), want a directory of 0700", mask, info, err)
			}
			want := map[string]fs.FileMode{
				"answers.tsv": 0o600, "render-record.tsv": 0o600,
				"evidence": 0o700, "evidence/seat-a": 0o700, "evidence/seat-a/01-demo": 0o700, "evidence/seat-a/01-demo/notes.txt": 0o600,
				"evidence/seat-b": 0o700, "evidence/seat-b/01-demo": 0o700, "evidence/seat-b/01-demo/notes.txt": 0o600,
			}
			got := walkModes(t, dest)
			for p, m := range want {
				if got[p] != m {
					t.Errorf("umask %#o: %s has mode %#o, want %#o", mask, p, got[p], m)
				}
			}
			if len(got) != len(want) {
				t.Errorf("umask %#o: the output holds %d entries, want %d: %v", mask, len(got), len(want), got)
			}
		})
	}
}

func TestWriteTreeAtomic_RefusesWhatExistsAndWritesNothing(t *testing.T) {
	parent := t.TempDir()
	if err := os.Mkdir(filepath.Join(parent, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	filesWrite(t, filepath.Join(parent, "file"), "x")
	before := dirNames(t, parent)
	files := []outputFile{{Path: "a.txt", Data: []byte("a")}}
	for _, name := range []string{"out", "file"} {
		if err := writeTreeAtomic(filepath.Join(parent, name), files); !errors.Is(err, ErrOutputExists) || !isInput(err) {
			t.Errorf("%s: err = %v, want an *InputError of ErrOutputExists", name, err)
		}
	}
	if got := dirNames(t, parent); !slices.Equal(got, before) {
		t.Errorf("the parent holds %v after the refusals, want %v", got, before)
	}
	if got := dirNames(t, filepath.Join(parent, "out")); len(got) != 0 {
		t.Errorf("the existing directory was written into: %v", got)
	}
}

// Any failure part-way removes the temporary tree, files written before it included.
func TestWriteTreeAtomic_AFailurePartWayLeavesNothing(t *testing.T) {
	parent := t.TempDir()
	tooLong := strings.Repeat("a", 300) // longer than NAME_MAX: the create fails after the first file is written
	files := []outputFile{
		{Path: "first.txt", Data: []byte("written before the failure")},
		{Path: "dir/second.txt", Data: []byte("also written")},
		{Path: tooLong, Data: []byte("cannot be created")},
	}
	err := writeTreeAtomic(filepath.Join(parent, "out"), files)
	if err == nil {
		t.Fatal("a file that cannot be created did not fail the write")
	}
	if got := dirNames(t, parent); len(got) != 0 {
		t.Errorf("the parent holds %v after the failure, want nothing (the temporary tree is removed)", got)
	}
}

// What is refused before anything is made.
func TestWriteTreeAtomic_RefusesBadPathsBeforeMakingAnything(t *testing.T) {
	ok := []byte("x")
	cases := []struct {
		name  string
		files []outputFile
	}{
		{"no file", nil},
		{"an empty path", []outputFile{{Path: "", Data: ok}}},
		{"the root", []outputFile{{Path: ".", Data: ok}}},
		{"an absolute path", []outputFile{{Path: "/etc/x", Data: ok}}},
		{"a parent element", []outputFile{{Path: "../x", Data: ok}}},
		{"a parent element inside", []outputFile{{Path: "a/../../x", Data: ok}}},
		{"an empty element", []outputFile{{Path: "a//b", Data: ok}}},
		{"a trailing slash", []outputFile{{Path: "a/", Data: ok}}},
		{"a backslash", []outputFile{{Path: "a\\b", Data: ok}}},
		{"the same path twice", []outputFile{{Path: "a/b", Data: ok}, {Path: "a/b", Data: ok}}},
		{"a file that is the directory of another", []outputFile{{Path: "a", Data: ok}, {Path: "a/b", Data: ok}}},
		{"a file that is the directory of another, the other way round", []outputFile{{Path: "a/b/c", Data: ok}, {Path: "a/b", Data: ok}}},
	}
	for _, c := range cases {
		parent := t.TempDir()
		if err := writeTreeAtomic(filepath.Join(parent, "out"), c.files); err == nil {
			t.Errorf("%s: was written", c.name)
		}
		if got := dirNames(t, parent); len(got) != 0 {
			t.Errorf("%s: the parent holds %v after the refusal, want nothing", c.name, got)
		}
	}
}

// The mode is held after the creation: a umask that takes the owner's bits makes the write
// fail and leave nothing, instead of leaving a file that the operator cannot use or that is
// not the mode that was asked for. The failure is the output's environment: an *OutputError
// (exit 3), not an existing output.
func TestWriteFileAtomic_AUmaskThatTakesTheOwnersBitsFailsAndLeavesNothing(t *testing.T) {
	dir := t.TempDir() // made under the usual umask: only what the writer makes is under 0200
	withUmask(t, 0o200, func() {
		if _, err := writeFileAtomic(filepath.Join(dir, "out.tsv"), []byte("x")); err == nil {
			t.Error("a file of mode 0400 was left in place of one of 0600")
		} else if !isOutput(err) || isInput(err) {
			t.Errorf("the single file: err = %v, want an *OutputError (exit 3)", err)
		}
		if got := dirNames(t, dir); len(got) != 0 {
			t.Errorf("the directory holds %v after the failure, want nothing", got)
		}
		if err := writeTreeAtomic(filepath.Join(dir, "out"), []outputFile{{Path: "a.txt", Data: []byte("x")}}); err == nil {
			t.Error("a tree of directories of mode 0500 was left in place of ones of 0700")
		} else if !isOutput(err) || isInput(err) {
			t.Errorf("the tree: err = %v, want an *OutputError (exit 3)", err)
		}
		if got := dirNames(t, dir); len(got) != 0 {
			t.Errorf("the directory holds %v after the failure, want nothing", got)
		}
	})
}

// ADR-0056 D20 (exit 3 and the commit point, amendment 13 as revised), V87 and V92: the failures
// of the five steps of the seam writeFault (a write, the link, the rename, the two removes) are
// made to happen through it, never through a permission (a test may run as root, which a mode
// does not stop). A Sync or a Close that fails has no seam and no test; a temporary that cannot
// be created and a mode the umask took a bit of are caused for real (the umask test above, and
// the name over the limit of cmd/scoreboard's exit 3 test).

// withWriteFault makes the steps of fail fail with their error for the length of the test.
func withWriteFault(t *testing.T, fail map[string]error) {
	t.Helper()
	writeFault = func(step string) error { return fail[step] }
	t.Cleanup(func() { writeFault = nil })
}

func isInput(err error) bool {
	var in *InputError
	return errors.As(err, &in)
}

func isOutput(err error) bool {
	var out *OutputError
	return errors.As(err, &out)
}

// leftOf is the names the *OutputError of err lists as left behind.
func leftOf(err error) []string {
	var out *OutputError
	if errors.As(err, &out) {
		return out.Left
	}
	return nil
}

// tempNames is the names in dir other than keep, as a message shows them (shownName).
func tempNames(t *testing.T, dir, keep string) []string {
	t.Helper()
	var out []string
	for _, n := range dirNames(t, dir) {
		if n != keep {
			out = append(out, shownName(n))
		}
	}
	return out
}

// Before the commit point (the link), a failure of the write of the data or of the link itself
// is an *OutputError (exit 3): nothing is at the destination and the temporary is removed.
func TestWriteFileAtomic_AFailureBeforeTheLinkIsAnOutputErrorAndLeavesNothing(t *testing.T) {
	for _, c := range []struct {
		step string
		err  error
	}{
		{faultWrite, syscall.ENOSPC},
		{faultLink, syscall.EPERM}, // a file system that has no hard link
	} {
		dir := t.TempDir()
		withWriteFault(t, map[string]error{c.step: c.err})
		left, err := writeFileAtomic(filepath.Join(dir, "digests.tsv"), []byte("one line\n"))
		if !isOutput(err) || isInput(err) || !errors.Is(err, c.err) || len(left) != 0 || len(leftOf(err)) != 0 {
			t.Errorf("%s fails: (%v, %v), want an *OutputError of %v, no name left", c.step, left, err, c.err)
		}
		if got := dirNames(t, dir); len(got) != 0 {
			t.Errorf("%s fails: the directory holds %v, want nothing (no output, no temporary)", c.step, got)
		}
	}
}

// Before the commit point, a cleanup that fails too: still exit 3, the destination is not made,
// the temporary name that is left is listed (cut short, never a value), and the same write given
// again succeeds (the name left is not the next one's).
func TestWriteFileAtomic_ACleanupThatFailsBeforeTheLinkListsTheNameAndDoesNotStopTheNextRun(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "digests.tsv")
	withWriteFault(t, map[string]error{faultWrite: syscall.ENOSPC, faultRemove: syscall.EIO})
	left, err := writeFileAtomic(dest, []byte("one line\n"))
	if !isOutput(err) || isInput(err) || len(left) != 0 {
		t.Fatalf("(%v, %v), want an *OutputError and no warning", left, err)
	}
	if _, err := os.Lstat(dest); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the destination is there after a failure: %v", err)
	}
	tmp := tempNames(t, dir, "")
	if len(tmp) != 1 || !slices.Equal(leftOf(err), tmp) {
		t.Errorf("the error lists %v as left, and the directory holds %v; want the one temporary name", leftOf(err), tmp)
	}
	if len(tmp) == 1 && (len(tmp[0]) > maxShownName+len(`""...`) || !strings.Contains(tmp[0], ".digests.tsv.tmp-")) {
		t.Errorf("the name left is shown as %q, want the temporary name, quoted and cut short", tmp[0])
	}

	writeFault = nil
	left, err = writeFileAtomic(dest, []byte("one line\n"))
	if err != nil || len(left) != 0 {
		t.Fatalf("the same write again: (%v, %v), want it to succeed", left, err)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "one line\n" {
		t.Errorf("the destination holds (%q, %v)", got, err)
	}
}

// After the commit point, a temporary name that cannot be removed is a warning, not an error:
// the destination is the whole output, of mode 0600, and the name is given back.
func TestWriteFileAtomic_ANameLeftAfterTheLinkIsAWarning(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "digests.tsv")
	withWriteFault(t, map[string]error{faultRemove: syscall.EIO})
	left, err := writeFileAtomic(dest, []byte("one line\n"))
	if err != nil {
		t.Fatalf("err = %v, want none: the output is in place once the link succeeded", err)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "one line\n" {
		t.Errorf("the destination holds (%q, %v), want the output", got, err)
	}
	if info, err := os.Lstat(dest); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the destination is (%v, %v), want mode 0600", info, err)
	}
	if tmp := tempNames(t, dir, "digests.tsv"); len(tmp) != 1 || !slices.Equal(left, tmp) {
		t.Errorf("the warning is %v and the directory holds the temporary names %v; want the one name", left, tmp)
	}
}

// The EEXIST of the link with a cleanup that fails too: the kind is still the existing output's
// (an *InputError, exit 2), and the name left is listed beside it.
func TestWriteFileAtomic_AnExistingOutputWithACleanupThatFailsIsStillAnInputError(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "digests.tsv")
	withBeforeLink(t, func(path string) { filesWrite(t, path, "made by another process") })
	withWriteFault(t, map[string]error{faultRemove: syscall.EIO})
	left, err := writeFileAtomic(dest, []byte("new"))
	if !isInput(err) || !errors.Is(err, ErrOutputExists) || len(left) != 0 {
		t.Fatalf("(%v, %v), want an *InputError of ErrOutputExists", left, err)
	}
	if tmp := tempNames(t, dir, "digests.tsv"); len(tmp) != 1 || !slices.Equal(leftOf(err), tmp) {
		t.Errorf("the error lists %v as left and the directory holds %v; want the one temporary name", leftOf(err), tmp)
	}
	if got, _ := os.ReadFile(dest); string(got) != "made by another process" {
		t.Errorf("the other process's file was changed: %q", got)
	}
}

// A tree: a failure of a write or of the rename (the commit point) is an *OutputError and
// nothing is left; a RemoveAll that fails too lists the temporary tree, and the next run is not
// stopped by it.
func TestWriteTreeAtomic_AFailureBeforeTheRenameIsAnOutputError(t *testing.T) {
	files := []outputFile{{Path: "answers.tsv", Data: []byte("a")}, {Path: "evidence/s1/01-demo/x.txt", Data: []byte("b")}}
	for _, c := range []struct {
		step string
		err  error
	}{
		{faultWrite, syscall.ENOSPC},
		{faultRename, syscall.EXDEV},
	} {
		parent := t.TempDir()
		withWriteFault(t, map[string]error{c.step: c.err})
		err := writeTreeAtomic(filepath.Join(parent, "out"), files)
		if !isOutput(err) || isInput(err) || !errors.Is(err, c.err) || len(leftOf(err)) != 0 {
			t.Errorf("%s fails: err = %v, want an *OutputError of %v and no name left", c.step, err, c.err)
		}
		if got := dirNames(t, parent); len(got) != 0 {
			t.Errorf("%s fails: the parent holds %v, want nothing", c.step, got)
		}
	}

	parent := t.TempDir()
	dest := filepath.Join(parent, "out")
	withWriteFault(t, map[string]error{faultWrite: syscall.ENOSPC, faultRemoveAll: syscall.EIO})
	err := writeTreeAtomic(dest, files)
	if !isOutput(err) || isInput(err) {
		t.Fatalf("err = %v, want an *OutputError", err)
	}
	if _, err := os.Lstat(dest); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the output is there after a failure: %v", err)
	}
	if tmp := tempNames(t, parent, ""); len(tmp) != 1 || !slices.Equal(leftOf(err), tmp) {
		t.Errorf("the error lists %v as left and the parent holds %v; want the one temporary tree", leftOf(err), tmp)
	}
	writeFault = nil
	if err := writeTreeAtomic(dest, files); err != nil {
		t.Fatalf("the same write again: %v, want it to succeed", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "answers.tsv")); err != nil || string(got) != "a" {
		t.Errorf("the output holds (%q, %v)", got, err)
	}
}

// replaceTreeAtomic replaces a directory only (replaceableDir): a destination that is a regular
// file is an *InputError and is left as it was, with nothing made beside it; a destination that
// cannot be looked at (its Lstat fails with something else than "does not exist": here ENOTDIR,
// a path under a regular file, which needs no permission to cause) is an *OutputError, and
// nothing is made either.
func TestReplaceTreeAtomic_RefusesWhatIsNotADirectory(t *testing.T) {
	files := []outputFile{{Path: "answers.tsv", Data: []byte("a")}}

	dir := t.TempDir()
	dest := filepath.Join(dir, "practice")
	filesWrite(t, dest, "a file where the directory would be\n")
	left, err := replaceTreeAtomic(dest, files)
	if !isInput(err) || isOutput(err) || len(left) != 0 {
		t.Errorf("a regular file at the destination: (%v, %v), want an *InputError", left, err)
	}
	if got, rerr := os.ReadFile(dest); rerr != nil || string(got) != "a file where the directory would be\n" {
		t.Errorf("the file at the destination is (%q, %v), want it as it was", got, rerr)
	}
	if got := dirNames(t, dir); !slices.Equal(got, []string{"practice"}) {
		t.Errorf("the directory holds %v, want the file only (nothing made beside it)", got)
	}

	dir = t.TempDir()
	filesWrite(t, filepath.Join(dir, "edition"), "a file where the edition directory would be\n")
	left, err = replaceTreeAtomic(filepath.Join(dir, "edition", "practice"), files)
	if !isOutput(err) || isInput(err) || len(left) != 0 || !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("a destination under a regular file: (%v, %v), want an *OutputError of ENOTDIR", left, err)
	}
	if got := dirNames(t, dir); !slices.Equal(got, []string{"edition"}) {
		t.Errorf("the directory holds %v, want the file only", got)
	}
}
