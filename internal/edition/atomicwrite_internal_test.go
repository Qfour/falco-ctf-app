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
			if err := writeFileAtomic(dest, []byte("one line\n")); err != nil {
				t.Fatalf("umask %#o: writeFileAtomic: %v", mask, err)
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
			if got := dirNames(t,dir); !slices.Equal(got, []string{"digests.tsv"}) {
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
	before := dirNames(t,dir)
	for _, name := range []string{"file.tsv", "dir.tsv", "dangling.tsv"} {
		if err := writeFileAtomic(filepath.Join(dir, name), []byte("new")); !errors.Is(err, ErrOutputExists) {
			t.Errorf("%s: err = %v, want ErrOutputExists", name, err)
		}
	}
	if got := dirNames(t,dir); !slices.Equal(got, before) {
		t.Errorf("the directory holds %v after the refusals, want %v (nothing made, nothing left)", got, before)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "file.tsv")); string(got) != "an earlier output" {
		t.Errorf("the earlier output was changed: %q", got)
	}
}

func TestWriteFileAtomic_NoDirectoryNoOutput(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "missing-dir", "digests.tsv")
	if err := writeFileAtomic(dest, []byte("x")); err == nil {
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
			if got := dirNames(t,parent); !slices.Equal(got, []string{"out"}) {
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
	before := dirNames(t,parent)
	files := []outputFile{{Path: "a.txt", Data: []byte("a")}}
	for _, name := range []string{"out", "file"} {
		if err := writeTreeAtomic(filepath.Join(parent, name), files); !errors.Is(err, ErrOutputExists) {
			t.Errorf("%s: err = %v, want ErrOutputExists", name, err)
		}
	}
	if got := dirNames(t,parent); !slices.Equal(got, before) {
		t.Errorf("the parent holds %v after the refusals, want %v", got, before)
	}
	if got := dirNames(t,filepath.Join(parent, "out")); len(got) != 0 {
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
	if got := dirNames(t,parent); len(got) != 0 {
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
		if got := dirNames(t,parent); len(got) != 0 {
			t.Errorf("%s: the parent holds %v after the refusal, want nothing", c.name, got)
		}
	}
}

// The mode is held after the creation: a umask that takes the owner's bits makes the write
// fail and leave nothing, instead of leaving a file that the operator cannot use or that is
// not the mode that was asked for.
func TestWriteFileAtomic_AUmaskThatTakesTheOwnersBitsFailsAndLeavesNothing(t *testing.T) {
	dir := t.TempDir() // made under the usual umask: only what the writer makes is under 0200
	withUmask(t, 0o200, func() {
		if err := writeFileAtomic(filepath.Join(dir, "out.tsv"), []byte("x")); err == nil {
			t.Error("a file of mode 0400 was left in place of one of 0600")
		}
		if got := dirNames(t,dir); len(got) != 0 {
			t.Errorf("the directory holds %v after the failure, want nothing", got)
		}
		if err := writeTreeAtomic(filepath.Join(dir, "out"), []outputFile{{Path: "a.txt", Data: []byte("x")}}); err == nil {
			t.Error("a tree of directories of mode 0500 was left in place of ones of 0700")
		}
		if got := dirNames(t,dir); len(got) != 0 {
			t.Errorf("the directory holds %v after the failure, want nothing", got)
		}
	})
}
