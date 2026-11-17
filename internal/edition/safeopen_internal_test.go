package edition

// ADR-0056 V57 and D20 (the form of the files): openRegular (safeopen.go), the one way the validator opens a
// file of its input, and the readers that use it. A file that is a link, is not a regular file,
// or is swapped for a link or another file between the Lstat and the open is refused. The seam
// that does the swapping, afterLstat, is set by these tests and by nothing else; no test of this
// package runs in parallel with another, so a test that sets it owns it. Every value is a
// placeholder.

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// withAfterLstat sets the seam for the length of the test.
func withAfterLstat(t *testing.T, hook func(path string)) {
	t.Helper()
	afterLstat = hook
	t.Cleanup(func() { afterLstat = nil })
}

func readAll(t *testing.T, f *os.File) string {
	t.Helper()
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestOpenRegular_OpensARegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.txt")
	filesWrite(t, p, "content")
	calls := 0
	withAfterLstat(t, func(path string) {
		if path == p {
			calls++
		}
	})
	f, err := openRegular(p)
	if err != nil {
		t.Fatalf("openRegular: %v", err)
	}
	if got := readAll(t, f); got != "content" {
		t.Errorf("read %q, want the file's content", got)
	}
	if calls != 1 {
		t.Errorf("the seam was called %d times, want once (between the Lstat and the open)", calls)
	}
}

func TestOpenRegular_RefusesWhatIsNotARegularFile(t *testing.T) {
	dir := t.TempDir()
	filesWrite(t, filepath.Join(dir, "real.txt"), "content")
	if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		path string
		want error
	}{
		{"a link to a regular file", filepath.Join(dir, "link.txt"), errNotRegular},
		{"a dangling link", filepath.Join(dir, "dangling.txt"), errNotRegular},
		{"a directory", filepath.Join(dir, "sub"), errNotRegular},
		{"a path that does not exist", filepath.Join(dir, "missing.txt"), fs.ErrNotExist},
	}
	for _, c := range cases {
		f, err := openRegular(c.path)
		if f != nil {
			f.Close()
		}
		if f != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: openRegular = (%v, %v), want no file and %v", c.name, f, err, c.want)
		}
	}
}

// V57, the first case: the file is swapped for a link after the Lstat. O_NOFOLLOW refuses it, so
// the content that the link points at is never read.
func TestOpenRegular_RefusesAFileSwappedForALinkAfterTheLstat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	elsewhere := filepath.Join(t.TempDir(), "secret.txt")
	filesWrite(t, p, "the file that was looked at")
	filesWrite(t, elsewhere, "another file")
	withAfterLstat(t, func(path string) {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(elsewhere, path); err != nil {
			t.Error(err)
		}
	})
	f, err := openRegular(p)
	if f != nil {
		defer f.Close()
	}
	if f != nil || err == nil {
		t.Fatalf("openRegular = (%v, %v), want a refusal of the link", f, err)
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("err = %v, want the operating system's refusal of O_NOFOLLOW (ELOOP)", err)
	}
}

// V57, the FIFO case: the file is swapped for a FIFO after the Lstat. open(2) of a FIFO for
// reading waits for a writer, so without O_NONBLOCK the open would block for ever and never
// reach the Stat that refuses it. The open runs in a goroutine, and the test fails after a
// timeout instead of hanging; a FIFO that is there from the start is refused by the Lstat.
func TestOpenRegular_RefusesAFileSwappedForAFIFOAfterTheLstatWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	direct := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(direct, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := openRegular(direct); f != nil || !errors.Is(err, errNotRegular) {
		t.Errorf("openRegular of a FIFO = (%v, %v), want no file and errNotRegular", f, err)
	}

	p := filepath.Join(dir, "a.txt")
	filesWrite(t, p, "the file that was looked at")
	withAfterLstat(t, func(path string) {
		if path != p {
			return
		}
		if err := os.Remove(path); err != nil {
			t.Error(err)
			return
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Error(err)
		}
	})
	type result struct {
		f   *os.File
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, err := openRegular(p)
		done <- result{f, err}
	}()
	select {
	case r := <-done:
		if r.f != nil {
			r.f.Close()
		}
		if r.f != nil || !errors.Is(r.err, errNotRegular) {
			t.Fatalf("openRegular of a file swapped for a FIFO = (%v, %v), want no file and errNotRegular", r.f, r.err)
		}
	case <-time.After(5 * time.Second):
		// A writer lets the blocked open of the reader return, so the goroutine does not outlive the test.
		if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatal("openRegular blocked on a path that became a FIFO after the Lstat: the open does not use O_NONBLOCK")
	}
}

// V57, the second case: the file is replaced by another regular file (another inode) after the
// Lstat. The open succeeds, and the Stat of the open descriptor, held to the Lstat, refuses it.
func TestOpenRegular_RefusesAFileReplacedByAnotherInodeAfterTheLstat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	other := filepath.Join(t.TempDir(), "b.txt")
	filesWrite(t, p, "the file that was looked at")
	filesWrite(t, other, "another regular file")
	withAfterLstat(t, func(path string) {
		if err := os.Rename(other, path); err != nil {
			t.Error(err)
		}
	})
	f, err := openRegular(p)
	if f != nil {
		defer f.Close()
	}
	if f != nil || !errors.Is(err, errReplaced) {
		t.Fatalf("openRegular = (%v, %v), want no file and errReplaced", f, err)
	}
}

// V57 through the readers: a bundle file that is swapped is a B2 violation, the same one as a
// file that cannot be read, and the content of neither file is in the message.
func TestReadBundles_RefusesAFileSwappedAfterTheLstat(t *testing.T) {
	swaps := map[string]func(t *testing.T, path string){
		"a link": func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "target.txt")
			filesWrite(t, target, contentSentinel)
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Error(err)
			}
		},
		"another inode": func(t *testing.T, path string) {
			other := filepath.Join(t.TempDir(), "other.txt")
			filesWrite(t, other, contentSentinel)
			if err := os.Rename(other, path); err != nil {
				t.Error(err)
			}
		},
	}
	for name, swap := range swaps {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			filesWrite(t, filepath.Join(root, "seat-a", "01-demo", "notes.txt"), "bundle notes")
			// the control: the tree reads
			if _, err := ReadBundles(root); err != nil {
				t.Fatalf("ReadBundles of the tree before the swap: %v", err)
			}
			done := false
			withAfterLstat(t, func(path string) {
				if !done && filepath.Base(path) == "notes.txt" {
					done = true
					swap(t, path)
				}
			})
			_, err := ReadBundles(root)
			if !done {
				t.Fatal("the seam did not run: the reader does not open the file through openRegular")
			}
			var v *Violation
			if !errors.As(err, &v) || v.Rule != RuleBundleShape || v.File != "notes.txt" || v.Seat != "seat-a" || v.CID != "01-demo" {
				t.Fatalf("err = %v, want a B2 violation of seat-a / 01-demo / notes.txt", err)
			}
			if !strings.Contains(err.Error(), "cannot be read") {
				t.Errorf("the message is %q, want it to say the file cannot be read", err.Error())
			}
			if strings.Contains(err.Error(), contentSentinel) || strings.Contains(err.Error(), "bundle notes") {
				t.Errorf("the error carries a content: %v", err)
			}
		})
	}
}

// The same reader reads a template and a corpus file (readCapped): a swapped file is refused.
func TestReadCapped_RefusesASwappedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "corpus.txt")
	other := filepath.Join(t.TempDir(), "other.txt")
	filesWrite(t, p, "public text")
	filesWrite(t, other, "another file")
	if data, err := readCapped(p, 1024); err != nil || string(data) != "public text" {
		t.Fatalf("readCapped of an unswapped file = (%q, %v)", data, err)
	}
	withAfterLstat(t, func(path string) {
		if err := os.Rename(other, path); err != nil {
			t.Error(err)
		}
	})
	if data, err := readCapped(p, 1024); err == nil || data != nil {
		t.Errorf("readCapped of a swapped file = (%q, %v), want a refusal", data, err)
	}
}

// The answers file. The validator's opener refuses a link; the start-up's follows it, because
// the answers Secret is a directory volume whose files are links (..data/<key>), and a
// scoreboard that refused one would not start on any cluster. Both are pinned.
func TestReadTable_TheTwoOpeners(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "..data-answers.tsv")
	link := filepath.Join(dir, PracticeAnswersFileName)
	filesWrite(t, target, "table bytes")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if data, err := readTable(link, openFollowing); err != nil || string(data) != "table bytes" {
		t.Errorf("the start-up's opener on a link (a Secret volume's file) = (%q, %v), want the table", data, err)
	}
	if data, err := readTable(link, openRegular); err == nil || data != nil {
		t.Errorf("the validator's opener on a link = (%q, %v), want a refusal", data, err)
	}
	for name, open := range map[string]fileOpener{"openFollowing": openFollowing, "openRegular": openRegular} {
		if data, err := readTable(target, open); err != nil || string(data) != "table bytes" {
			t.Errorf("%s on the file itself = (%q, %v), want the table", name, data, err)
		}
		if data, err := readTable(dir, open); err == nil || data != nil {
			t.Errorf("%s on a directory = (%q, %v), want a refusal", name, data, err)
		}
	}
	// A swap after the Lstat is refused by the validator's opener (V57).
	swapped := filepath.Join(dir, "swapped.tsv")
	other := filepath.Join(t.TempDir(), "other.tsv")
	filesWrite(t, swapped, "table bytes")
	filesWrite(t, other, "another file")
	withAfterLstat(t, func(path string) {
		if path == swapped {
			if err := os.Rename(other, path); err != nil {
				t.Error(err)
			}
		}
	})
	if data, err := readTable(swapped, openRegular); err == nil || data != nil {
		t.Errorf("readTable of a swapped file = (%q, %v), want a refusal", data, err)
	}
}
