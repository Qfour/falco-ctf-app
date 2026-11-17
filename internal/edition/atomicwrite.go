package edition

// atomicwrite.go is how the validator and the renderer put an output where an operator reads
// it (ADR-0056 D20, D19 A4e-1): all of it or none of it, never a half-written file or a tree
// that is missing a part. The callers are `edition check` (--digests-out, one file) and
// `edition render` (--out, a tree); this stage has the helpers and their tests only.
//
//   - the output is made as a temporary sibling of its destination (the same directory, so
//     the same file system, and the rename at the end is atomic), never at the destination;
//   - a directory of the output is created with mode 0700 and a file with 0600, by os.Mkdir
//     and by OpenFile with O_CREAT|O_EXCL|O_NOFOLLOW (nothing that was there is reused, and
//     nothing is followed), and the mode is read back and held to that value after the
//     creation: the mode asked for is not the mode the file got when the process's umask took
//     a bit of it, and an output of the operator's secrets that is not 0600 is refused, not
//     left (the result does not depend on the umask: 0700 and 0600 keep the owner's bits under
//     the usual ones, and an unusual umask that takes them makes the write fail);
//   - when every file is written, the temporary is renamed to the destination. The destination
//     must not exist (an existing file, directory or link, even a dangling link, is refused
//     before anything is made), so an earlier output is never replaced;
//   - when anything fails, the temporary file or tree is removed and nothing is left at the
//     destination or beside it.
//
// What this does not do: the check that the destination does not exist and the rename are
// two steps, so a path created by another process in between could be replaced by the rename
// of a file (a directory is not: rename refuses a directory that is not empty); the output
// directory belongs to the one operator who runs the command. The data is synced before the
// rename and the parent directory is not.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// outputDirMode and outputFileMode are the modes of an output (D20): the operator only.
	outputDirMode  fs.FileMode = 0o700
	outputFileMode fs.FileMode = 0o600

	// tempTries is how many random names are tried for the temporary before giving up.
	tempTries = 8
)

// ErrOutputExists is the refusal of a destination that already exists.
var ErrOutputExists = errors.New("edition: the output path already exists")

// outputFile is one file of a tree that writeTreeAtomic writes: Path is slash-separated,
// relative, with no `.`, `..` or empty element (fs.ValidPath), and the directories above the
// file are made as they are needed.
type outputFile struct {
	Path string
	Data []byte
}

// writeFileAtomic writes data to dest (a path that does not exist, in a directory that does)
// as described at the top of this file.
func writeFileAtomic(dest string, data []byte) (err error) {
	if err := refuseExisting(dest); err != nil {
		return err
	}
	tmp, f, err := createTempFile(dest)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close() // closed already on the paths below that close it: a second Close is an error we do not read
			_ = os.Remove(tmp)
		}
	}()
	if err = assertMode(f, outputFileMode); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("edition: writing the output: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("edition: syncing the output: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("edition: closing the output: %w", err)
	}
	if err = refuseExisting(dest); err != nil {
		return err
	}
	if err = os.Rename(tmp, dest); err != nil {
		return fmt.Errorf("edition: putting the output in place: %w", err)
	}
	return nil
}

// writeTreeAtomic writes files as a tree at dest (a path that does not exist, in a directory
// that does) as described at the top of this file. files is not empty, the paths are valid
// and distinct, and no path is a directory of another (a file `a` and a file `a/b`): they are
// held to that before anything is made.
func writeTreeAtomic(dest string, files []outputFile) (err error) {
	if err := checkOutputPaths(files); err != nil {
		return err
	}
	if err := refuseExisting(dest); err != nil {
		return err
	}
	tmp, err := createTempDir(dest)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if rmErr := os.RemoveAll(tmp); rmErr != nil {
				err = errors.Join(err, fmt.Errorf("edition: removing the temporary output: %w", rmErr))
			}
		}
	}()
	made := map[string]struct{}{tmp: {}}
	for _, of := range files {
		full := filepath.Join(tmp, filepath.FromSlash(of.Path))
		if err = mkdirOwner(filepath.Dir(full), made); err != nil {
			return err
		}
		if err = writeNewFile(full, of.Data); err != nil {
			return err
		}
	}
	if err = refuseExisting(dest); err != nil {
		return err
	}
	if err = os.Rename(tmp, dest); err != nil {
		return fmt.Errorf("edition: putting the output in place: %w", err)
	}
	return nil
}

// refuseExisting is ErrOutputExists for a path that exists in any form (Lstat: a link is
// not followed, so a dangling link is an existing path).
func refuseExisting(dest string) error {
	_, err := os.Lstat(dest)
	switch {
	case err == nil:
		return ErrOutputExists
	case errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return fmt.Errorf("edition: the output path: %w", err)
}

// checkOutputPaths holds the paths of a tree to the rules of writeTreeAtomic.
func checkOutputPaths(files []outputFile) error {
	if len(files) == 0 {
		return errors.New("edition: a tree of no file is not written")
	}
	seen := make(map[string]struct{}, len(files))
	dirs := make(map[string]struct{})
	for _, of := range files {
		if of.Path == "." || !fs.ValidPath(of.Path) || strings.Contains(of.Path, "\\") {
			return errors.New("edition: an output path is not a relative, slash-separated path without `.` or `..`")
		}
		if _, dup := seen[of.Path]; dup {
			return errors.New("edition: two output files have the same path")
		}
		seen[of.Path] = struct{}{}
		for d := path.Dir(of.Path); d != "."; d = path.Dir(d) {
			dirs[d] = struct{}{}
		}
	}
	for p := range seen {
		if _, clash := dirs[p]; clash {
			return errors.New("edition: an output path is both a file and the directory of another file")
		}
	}
	return nil
}

// tempName is a sibling of dest: a hidden name that holds a random part.
func tempName(dest string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("edition: no random name for the temporary output: %w", err)
	}
	return filepath.Join(filepath.Dir(dest), "."+filepath.Base(dest)+".tmp-"+hex.EncodeToString(b[:])), nil
}

// createTempFile creates the temporary file beside dest (0600, O_CREAT|O_EXCL|O_NOFOLLOW).
func createTempFile(dest string) (string, *os.File, error) {
	for i := 0; i < tempTries; i++ {
		tmp, err := tempName(dest)
		if err != nil {
			return "", nil, err
		}
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, outputFileMode)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, fmt.Errorf("edition: creating the temporary output: %w", err)
		}
		return tmp, f, nil
	}
	return "", nil, errors.New("edition: no unused name for the temporary output")
}

// createTempDir creates the temporary directory beside dest (0700; os.Mkdir does not reuse
// an existing entry and does not follow a link), and holds its mode.
func createTempDir(dest string) (string, error) {
	for i := 0; i < tempTries; i++ {
		tmp, err := tempName(dest)
		if err != nil {
			return "", err
		}
		err = os.Mkdir(tmp, outputDirMode)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("edition: creating the temporary output: %w", err)
		}
		if err := assertDirMode(tmp); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
		return tmp, nil
	}
	return "", errors.New("edition: no unused name for the temporary output")
}

// mkdirOwner makes dir and the directories above it that are not in made yet, each with
// os.Mkdir (0700, an existing entry is an error) and held to 0700 after it is made. made
// holds the directories of the temporary tree that exist, the root of it included.
func mkdirOwner(dir string, made map[string]struct{}) error {
	if _, ok := made[dir]; ok {
		return nil
	}
	if err := mkdirOwner(filepath.Dir(dir), made); err != nil {
		return err
	}
	if err := os.Mkdir(dir, outputDirMode); err != nil {
		return fmt.Errorf("edition: creating a directory of the output: %w", err)
	}
	made[dir] = struct{}{}
	return assertDirMode(dir)
}

// writeNewFile creates the file at p (0600, O_CREAT|O_EXCL|O_NOFOLLOW), holds its mode and
// writes data to it.
func writeNewFile(p string, data []byte) (err error) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, outputFileMode)
	if err != nil {
		return fmt.Errorf("edition: creating a file of the output: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("edition: closing a file of the output: %w", cerr)
		}
	}()
	if err := assertMode(f, outputFileMode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("edition: writing a file of the output: %w", err)
	}
	return nil
}

// assertMode is an error unless the open file has exactly the permission bits want.
func assertMode(f *os.File, want fs.FileMode) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("edition: the mode of an output file: %w", err)
	}
	if got := info.Mode().Perm(); got != want {
		return fmt.Errorf("edition: an output file has mode %#o, want %#o (the process's umask took a bit of it)", got, want)
	}
	return nil
}

// assertDirMode is an error unless the directory at p has exactly the permission bits 0700.
func assertDirMode(p string) error {
	info, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("edition: the mode of an output directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("edition: an output directory is not a directory")
	}
	if got := info.Mode().Perm(); got != outputDirMode {
		return fmt.Errorf("edition: an output directory has mode %#o, want %#o (the process's umask took a bit of it)", got, outputDirMode)
	}
	return nil
}
