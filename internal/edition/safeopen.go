package edition

// safeopen.go is how the validator opens a file of its input (ADR-0056 D20 on the form of the
// files, the ownership of the input tree in D9, V57, D19 A4e-1). The tree the validator reads
// is the operator's, and is mounted read-only into its container; still, a reader that follows a link or takes
// whatever is at a path when it gets there would read a file that is not the one that was
// looked at. openRegular is the one way a file is opened for that:
//
//   - Lstat the path first (no link is followed) and refuse what is not a regular file: a
//     link, a directory, a special file;
//   - open it with O_NOFOLLOW, so that a path that became a link after the Lstat is refused by
//     the operating system and is never followed;
//   - Stat the OPEN descriptor, and hold it to the Lstat: a regular file, and the same device
//     and inode. A path that was replaced by another regular file between the two is refused.
//
// Every reader of a file of the validator's input uses it: the answers table (readTable), the
// files of a bundle, of a template and of the corpus (readCapped), and the practice answers
// (loadPractice). The readers of the other files of D20 (the key, the seats, the previous
// seats and digests) are A4e-2's and A4e-3's, and use it too.
//
// The scoreboard's start-up does NOT use it for ANSWERS_FILE: the answers Secret is a
// directory volume, and a file in one is a link (..data/<key>) by the way Kubernetes makes it
// atomic, so O_NOFOLLOW would refuse every real deployment. The start-up opens it with
// openFollowing. That is the only difference between the two paths of reading the table (the
// shared function loadChecked takes the opener), and safeopen_source_test.go pins which
// opener each door passes, and that no other file of the package opens, reads or writes a
// file by itself.

import (
	"errors"
	"os"
	"syscall"
)

// fileOpener opens a file for reading: openRegular for the validator, openFollowing for the
// start-up's answers file.
type fileOpener func(path string) (*os.File, error)

var (
	errNotRegular = errors.New("the path is not a regular file (a link, a directory or a special file is refused)")
	errReplaced   = errors.New("the file at the path changed while it was being opened")
)

// afterLstat is a seam for the tests of V57: when it is not nil, openRegular calls it between
// its Lstat and its open, which is where a file is swapped by an attacker with the right to
// write the tree. Nothing but a test file assigns it (safeopen_source_test.go reads the
// sources for that), it is nil in every build of the program, and a test that sets it does not
// run in parallel with another one (the package has no parallel test).
var afterLstat func(path string)

// openRegular is described at the top of this file. The caller reads and closes the file.
// The errors name the operating system's reason and never a byte of the file.
func openRegular(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if afterLstat != nil {
		afterLstat(path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !after.Mode().IsRegular() {
		_ = f.Close()
		return nil, errNotRegular
	}
	if !os.SameFile(before, after) {
		_ = f.Close()
		return nil, errReplaced
	}
	return f, nil
}

// openFollowing is os.Open: the scoreboard's start-up reads ANSWERS_FILE through it (see the
// top of this file for why it cannot be openRegular).
func openFollowing(path string) (*os.File, error) { return os.Open(path) }
