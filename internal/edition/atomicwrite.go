package edition

// atomicwrite.go is how the validator and the renderer put an output where an operator reads
// it (ADR-0056 D20, D19 A4e-1): all of it or none of it, never a half-written file or a tree
// that is missing a part. The callers are `edition check` (--digests-out, one file),
// `edition render` (--out, a tree) and `edition render --practice` (practice/, a tree that
// replaces the earlier one: replaceTreeAtomic, at the end of this header).
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
//   - every file is synced (f.Sync, after its last write and before it is closed) before the
//     output is put in place: the single file of writeFileAtomic and every file of a tree
//     (writeNewFile). safeopen_source_test.go pins the two calls. No directory is synced, neither the
//     temporary tree's nor the parent of the destination, so a crash can lose the output
//     as a whole (it is then not at the destination), and what is at the destination has
//     the data of its files on disk;
//   - when every file is written, the temporary is put at the destination, and the
//     destination must not exist (an existing file, directory or link, even a dangling link,
//     is refused before anything is made, so an earlier output is never replaced). A single
//     file is put there with os.Link (the temporary's name is removed after it), which fails
//     with EEXIST when the destination exists: a path that another process creates between
//     the check and the link is refused, not replaced. A tree is put there with os.Rename
//     (see below);
//   - when anything fails, the temporary file or tree is removed and nothing is left at the
//     destination or beside it.
//
// The errors are of the kinds the commands turn into exit codes (D20, amendment 13 as revised):
//
//   - a destination that already exists, whether it is seen by the check before anything is
//     made or by the put-in-place itself (EEXIST), is an *InputError that wraps ErrOutputExists
//     (exit 2): the input of the command names an output that is there;
//   - any other failure before the COMMIT POINT is an *OutputError (exit 3: every check passed,
//     and the output's environment failed: no space, no hard link, a name that is too long, a
//     mode the umask took a bit of). The destination does not exist. The temporary is removed
//     as far as it can be (best effort): a temporary name that could not be removed is listed in
//     the error's Left, as a message shows a file name (shownName: cut short, never a value), so
//     the command can tell the operator; it is a name of its own (O_EXCL, a random part), so it
//     does not stand in the way of the next run;
//   - the commit point is the os.Link of the single file and the os.Rename of a tree. After it
//     the output is in place, whole and synced: a temporary name of the single file that cannot
//     be removed then is NOT an error but a warning (writeFileAtomic's left), which the command
//     prints before it exits 0. Undoing the output instead would fail for the same reason in the
//     same directory and leave both names, and the next run would then refuse the output that is
//     there (exit 2).
//
// writeFault is the seam that lets the tests make seven steps fail (V81, V87, V92) without a
// permission (a test may run as root): the write of a file's data, the link, the rename and the
// two removes, and the two renames of a replacement (below). The other failures (a temporary
// that cannot be created, a mode the umask took a bit of, a Sync or a Close that fails) have no
// seam: the tests cause the first two for real (a name over the limit, a umask), and the last two
// are not caused by any test.
//
// The practice edition (D20 `edition render --practice`, A4e-3b) is the one tree that is put IN
// PLACE OF an earlier one: replaceTreeAtomic writes the new tree as a temporary sibling of
// practice/, moves the practice/ that is there aside (a second sibling name), renames the new
// tree to practice/ (the COMMIT POINT) and removes what was moved aside. A failure before the
// commit point moves the earlier practice/ back, so practice/ is as it was, byte for byte (V81),
// and is an *OutputError (exit 3); an earlier practice/ that cannot be moved back is named in the
// error's Restore, not its Left (it is the name beside practice/ that holds it, to be moved back,
// not a temporary to be removed). After the commit point, a moved
// aside practice/ that cannot be removed is a warning (left), as for the single file. A practice
// edition is the public repository's: its directories are 0755 and its files 0644 (D20), set
// after the creation (fchmod of the open file, chmod of the directory just made) so that they do
// not depend on the umask either, and held to that value.
//
// What this does not do:
//   - A tree: os.Rename of a directory replaces an EMPTY directory that another process made
//     at the destination between the check and the rename (it refuses a file, a link and a
//     directory that is not empty). Linux's renameat2 with RENAME_NOREPLACE would close it,
//     but it is Linux only, and golang.org/x/sys is not a direct dependency of this module,
//     so it is not used. The parent directory of the destination belongs to the one operator
//     who runs the command, and nothing else writes in it (ADR-0056 D20): that is the
//     assumption of this case.
//   - A single file: os.Link needs a file system that has hard links. One that has none (or
//     a parent directory that refuses them) is an error, not a fallback to a rename that
//     would replace.

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

	// publicDirMode and publicFileMode are the modes of a practice edition (D20): a tree of the
	// public repository, which git and the image read.
	publicDirMode  fs.FileMode = 0o755
	publicFileMode fs.FileMode = 0o644

	// tempTries is how many random names are tried for the temporary before giving up.
	tempTries = 8
)

// ErrOutputExists is the refusal of a destination that already exists.
var ErrOutputExists = errors.New("edition: the output path already exists")

// OutputError is the failure to put an output in place after every check of the command passed
// (ADR-0056 D20, exit 3, amendment 13): the destination was not made, and the input is one that
// can be given again as it is once the output's environment is fixed. Err is the cause (the
// operating system's reason; never a byte of the output). Left are the temporary names beside
// the destination that could not be removed, as a message shows a file name (cut short and
// quoted: shownName), for the command to print: each is a temporary that may be removed.
// Restore are the names that hold an EARLIER output which was moved aside to be replaced and
// could not be moved back (replaceTreeAtomic, the practice edition's practice/): they are not
// temporaries, and the command tells the operator to move them back in place of the output, not
// to remove them.
type OutputError struct {
	Err     error
	Left    []string
	Restore []string
}

func (e *OutputError) Error() string {
	msg := "the output was not put in place (every check passed: the output's environment failed)"
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *OutputError) Unwrap() error { return e.Err }

// beforeLink is a seam for the tests of the single file's put-in-place: when it is not nil,
// writeFileAtomic calls it between its last check of the destination and the os.Link, which is
// where another process would create the destination. Nothing but a test file assigns it
// (safeopen_source_test.go reads the sources for that), it is nil in every build of the
// program, and a test that sets it does not run in parallel with another one.
var beforeLink func(dest string)

// writeFault is a seam for the tests of exit 3 (ADR-0056 V87, V92): when it is not nil, the
// writers call it (through injected) at each of the steps listed below (not at every step that
// can fail: see the top of this file), before the operating system's call of that step, and an error it returns
// is the failure of the step, the call not being made. Like beforeLink, nothing but a test file
// assigns it (safeopen_source_test.go), it is nil in every build of the program, and a test
// that sets it does not run in parallel with another one.
var writeFault func(step string) error

// The steps writeFault is called at.
const (
	faultWrite     = "write"      // the write of a file's data (ENOSPC, for one)
	faultLink      = "link"       // the os.Link of the single file (the commit point)
	faultRemove    = "remove"     // the os.Remove of the single file's temporary name
	faultRename    = "rename"     // the os.Rename of a tree (the commit point)
	faultRemoveAll = "remove-all" // the os.RemoveAll of a temporary tree (or of a tree moved aside)
	faultBackup    = "backup"     // the os.Rename that moves the earlier tree aside (a replacement)
	faultRestore   = "restore"    // the os.Rename that moves it back after a failure (a replacement)
)

// treeModes are the permission bits of the directories and of the files of a tree, and whether
// they are set after the creation (set: the public practice edition, whatever the umask) or only
// held to after it (the operator's output, whose modes keep the owner's bits under any usual
// umask, and which is refused, not widened, when the umask took one of them).
type treeModes struct {
	dir, file fs.FileMode
	set       bool
}

// ownerTree is the modes of an operator's output (`edition render`'s --out), publicTree the
// modes of a practice edition (`edition render --practice`).
func ownerTree() treeModes { return treeModes{dir: outputDirMode, file: outputFileMode} }

func publicTree() treeModes {
	return treeModes{dir: publicDirMode, file: publicFileMode, set: true}
}

// injected is the failure writeFault gives for step, or nil.
func injected(step string) error {
	if writeFault == nil {
		return nil
	}
	return writeFault(step)
}

// outputPathErr is the kind of a refusal of refuseExisting while the output is written: a
// destination that exists is the command's input naming one (an *InputError, exit 2), and
// anything else is the output's environment (an *OutputError).
func outputPathErr(err error) error {
	if errors.Is(err, ErrOutputExists) {
		return &InputError{Msg: "the output", Err: err}
	}
	return &OutputError{Err: err}
}

// leftBehind is err with the temporary name tmp, which could not be removed, recorded: in err's
// *OutputError when it has one, and otherwise in an *OutputError joined to it (the kind of err,
// an *InputError for one, is what the exit code is made of: a join with an *InputError is 2).
func leftBehind(err error, tmp string, rmErr error) error {
	name := shownName(filepath.Base(tmp))
	var oe *OutputError
	if errors.As(err, &oe) {
		oe.Left = append(oe.Left, name)
		return err
	}
	return errors.Join(err, &OutputError{Err: fmt.Errorf("edition: a temporary output could not be removed: %w", rmErr), Left: []string{name}})
}

// removeTemp removes the single file's temporary name.
func removeTemp(tmp string) error {
	if err := injected(faultRemove); err != nil {
		return err
	}
	return os.Remove(tmp)
}

// outputFile is one file of a tree that writeTreeAtomic writes: Path is slash-separated,
// relative, with no `.`, `..` or empty element (fs.ValidPath), and the directories above the
// file are made as they are needed.
type outputFile struct {
	Path string
	Data []byte
}

// writeFileAtomic writes data to dest (a path that does not exist, in a directory that does)
// as described at the top of this file. The error is an *InputError (dest exists) or an
// *OutputError (the output's environment), and dest does not exist then. left is not empty
// only when err is nil: the output is in place (the commit point, os.Link, was passed) and its
// temporary name could not be removed after it (a warning, never an error).
func writeFileAtomic(dest string, data []byte) (left []string, err error) {
	if err := refuseExisting(dest); err != nil {
		return nil, outputPathErr(err)
	}
	tmp, f, err := createTempFile(dest)
	if err != nil {
		return nil, &OutputError{Err: err}
	}
	defer func() {
		if err == nil {
			return
		}
		_ = f.Close() // closed already on the paths below that close it: a second Close is an error we do not read
		if rmErr := removeTemp(tmp); rmErr != nil {
			err = leftBehind(err, tmp, rmErr)
		}
	}()
	if err = assertMode(f, outputFileMode); err != nil {
		return nil, &OutputError{Err: err}
	}
	if err = injected(faultWrite); err != nil {
		return nil, &OutputError{Err: fmt.Errorf("edition: writing the output: %w", err)}
	}
	if _, err = f.Write(data); err != nil {
		return nil, &OutputError{Err: fmt.Errorf("edition: writing the output: %w", err)}
	}
	if err = f.Sync(); err != nil {
		return nil, &OutputError{Err: fmt.Errorf("edition: syncing the output: %w", err)}
	}
	if err = f.Close(); err != nil {
		return nil, &OutputError{Err: fmt.Errorf("edition: closing the output: %w", err)}
	}
	if beforeLink != nil {
		beforeLink(dest)
	}
	// os.Link is the check and the put-in-place in one step: it fails with EEXIST when anything
	// is at dest (a file, a directory, a link, a dangling link: link(2) does not follow one).
	if err = injected(faultLink); err == nil {
		err = os.Link(tmp, dest)
	}
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, &InputError{Msg: "the output", Err: ErrOutputExists}
		}
		return nil, &OutputError{Err: fmt.Errorf("edition: putting the output in place: %w", err)}
	}
	// The commit point is passed: the output is in place, whole and synced. Its temporary name
	// is a second name of the same file; one that cannot be removed is a warning for the
	// operator (the top of this file says why it is not an error).
	if rmErr := removeTemp(tmp); rmErr != nil {
		return []string{shownName(filepath.Base(tmp))}, nil
	}
	return nil, nil
}

// writeTreeAtomic writes files as a tree at dest (a path that does not exist, in a directory
// that does) as described at the top of this file. files is not empty, the paths are valid
// and distinct, and no path is a directory of another (a file `a` and a file `a/b`): they are
// held to that before anything is made (a plain error: a caller's mistake, not the output's
// environment). Otherwise the error is an *InputError (dest exists) or an *OutputError, and
// dest does not exist then. The commit point is the os.Rename: after it there is nothing left to
// remove.
func writeTreeAtomic(dest string, files []outputFile) (err error) {
	if err := checkOutputPaths(files); err != nil {
		return err
	}
	if err := refuseExisting(dest); err != nil {
		return outputPathErr(err)
	}
	tmp, err := createTempDir(dest, ownerTree())
	if err != nil {
		return &OutputError{Err: err}
	}
	defer func() {
		if err == nil {
			return
		}
		if rmErr := removeTree(tmp); rmErr != nil {
			err = leftBehind(err, tmp, rmErr)
		}
	}()
	if err = writeTreeFiles(tmp, files, ownerTree()); err != nil {
		return &OutputError{Err: err}
	}
	if err = refuseExisting(dest); err != nil {
		return outputPathErr(err)
	}
	if err = injected(faultRename); err == nil {
		err = os.Rename(tmp, dest)
	}
	if err != nil {
		// A directory that another process made at dest in the meantime and that is not empty is
		// refused by rename(2) with EEXIST or ENOTEMPTY (both are fs.ErrExist): dest exists.
		if errors.Is(err, fs.ErrExist) {
			return &InputError{Msg: "the output", Err: ErrOutputExists}
		}
		return &OutputError{Err: fmt.Errorf("edition: putting the output in place: %w", err)}
	}
	return nil
}

// replaceTreeAtomic writes files as a tree at dest, in place of the directory that is at dest
// when there is one (a practice edition's practice/: D20 `edition render --practice`), as the
// top of this file describes: the modes are publicTree's, the commit point is the os.Rename of
// the new tree to dest, and before it dest is what it was. files is held to the rules of
// writeTreeAtomic first (a plain error). A dest that is there and is not a directory (a file, or
// a link, even to a directory) is an *InputError and nothing is made: what is replaced is a
// directory, and a link is never followed. Every other failure before the commit point is an
// *OutputError: the new tree is removed (a name of it that is left is in Left) and the earlier
// directory is moved back to dest (when it cannot be, its name beside dest is in Restore, and dest
// does not exist). left is not empty only when err is nil: the new tree is at dest and the
// earlier one, moved aside, could not be removed after the commit point (a warning).
func replaceTreeAtomic(dest string, files []outputFile) (left []string, err error) {
	if err := checkOutputPaths(files); err != nil {
		return nil, err
	}
	had, err := replaceableDir(dest)
	if err != nil {
		return nil, err
	}
	modes := publicTree()
	tmp, err := createTempDir(dest, modes)
	if err != nil {
		return nil, &OutputError{Err: err}
	}
	aside := ""
	defer func() {
		if err == nil {
			return
		}
		if aside != "" {
			if bErr := putBack(aside, dest); bErr != nil {
				var oe *OutputError
				if errors.As(err, &oe) {
					oe.Err = errors.Join(oe.Err, fmt.Errorf("edition: the earlier output could not be moved back (it is the name to restore beside it): %w", bErr))
					oe.Restore = append(oe.Restore, shownName(filepath.Base(aside)))
				}
			}
		}
		if rmErr := removeTree(tmp); rmErr != nil {
			err = leftBehind(err, tmp, rmErr)
		}
	}()
	if err = writeTreeFiles(tmp, files, modes); err != nil {
		return nil, &OutputError{Err: err}
	}
	if had {
		if aside, err = moveAside(dest); err != nil {
			return nil, &OutputError{Err: err}
		}
	}
	if err = injected(faultRename); err == nil {
		err = os.Rename(tmp, dest)
	}
	if err != nil {
		return nil, &OutputError{Err: fmt.Errorf("edition: putting the output in place: %w", err)}
	}
	// The commit point is passed: the new tree is dest. What was moved aside is the earlier one;
	// one that cannot be removed is a warning for the operator.
	if aside != "" {
		if rmErr := removeTree(aside); rmErr != nil {
			return []string{shownName(filepath.Base(aside))}, nil
		}
	}
	return nil, nil
}

// replaceableDir reports whether dest is a directory that replaceTreeAtomic replaces (false: dest
// does not exist). A dest of another kind (Lstat: a link is not followed) is an *InputError, and
// a dest that cannot be looked at is an *OutputError (the output's environment).
func replaceableDir(dest string) (bool, error) {
	info, err := os.Lstat(dest)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, &OutputError{Err: fmt.Errorf("edition: the output path: %w", err)}
	case !info.IsDir():
		return false, inputErr("the output that is replaced is not a directory (a link or a file is refused)")
	}
	return true, nil
}

// writeTreeFiles writes files under root (a directory that exists and holds nothing): the
// directories above each file are made as they are needed, with the modes of m.
func writeTreeFiles(root string, files []outputFile, m treeModes) error {
	made := map[string]struct{}{root: {}}
	for _, of := range files {
		full := filepath.Join(root, filepath.FromSlash(of.Path))
		if err := mkdirTree(filepath.Dir(full), made, m); err != nil {
			return err
		}
		if err := writeNewFile(full, of.Data, m); err != nil {
			return err
		}
	}
	return nil
}

// removeTree removes a temporary tree, or a tree that was moved aside.
func removeTree(p string) error {
	if err := injected(faultRemoveAll); err != nil {
		return err
	}
	return os.RemoveAll(p)
}

// moveAside renames the directory dest to a new sibling name (hidden, with a random part, that
// did not exist) and returns that name.
func moveAside(dest string) (string, error) {
	for i := 0; i < tempTries; i++ {
		aside, err := siblingName(dest, "old")
		if err != nil {
			return "", err
		}
		if _, err := os.Lstat(aside); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("edition: moving the earlier output aside: %w", err)
		}
		if err := injected(faultBackup); err != nil {
			return "", fmt.Errorf("edition: moving the earlier output aside: %w", err)
		}
		if err := os.Rename(dest, aside); err != nil {
			return "", fmt.Errorf("edition: moving the earlier output aside: %w", err)
		}
		return aside, nil
	}
	return "", errors.New("edition: no unused name to move the earlier output aside")
}

// putBack renames the directory moved aside back to dest.
func putBack(aside, dest string) error {
	if err := injected(faultRestore); err != nil {
		return err
	}
	return os.Rename(aside, dest)
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
func tempName(dest string) (string, error) { return siblingName(dest, "tmp") }

// siblingName is a hidden sibling name of dest of the kind given (`tmp` for a temporary, `old`
// for an earlier tree moved aside), with a random part.
func siblingName(dest, kind string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("edition: no random name for the temporary output: %w", err)
	}
	return filepath.Join(filepath.Dir(dest), "."+filepath.Base(dest)+"."+kind+"-"+hex.EncodeToString(b[:])), nil
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

// createTempDir creates the temporary directory beside dest (m.dir; os.Mkdir does not reuse
// an existing entry and does not follow a link), and sets (m.set) and holds its mode.
func createTempDir(dest string, m treeModes) (string, error) {
	for i := 0; i < tempTries; i++ {
		tmp, err := tempName(dest)
		if err != nil {
			return "", err
		}
		err = os.Mkdir(tmp, m.dir)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("edition: creating the temporary output: %w", err)
		}
		if err := setDirMode(tmp, m); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
		return tmp, nil
	}
	return "", errors.New("edition: no unused name for the temporary output")
}

// mkdirTree makes dir and the directories above it that are not in made yet, each with
// os.Mkdir (m.dir, an existing entry is an error), its mode set (m.set) and held to m.dir after
// it is made. made holds the directories of the temporary tree that exist, the root of it
// included.
func mkdirTree(dir string, made map[string]struct{}, m treeModes) error {
	if _, ok := made[dir]; ok {
		return nil
	}
	if err := mkdirTree(filepath.Dir(dir), made, m); err != nil {
		return err
	}
	if err := os.Mkdir(dir, m.dir); err != nil {
		return fmt.Errorf("edition: creating a directory of the output: %w", err)
	}
	made[dir] = struct{}{}
	return setDirMode(dir, m)
}

// setDirMode sets the mode of the directory p that was just made to m.dir when m.set (the
// directory is the process's own, made inside its temporary tree, so the path is not another
// process's), and holds it to m.dir.
func setDirMode(p string, m treeModes) error {
	if m.set {
		if err := os.Chmod(p, m.dir); err != nil {
			return fmt.Errorf("edition: setting the mode of an output directory: %w", err)
		}
	}
	return assertDirMode(p, m.dir)
}

// writeNewFile creates the file at p (m.file, O_CREAT|O_EXCL|O_NOFOLLOW), sets (m.set, on the
// open descriptor) and holds its mode, writes data to it and syncs it before it is closed.
func writeNewFile(p string, data []byte, m treeModes) (err error) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, m.file)
	if err != nil {
		return fmt.Errorf("edition: creating a file of the output: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("edition: closing a file of the output: %w", cerr)
		}
	}()
	if m.set {
		if err := f.Chmod(m.file); err != nil {
			return fmt.Errorf("edition: setting the mode of an output file: %w", err)
		}
	}
	if err := assertMode(f, m.file); err != nil {
		return err
	}
	if err := injected(faultWrite); err != nil {
		return fmt.Errorf("edition: writing a file of the output: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("edition: writing a file of the output: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("edition: syncing a file of the output: %w", err)
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

// assertDirMode is an error unless the directory at p (Lstat: not a link) has exactly the
// permission bits want.
func assertDirMode(p string, want fs.FileMode) error {
	info, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("edition: the mode of an output directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("edition: an output directory is not a directory")
	}
	if got := info.Mode().Perm(); got != want {
		return fmt.Errorf("edition: an output directory has mode %#o, want %#o (the process's umask took a bit of it)", got, want)
	}
	return nil
}
