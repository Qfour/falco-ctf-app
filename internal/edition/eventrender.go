package edition

// eventrender.go is `scoreboard edition render` (the event's) as a function (ADR-0056 D20, D19
// A4e-3a): it reads the inputs, renders every investigate challenge of the scope, checks its own
// output and puts the output in place, in the order D20 gives. The command (cmd/scoreboard)
// only reads its arguments, calls RenderEvent and prints; it opens and writes no file.
//
// The steps (D20 `edition render`, the numbers are D20's):
//
//	(0) the arguments and the guard of --out: every argument given, exactly one of the previous
//	    seats and --no-previous, and an output path that does not exist, whose directory does,
//	    that is not in a git worktree (no .git, a directory or a file, in the directory of the
//	    output or above it, the links of the directory resolved) and not in the challenges
//	    tree. The guard is of the path the operator gives: a public repository must not get a
//	    rendered event by a mistake of a path. It sees the paths the process sees and nothing
//	    else: run in a container whose parent of --out is a bind mount, it does not see a git
//	    worktree on the host's side of the mount, and the guard of that way is the platform's
//	    (a check on the host, ADR-0056 V83). --practice (A4e-3b) has none of this;
//	1.  the inputs: the seats, the previous seats, the key, catalog.LoadScored (a scope with no
//	    investigate challenge is a usage error), the event edition of every challenge (the set
//	    of the directories is E2), and per challenge E1 (ParseSpec), E2 and B8 (a1)
//	    (CheckQuestions) and B8 (a2) (CheckSeatSpace for the seats given, the renderer's rule E3);
//	2.  the run id: 128 bits of crypto/rand, never all zeros;
//	3.  Render for every challenge (E3 included), with the previous seats or NoPreviousSeats;
//	4.  the self check of the output: B7 (CheckDecoySpread) and B8 (b) (CheckOutputSpace) on the
//	    bundles, and the bytes of the answers table through checkAnswersData (load.go: Parse and
//	    Check in the event mode with the practice answers and the flags, the one Parse and Check
//	    of the program) and MaxTableBytes;
//	5.  the tree (answers.tsv, evidence/<seat>/<cid>/<file>, render-record.tsv: the Event* names
//	    of practicelayout.go) written as a temporary sibling of --out and renamed to it
//	    (writeTreeAtomic: directories 0700 and files 0600 whatever the umask). No digests file is
//	    written: the event's digests are `edition check`'s (--digests-out), for a *CheckedEvent.
//
// Wherever it stops, nothing is at --out. The errors are the kinds of `edition check`'s, and the
// command gives them its exit codes: a *Violation (or a join of them) is a rule's refusal (exit
// 1), an *InputError a usage error or an input that cannot be read or is not in its form (exit
// 2), and the *OutputError of step 5 a failure of the output's environment after every check
// passed (exit 3). Nothing here names a value, the key or a word of a vocabulary.
//
// Reach (D9, D13, V78): this file is the ONE file outside the render files that refers to what
// they declare (render_reach_test.go's renderCallers), and RenderEvent is called by the
// command's runEditionRender and by nothing else (load_source_test.go). It is not named
// render*.go because it reads files and the clockless, diskless rule of the render files is not
// its rule (render_reach_test.go, TestRenderFilesAreDeterministicAndPure).

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

const (
	// maxKeyFileBytes bounds the key file, which is one line of hex.
	maxKeyFileBytes = 4 << 10
	// keyFileOthersBits are the permission bits of the group and of others: a key file has none
	// of them (D20: mode & 0o077 == 0).
	keyFileOthersBits fs.FileMode = 0o077
	// gitEntryName is what makes a directory a git worktree (a directory, or a file in a linked
	// worktree or a submodule).
	gitEntryName = ".git"
	// runIDTries is how many random run ids are drawn before giving up on one that is not all
	// zeros (one draw in 2^128 is).
	runIDTries = 8
)

// RenderEventInput is what `edition render` (the event's) is given: the paths of its arguments
// (D20). Every one is required, except that exactly one of PreviousSeatsFile and NoPrevious is
// given. The files are opened by this package's readers (safeopen.go), never by the caller.
type RenderEventInput struct {
	// Challenges (`--challenges`), ScenarioFile and FlagsFile are catalog.LoadScored's inputs.
	// The flags are this event's (T7 and B3 of the self check).
	Challenges   string
	ScenarioFile string
	FlagsFile    string
	// EditionRoot is the tree <cid>/{edition.yaml, template/<file>} of the event edition
	// (`--edition-root`), SeatsFile the ordered list of the seats (`--seats`).
	EditionRoot string
	SeatsFile   string
	// PreviousSeatsFile is the seats file of the last render of this event (`--previous-seats`,
	// at least one seat), NoPrevious says this is the first one (`--no-previous`): one of the
	// two and not both, so that a previous list that was lost is never read as a first render.
	PreviousSeatsFile string
	NoPrevious        bool
	// KeyFile is the master key (`--key-file`): one line of lower-case hex, an even number of
	// digits and at least 2 x MinMasterKeyBytes of them, in a regular file that its group and
	// others cannot read. The key is given in a file and nowhere else.
	KeyFile string
	// Out is the output directory (`--out`): it must not exist yet, its directory must, and it
	// is neither in a git worktree nor in the challenges tree.
	Out string
}

// validate is step (0): the usage errors that need no file but the guard of the output path.
func (in RenderEventInput) validate() error {
	for _, a := range []struct{ name, val string }{
		{"challenges", in.Challenges},
		{"scenario", in.ScenarioFile},
		{"flags-file", in.FlagsFile},
		{"edition-root", in.EditionRoot},
		{"seats", in.SeatsFile},
		{"key-file", in.KeyFile},
		{"out", in.Out},
	} {
		if a.val == "" {
			return inputErr("the argument " + a.name + " is missing or empty (every argument is required)")
		}
	}
	if in.NoPrevious == (in.PreviousSeatsFile != "") {
		return inputErr("exactly one of previous-seats and no-previous is required (a previous list that was lost must not read as a first render)")
	}
	return checkRenderOut(in.Out, in.Challenges)
}

// checkRenderOut is the guard of `--out` (D20): out does not exist (in any form: a dangling link
// is a path that exists), the directory of out exists, and neither a .git (a directory or a
// file) in that directory or in one above it, once its links are resolved (filepath.Abs, and
// filepath.EvalSymlinks of the directory of out), nor the challenges tree holds out. Every
// refusal is an *InputError; a directory above out that cannot be looked at is one too (the
// guard is not passed by what it could not see).
func checkRenderOut(out, challenges string) error {
	if err := refuseExisting(out); err != nil {
		return &InputError{Msg: "the output (--out)", Err: err}
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return &InputError{Msg: "the output (--out) has no absolute path", Err: err}
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return &InputError{Msg: "the directory of the output (--out) does not exist or cannot be resolved", Err: err}
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return inputErr("the directory of the output (--out) is not a directory")
	}
	for d := dir; ; d = filepath.Dir(d) {
		_, err := os.Lstat(filepath.Join(d, gitEntryName))
		switch {
		case err == nil:
			return inputErr("the output (--out) is inside a git worktree (a " + gitEntryName + " is in its directory or above it): a rendered event is not put where a repository can take it in")
		case !errors.Is(err, fs.ErrNotExist):
			return &InputError{Msg: "a directory above the output (--out) cannot be looked at for a " + gitEntryName, Err: err}
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	tree, err := filepath.Abs(challenges)
	if err == nil {
		tree, err = filepath.EvalSymlinks(tree)
	}
	if err != nil {
		return &InputError{Msg: "the challenges tree (--challenges) cannot be resolved", Err: err}
	}
	if pathWithin(tree, filepath.Join(dir, filepath.Base(abs))) {
		return inputErr("the output (--out) is inside the challenges tree (--challenges)")
	}
	return nil
}

// pathWithin reports whether p is base or a path under it (both absolute and clean).
func pathWithin(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// readKeyFile reads `--key-file` (D20): a regular file opened by openRegular (no link is
// followed), whose group and others have no permission bit (the mode of the open descriptor),
// of one line that is an even number of lower-case hex digits, at least 2 x MinMasterKeyBytes,
// ending with a newline, and at most maxKeyFileBytes. Every defect is an *InputError whose
// message names no byte of the file.
//
// The copies of the key: the file is read into one buffer of maxKeyFileBytes+1 bytes (no
// growing buffer leaves an earlier copy behind), its form is checked on those bytes (no string
// is made of them), and they are decoded into a second buffer; both are cleared before it
// returns. What is left is the copy NewMasterKey makes, which the MasterKey holds for the render
// (and which nothing clears: it lives until the garbage collector frees it), and whatever the
// kernel and the file system keep of the file.
func readKeyFile(path string) (MasterKey, error) {
	bad := func(msg string) error { return inputErr("the key file (--key-file) " + msg) }
	f, err := openRegular(path)
	if err != nil {
		return MasterKey{}, &InputError{Msg: "the key file (--key-file) cannot be read", Err: err}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return MasterKey{}, &InputError{Msg: "the key file (--key-file) cannot be read", Err: err}
	}
	if perm := info.Mode().Perm(); perm&keyFileOthersBits != 0 {
		return MasterKey{}, bad(fmt.Sprintf("has mode %#o: its group and others must have no permission on it (0600 or 0400)", perm))
	}
	buf := make([]byte, maxKeyFileBytes+1)
	defer clear(buf)
	n, err := io.ReadFull(f, buf)
	switch {
	case err == nil:
		return MasterKey{}, bad("is larger than its limit")
	case err != io.EOF && err != io.ErrUnexpectedEOF:
		return MasterKey{}, &InputError{Msg: "the key file (--key-file) cannot be read", Err: err}
	}
	data := buf[:n]
	switch {
	case len(data) == 0:
		return MasterKey{}, bad("is empty")
	case data[len(data)-1] != '\n':
		return MasterKey{}, bad("must end with a newline")
	}
	digits := data[:len(data)-1]
	switch {
	case bytes.IndexByte(digits, '\n') >= 0:
		return MasterKey{}, bad("is more than one line")
	case !lowerHex(digits):
		// a carriage return, a byte that is not UTF-8 and an invisible rune are refused here too
		return MasterKey{}, bad("is not lower-case hex digits only")
	case len(digits)%2 != 0:
		return MasterKey{}, bad("has an odd number of hex digits")
	case len(digits) < 2*MinMasterKeyBytes:
		return MasterKey{}, bad(fmt.Sprintf("is shorter than %d hex digits (%d bytes)", 2*MinMasterKeyBytes, MinMasterKeyBytes))
	}
	raw := make([]byte, len(digits)/2)
	defer clear(raw)
	if _, err := hex.Decode(raw, digits); err != nil {
		return MasterKey{}, bad("is not lower-case hex digits only")
	}
	key, err := NewMasterKey(raw)
	if err != nil {
		return MasterKey{}, &InputError{Msg: "the key file (--key-file) is not a key an event is rendered with", Err: err}
	}
	return key, nil
}

// newRunID is step 2: 32 lower-case hex digits of crypto/rand, never the practice run id.
func newRunID() (string, error) {
	for i := 0; i < runIDTries; i++ {
		b := make([]byte, runIDLen/2) // the run id's length is the table's (runIDLen hex digits)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("edition: no random run id: %w", err)
		}
		if id := hex.EncodeToString(b); validRunID(id) && id != PracticeRunID {
			return id, nil
		}
	}
	return "", errors.New("edition: every random run id was all zeros")
}

// RenderedEvent is an event that RenderEvent rendered, checked and put at --out. It carries
// what the command's one line of success says: the run id, how many seats and challenges were
// rendered, and the key's fingerprint (a value that may be shown: it does not give the key
// back, and the render record holds it too). It holds no value and no key.
type RenderedEvent struct {
	runID       string
	seats       int
	challenges  int
	fingerprint string
}

// RunID is the run id of the render (the answers table's and the render record's).
func (ev *RenderedEvent) RunID() string { return ev.runID }

// Seats is how many seats were rendered.
func (ev *RenderedEvent) Seats() int { return ev.seats }

// Challenges is how many investigate challenges were rendered.
func (ev *RenderedEvent) Challenges() int { return ev.challenges }

// KeyFingerprint is the key's fingerprint, as the render record holds it.
func (ev *RenderedEvent) KeyFingerprint() string { return ev.fingerprint }

// RenderEvent runs the steps of the header on in and returns the *RenderedEvent only when the
// output is in place at in.Out; otherwise it returns no event, an error (the kinds are in the
// header) and nothing is at in.Out.
func RenderEvent(in RenderEventInput) (*RenderedEvent, error) {
	// (0) The arguments and the guard of the output path.
	if err := in.validate(); err != nil {
		return nil, err
	}

	// 1. The inputs.
	seats, err := readSeatsFile(in.SeatsFile)
	if err != nil {
		return nil, err
	}
	previous := NoPreviousSeats()
	if !in.NoPrevious {
		prev, err := readSeatsFile(in.PreviousSeatsFile)
		if err != nil {
			return nil, &InputError{Msg: "the previous seats file (--previous-seats)", Err: err}
		}
		previous = PreviousSeatsOf(prev)
	}
	key, err := readKeyFile(in.KeyFile)
	if err != nil {
		return nil, err
	}
	scored, err := catalog.LoadScored(in.Challenges, in.ScenarioFile, in.FlagsFile)
	if err != nil {
		return nil, &InputError{Msg: "the challenges, the scenario or the flags file cannot be loaded", Err: err}
	}
	scope := ScopeOf(scored.Catalog)
	if !scope.HasInvestigate() {
		return nil, inputErr("the scenario has no investigate challenge, so there is no edition to render")
	}
	editions, err := readEditions(in.EditionRoot, scope)
	if err != nil {
		return nil, classify("the edition root cannot be read", err)
	}
	cids := scope.sortedCIDs()
	var refusals []error
	for _, cid := range cids {
		ed := editions[cid]
		spec, err := ParseSpec(ed.specData)
		if err != nil {
			refusals = append(refusals, err)
			continue
		}
		ed.spec = spec
		refusals = append(refusals,
			spec.CheckQuestions(cid, scope[cid]),
			spec.CheckSeatSpace(cid, scope[cid], len(seats), RuleSpecRender))
	}
	if err := errors.Join(refusals...); err != nil {
		return nil, err
	}

	// 2. The run id.
	runID, err := newRunID()
	if err != nil {
		return nil, err
	}

	// 3. The render of every challenge.
	bundles := make(map[string][]*Bundle, len(cids))
	var rows []AnswerRow
	for _, cid := range cids {
		ed := editions[cid]
		r, err := Render(RenderInput{
			CID:       cid,
			Questions: scope[cid],
			Spec:      ed.spec,
			Template:  ed.template,
			Key:       key,
			Seats:     seats,
			Previous:  previous,
		})
		if err != nil {
			refusals = append(refusals, err)
			continue
		}
		bundles[cid] = r.Bundles
		rows = append(rows, r.Rows...)
	}
	if err := errors.Join(refusals...); err != nil {
		return nil, err
	}

	// 4. The self check: what is about to be written is held to the validator's own rules of
	// the output, and the table to the one Parse and Check of the program.
	for _, cid := range cids {
		ed := editions[cid]
		refusals = append(refusals,
			CheckDecoySpread(cid, ed.spec, scope[cid], ed.template, bundles[cid]),
			CheckOutputSpace(cid, scope[cid], bundles[cid]))
	}
	var table bytes.Buffer
	if err := WriteAnswers(&table, runID, rows); err != nil {
		refusals = append(refusals, err)
	} else if table.Len() > MaxTableBytes {
		refusals = append(refusals, newViolation(RuleShape, "the answers table of the render is larger than the size limit", 0, cell{}, nil))
	} else if _, _, _, err := checkAnswersData(scored, table.Bytes(), true); err != nil {
		refusals = append(refusals, classify("the answers table of the render cannot be checked", err))
	}
	if err := errors.Join(refusals...); err != nil {
		return nil, err
	}
	var record bytes.Buffer
	if err := WriteRenderRecord(&record, runID, key); err != nil {
		return nil, err
	}

	// 5. The output, as one tree put at --out.
	files := []outputFile{{Path: EventAnswersFileName, Data: table.Bytes()}}
	for _, cid := range cids {
		for _, b := range bundles[cid] {
			for _, f := range b.Files {
				files = append(files, outputFile{Path: EventEvidenceDirName + "/" + b.Seat + "/" + b.CID + "/" + f.Name, Data: f.Data})
			}
		}
	}
	files = append(files, outputFile{Path: EventRenderRecordFileName, Data: record.Bytes()})
	if err := writeTreeAtomic(in.Out, files); err != nil {
		return nil, err
	}
	return &RenderedEvent{runID: runID, seats: len(seats), challenges: len(cids), fingerprint: key.Fingerprint()}, nil
}
