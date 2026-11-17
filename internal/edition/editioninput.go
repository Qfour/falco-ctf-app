package edition

// editioninput.go is the readers of the inputs of `edition check` that are not an answers table,
// a bundle tree or a corpus (ADR-0056 D20, D19 A4e-2): the list of the seats, the previous
// digests, the render record and the event edition (edition.yaml and template per challenge).
// Every file is opened by openRegular through readCapped (safeopen.go: O_NOFOLLOW, O_NONBLOCK
// and the open descriptor's Stat held to the Lstat), never by a function of its own, and a
// directory is listed with os.ReadDir (the guarantee is the last element of a path, D9). The
// key's reader is eventrender.go's (readKeyFile, A4e-3a: it makes a key, which only that file
// outside the render files may), and `edition render` reads its seats and its previous seats
// with readSeatsFile below.
//
// Two kinds of defect, as in checkevent.go: a file that cannot be read (missing, a link, not a
// regular file), or whose form is wrong (a seats file, a previous digests file, a render record),
// and an entry of the edition root named like a challenge id that is not a directory, is an
// *InputError (exit 2); an edition root whose set of challenges is not the scope's, and a
// defect of the content of a template file (B2), are a rule's violation (exit 1). A message
// names a line or a challenge, never a byte of a file.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/sourcehygiene"
)

const (
	// seatsHeader is the first line of a seats file (D20).
	seatsHeader = "# falco-ctf seats v1"
	// maxRenderRecordBytes bounds the render record, which is three short lines.
	maxRenderRecordBytes = 4 << 10
)

// controlText is the text of a small control file (the seats, the render record) without its
// final newline: UTF-8, LF only, no rune sourcehygiene.Hidden reports, and a final newline. The
// error names a line and never a byte.
func controlText(data []byte) (string, error) {
	switch {
	case len(data) == 0:
		return "", errors.New("the file is empty")
	case !utf8.Valid(data):
		return "", errors.New("the file is not valid UTF-8")
	}
	if i := bytes.IndexByte(data, '\r'); i >= 0 {
		return "", fmt.Errorf("line %d: a carriage return is not allowed", lineAt(data, i))
	}
	if found := sourcehygiene.Hidden(data); len(found) > 0 {
		return "", fmt.Errorf("line %d: an invisible or bidi control character", found[0].Line)
	}
	if data[len(data)-1] != '\n' {
		return "", errors.New("the file must end with a newline")
	}
	return string(data[:len(data)-1]), nil
}

// readSeatsFile reads `--seats`: seatsHeader, then one seat per line (ADR-0042's grammar), in
// order, no repeat, no blank line and no comment, at least one seat. Every defect is an
// *InputError.
func readSeatsFile(path string) ([]string, error) {
	data, err := readCapped(path, MaxTableBytes)
	if err != nil {
		return nil, &InputError{Msg: "the seats file cannot be read", Err: err}
	}
	seats, err := parseSeats(data)
	if err != nil {
		return nil, &InputError{Msg: "the seats file is not in its form", Err: err}
	}
	return seats, nil
}

func parseSeats(data []byte) ([]string, error) {
	text, err := controlText(data)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(text, "\n")
	if lines[0] != seatsHeader {
		return nil, errors.New("line 1: the first line must be the seats v1 header")
	}
	seats := make([]string, 0, len(lines)-1)
	seen := make(map[string]struct{}, len(lines)-1)
	for i, ln := range lines[1:] {
		no := i + 2
		if !identity.ValidSeat(ln) {
			return nil, fmt.Errorf("line %d: not a seat of the seat grammar (ADR-0042; no blank line, no comment)", no)
		}
		if _, dup := seen[ln]; dup {
			return nil, fmt.Errorf("line %d: a seat is listed twice", no)
		}
		seen[ln] = struct{}{}
		seats = append(seats, ln)
	}
	if len(seats) == 0 {
		return nil, errors.New("the file lists no seat (a header alone is not a seat list)")
	}
	return seats, nil
}

// readPreviousDigests reads `--previous-digests` with ParseDigests (D9's form). A header alone
// (no row) is refused as ParseDigests refuses it: a previous file that was cut short must not
// read as a first check, which is `--no-previous` and nothing else. Every defect is an
// *InputError.
func readPreviousDigests(path string) ([]DigestRow, error) {
	data, err := readCapped(path, MaxTableBytes)
	if err != nil {
		return nil, &InputError{Msg: "the previous digests file cannot be read", Err: err}
	}
	_, rows, err := ParseDigests(data)
	if err != nil {
		return nil, &InputError{Msg: "the previous digests file is not in its form (a header alone is not a first check: that is --no-previous)", Err: err}
	}
	return rows, nil
}

// readRenderRecord reads `--render-record` and returns its run id. A file that cannot be read,
// and a record that is not D20's three lines (the header, run-id TAB a run id that is not all
// zeros, key-fingerprint TAB 64 hex digits; the names are renderrecord.go's, which writes
// them), are an *InputError (exit 2: the form of an input file is wrong).
func readRenderRecord(path string) (string, error) {
	data, err := readCapped(path, maxRenderRecordBytes)
	if err != nil {
		return "", &InputError{Msg: "the render record cannot be read", Err: err}
	}
	return parseRenderRecord(data)
}

func parseRenderRecord(data []byte) (string, error) {
	// A record that is not in its form is an input whose form is wrong (D20: exit 2), like a
	// seats file or a key; the run id it holds not matching the table's is a rule's refusal
	// (CheckEvent, step 3).
	bad := func(msg string, line int) error {
		if line > 0 {
			msg += " (line " + strconv.Itoa(line) + ")"
		}
		return inputErr(msg)
	}
	text, err := controlText(data)
	if err != nil {
		return "", bad("the render record is not in its form: "+err.Error(), 0)
	}
	lines := strings.Split(text, "\n")
	if len(lines) != 3 {
		return "", bad("the render record is three lines: the header, the run id and the key fingerprint", 0)
	}
	if lines[0] != renderRecordHeader {
		return "", bad("the first line of the render record must be the render-record v1 header", 1)
	}
	id, ok := strings.CutPrefix(lines[1], renderRecordRunID+"\t")
	if !ok || !validRunID(id) || id == PracticeRunID {
		return "", bad("the second line of the render record must be the run id: 32 lower-case hex digits, not all zeros", 2)
	}
	if fp, ok := strings.CutPrefix(lines[2], renderRecordFingerprint+"\t"); !ok || !ValidDigest(fp) {
		return "", bad("the third line of the render record must be the key fingerprint: 64 lower-case hex digits", 3)
	}
	return id, nil
}

// eventEdition is the event edition of one challenge as `--edition-root` holds it:
// <root>/<cid>/edition.yaml (read as bytes: ParseSpec is E1, step 4) and the files of
// <root>/<cid>/template/. spec is set by checkEditions once the file parsed.
type eventEdition struct {
	specData []byte
	spec     *Spec
	template []BundleFile
}

// readEditions reads the event edition of every challenge of the scope. The set of directories
// of the root must be the scope's (a directory of another challenge, a name that is not a
// challenge id, and a challenge with no directory are violations of E2, which lists every one
// before it stops). An entry named like a challenge id that is not a directory (a file, or a
// link, even to a directory) is an input that is not of its kind, an *InputError (exit 2,
// D20 as amendment 13 revised it: not E2), returned as soon as it is seen. A directory's
// edition.yaml that cannot be read, and a template directory that has no file, are an
// *InputError; the template files are read as a bundle is (readFlatDir, B2: a defect of one is
// a B2 violation).
func readEditions(root string, scope Scope) (map[string]*eventEdition, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, &InputError{Msg: "the edition root cannot be read", Err: err}
	}
	var c collector
	have := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		name := e.Name()
		switch _, inScope := scope[name]; {
		case !challengeid.Valid(name):
			c.add(newBundleViolation(RuleSpecQuestion, "an entry of the edition root is not named like a challenge id", cell{}, name))
		case !e.IsDir():
			// os.ReadDir reports the entry's own type (it does not follow a link), so a link to a
			// directory is not a directory here.
			return nil, inputErr("the entry " + name + " of the edition root is not a directory (a link or a file is refused)")
		case !inScope:
			c.add(newViolation(RuleSpecQuestion, "the edition root has a directory of a challenge that is not an investigate challenge of the scope", 0, cell{cid: name}, nil))
		default:
			have[name] = struct{}{}
		}
	}
	for _, cid := range scope.sortedCIDs() {
		if _, ok := have[cid]; !ok {
			c.add(newViolation(RuleSpecQuestion, "the edition root has no directory for this investigate challenge of the scope", 0, cell{cid: cid}, nil))
		}
	}
	if err := c.err(); err != nil {
		return nil, err
	}
	out := make(map[string]*eventEdition, len(scope))
	for _, cid := range scope.sortedCIDs() {
		ed, err := readEditionFiles(cid, filepath.Join(root, cid))
		if err != nil {
			return nil, err
		}
		out[cid] = ed
	}
	return out, nil
}

// readEditionFiles reads the edition of the challenge cid at dir: dir/edition.yaml (as bytes) and
// the files of dir/template/. It is the reader of an event edition (readEditions, the directory
// <root>/<cid>) and of the image's edition that `edition render --practice` renders
// (RenderPracticeEdition, the directory <challenges>/<cid>/edition), so the two are read alike.
// An edition.yaml that cannot be read, an entry of the template directory that is not a regular
// file and a template directory that is missing or has no file are an *InputError; the template
// files are read as a bundle is (readFlatDir, B2).
func readEditionFiles(cid, dir string) (*eventEdition, error) {
	spec, err := readCapped(filepath.Join(dir, SpecFileName), MaxSpecBytes+1)
	if err != nil {
		return nil, &InputError{Msg: "the " + SpecFileName + " of " + cid + " cannot be read", Err: err}
	}
	// An entry of the template directory that is not a regular file (a link, a directory, a
	// special file) is an input that is not a file of its kind: exit 2 (D20), before the
	// content of the files is held to B2.
	if list, lerr := os.ReadDir(filepath.Join(dir, TemplateDirName)); lerr == nil {
		for _, e := range list {
			if !e.Type().IsRegular() {
				return nil, inputErr("an entry of the " + TemplateDirName + " directory of " + cid + " is not a regular file (a link or a directory is refused)")
			}
		}
	}
	template, err := readFlatDir(cid, dir, TemplateDirName)
	if err != nil {
		return nil, err
	}
	if len(template) == 0 {
		return nil, inputErr("the " + TemplateDirName + " directory of " + cid + " is missing or has no file")
	}
	return &eventEdition{specData: spec, template: template}, nil
}
