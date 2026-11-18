package edition

// digests.go is the digests file of an event (ADR-0056 D9, D11, D19 A4b): what
// `scoreboard edition check` writes when it accepts a tree of bundles (--digests-out),
// and what deploy-user.sh and the platform's preflight read to hold the bytes they
// plant to the bytes the validator accepted. The file is
//
//	# falco-ctf evidence-digests v1 run=<32 lower-case hex digits>
//	<seat> TAB <cid> TAB <digest>          one row per (seat, challenge), digest = BundleDigest
//
// WriteDigests and ParseDigests are its two ends in Go (a practice edition's file, the run id
// of all zeros and the seat *, has its own two: WritePracticeDigests and ParsePracticeDigests,
// over the same reader and the same row grammar; deploy-user.sh's practice path reads that
// file, ADR-0056 A5c-2); CheckDigestSet is V48's Go side:
// the (seat, cid) pairs of the rows are exactly the seats x the investigate challenges of
// the scope. The run id is the answers table's (D9): a digests file whose run id is not
// the table's is a table and a bundle from two different renders.

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/sourcehygiene"
)

const (
	// RuleDigests is the rule of a digests file and of the (seat, cid) set it holds
	// (D9, V48).
	RuleDigests = "D9"

	digestsHeaderPrefix = "# falco-ctf evidence-digests v1 run="
	digestColumns       = 3
	digestHexLen        = 64
)

// DigestRow is the digest of the bundle of one (seat, challenge) pair.
type DigestRow struct {
	Seat   string
	CID    string
	Digest string
}

// ValidDigest reports whether s is a digest: 64 lower-case hex digits.
func ValidDigest(s string) bool { return len(s) == digestHexLen && lowerHex(s) }

// digestsRunIDAllowed is the one rule of the run id of a digests file, for its two doors
// (D9): an event's is 32 lower-case hex digits and not all zeros, a practice edition's is
// the run id of all zeros and no other. The writers and the readers of both doors use it.
func digestsRunIDAllowed(runID string, practice bool) bool {
	if practice {
		return runID == PracticeRunID
	}
	return validRunID(runID) && runID != PracticeRunID
}

// checkDigestRowOf is the shape of one row for the door named by practice: checkDigestRow
// for an event, checkPracticeDigestRow for a practice edition.
func checkDigestRowOf(r DigestRow, line int, practice bool) error {
	if practice {
		return checkPracticeDigestRow(r, line)
	}
	return checkDigestRow(r, line)
}

// checkPracticeDigestRow is the shape of one row of a practice digests file: the seat * and
// no other, a challenge id and a digest in their grammars. line is 0 for a row that was not
// read from a file.
func checkPracticeDigestRow(r DigestRow, line int) error {
	c := cell{seat: r.Seat, cid: r.CID}
	switch {
	case r.Seat != AnySeat:
		return newViolation(RuleDigests, "a practice digests file has the seat * only", line, c, nil)
	case !challengeid.Valid(r.CID):
		return newViolation(RuleDigests, "cid is not a challenge id", line, c, nil)
	case !ValidDigest(r.Digest):
		return newViolation(RuleDigests, "digest is not 64 lower-case hex digits", line, c, nil)
	}
	return nil
}

// checkDigestRow is the shape of one row: a seat (never the practice seat *), a
// challenge id and a digest, each in its own grammar. line is 0 for a row that was not
// read from a file.
func checkDigestRow(r DigestRow, line int) error {
	c := cell{seat: r.Seat, cid: r.CID}
	switch {
	case !identity.ValidSeat(r.Seat):
		return newViolation(RuleDigests, "seat is outside the seat grammar (ADR-0042)", line, c, nil)
	case !challengeid.Valid(r.CID):
		return newViolation(RuleDigests, "cid is not a challenge id", line, c, nil)
	case !ValidDigest(r.Digest):
		return newViolation(RuleDigests, "digest is not 64 lower-case hex digits", line, c, nil)
	}
	return nil
}

// WriteDigests writes the digests file of an event that went through every check of D20
// (ADR-0056 D9 M2, amendment 12): the header with the run id of the answers table the event
// was checked against (ev.RunID), then the rows in byte order of (seat, cid), so one set of rows
// is one file. It takes a *CheckedEvent and nothing weaker: CheckEvent makes one only when E1,
// E2, B8 (a1) and (a2), B1 to B10 and the run id of the render record have all passed, so
// there is no way to write a digests file for an event that a rule refused, or for rows that
// CheckBundles did not give, or under another run id than the table's. It still refuses what it
// always refused, so that the one writer cannot make a file the readers refuse: a run id that
// is not 32 lower-case hex digits or is all zeros (a digests file exists only for an event: the
// practice mode has none), no row, a row that is not in its grammar and a repeated (seat, cid);
// and a nil ev. Nothing is written when it refuses.
func WriteDigests(w io.Writer, ev *CheckedEvent) error {
	if ev == nil {
		return newViolation(RuleDigests, "there is no checked event to write the digests of", 0, cell{}, nil)
	}
	return writeDigestRows(w, ev.runID, ev.rows)
}

// WriteDigestsFile writes the digests file of ev to dest (a path that does not exist, in a
// directory that does) as one output: the bytes of WriteDigests go to a temporary file beside
// dest (0600, synced), which is then linked to dest, so dest is all of the file or does not
// exist, and an existing dest is refused (an *InputError that wraps ErrOutputExists) and left as
// it was (atomicwrite.go). It is what `edition check` writes `--digests-out` with, so the command
// opens and writes no file by itself (D20: the readers and the writers are this package's).
//
// The commit point is the link (D20, amendment 13 as revised): a failure before it is an
// *OutputError (exit 3, dest not made, Left the temporary names that could not be removed), and
// after it the file is in place and the result is no error; left is then the temporary name that
// could not be removed, if any, a warning the command prints before it exits 0.
func WriteDigestsFile(dest string, ev *CheckedEvent) (left []string, err error) {
	var buf bytes.Buffer
	if err := WriteDigests(&buf, ev); err != nil {
		return nil, err
	}
	return writeFileAtomic(dest, buf.Bytes())
}

// writeDigestRows is WriteDigests's body: the rows and the run id of a CheckedEvent.
func writeDigestRows(w io.Writer, runID string, rows []DigestRow) error {
	if !digestsRunIDAllowed(runID, false) {
		return newViolation(RuleDigests, "the run id must be 32 lower-case hex digits and not all zeros", 0, cell{}, nil)
	}
	if len(rows) == 0 {
		return newViolation(RuleDigests, "there is no digest row", 0, cell{}, nil)
	}
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b DigestRow) int {
		if d := strings.Compare(a.Seat, b.Seat); d != 0 {
			return d
		}
		return strings.Compare(a.CID, b.CID)
	})
	var sb strings.Builder
	sb.WriteString(digestsHeaderPrefix + runID + "\n")
	seen := make(map[cell]struct{}, len(sorted))
	for _, r := range sorted {
		if err := checkDigestRow(r, 0); err != nil {
			return err
		}
		k := cell{seat: r.Seat, cid: r.CID}
		if _, dup := seen[k]; dup {
			return newViolation(RuleDigests, "a (seat, cid) has two digest rows", 0, k, nil)
		}
		seen[k] = struct{}{}
		sb.WriteString(r.Seat + "\t" + r.CID + "\t" + r.Digest + "\n")
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// WritePracticeDigests writes the digests file of a practice edition (practice/digests.tsv,
// D8, D9): the v1 header with the run id of all zeros, and a row  *  TAB  cid  TAB  digest
// for each challenge, in byte order of the cid. It asks for the run id of all zeros and the
// seat * and refuses everything else: those are the two things the event's WriteDigests
// refuses, so a file of one cannot be written by the other. It also refuses no row, a cid
// or a digest outside its grammar, and a cid twice. Nothing is written when it refuses.
// (It is the practice edition's door; the event's, WriteDigests, takes a *CheckedEvent.
// Its reader is ParsePracticeDigests.)
func WritePracticeDigests(w io.Writer, runID string, rows []DigestRow) error {
	if !digestsRunIDAllowed(runID, true) {
		return newViolation(RuleDigests, "a practice digests file carries the run id of all zeros and no other", 0, cell{}, nil)
	}
	if len(rows) == 0 {
		return newViolation(RuleDigests, "there is no digest row", 0, cell{}, nil)
	}
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b DigestRow) int { return strings.Compare(a.CID, b.CID) })
	var sb strings.Builder
	sb.WriteString(digestsHeaderPrefix + runID + "\n")
	seen := make(map[string]struct{}, len(sorted))
	for _, r := range sorted {
		c := cell{seat: r.Seat, cid: r.CID}
		if err := checkPracticeDigestRow(r, 0); err != nil {
			return err
		}
		if _, dup := seen[r.CID]; dup {
			return newViolation(RuleDigests, "a cid has two digest rows", 0, c, nil)
		}
		seen[r.CID] = struct{}{}
		sb.WriteString(r.Seat + "\t" + r.CID + "\t" + r.Digest + "\n")
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// ParseDigests reads a digests file: the v1 header with a 32-digit lower-case hex run id
// that is not all zeros, then one row of three TAB-separated columns per line. Refused,
// with the first failure as a *Violation: a file over MaxTableBytes, invalid UTF-8, a CR,
// a double quote, a rune sourcehygiene.Hidden reports, a missing final newline, a row of
// another width or with an empty column, a row outside its grammar (checkDigestRow), a
// repeated (seat, cid) and a file with no row. The order of the rows is not constrained.
// It returns the run id and the rows in file order. A practice edition's digests file (the
// run id of all zeros, the seat *) is refused: its reader is ParsePracticeDigests.
func ParseDigests(data []byte) (string, []DigestRow, error) {
	return parseDigestsFile(data, false)
}

// ParsePracticeDigests reads the digests file of a practice edition (practice/digests.tsv,
// D8, D9 and amendment 9): the v1 header with the run id of all zeros and no other, then one
// row  *  TAB  cid  TAB  digest  per line. Everything else ParseDigests refuses it refuses
// the same way (it is the same reader, parseDigestsFile); the two rules that differ are the
// two that tell the doors apart: an event's run id (not all zeros) and a seat of the seat
// grammar are refused here, as the practice run id and the seat * are refused there. So a
// file of one door is never read by the other. It returns the rows in file order; the run
// id is PracticeRunID whenever it returns no error. Which challenges the rows must be for
// is the caller's to check (a practice edition's file has one row, its own challenge's).
func ParsePracticeDigests(data []byte) ([]DigestRow, error) {
	_, rows, err := parseDigestsFile(data, true)
	return rows, err
}

// parseDigestsFile is the one reader of a digests file, for both doors: the size, the bytes,
// the header prefix, the three non-empty columns, a repeated (seat, cid) and at least one row
// are the same; practice picks the run id the header may carry (digestsRunIDAllowed) and the
// shape of a row (checkDigestRowOf).
func parseDigestsFile(data []byte, practice bool) (string, []DigestRow, error) {
	shape := func(msg string, line int) error {
		return newViolation(RuleDigests, msg, line, cell{}, nil)
	}
	switch {
	case len(data) == 0:
		return "", nil, shape("digests file is empty", 0)
	case len(data) > MaxTableBytes:
		return "", nil, shape("digests file is larger than the size limit", 0)
	case !utf8.Valid(data):
		return "", nil, shape("digests file is not valid UTF-8", 0)
	}
	if i := bytes.IndexByte(data, '\r'); i >= 0 {
		return "", nil, shape("carriage return is not allowed", lineAt(data, i))
	}
	if i := bytes.IndexByte(data, '"'); i >= 0 {
		return "", nil, shape("double quote is not allowed", lineAt(data, i))
	}
	if found := sourcehygiene.Hidden(data); len(found) > 0 {
		return "", nil, shape("invisible or bidi control character", found[0].Line)
	}
	if data[len(data)-1] != '\n' {
		return "", nil, shape("digests file must end with a newline", lineAt(data, len(data)-1))
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	id, ok := strings.CutPrefix(lines[0], digestsHeaderPrefix)
	if !ok || !digestsRunIDAllowed(id, practice) {
		if practice {
			return "", nil, shape("first line must be the v1 header with the run id of all zeros (a practice digests file)", 1)
		}
		return "", nil, shape("first line must be the v1 header with a 32-digit lower-case hex run id that is not all zeros", 1)
	}
	var rows []DigestRow
	seen := make(map[cell]struct{}, len(lines))
	for i, ln := range lines[1:] {
		lineNo := i + 2
		cols := strings.Split(ln, "\t")
		if len(cols) != digestColumns {
			return "", nil, shape("row does not have three columns", lineNo)
		}
		for _, col := range cols {
			if col == "" {
				return "", nil, shape("row has an empty column", lineNo)
			}
		}
		r := DigestRow{Seat: cols[0], CID: cols[1], Digest: cols[2]}
		if err := checkDigestRowOf(r, lineNo, practice); err != nil {
			return "", nil, err
		}
		k := cell{seat: r.Seat, cid: r.CID}
		if _, dup := seen[k]; dup {
			return "", nil, newViolation(RuleDigests, "a (seat, cid) has two digest rows", lineNo, k, nil)
		}
		seen[k] = struct{}{}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return "", nil, shape("digests file has no row", 0)
	}
	return id, rows, nil
}

// CheckDigestSet is V48's Go side: the (seat, cid) pairs of rows are exactly the seats
// x the investigate challenges of scope. It lists every pair that is missing, every
// row that is not expected (a seat that is not in seats, or a challenge that is not in
// scope) and every pair that has two rows, bounded like Check's list; an empty seat
// list or scope is itself refused (an empty set of pairs proves nothing).
func CheckDigestSet(rows []DigestRow, seats []string, scope Scope) error {
	var c collector
	if len(seats) == 0 {
		c.add(newViolation(RuleDigests, "the seat list is empty", 0, cell{}, nil))
	}
	if len(scope) == 0 {
		c.add(newViolation(RuleDigests, "the scope has no investigate challenge", 0, cell{}, nil))
	}
	wantSeat := make(map[string]struct{}, len(seats))
	for _, s := range seats {
		wantSeat[s] = struct{}{}
	}
	have := make(map[cell]struct{}, len(rows))
	for _, r := range rows {
		k := cell{seat: r.Seat, cid: r.CID}
		if _, dup := have[k]; dup {
			c.add(newViolation(RuleDigests, "a (seat, cid) has two digest rows", 0, k, nil))
		}
		have[k] = struct{}{}
		_, seatOK := wantSeat[r.Seat]
		_, cidOK := scope[r.CID]
		if !seatOK || !cidOK {
			c.add(newViolation(RuleDigests, "a digest row is not for a seat of the seat list and an investigate challenge of the scope", 0, k, nil))
		}
	}
	for _, seat := range sortedKeys(wantSeat) {
		for _, cid := range scope.sortedCIDs() {
			if _, ok := have[cell{seat: seat, cid: cid}]; !ok {
				c.add(newViolation(RuleDigests, "no digest row for this seat and challenge", 0, cell{seat: seat, cid: cid}, nil))
			}
		}
	}
	return c.err()
}
