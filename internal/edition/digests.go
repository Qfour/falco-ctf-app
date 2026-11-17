package edition

// digests.go is the digests file of an event (ADR-0056 D9, D11, D19 A4b): what
// `scoreboard edition check` writes when it accepts a tree of bundles (--digests-out),
// and what deploy-user.sh and the platform's preflight read to hold the bytes they
// plant to the bytes the validator accepted. The file is
//
//	# falco-ctf evidence-digests v1 run=<32 lower-case hex digits>
//	<seat> TAB <cid> TAB <digest>          one row per (seat, challenge), digest = BundleDigest
//
// WriteDigests and ParseDigests are its two ends in Go; CheckDigestSet is V48's Go side:
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
func ValidDigest(s string) bool {
	if len(s) != digestHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
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

// WriteDigests writes the digests file of a tree of bundles that CheckBundles accepted: the
// header with the run id of the answers table the tree was checked against (cb.RunID), then
// the rows in byte order of (seat, cid), so one set of rows is one file. It takes a
// *CheckedBundles and nothing weaker (ADR-0056 D9 M2, D19 A4e-1): there is no way to write
// a digests file for rows that CheckBundles did not give, or under another run id than the
// table's. It still refuses what it always refused, so that the one writer cannot make a file
// the readers refuse: a run id that is not 32 lower-case hex digits or is all zeros (a
// digests file exists only for an event: the practice mode has none), no row, a row that is
// not in its grammar and a repeated (seat, cid); and a nil cb. Nothing is written when it
// refuses.
func WriteDigests(w io.Writer, cb *CheckedBundles) error {
	if cb == nil {
		return newViolation(RuleDigests, "there is no checked set of bundles to write the digests of", 0, cell{}, nil)
	}
	return writeDigestRows(w, cb.runID, cb.rows)
}

// writeDigestRows is WriteDigests's body: the rows and the run id of a CheckedBundles.
func writeDigestRows(w io.Writer, runID string, rows []DigestRow) error {
	if !validRunID(runID) || runID == PracticeRunID {
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
// (It is the practice edition's door; the event's, WriteDigests, takes a *CheckedBundles.
// Its reader, ParsePracticeDigests, is A5c-2's.)
func WritePracticeDigests(w io.Writer, runID string, rows []DigestRow) error {
	if runID != PracticeRunID {
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
		switch {
		case r.Seat != AnySeat:
			return newViolation(RuleDigests, "a practice digests file has the seat * only", 0, c, nil)
		case !challengeid.Valid(r.CID):
			return newViolation(RuleDigests, "cid is not a challenge id", 0, c, nil)
		case !ValidDigest(r.Digest):
			return newViolation(RuleDigests, "digest is not 64 lower-case hex digits", 0, c, nil)
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
// It returns the run id and the rows in file order.
func ParseDigests(data []byte) (string, []DigestRow, error) {
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
	if !ok || !validRunID(id) || id == PracticeRunID {
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
		if err := checkDigestRow(r, lineNo); err != nil {
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
