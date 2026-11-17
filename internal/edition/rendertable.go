package edition

// rendertable.go is what the renderer writes (ADR-0056 D9, D12 and amendment 9, D19
// A4d-2): the answers table of a render, the digests file of a practice edition, and the
// three files of a practice edition (`practice/`).
//
// The answers table is written here and READ by Parse (table.go): the table has one
// grammar, and the tests of this stage run what they write through Parse and Check. This
// file builds no Table (table.go makes them, and load_source_test.go keeps it so): it
// makes bytes.
//
// The digests file has two doors (D9), both in digests.go: the event's WriteDigests /
// ParseDigests refuse the run id of all zeros and the seat *, and WritePracticeDigests is the
// practice edition's, which asks for exactly those two and nothing else. A file of one is
// refused by the other's reader (V66's Go side; the practice reader, ParsePracticeDigests,
// is A5c-2's). PracticeOutput below calls WritePracticeDigests.

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/sourcehygiene"
)

// WriteAnswers writes the answers table (D10 T3) of runID: the header, and the rows in
// byte order of (seat, cid, qid), so one set of rows is one file. A table with the
// practice run id (32 zeros) has the seat * only, and an event table has seats of the seat
// grammar (ADR-0042) and no seat *: the pairing Check holds a table to. A row has a seat, a
// cid and a qid in their grammars and a value that is not empty, is UTF-8, holds no
// rune sourcehygiene.Hidden reports and no tab, line break or double quote (what Parse
// would refuse); a (seat, cid, qid) is in at most one row. It writes nothing when it
// refuses, and its errors name a rule, a seat, a cid and a qid, never a value.
func WriteAnswers(w io.Writer, runID string, rows []AnswerRow) error {
	if !validRunID(runID) {
		return newViolation(RuleShape, "the run id must be 32 lower-case hex digits", 1, cell{}, nil)
	}
	if len(rows) == 0 {
		return newViolation(RuleShape, "there is no row to write", 0, cell{}, nil)
	}
	practice := runID == PracticeRunID
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b AnswerRow) int {
		if d := strings.Compare(a.Seat, b.Seat); d != 0 {
			return d
		}
		if d := strings.Compare(a.CID, b.CID); d != 0 {
			return d
		}
		return strings.Compare(a.QID, b.QID)
	})
	var sb strings.Builder
	sb.WriteString(headerPrefix + runID + "\n")
	seen := make(map[cell]struct{}, len(sorted))
	for _, r := range sorted {
		if err := checkAnswerRow(r, practice); err != nil {
			return err
		}
		c := cell{seat: r.Seat, cid: r.CID, qid: r.QID}
		if _, dup := seen[c]; dup {
			return newViolation(RuleComplete, "two rows have the same seat, cid and qid", 0, c, nil)
		}
		seen[c] = struct{}{}
		sb.WriteString(r.Seat + "\t" + r.CID + "\t" + r.QID + "\t" + r.Value + "\n")
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// checkAnswerRow is the shape of one row of the answers table.
func checkAnswerRow(r AnswerRow, practice bool) error {
	c := cell{seat: r.Seat, cid: r.CID, qid: r.QID}
	switch {
	case practice && r.Seat != AnySeat:
		return newViolation(RuleShape, "a table with the practice run id has the seat * only", 0, c, nil)
	case !practice && !identity.ValidSeat(r.Seat):
		return newViolation(RuleShape, "an event table has seats of the seat grammar (ADR-0042) and no seat *", 0, c, nil)
	case !challengeid.Valid(r.CID):
		return newViolation(RuleShape, "cid is not a challenge id", 0, c, nil)
	case !answerformat.ValidID(r.QID):
		return newViolation(RuleShape, "qid is outside the id grammar "+answerformat.IDPattern, 0, c, nil)
	case r.Value == "" || !utf8.ValidString(r.Value) || strings.ContainsAny(r.Value, "\t\n\r\""):
		return newViolation(RuleShape, "a value is empty, is not UTF-8, or holds a tab, a line break or a double quote", 0, c, nil)
	case len(sourcehygiene.Hidden([]byte(r.Value))) > 0:
		return newViolation(RuleShape, "a value holds an invisible or bidi control character", 0, c, nil)
	}
	return nil
}

// PracticeFiles is what practice/ of a challenge holds (D8, amendment 9): the bundle of
// the practice edition (evidence/<file>, the only part that reaches a seat), the answers
// table and the digests file (which never do).
type PracticeFiles struct {
	Evidence []BundleFile
	Answers  []byte
	Digests  []byte
}

// PracticeOutput is the files of practice/ for a practice render (RenderPractice): the
// bundle of the seat *, the answers table (the practice run id, the seat *) and the
// digests file (one row, the digest of the bundle). It is the one place the three are made
// from a render, so the golden of V67 compares what the renderer gives with what is
// committed.
func PracticeOutput(r *Rendered) (*PracticeFiles, error) {
	if r == nil || len(r.Bundles) != 1 || r.Bundles[0] == nil || r.Bundles[0].Seat != AnySeat {
		return nil, errors.New("edition: a practice output is one bundle of the seat *")
	}
	b := r.Bundles[0]
	var answers, digests bytes.Buffer
	if err := WriteAnswers(&answers, PracticeRunID, r.Rows); err != nil {
		return nil, err
	}
	row := DigestRow{Seat: AnySeat, CID: b.CID, Digest: b.Digest()}
	if err := WritePracticeDigests(&digests, PracticeRunID, []DigestRow{row}); err != nil {
		return nil, err
	}
	return &PracticeFiles{Evidence: b.Files, Answers: answers.Bytes(), Digests: digests.Bytes()}, nil
}
