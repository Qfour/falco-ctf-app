// Package edition is the event-edition side of an investigate challenge
// (ADR-0056, Proposed): the answers table, its checks (D10 T1-T8) and the Judge
// that compares an input with a table value without keeping the value (D5 4).
//
// Stage A2a is pure (ADR-0056 D19): it reads no environment and no file, writes
// no log and ends no process. Stage A2b adds exactly one door, Load (load.go),
// which reads the answers file (at most MaxTableBytes+1 bytes) and is the only
// caller of Parse and NewJudge; cmd/scoreboard is the only caller of Load and does
// the logging and the exit (A4 adds the bundle checks B1-B9 and the renderer).
//
// Every rule that is decided here is decided ONCE and from the existing
// definitions: the answer formats and their normalisation are
// internal/catalog/answerformat, the seat grammar is identity.ValidSeat
// (ADR-0042), the challenge-id grammar is challengeid.Valid, the flag shape is
// catalog.MentionsFlag, and "no invisible character" is sourcehygiene.Hidden.
// This package spells none of those grammars itself.
//
// Nothing here ever returns, formats or logs a table value (ADR-0056 D13): an
// error names a rule, a line, and a seat / cid / qid that is itself inside its
// own grammar; the Table and the Judge print as a fixed string under every
// fmt verb and under encoding/json.
package edition

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/sourcehygiene"
)

const (
	// MaxTableBytes is the largest input Parse accepts (inclusive: this many bytes
	// pass the size check, one more is refused). A real table is a few hundred
	// seats x a few tens of questions x ~150 bytes (about 1 MiB); 4 MiB is far above
	// that and still small enough to hold in memory twice. The limit exists so that an
	// unbounded file cannot be loaded at start-up, not to describe a legal size.
	MaxTableBytes = 4 << 20

	// AnySeat is the seat of a practice table (ADR-0056 D8, D12): the answer applies
	// to every seat. An event table never has it (T4).
	AnySeat = "*"

	// PracticeRunID is the run id of a practice table: 32 zeros (D10 T3).
	PracticeRunID = "00000000" + "00000000" + "00000000" + "00000000"

	headerPrefix = "# falco-ctf answers v1 run="
	runIDLen     = 32
	columns      = 4
)

// cell is the key of one table row.
type cell struct {
	seat string
	cid  string
	qid  string
}

type row struct {
	line  int
	c     cell
	value string
}

// Table is a parsed answers table. It holds the plaintext values, so it lives
// only as long as it takes to Check it and build a Judge from it: the scoreboard
// process drops it after that. It has no accessor that returns a value.
type Table struct {
	runID string
	rows  []row
	index map[cell]int
}

// RunID is the run id of the table's first line (32 lower-case hex digits).
func (t *Table) RunID() string { return t.runID }

// Seats is the sorted set of seats that have at least one row.
func (t *Table) Seats() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, r := range t.rows {
		if _, ok := seen[r.c.seat]; !ok {
			seen[r.c.seat] = struct{}{}
			out = append(out, r.c.seat)
		}
	}
	sort.Strings(out)
	return out
}

func (t *Table) hasSeat(seat string) bool {
	for _, r := range t.rows {
		if r.c.seat == seat {
			return true
		}
	}
	return false
}

const redactedTable = "edition.Table{redacted}"

// Format, String, GoString and MarshalJSON make a Table print as a fixed string
// under every fmt verb and under encoding/json (value receivers, so a copy does
// too).
func (Table) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedTable) }

// String: see Format.
func (Table) String() string { return redactedTable }

// GoString: see Format.
func (Table) GoString() string { return redactedTable }

// MarshalJSON: see Format.
func (Table) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedTable + `"`), nil }

// Parse is D10 T3 (and the duplicate-row rule of T4): the first line is
// `# falco-ctf answers v1 run=<32 lower-case hex digits>`, then one row per line
// of four TAB-separated, non-empty columns (seat, cid, qid, value). Refused: a
// file over MaxTableBytes, invalid UTF-8, a CR, a double quote, any rune
// sourcehygiene.Hidden reports, a missing final newline, a row of another width,
// an empty column and a repeated (seat, cid, qid). The first failure is returned,
// as a *Violation.
//
// Parse checks the SHAPE only. Whether a seat, cid, qid or value is acceptable is
// Check's.
func Parse(data []byte) (*Table, error) {
	shape := func(msg string, line int) error {
		return newViolation(RuleShape, msg, line, cell{}, nil)
	}
	switch {
	case len(data) == 0:
		return nil, shape("table is empty", 0)
	case len(data) > MaxTableBytes:
		return nil, shape("table is larger than the size limit", 0)
	case !utf8.Valid(data):
		return nil, shape("table is not valid UTF-8", 0)
	}
	if i := bytes.IndexByte(data, '\r'); i >= 0 {
		return nil, shape("carriage return is not allowed", lineAt(data, i))
	}
	if i := bytes.IndexByte(data, '"'); i >= 0 {
		return nil, shape("double quote is not allowed", lineAt(data, i))
	}
	if found := sourcehygiene.Hidden(data); len(found) > 0 {
		return nil, shape("invisible or bidi control character", found[0].Line)
	}
	if data[len(data)-1] != '\n' {
		return nil, shape("table must end with a newline", lineAt(data, len(data)-1))
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	id, ok := strings.CutPrefix(lines[0], headerPrefix)
	if !ok || !validRunID(id) {
		return nil, shape("first line must be the v1 header with a 32-digit lower-case hex run id", 1)
	}
	t := &Table{runID: id, index: make(map[cell]int, len(lines))}
	for i, ln := range lines[1:] {
		lineNo := i + 2
		cols := strings.Split(ln, "\t")
		if len(cols) != columns {
			return nil, shape(fmt.Sprintf("row has %d columns, want %d", len(cols), columns), lineNo)
		}
		for _, col := range cols {
			if col == "" {
				return nil, shape("row has an empty column", lineNo)
			}
		}
		c := cell{seat: cols[0], cid: cols[1], qid: cols[2]}
		if _, dup := t.index[c]; dup {
			return nil, newViolation(RuleComplete, "duplicate row for the same seat, cid and qid", lineNo, c, nil)
		}
		t.index[c] = len(t.rows)
		t.rows = append(t.rows, row{line: lineNo, c: c, value: cols[3]})
	}
	return t, nil
}

// lineAt is the 1-based line of byte offset i.
func lineAt(data []byte, i int) int { return 1 + bytes.Count(data[:i], []byte{'\n'}) }

func validRunID(s string) bool {
	if len(s) != runIDLen {
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
