package edition

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sort"
)

// keyLen is the size of the per-process HMAC key (ADR-0056 D5 4: 32 bytes).
const keyLen = 32

const redactedJudge = "edition.Judge{redacted}"

type qkey struct {
	cid string
	qid string
}

type seatMAC struct {
	seat string
	mac  [sha256.Size]byte
}

// Judge compares a normalised input with the expected value of (seat, cid, qid)
// (ADR-0056 D5 4). It keeps HMAC-SHA256(k_proc, value) of every table value and
// nothing else: the plaintext is not held, and no method returns one. k_proc is 32
// bytes from crypto/rand, made once per process and never written anywhere, so a
// MAC is meaningless outside this process. After NewJudge it is read-only and safe
// for concurrent use.
//
// The Judge compares; it does not decide what an attempt costs or when a challenge
// is solved. That order (count first, then compare) is the Grader's (A3).
type Judge struct {
	key        []byte
	exp        map[cell][sha256.Size]byte
	byQuestion map[qkey][]seatMAC
}

// NewJudge builds a Judge from a table that Check has accepted. It validates
// nothing itself. The caller drops the Table afterwards.
func NewJudge(t *Table) (*Judge, error) {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("edition: judge key: %w", err)
	}
	return newJudge(t, key)
}

func newJudge(t *Table, key []byte) (*Judge, error) {
	if t == nil || len(t.rows) == 0 {
		return nil, errors.New("edition: a judge needs a table with at least one row")
	}
	j := &Judge{
		key:        key,
		exp:        make(map[cell][sha256.Size]byte, len(t.rows)),
		byQuestion: make(map[qkey][]seatMAC),
	}
	for _, r := range t.rows {
		m := j.mac(r.value)
		j.exp[r.c] = m
		k := qkey{cid: r.c.cid, qid: r.c.qid}
		j.byQuestion[k] = append(j.byQuestion[k], seatMAC{seat: r.c.seat, mac: m})
	}
	for _, l := range j.byQuestion {
		sort.Slice(l, func(a, b int) bool { return l[a].seat < l[b].seat })
	}
	return j, nil
}

func (j *Judge) mac(v string) [sha256.Size]byte {
	h := hmac.New(sha256.New, j.key)
	_, _ = h.Write([]byte(v)) // a hash.Hash's Write never fails
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Match compares normalizedInput (already through answerformat.Normalize) with the
// value of (seat, cid, qid) in constant time. known is false when the table has no
// row for that cell (a seat the table does not name, an unknown question); the
// caller treats it as an internal error (D5 4: logged, a 500), not as "incorrect". A
// practice table's seat * answers for every seat.
func (j *Judge) Match(seat, cid, qid, normalizedInput string) (ok bool, known bool) {
	want, found := j.exp[cell{seat: seat, cid: cid, qid: qid}]
	if !found {
		want, found = j.exp[cell{seat: AnySeat, cid: cid, qid: qid}]
	}
	if !found {
		return false, false
	}
	got := j.mac(normalizedInput)
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1, true
}

// OtherSeat is for the operator-only audit log of D5 6: the seat, other than
// ownSeat, whose value for (cid, qid) the input equals. It compares every seat (no
// early exit) and returns the first by seat order. The practice seat * is not a
// seat. The result is for the audit log only; it is never part of a response.
func (j *Judge) OtherSeat(ownSeat, cid, qid, normalizedInput string) (seat string, found bool) {
	got := j.mac(normalizedInput)
	for _, e := range j.byQuestion[qkey{cid: cid, qid: qid}] {
		if e.seat == ownSeat || e.seat == AnySeat {
			continue
		}
		if subtle.ConstantTimeCompare(got[:], e.mac[:]) == 1 && !found {
			seat, found = e.seat, true
		}
	}
	return seat, found
}

// Format, String, GoString and MarshalJSON make a Judge print as a fixed string
// under every fmt verb and under encoding/json (value receivers, so a copy does
// too). There is no method that returns a plaintext, a MAC or the key.
func (Judge) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedJudge) }

// String: see Format.
func (Judge) String() string { return redactedJudge }

// GoString: see Format.
func (Judge) GoString() string { return redactedJudge }

// MarshalJSON: see Format.
func (Judge) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedJudge + `"`), nil }
