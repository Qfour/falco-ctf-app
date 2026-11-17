package edition

// renderdrbg.go is the deterministic random source of the renderer (ADR-0056 D12, D19
// A4d-2, V4, E12): the values of a seat are a pure function of the master key and of
// (seat, challenge, slot), so one render can be repeated byte for byte and two keys give
// two renderings.
//
// The seed of a slot is the ADR's (D12, amendment 10)
//
//	HMAC-SHA256(master, len(v) || v || len(seat) || seat || len(cid) || cid || len(slot) || slot)
//
// where v is the version label "falco-ctf/edition/v1" and len is the byte count as 4
// bytes, big-endian (lengthPrefixed). Without the prefixes a concatenation reads two
// ways: ("ab", "c") and ("a", "bc") would be one input.
//
// One 32-byte block is too short for a path of sixteen positions, so the seed is
// expanded:  block(i) = HMAC-SHA256(seed, be32(i))  for i = 0, 1, ..., read in order (the
// ADR's, amendment 10; the same shape as HKDF's expand). The master key is used for the
// seed alone. There is no run id in the input.
//
// A choice among n things is made by rejection sampling on 64-bit draws
// (uniformBelow): a plain `r % n` over-represents the first 2^64 mod n values, and for a
// vocabulary that is the bias a counting attacker uses. Nothing here reads a clock or
// math/rand.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

// maxRejections bounds the draws uniformBelow rejects. A draw is rejected with a
// probability below 1/2, so 64 rejections in a row (2^-64) is a stream that is not random:
// an error, not a loop.
const maxRejections = 64

var (
	errDrawBudget = errors.New("the draws of a slot are used up")
	errBelowZero  = errors.New("a choice among no value")
)

// lengthPrefixed is the input of a seed: every field as its byte count (4 bytes,
// big-endian) and then its bytes.
func lengthPrefixed(fields ...string) []byte {
	var out []byte
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

// drbg is the stream of one slot of one seat. It is not safe for concurrent use.
type drbg struct {
	seed  [sha256.Size]byte
	ctr   uint32
	block [sha256.Size]byte
	left  int // the unread bytes at the end of block
}

// editionLabel is the version label that opens the input of every seed (amendment 10): a
// later algorithm gets another label, so its output never mixes with this one's.
const editionLabel = "falco-ctf/edition/v1"

func newDRBG(key MasterKey, seat, cid, slot string) *drbg {
	return newDRBGLabel(editionLabel, key, seat, cid, slot)
}

// newDRBGLabel is newDRBG with the label given, so that a test can show that the label is
// in the input of the seed.
func newDRBGLabel(label string, key MasterKey, seat, cid, slot string) *drbg {
	m := hmac.New(sha256.New, key.key)
	_, _ = m.Write(lengthPrefixed(label, seat, cid, slot)) // a hash.Hash's Write never fails
	d := &drbg{}
	copy(d.seed[:], m.Sum(nil))
	return d
}

// refill makes the next block of the stream.
func (d *drbg) refill() error {
	if d.ctr == math.MaxUint32 {
		return errDrawBudget
	}
	h := hmac.New(sha256.New, d.seed[:])
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], d.ctr)
	_, _ = h.Write(c[:])
	copy(d.block[:], h.Sum(nil))
	d.ctr++
	d.left = len(d.block)
	return nil
}

// bytes is the next n bytes of the stream.
func (d *drbg) bytes(n int) ([]byte, error) {
	out := make([]byte, 0, n)
	for len(out) < n {
		if d.left == 0 {
			if err := d.refill(); err != nil {
				return nil, err
			}
		}
		take := min(n-len(out), d.left)
		start := len(d.block) - d.left
		out = append(out, d.block[start:start+take]...)
		d.left -= take
	}
	return out, nil
}

// next is the next 64 bits of the stream (uint64Source).
func (d *drbg) next() (uint64, error) {
	b, err := d.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// below is a value of [0, n), uniform.
func (d *drbg) below(n uint64) (uint64, error) { return uniformBelow(d, n) }

// uint64Source is where uniformBelow takes its 64-bit draws from: the stream, and a
// scripted one in the test of the sampler.
type uint64Source interface {
	next() (uint64, error)
}

// uniformBelow is a value of [0, n) with every value equally likely: a draw below
// 2^64 mod n is rejected, so the draws that are kept are a multiple of n in number and
// `r % n` has no bias. n = 0 is an error.
func uniformBelow(src uint64Source, n uint64) (uint64, error) {
	if n == 0 {
		return 0, errBelowZero
	}
	// 2^64 mod n, in unsigned arithmetic: (-n) is 2^64 - n and has the same remainder.
	threshold := -n % n
	for i := 0; i < maxRejections; i++ {
		r, err := src.next()
		if err != nil {
			return 0, err
		}
		if r >= threshold {
			return r % n, nil
		}
	}
	return 0, errDrawBudget
}
