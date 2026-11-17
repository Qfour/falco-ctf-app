package edition

// renderrecord.go is the key's fingerprint and the record of a render (ADR-0056 D12,
// amendment 10 as revised, D19 A4d-2a, V76). The run id is not an input of the values, so a
// key used for two events gives the two events the same answers: the platform keeps a ledger
// of the fingerprints of the keys it has used, and refuses a render whose fingerprint is in
// it (P1b-2). The fingerprint is  HMAC-SHA256(key, len || "falco-ctf/edition/key-fingerprint/v1")
// in hex: its input is a label of another domain than the seeds' (editionLabel), so it is
// not a block of any stream of values, and it does not give the key back (the key is at least
// MinMasterKeyBytes long).
//
// The record is a version header, `# falco-ctf render-record v1` (the way the answers table and
// the digests file open with theirs), and then two lines, `key TAB value`, made of the run id
// and the fingerprint. It holds no key and no value.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// keyFingerprintLabel is the domain label of the fingerprint (amendment 10).
const keyFingerprintLabel = "falco-ctf/edition/key-fingerprint/v1"

// The header line and the two keys of the render record. This is the one place that spells
// them (the form of the record is A4d-2a's: the ADR names its two contents and no layout).
const (
	renderRecordHeader      = "# falco-ctf render-record v1"
	renderRecordRunID       = "run-id"
	renderRecordFingerprint = "key-fingerprint"
)

// Fingerprint is the key's fingerprint: 64 lower-case hex digits. It is a function of the key
// alone, and of nothing that a seat or a value is made of.
func (k MasterKey) Fingerprint() string {
	m := hmac.New(sha256.New, k.key)
	_, _ = m.Write(lengthPrefixed(keyFingerprintLabel)) // a hash.Hash's Write never fails
	return hex.EncodeToString(m.Sum(nil))
}

// WriteRenderRecord writes the record of a render of an event: the version header, and then
// the run id and the key's fingerprint, one `key TAB value` line each, in that order. The run id must be 32
// lower-case hex digits and not all zeros (a record exists for an event only), the key must
// be a key an event is rendered with (not empty, not the public practice key). Nothing is
// written when it refuses. It names neither the key nor a value.
func WriteRenderRecord(w io.Writer, runID string, key MasterKey) error {
	if !validRunID(runID) || runID == PracticeRunID {
		return newViolation(RuleSpecRender, "the run id of a render record must be 32 lower-case hex digits and not all zeros", 0, cell{}, nil)
	}
	if len(key.key) == 0 || key.isPractice() {
		return newViolation(RuleSpecRender, "the render record of an event needs an event key", 0, cell{}, nil)
	}
	text := renderRecordHeader + "\n" + renderRecordRunID + "\t" + runID + "\n" + renderRecordFingerprint + "\t" + key.Fingerprint() + "\n"
	if _, err := io.WriteString(w, text); err != nil {
		return errors.New("edition: the render record could not be written")
	}
	return nil
}
