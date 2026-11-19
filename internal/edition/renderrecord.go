package edition

// renderrecord.go is the key's fingerprint and the record of a render (ADR-0056 D12,
// amendment 10 as revised, D19 A4d-2a, V76, and amendment 19, A4e-6). The run id is not an input
// of the values, so a key used for two events gives the two events the same answers: the platform
// keeps a ledger of the fingerprints of the keys it has used, and refuses a render whose
// fingerprint is in it (P1b-2). The fingerprint is
// HMAC-SHA256(key, len || "falco-ctf/edition/key-fingerprint/v1") in hex: its input is a label of
// another domain than the seeds' (editionLabel), so it is not a block of any stream of values, and
// it does not give the key back (the key is at least MinMasterKeyBytes long).
//
// The record is a version header, `# falco-ctf render-record v2` (the way the answers table and
// the digests file open with theirs), and then three lines, `key TAB value`, made of the run id,
// the fingerprint and the digest of the scope the render was given (ScopeDigest, B12). It holds
// no key and no value. The first form (v1: the header and two lines, no scope) is read by
// nothing: a v1 record is a form error of `edition check` (exit 2), and the flag-guard still
// refuses its header in a tracked file (V84).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
)

// keyFingerprintLabel is the domain label of the fingerprint (amendment 10).
const keyFingerprintLabel = "falco-ctf/edition/key-fingerprint/v1"

// The header line and the three keys of the render record. This is the one place that spells
// them (the form of the record is A4d-2a's and amendment 19's).
const (
	renderRecordHeader      = "# falco-ctf render-record v2"
	renderRecordRunID       = "run-id"
	renderRecordFingerprint = "key-fingerprint"
	renderRecordScope       = "scope"
	// renderRecordHeaderV1 is the header of the first form, which no reader takes. It is kept
	// for the reader's message and for the flag-guard (scripts/check-edition-headers.sh, V84),
	// which refuses it in a tracked file as it refuses the current one.
	renderRecordHeaderV1 = "# falco-ctf render-record v1"
)

// Fingerprint is the key's fingerprint: 64 lower-case hex digits. It is a function of the key
// alone, and of nothing that a seat or a value is made of.
func (k MasterKey) Fingerprint() string {
	m := hmac.New(sha256.New, k.key)
	_, _ = m.Write(lengthPrefixed(keyFingerprintLabel)) // a hash.Hash's Write never fails
	return hex.EncodeToString(m.Sum(nil))
}

// WriteRenderRecord writes the record of a render of an event: the version header, and then the
// run id, the key's fingerprint and the digest of the scope (ScopeDigest of scope, the ordered ids
// of the challenges catalog.LoadScored returned for the render), one `key TAB value` line each, in
// that order. The run id must be 32 lower-case hex digits and not all zeros (a record exists for
// an event only), the key must be a key an event is rendered with (not empty, not the public
// practice key), and the scope must have at least one id, each in the challenge id grammar. Nothing
// is written when it refuses. It names neither the key nor a value.
func WriteRenderRecord(w io.Writer, runID string, key MasterKey, scope []string) error {
	if !validRunID(runID) || runID == PracticeRunID {
		return newViolation(RuleSpecRender, "the run id of a render record must be 32 lower-case hex digits and not all zeros", 0, cell{}, nil)
	}
	if len(key.key) == 0 || key.isPractice() {
		return newViolation(RuleSpecRender, "the render record of an event needs an event key", 0, cell{}, nil)
	}
	if len(scope) == 0 {
		return newViolation(RuleSpecRender, "the render record of an event needs the scope it was rendered for", 0, cell{}, nil)
	}
	for _, id := range scope {
		if !challengeid.Valid(id) {
			return newViolation(RuleSpecRender, "an id of the scope of a render record is not in the challenge id grammar", 0, cell{}, nil)
		}
	}
	text := renderRecordHeader + "\n" +
		renderRecordRunID + "\t" + runID + "\n" +
		renderRecordFingerprint + "\t" + key.Fingerprint() + "\n" +
		renderRecordScope + "\t" + ScopeDigest(scope) + "\n"
	if _, err := io.WriteString(w, text); err != nil {
		return errors.New("edition: the render record could not be written")
	}
	return nil
}
