package edition

// scopedigest.go is the ONE definition of the digest of a scope (ADR-0056 D10 B12, amendment 19,
// A4e-6). The scope is the ordered list of the ids of the challenges that catalog.LoadScored
// returned for `--scenario <file>` or `--all-challenges` (Scored.Order). `edition render` writes
// its digest in the render record (WriteRenderRecord, the scope line), and `edition check`
// computes it of its own scope and refuses a record whose digest is another (CheckEvent, step 1b,
// B12). Both call ScopeDigest and nothing else computes it (scopedigest_test.go reads the sources).
//
// The bytes the digest is the sha256 of: the label scopeDigestLabel, one LF (0x0A), and then
// every id of the scope in its order, each followed by one LF (every id ends with a LF: it is not
// a join). An id is in the grammar of challengeid.Pattern, so it holds no LF. The digest is the
// 64 lower-case hex digits of that sha256. The golden of a scope of one and of two ids is
// testdata/scope-digest/cases.tsv, computed outside this code.
//
// The input is the ordered list of the ids and nothing else. An input added to it is a new
// definition, and it takes a new label (falco-ctf/edition/scope/v2) in an amendment of the ADR.

import (
	"crypto/sha256"
	"encoding/hex"
)

// scopeDigestLabel is the domain label of the digest of a scope (amendment 19).
const scopeDigestLabel = "falco-ctf/edition/scope/v1"

// ScopeDigest is the digest of the scope ids, in their order: 64 lower-case hex digits. The same
// ids in another order are another scope, and another digest.
func ScopeDigest(ids []string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(scopeDigestLabel + "\n")) // a hash.Hash's Write never fails
	for _, id := range ids {
		_, _ = h.Write([]byte(id + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
