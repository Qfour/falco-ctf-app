package edition

import (
	"slices"
	"testing"
)

// export_test.go is compiled into the package's TEST binary only: it hands the external tests
// (package edition_test) the two values that production code can make through one door each,
// so that a test of a rule that sits behind a door (B1 to B9 of CheckBundles, the writers of
// the digests file) can give it an input that is not what the whole chain would produce. It is
// not part of the package's API and no non-test file can use it (a _test.go file is not in a
// build of the program), and the source tests that fix the doors read non-test files, which
// is where the doors are (validator_door_source_test.go).
//
// The tests of the doors themselves do not use it: load_event_table_test.go calls
// LoadEventTable, the tests that want a *CheckedBundles of a real tree call CheckBundles, and
// checkevent_test.go runs CheckEvent for the *CheckedEvent of a real event.

// CheckedTableForTest is a *CheckedTable around a table that Parse read, WITHOUT Check having
// run on it (the tests of CheckBundles check the bundle rules, and several of them give a
// table that Check would not accept: only Parse read it, as before the type existed). It
// carries no practice answers and no practice files.
func CheckedTableForTest(t *Table) *CheckedTable { return &CheckedTable{table: t} }

// CheckedEventForTest is a *CheckedEvent of the given run id and rows, whatever they are:
// WriteDigests holds them to the digests file's grammar itself, and its tests give it rows and
// run ids that CheckEvent would never return. (The one other way to a *CheckedEvent is
// CheckEvent, which makes one only after every check of D20.)
func CheckedEventForTest(runID string, rows []DigestRow) *CheckedEvent {
	return &CheckedEvent{runID: runID, rows: slices.Clone(rows)}
}

// SeatAnswersOfRowsForTest is the answers RenderEvent's self check hands B7 (seatAnswersOfRows),
// for the test that drops one of them and sees B7 refuse (ADR-0056 amendment 28, A7-x PR 2).
func SeatAnswersOfRowsForTest(rows []AnswerRow) map[string]SeatAnswers {
	return seatAnswersOfRows(rows)
}

// SeatAnswersOfTableForTest is the answers of challenge cid in a table that Parse read, in the form
// `edition check` hands B7 and B13 to B16 (seatAnswersOf), for the test that applies B13 to B16 to
// the practice editions of the image (their answers.tsv, seat *).
func SeatAnswersOfTableForTest(tb *Table, cid string) SeatAnswers {
	return seatAnswersOf(tb, cid)
}

// The steps of atomicwrite.go's seam writeFault (ADR-0056 V87, V92), for the external tests of
// the writers' failures: the write of a file's data, the link and the remove of the single
// file, the rename and the remove of a tree, and the two renames of a replacement (the earlier
// tree moved aside, and moved back: V81).
const (
	FaultWriteForTest     = faultWrite
	FaultLinkForTest      = faultLink
	FaultRemoveForTest    = faultRemove
	FaultRenameForTest    = faultRename
	FaultRemoveAllForTest = faultRemoveAll
	FaultBackupForTest    = faultBackup
	FaultRestoreForTest   = faultRestore
)

// SetWriteFaultForTest makes the steps of fail fail with their error until the test ends (the
// seam is put back to nil by the test's cleanup). No test of this package runs in parallel, so
// the seam is the test's own while it runs.
func SetWriteFaultForTest(t testing.TB, fail map[string]error) {
	t.Helper()
	writeFault = func(step string) error { return fail[step] }
	t.Cleanup(func() { writeFault = nil })
}
