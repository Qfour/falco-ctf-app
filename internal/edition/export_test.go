package edition

import "slices"

// export_test.go is compiled into the package's TEST binary only: it hands the external tests
// (package edition_test) the two values that production code can make through one door each,
// so that a test of a rule that sits behind a door (B1 to B9 of CheckBundles, the writers of
// the digests file) can give it an input that is not what the whole chain would produce. It is
// not part of the package's API and no non-test file can use it (a _test.go file is not in a
// build of the program), and the source tests that fix the doors read non-test files, which
// is where the doors are (validator_door_source_test.go).
//
// The tests of the doors themselves do not use it: load_event_table_test.go calls
// LoadEventTable, and the tests that want a *CheckedBundles of a real tree call CheckBundles.

// CheckedTableForTest is a *CheckedTable around a table that Parse read, WITHOUT Check having
// run on it (the tests of CheckBundles check the bundle rules, and several of them give a
// table that Check would not accept: only Parse read it, as before the type existed). It
// carries no practice answers and no practice files.
func CheckedTableForTest(t *Table) *CheckedTable { return &CheckedTable{table: t} }

// CheckedBundlesForTest is a *CheckedBundles of the given run id and rows, whatever they are:
// WriteDigests holds them to the digests file's grammar itself, and its tests give it rows and
// run ids that CheckBundles would never return.
func CheckedBundlesForTest(runID string, rows []DigestRow) *CheckedBundles {
	return &CheckedBundles{runID: runID, rows: slices.Clone(rows)}
}
