package apispec

// ADR-0006 (P25) Verification 1: internal/qa must be physically separate
// from internal/store and internal/scoreboard/scoring — the QA ticket-chat
// persistence layer must never import either, so a future change to the
// scoring/store packages cannot accidentally couple to (or corrupt) QA
// state, and vice versa. This is the SAME shape of check
// dependency_boundary_test.go already applies to internal/apispec vs.
// internal/apispec/specparity, reusing that file's transitiveModuleImports
// helper (same package, same test binary) rather than re-implementing an
// import-graph BFS a second time.

import (
	"path/filepath"
	"testing"
)

// qaImportPath / storeImportPath / scoringImportPath are the three
// module-qualified package paths this check is about.
const (
	qaImportPath      = modulePrefix + "internal/qa"
	storeImportPath   = modulePrefix + "internal/store"
	scoringImportPath = modulePrefix + "internal/scoreboard/scoring"
)

// TestQaPackageDoesNotImportStoreOrScoring is ADR-0006 Verification 1: walk
// internal/qa's own module-internal import closure and fail if it ever
// includes internal/store or internal/scoreboard/scoring — directly OR
// transitively (the real risk, per dependency_boundary_test.go's own doc:
// a transitive pull-in via some future helper package is the failure mode
// that actually happens, not a direct import of the forbidden package).
func TestQaPackageDoesNotImportStoreOrScoring(t *testing.T) {
	root := repoRoot(t)
	closure := transitiveModuleImports(t, root, qaImportPath)
	if closure[storeImportPath] {
		t.Errorf("internal/qa's module-internal import closure includes %s — ADR-0006 mandates internal/qa stay physically separate from the scoring/solve persistence layer (Verification 1)", storeImportPath)
	}
	if closure[scoringImportPath] {
		t.Errorf("internal/qa's module-internal import closure includes %s — ADR-0006 mandates internal/qa stay physically separate from the scoring domain logic (Verification 1)", scoringImportPath)
	}
}

// TestQaPackageDoesNotImportStoreOrScoring_CatchesTransitiveImport is this
// check's own V8 proof (ADR-0005's "prove the detector isn't vacuous"
// discipline, applied here per ADR-0006 Verification 1's own text: "故意に
// importを足したコピーでredになることをテストケースとして固定する"). Mirrors
// TestNoProductionBinaryImportsSpecparity_CatchesTransitiveImport's
// synthetic two-hop chain shape exactly, substituting internal/qa's own
// forbidden target.
func TestQaPackageDoesNotImportStoreOrScoring_CatchesTransitiveImport(t *testing.T) {
	root := t.TempDir()
	mustWriteGoFile(t, filepath.Join(root, "internal", "qa"), "qa.go",
		`package qa

import _ "`+modulePrefix+`internal/fixture-b"
`)
	mustWriteGoFile(t, filepath.Join(root, "internal", "fixture-b"), "b.go",
		`package fixtureb

import _ "`+storeImportPath+`"
`)
	closure := transitiveModuleImports(t, root, qaImportPath)
	if !closure[storeImportPath] {
		t.Fatalf("expected the synthetic internal/qa -> internal/fixture-b -> %s chain to be found in the closure, got %v", storeImportPath, closure)
	}
}
