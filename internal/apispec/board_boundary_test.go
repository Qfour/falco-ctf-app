package apispec

// app#292 Phase 1 / QA Board destination model: internal/board must be
// physically separate from internal/store and internal/scoreboard/scoring,
// the SAME shape ADR-0006 Verification 1 already applies to internal/qa
// (qa_boundary_test.go) — internal/board's package doc states this
// explicitly. This file is that same check with internal/board substituted
// as the subject package, reusing dependency_boundary_test.go's
// transitiveModuleImports helper (same package, same test binary) rather
// than re-implementing an import-graph BFS a third time.

import (
	"path/filepath"
	"testing"
)

// boardImportPath is the module-qualified package path this check is about.
// storeImportPath / scoringImportPath are already declared in
// qa_boundary_test.go (same package apispec) — reused here rather than
// redeclared.
const boardImportPath = modulePrefix + "internal/board"

// TestBoardPackageDoesNotImportStoreOrScoring is app#292 Phase 1's
// counterpart to TestQaPackageDoesNotImportStoreOrScoring: walk
// internal/board's own module-internal import closure and fail if it ever
// includes internal/store or internal/scoreboard/scoring — directly OR
// transitively.
func TestBoardPackageDoesNotImportStoreOrScoring(t *testing.T) {
	root := repoRoot(t)
	closure := transitiveModuleImports(t, root, boardImportPath)
	if closure[storeImportPath] {
		t.Errorf("internal/board's module-internal import closure includes %s — internal/board must stay physically separate from the scoring/solve persistence layer (mirrors ADR-0006 Verification 1)", storeImportPath)
	}
	if closure[scoringImportPath] {
		t.Errorf("internal/board's module-internal import closure includes %s — internal/board must stay physically separate from the scoring domain logic (mirrors ADR-0006 Verification 1)", scoringImportPath)
	}
}

// TestBoardPackageDoesNotImportStoreOrScoring_CatchesTransitiveImport is
// this check's own "prove the detector isn't vacuous" proof (same shape as
// TestQaPackageDoesNotImportStoreOrScoring_CatchesTransitiveImport): a
// synthetic two-hop chain (internal/board -> internal/fixture-b ->
// internal/store) must be found in the closure, confirming the check
// actually walks transitively rather than only checking direct imports.
func TestBoardPackageDoesNotImportStoreOrScoring_CatchesTransitiveImport(t *testing.T) {
	root := t.TempDir()
	mustWriteGoFile(t, filepath.Join(root, "internal", "board"), "board.go",
		`package board

import _ "`+modulePrefix+`internal/fixture-b"
`)
	mustWriteGoFile(t, filepath.Join(root, "internal", "fixture-b"), "b.go",
		`package fixtureb

import _ "`+storeImportPath+`"
`)
	closure := transitiveModuleImports(t, root, boardImportPath)
	if !closure[storeImportPath] {
		t.Fatalf("expected the synthetic internal/board -> internal/fixture-b -> %s chain to be found in the closure, got %v", storeImportPath, closure)
	}
}
