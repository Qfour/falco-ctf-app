package apispec

// ADR-0039 S1 (review-5x 37, R4#5): specparity's TextOrigin gate checks every
// docs/openapi-*.yaml it finds by glob (it cannot import this package's
// specNameForCmd: specparity imports apispec). This test closes the gap
// between the two enumerations: the glob's set must equal specNameForCmd's
// values, both ways. A spec file nobody maps to a binary, or a mapped name
// with no file, fails here instead of one side checking a different set.

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestSpecFilesAreExactlyTheMuxOwningBinariesSpecs(t *testing.T) {
	root := repoRoot(t)
	paths, err := filepath.Glob(filepath.Join(root, "docs", "openapi-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, p := range paths {
		onDisk[filepath.Base(p)] = true
	}
	mapped := map[string]bool{}
	for _, f := range specNameForCmd {
		mapped[f] = true
	}
	if len(onDisk) == 0 || len(mapped) == 0 {
		t.Fatalf("empty enumeration (glob %d files, specNameForCmd %d values): this check would be a silent no-op", len(onDisk), len(mapped))
	}
	var onlyDisk, onlyMapped []string
	for f := range onDisk {
		if !mapped[f] {
			onlyDisk = append(onlyDisk, f)
		}
	}
	for f := range mapped {
		if !onDisk[f] {
			onlyMapped = append(onlyMapped, f)
		}
	}
	sort.Strings(onlyDisk)
	sort.Strings(onlyMapped)
	if len(onlyDisk) > 0 || len(onlyMapped) > 0 {
		t.Fatalf("docs/openapi-*.yaml and specNameForCmd disagree: only on disk %v (map it to a mux-owning cmd in specNameForCmd), only in specNameForCmd %v (the file is missing)", onlyDisk, onlyMapped)
	}
}
