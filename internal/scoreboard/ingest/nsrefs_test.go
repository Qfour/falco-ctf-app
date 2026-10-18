package ingest

// app#469 review-5x: with NSCounter the cap is structural (the vec is
// unexported; Inc is the only way to count), so the old repo-wide AST guard
// shrinks to one statement: of the program's non-test sources, only package
// metrics (the declaration) and package ingest (the two Inc call sites) refer
// to the two ns-labelled counters. A third package counting into them would be
// a new writer of a security-observed metric and is a review item, not a
// drive-by.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var nsCounters = map[string]bool{"FalcoEventsRateLimited": true, "FalcoEventsScoringOverflow": true}

// nsCounterRefViolations lists every identifier naming one of the two counters in
// a package other than metrics and ingest, and counts the references it saw in
// ingest (a scan that saw none is broken, not clean).
func nsCounterRefViolations(srcs map[string]string) (violations []string, ingestRefs int) {
	fset := token.NewFileSet()
	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, srcs[name], 0)
		if err != nil {
			return []string{name + ": " + err.Error()}, 0
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || !nsCounters[id.Name] {
				return true
			}
			switch f.Name.Name {
			case "metrics":
			case "ingest":
				ingestRefs++
			default:
				violations = append(violations, fmt.Sprintf("%s: %s is referenced from package %s (only metrics declares it and ingest counts into it)", fset.Position(id.Pos()), id.Name, f.Name.Name))
			}
			return true
		})
	}
	return violations, ingestRefs
}

func TestNSCounters_OnlyMetricsAndIngestReferenceThem(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	srcs := map[string]string{}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			srcs[path] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(srcs) < 20 {
		t.Fatalf("scanned only %d non-test files: the walk is not seeing the tree", len(srcs))
	}
	v, ingestRefs := nsCounterRefViolations(srcs)
	if len(v) > 0 {
		t.Fatalf("a package other than metrics/ingest refers to an ns counter:\n  %s", strings.Join(v, "\n  "))
	}
	if ingestRefs != 2 {
		t.Fatalf("saw %d references in package ingest, want 2 (rate_limited and scoring_overflow): the scan is not seeing them", ingestRefs)
	}
}

func TestNSCounters_RefGuardCatchesAThirdPackage(t *testing.T) {
	ok := map[string]string{
		"m.go": "package metrics\nvar FalcoEventsRateLimited = 1\n",
		"i.go": "package ingest\nfunc f(){ metrics.FalcoEventsRateLimited.Inc(ns)\nmetrics.FalcoEventsScoringOverflow.Inc(ns) }\n",
	}
	if v, n := nsCounterRefViolations(ok); len(v) != 0 || n != 2 {
		t.Fatalf("the allowed shape was flagged or not counted: %v (%d)", v, n)
	}
	bad := map[string]string{"o.go": "package api\nfunc f(){ metrics.FalcoEventsScoringOverflow.Inc(ns) }\n"}
	if v, _ := nsCounterRefViolations(bad); len(v) != 1 {
		t.Fatalf("a use from another package was not flagged: %v", v)
	}
}
