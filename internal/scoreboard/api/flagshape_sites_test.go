package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// app#456: a flag-shape gate and its log line are one thing. A text reaches
// flagShapePattern only through refuseFlagShape (gate + 400 + log in one call) or
// through validDisplayName, whose sentinel errDisplayNameFlagShape every caller must
// turn into logFlagShapeRefused. flagShapeSiteProblems reads the package's non-test
// sources and reports a gate that is not one of those, so a 7th site added by hand
// without its log line is red here, not silently quiet.

// flagShapeSiteProblems takes file name -> Go source.
func flagShapeSiteProblems(files map[string]string) []string {
	var out []string
	fset := token.NewFileSet()
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var gotRefuse, gotValid int
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, files[name], 0)
		if err != nil {
			out = append(out, name+": "+err.Error())
			continue
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			uses := countIdent(fn.Body, "flagShapePattern")
			switch fn.Name.Name {
			case "refuseFlagShape":
				gotRefuse += uses
				if countCall(fn.Body, "logFlagShapeRefused") == 0 {
					out = append(out, "refuseFlagShape does not call logFlagShapeRefused")
				}
			case "validDisplayName":
				gotValid += uses
			default:
				if uses > 0 {
					out = append(out, name+": "+fn.Name.Name+" uses flagShapePattern; use h.refuseFlagShape (gate + log in one call)")
				}
			}
			// A caller of validDisplayName that is not the stored-name check must turn
			// the sentinel into the log line.
			if calls := countCall(fn.Body, "validDisplayName"); calls > 0 && fn.Name.Name != "StoredDisplayNameViolations" && fn.Name.Name != "validDisplayName" {
				if !sentinelBranchLogs(fn.Body) {
					out = append(out, name+": "+fn.Name.Name+" calls validDisplayName but has no errors.Is(err, errDisplayNameFlagShape) branch that calls logFlagShapeRefused")
				}
			}
		}
	}
	if gotRefuse != 1 || gotValid != 1 {
		out = append(out, "expected exactly one flagShapePattern use in refuseFlagShape and one in validDisplayName (is the scan reading the sources?)")
	}
	return out
}

func countIdent(n ast.Node, name string) (c int) {
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && id.Name == name {
			c++
		}
		return true
	})
	return c
}

// countCall counts calls of a function or method called name.
func countCall(n ast.Node, name string) (c int) {
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == name {
				c++
			}
		case *ast.SelectorExpr:
			if f.Sel.Name == name {
				c++
			}
		}
		return true
	})
	return c
}

// sentinelBranchLogs reports whether the body has an `if` whose condition names
// errDisplayNameFlagShape and whose block calls logFlagShapeRefused.
func sentinelBranchLogs(body *ast.BlockStmt) (found bool) {
	ast.Inspect(body, func(x ast.Node) bool {
		is, ok := x.(*ast.IfStmt)
		if ok && countIdent(is.Cond, "errDisplayNameFlagShape") > 0 && countCall(is.Body, "logFlagShapeRefused") > 0 {
			found = true
		}
		return true
	})
	return found
}

func TestFlagShapeGates_EachOneLogs(t *testing.T) {
	files := map[string]string{}
	paths, err := filepath.Glob("*.go")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no sources: %v", err)
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		files[p] = string(b)
	}
	if p := flagShapeSiteProblems(files); len(p) != 0 {
		t.Fatalf("flag-shape gate without its log line: %v", p)
	}
}

// Mutation: the scan goes red on a hand-written gate, on a gate helper that stopped
// logging, and on a validDisplayName caller that dropped the sentinel branch.
func TestFlagShapeGates_ScanCatchesAGateWithoutALog(t *testing.T) {
	base := map[string]string{
		"a.go": `package api
func (h *Handler) refuseFlagShape() bool { if flagShapePattern.MatchString("") { h.logFlagShapeRefused(); return true }; return false }
func validDisplayName() { _ = flagShapePattern.MatchString("") }
func (h *Handler) setProfile() { _, err := validDisplayName(); if errors.Is(err, errDisplayNameFlagShape) { h.logFlagShapeRefused() } }
`}
	if p := flagShapeSiteProblems(base); len(p) != 0 {
		t.Fatalf("the reference source is rejected: %v", p)
	}
	mut := func(old, new string) map[string]string {
		return map[string]string{"a.go": strings.Replace(base["a.go"], old, new, 1)}
	}
	for name, files := range map[string]map[string]string{
		"a 7th hand-written gate":     {"a.go": base["a.go"], "b.go": "package api\nfunc (h *Handler) newRoute() { if flagShapePattern.MatchString(\"\") { return } }\n"},
		"the helper stops logging":    mut("h.logFlagShapeRefused(); return true", "return true"),
		"the caller drops the log":    mut("{ h.logFlagShapeRefused() } }\n", "{ } }\n"),
		"the caller drops the branch": mut("if errors.Is(err, errDisplayNameFlagShape) { h.logFlagShapeRefused() }", ""),
	} {
		if p := flagShapeSiteProblems(files); len(p) == 0 {
			t.Errorf("%s: the scan accepted it", name)
		}
	}
}
