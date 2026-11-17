package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ADR-0056 D9 / D13 and D19 A4d-2, fixed by reading the sources (the way load_source_test.go
// fixes the door of the answers table): the renderer is not reachable from the
// scoreboard's HTTP side.
//
// Every file of the renderer stage is named internal/edition/render*.go (a non-test file).
// What they declare is the renderer: the master key and the render functions, and what the
// later files of the stage add (the answers writer): all of it holds or produces the
// event's answers. B7 and B8 (b) of the validator (A4d-2c) are NOT of the stage: they hold
// no key and no answer, so they are in spread.go, which is not named render*.go
// (spread_source_test.go fixes that), and `edition check` reaches them as it reaches any other
// check of the package. The rule:
//
//   - no file of cmd/ or internal/ outside internal/edition refers to an EXPORTED name a
//     render file declares, through the import of the package, whatever name it is
//     imported under, as a call or as a value; a dot import of the package is refused
//     for the same reason, unless the file is in renderCallers;
//   - no non-test file of package edition outside the render files refers to an exported
//     name a render file declares, or calls an unexported function a render file declares:
//     Load, and so the scoreboard, cannot reach the renderer through the package either;
//   - renderCallers is the ONE file that may: internal/edition/eventrender.go, the
//     implementation of `edition render` (RenderEvent, ADR-0056 D20, D19 A4e-3a). It reads the
//     key and the inputs, calls the renderer and writes its output, so it is not a render file
//     (those read no file). The command of cmd/scoreboard does not refer to the renderer: it
//     calls edition.RenderEvent, which is declared in eventrender.go (who calls RenderEvent, and
//     where, is load_source_test.go's doorViolations: runEditionRender, once). `edition check`
//     does not call the renderer, and no file of cmd/scoreboard (the server's wiring or the
//     command) is in the list.
//
// A reference in a test file is not a use (nonTestSources reads no *_test.go).

var renderCallers = map[string]bool{"internal/edition/eventrender.go": true}

// isRenderFile reports whether the slash path (from the repo root) is a file of the
// renderer stage: internal/edition/render*.go, directly in the package's directory.
func isRenderFile(p string) bool {
	rest, ok := strings.CutPrefix(p, "internal/edition/")
	return ok && strings.HasPrefix(rest, "render") && !strings.Contains(rest, "/")
}

// isEditionPackageFile reports whether the path is a file of package edition itself.
func isEditionPackageFile(p string) bool {
	rest, ok := strings.CutPrefix(p, "internal/edition/")
	return ok && !strings.Contains(rest, "/")
}

// renderDeclarations are the top-level names the render files declare: every exported
// function, type, constant and variable, and every unexported function (a method is
// reached through a value of a type, which is guarded).
func renderDeclarations(t *testing.T, files map[string]string) (exported, unexported map[string]bool) {
	t.Helper()
	exported, unexported = map[string]bool{}, map[string]bool{}
	for p, src := range files {
		if !isRenderFile(p) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
		if err != nil {
			t.Fatalf("%s does not parse: %v", p, err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					continue
				}
				if d.Name.IsExported() {
					exported[d.Name.Name] = true
				} else {
					unexported[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							exported[s.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								exported[n.Name] = true
							}
						}
					}
				}
			}
		}
	}
	return exported, unexported
}

// renderReaches lists the places in files (slash path -> source, non-test files) that
// reach the renderer against the rule in the header. allowed are the files that may.
func renderReaches(t *testing.T, files map[string]string, allowed map[string]bool) []string {
	t.Helper()
	exported, unexported := renderDeclarations(t, files)
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	var out []string
	for _, p := range paths {
		if isRenderFile(p) || allowed[p] {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], 0)
		if err != nil {
			out = append(out, p+": does not parse: "+err.Error())
			continue
		}
		inPkg := isEditionPackageFile(p) && f.Name.Name == "edition"
		local := ""
		for _, imp := range f.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil || ip != editionImportPath {
				continue
			}
			switch {
			case imp.Name == nil:
				local = "edition"
			case imp.Name.Name == ".":
				out = append(out, p+": a dot import of the edition package (a name the renderer declares could be used unseen)")
			case imp.Name.Name != "_":
				local = imp.Name.Name
			}
		}
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && exported[x.Sel.Name] {
					out = append(out, p+": refers to edition."+x.Sel.Name+", which the renderer declares")
				}
				// The Sel of a selector is a field or a method, not a name of this package.
				ast.Inspect(x.X, visit)
				return false
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && inPkg && unexported[id.Name] {
					out = append(out, p+": calls "+id.Name+", which the renderer declares")
				}
			case *ast.Ident:
				if inPkg && exported[x.Name] {
					out = append(out, p+": refers to "+x.Name+", which the renderer declares")
				}
			}
			return true
		}
		ast.Inspect(f, visit)
	}
	return out
}

func TestRenderIsNotReachableFromTheScoreboard(t *testing.T) {
	files := nonTestSources(t)
	for _, v := range renderReaches(t, files, renderCallers) {
		t.Error(v)
	}
	// Positive: the render files are there and declare what is expected. A scan that finds
	// nothing is not a pass.
	n := 0
	for p := range files {
		if isRenderFile(p) {
			n++
		}
	}
	if n < 3 {
		t.Errorf("%d render files (internal/edition/render*.go), want at least renderdrbg.go, render.go and rendertemplate.go", n)
	}
	exported, unexported := renderDeclarations(t, files)
	for _, name := range []string{"Render", "RenderPractice", "RenderInput", "Rendered", "AnswerRow", "MasterKey", "NewMasterKey", "PracticeMasterKey"} {
		if !exported[name] {
			t.Errorf("the render files do not declare %s: the scan does not see the renderer", name)
		}
	}
	for _, name := range []string{"render", "compileTemplate", "newDRBG", "uniformBelow"} {
		if !unexported[name] {
			t.Errorf("the render files do not declare the function %s: the scan does not see the renderer", name)
		}
	}
	for p := range renderCallers {
		if _, ok := files[p]; !ok {
			t.Errorf("renderCallers lists %s, which is not a file", p)
		}
	}
	// The entry of the list is a caller (V78, A4e-3a): without it, the scan reports that file and
	// no other. An entry for a file that does not reach the renderer would be a hole kept open
	// for nothing.
	unlisted := renderReaches(t, files, nil)
	if len(unlisted) == 0 {
		t.Error("with no file allowed, the scan reports nothing: the listed caller does not reach the renderer")
	}
	for _, line := range unlisted {
		listed := false
		for p := range renderCallers {
			if strings.HasPrefix(line, p+":") {
				listed = true
			}
		}
		if !listed {
			t.Errorf("with no file allowed, the scan reports %q, a file that is not the listed caller", line)
		}
	}
}

// The scan itself: a copy with one deliberate reach is reported, and what is allowed is not.
func TestRenderReachScan_SeesAReach(t *testing.T) {
	const renderSrc = "package edition\n\nfunc Render() {}\n\nfunc render() {}\n\ntype MasterKey struct{}\n\nconst RuleSpecRender = \"x\"\n\nfunc (MasterKey) Method() {}\n"
	const loadSrc = "package edition\n\nfunc Load() { _ = 1 }\n"
	const mainSrc = "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc main() { edition.Load() }\n"
	base := map[string]string{
		"internal/edition/render.go": renderSrc,
		"internal/edition/load.go":   loadSrc,
		"cmd/scoreboard/main.go":     mainSrc,
	}
	if v := renderReaches(t, base, nil); len(v) != 0 {
		t.Fatalf("the allowed shape was reported: %v", v)
	}

	imp := "package main\n\nimport \"" + editionImportPath + "\"\n\n"
	cases := []struct {
		name string
		path string
		src  string
	}{
		{"a call from the server", "cmd/scoreboard/server.go", imp + "func f() { edition.Render() }\n"},
		{"a call through an alias", "internal/scoreboard/x.go", "package scoreboard\n\nimport ed \"" + editionImportPath + "\"\n\nfunc f() { ed.Render() }\n"},
		{"the function as a value", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.Render\n"},
		{"the type of the key", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nvar k edition.MasterKey\n"},
		{"a constant", "cmd/scoreboard/x.go", imp + "var r = edition.RuleSpecRender\n"},
		{"a dot import", "cmd/scoreboard/x.go", "package main\n\nimport . \"" + editionImportPath + "\"\n"},
		{"Load's file calls Render", "internal/edition/load.go", "package edition\n\nfunc Load() { Render() }\n"},
		{"another file of the package calls render", "internal/edition/other.go", "package edition\n\nfunc g() { render() }\n"},
		{"another file of the package uses the key's type", "internal/edition/other.go", "package edition\n\nvar k MasterKey\n"},
		{"another file of the package uses a constant", "internal/edition/other.go", "package edition\n\nvar r = RuleSpecRender\n"},
	}
	for _, c := range cases {
		files := rdCopyFiles(base)
		files[c.path] = c.src
		if v := renderReaches(t, files, nil); len(v) == 0 {
			t.Errorf("%s: no reach was reported", c.name)
		}
		// The same file, allowed by name, is not reported.
		if v := renderReaches(t, files, map[string]bool{c.path: true}); len(v) != 0 {
			t.Errorf("%s: an allowed file was reported: %v", c.name, v)
		}
	}

	// What is not a reach: a method of another type with the name, a call to what the
	// renderer does not declare, a file of another package named like the package.
	for name, c := range map[string]struct{ path, src string }{
		"a method of another type": {"internal/scoreboard/x.go", "package scoreboard\n\nfunc f(x interface{ Render() }) { x.Render() }\n"},
		"edition.Load":             {"cmd/scoreboard/y.go", imp + "func f() { edition.Load() }\n"},
		"a local name":             {"internal/scoreboard/x.go", "package scoreboard\n\nfunc render() {}\n\nfunc f() { render() }\n"},
	} {
		files := rdCopyFiles(base)
		files[c.path] = c.src
		if v := renderReaches(t, files, nil); len(v) != 0 {
			t.Errorf("%s was reported: %v", name, v)
		}
	}
}

// rdCopyFiles is a copy of m.
func rdCopyFiles(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// D12 / V4: the renderer is deterministic and pure. Its files import nothing that reads
// the environment, the disk, the network or a clock, and no source of randomness (the
// run id of an event is made by the command that calls it, A4e), and log nothing.
func TestRenderFilesAreDeterministicAndPure(t *testing.T) {
	forbidden := []string{
		"os", "io/ioutil", "io/fs", "net", "net/http", "log", "log/slog", "math/rand", "math/rand/v2", "crypto/rand",
		"os/exec", "syscall", "path/filepath",
	}
	n := 0
	for p, src := range nonTestSources(t) {
		if !isRenderFile(p) {
			continue
		}
		n++
		f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
		if err != nil {
			t.Fatalf("%s does not parse: %v", p, err)
		}
		for _, imp := range f.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: import %s: %v", p, imp.Path.Value, err)
			}
			if slices.Contains(forbidden, ip) {
				t.Errorf("%s imports %s: the renderer reads no file and no clock and draws no randomness of its own", p, ip)
			}
		}
		ast.Inspect(f, func(node ast.Node) bool {
			sel, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "time" && (sel.Sel.Name == "Now" || sel.Sel.Name == "Since" || sel.Sel.Name == "Until") {
				t.Errorf("%s calls time.%s: a render is a function of its input", p, sel.Sel.Name)
			}
			return true
		})
	}
	if n < 3 {
		t.Errorf("%d render files were read, want at least 3", n)
	}
}
