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

// ADR-0056 D19 A4a-3 / V47 (3rd item), fixed by reading the sources like the one-door
// checks of load_source_test.go: edition.Load takes ONE value for the catalog and the
// tree, the catalog.Scored that catalog.LoadScored returned, plus ANSWERS_FILE and the
// event mode. There is no separate challenges-directory argument, so the scope (what is
// scored) and the tree the practice answers are read from cannot be two different
// trees (review #628 R4#2). The checks:
//
//   - in internal/edition/load.go, Load is (catalog.Scored, string, bool), and
//     practiceJudge and loadPractice take (catalog.Scored) alone; no function of
//     package edition has a parameter named challengesDir;
//   - Scored.FullCatalog (the tree before the scenario restriction: it is for the
//     practice answers, and nothing that scores may read it) is named in two files
//     only: internal/catalog/flags.go (the field and LoadScored's value) and
//     internal/edition/load.go (the one read, in loadPractice);
//   - cmd/scoreboard calls edition.Load once, with a parameter of type catalog.Scored
//     as its first argument (startEdition's), not a field of it, a literal or a local
//     variable; that startEdition is called with the variable scoredFromEnv returned
//     is main_test.go's TestMainTakesCatalogOnlyFromScoredFromEnv (string pins).

// typeString is the source text of a parameter type (enough for the types here).
func typeString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return typeString(x.X) + "." + x.Sel.Name
	case *ast.StarExpr:
		return "*" + typeString(x.X)
	case *ast.ArrayType:
		return "[]" + typeString(x.Elt)
	case *ast.MapType:
		return "map[" + typeString(x.Key) + "]" + typeString(x.Value)
	}
	return "?"
}

// funcSig is the parameter names and types of a function, one entry per parameter.
type funcSig struct{ names, types []string }

func paramsOf(ft *ast.FuncType) funcSig {
	var s funcSig
	if ft.Params == nil {
		return s
	}
	for _, fld := range ft.Params.List {
		ty := typeString(fld.Type)
		if len(fld.Names) == 0 {
			s.names = append(s.names, "")
			s.types = append(s.types, ty)
			continue
		}
		for _, n := range fld.Names {
			s.names = append(s.names, n.Name)
			s.types = append(s.types, ty)
		}
	}
	return s
}

// funcSigs is the signature of every plain function (not a method) of f, by name.
func funcSigs(f *ast.File) map[string]funcSig {
	out := map[string]funcSig{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
			out[fd.Name.Name] = paramsOf(fd.Type)
		}
	}
	return out
}

// wantLoadSigs are the parameter types the functions of load.go must have.
var wantLoadSigs = map[string][]string{
	"Load":          {"catalog.Scored", "string", "bool"},
	"practiceJudge": {"catalog.Scored"},
	"loadPractice":  {"catalog.Scored"},
}

// fullCatalogAllowed are the files that may name Scored.FullCatalog.
var fullCatalogAllowed = []string{"internal/catalog/flags.go", "internal/edition/load.go"}

// loadInputViolations judges every non-test file (slash path -> source). fullReads is
// how many times load.go reads the field through a selector (the positive side).
func loadInputViolations(files map[string]string) (violations []string, fullReads int) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], 0)
		if err != nil {
			violations = append(violations, p+": does not parse: "+err.Error())
			continue
		}
		if strings.HasPrefix(p, "internal/edition/") {
			sigs := funcSigs(f)
			for name, s := range sigs {
				if slices.Contains(s.names, "challengesDir") {
					violations = append(violations, p+" (func "+name+"): has a challengesDir parameter; the tree comes from the catalog.Scored")
				}
			}
			if p == "internal/edition/load.go" {
				for name, want := range wantLoadSigs {
					got, ok := sigs[name]
					switch {
					case !ok:
						violations = append(violations, p+": func "+name+" not found")
					case !slices.Equal(got.types, want):
						violations = append(violations, p+" (func "+name+"): parameters are "+strings.Join(got.types, ", ")+", want "+strings.Join(want, ", "))
					}
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if x.Sel.Name == "FullCatalog" {
					if p == "internal/edition/load.go" {
						fullReads++
					}
					if !slices.Contains(fullCatalogAllowed, p) {
						violations = append(violations, p+": reads Scored.FullCatalog; only load.go's loadPractice may (nothing that scores reads the whole tree)")
					}
				}
			case *ast.KeyValueExpr:
				if id, ok := x.Key.(*ast.Ident); ok && id.Name == "FullCatalog" && !slices.Contains(fullCatalogAllowed, p) {
					violations = append(violations, p+": sets Scored.FullCatalog; only catalog.LoadScored does")
				}
			case *ast.Field:
				for _, id := range x.Names {
					if id.Name == "FullCatalog" && !slices.Contains(fullCatalogAllowed, p) {
						violations = append(violations, p+": declares a FullCatalog field")
					}
				}
			}
			return true
		})
	}
	return violations, fullReads
}

// loadCallViolations judges the calls of edition.Load in cmd/scoreboard: the first
// argument is a parameter of the enclosing function whose type is catalog.Scored (so
// it is passed on as it is: not a field of it, a literal or a local), with exactly
// three arguments. calls is the number of calls found (the positive side).
func loadCallViolations(files map[string]string) (violations []string, calls int) {
	paths := make([]string, 0, len(files))
	for p := range files {
		if strings.HasPrefix(p, "cmd/scoreboard/") {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	for _, p := range paths {
		f, err := parser.ParseFile(token.NewFileSet(), p, files[p], 0)
		if err != nil {
			violations = append(violations, p+": does not parse: "+err.Error())
			continue
		}
		local := ""
		for _, imp := range f.Imports {
			if path, err := strconv.Unquote(imp.Path.Value); err == nil && path == editionImportPath {
				local = "edition"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		if local == "" {
			continue
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			sig := paramsOf(fd.Type)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Load" {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); !ok || id.Name != local {
					return true
				}
				calls++
				where := p + " (func " + fd.Name.Name + ")"
				if len(call.Args) != 3 {
					violations = append(violations, where+": edition.Load has "+strconv.Itoa(len(call.Args))+" arguments, want 3 (Scored, ANSWERS_FILE, the event mode)")
					return true
				}
				arg, ok := call.Args[0].(*ast.Ident)
				if !ok {
					violations = append(violations, where+": the first argument of edition.Load is not a plain parameter (a field, a literal or a call is not the Scored LoadScored returned)")
					return true
				}
				if i := slices.Index(sig.names, arg.Name); i < 0 || sig.types[i] != "catalog.Scored" {
					violations = append(violations, where+": the first argument of edition.Load, "+arg.Name+", is not a parameter of type catalog.Scored")
				}
				return true
			})
		}
	}
	return violations, calls
}

func TestLoadTakesOneScoredInput(t *testing.T) {
	files := nonTestSources(t)

	violations, fullReads := loadInputViolations(files)
	for _, v := range violations {
		t.Error(v)
	}
	if fullReads != 1 {
		t.Errorf("load.go reads Scored.FullCatalog %d time(s), want exactly 1 (loadPractice); a scan that finds nothing is not a pass", fullReads)
	}

	violations, calls := loadCallViolations(files)
	for _, v := range violations {
		t.Error(v)
	}
	if calls != 1 {
		t.Errorf("cmd/scoreboard calls edition.Load %d time(s), want exactly 1", calls)
	}
}

// The scans themselves: the allowed shape passes, every other way is seen.
func TestLoadTakesOneScoredInput_ScanSeesAViolation(t *testing.T) {
	const loadSrc = "package edition\n\n" +
		"func Load(scored catalog.Scored, answersFile string, eventMode bool) {}\n\n" +
		"func practiceJudge(scored catalog.Scored) {}\n\n" +
		"func loadPractice(scored catalog.Scored) { _ = scored.FullCatalog }\n"
	const flagsSrc = "package catalog\n\ntype Scored struct{ FullCatalog Catalog }\n\nfunc LoadScored() { _ = Scored{FullCatalog: nil} }\n"
	base := func() map[string]string {
		return map[string]string{"internal/edition/load.go": loadSrc, "internal/catalog/flags.go": flagsSrc}
	}
	if v, reads := loadInputViolations(base()); len(v) != 0 || reads != 1 {
		t.Fatalf("the allowed shape: violations %v, reads %d; want none and 1", v, reads)
	}

	cases := []struct {
		name string
		path string
		src  string
	}{
		{"Load with a challengesDir argument", "internal/edition/load.go", strings.Replace(loadSrc, "func Load(scored catalog.Scored, answersFile string, eventMode bool)", "func Load(scored catalog.Scored, challengesDir, answersFile string, eventMode bool)", 1)},
		{"Load with a second string argument", "internal/edition/load.go", strings.Replace(loadSrc, "answersFile string, eventMode", "dir, answersFile string, eventMode", 1)},
		{"Load taking the scored catalog only", "internal/edition/load.go", strings.Replace(loadSrc, "scored catalog.Scored, answersFile string", "cat catalog.Catalog, answersFile string", 1)},
		{"loadPractice taking a directory", "internal/edition/load.go", strings.Replace(loadSrc, "func loadPractice(scored catalog.Scored)", "func loadPractice(scored catalog.Scored, dir string)", 1)},
		{"practiceJudge taking a catalog and a directory", "internal/edition/load.go", strings.Replace(loadSrc, "func practiceJudge(scored catalog.Scored)", "func practiceJudge(cat catalog.Catalog, dir string)", 1)},
		{"practiceJudge missing", "internal/edition/load.go", strings.Replace(loadSrc, "func practiceJudge(scored catalog.Scored) {}\n\n", "", 1)},
		{"a challengesDir parameter in another file of the package", "internal/edition/other.go", "package edition\n\nfunc f(challengesDir string) {}\n"},
		{"FullCatalog read by the scoreboard package", "internal/scoreboard/x.go", "package scoreboard\n\nfunc f(s catalog.Scored) { _ = s.FullCatalog }\n"},
		{"FullCatalog set by a literal elsewhere", "cmd/scoreboard/y.go", "package main\n\nvar s = catalog.Scored{FullCatalog: nil}\n"},
		{"a second FullCatalog field", "internal/scoreboard/z.go", "package scoreboard\n\ntype T struct{ FullCatalog int }\n"},
	}
	for _, c := range cases {
		files := base()
		files[c.path] = c.src
		if v, _ := loadInputViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	// FullCatalog read twice in load.go still counts (a second reader is a change to see).
	twice := base()
	twice["internal/edition/load.go"] = loadSrc + "\nfunc other(s catalog.Scored) { _ = s.FullCatalog }\n"
	if _, reads := loadInputViolations(twice); reads != 2 {
		t.Errorf("a second read in load.go counted %d, want 2", reads)
	}

	const imp = "import \"" + editionImportPath + "\"\n\n"
	const goodCall = "package main\n\n" + imp + "func startEdition(scored catalog.Scored) { edition.Load(scored, \"\", false) }\n"
	if v, n := loadCallViolations(map[string]string{"cmd/scoreboard/edition.go": goodCall}); len(v) != 0 || n != 1 {
		t.Fatalf("the allowed call: violations %v, calls %d; want none and 1", v, n)
	}
	for _, c := range [][2]string{
		{"a field of the Scored", "package main\n\n" + imp + "func startEdition(scored catalog.Scored) { edition.Load(scored.Catalog, \"\", false) }\n"},
		{"a literal", "package main\n\n" + imp + "func startEdition(scored catalog.Scored) { edition.Load(catalog.Scored{}, \"\", false) }\n"},
		{"a local variable", "package main\n\n" + imp + "func startEdition() { s := make(); edition.Load(s, \"\", false) }\n"},
		{"a parameter of another type", "package main\n\n" + imp + "func startEdition(scored catalog.Catalog) { edition.Load(scored, \"\", false) }\n"},
		{"a fourth argument (a dir)", "package main\n\n" + imp + "func startEdition(scored catalog.Scored) { edition.Load(scored, dir, \"\", false) }\n"},
		{"a call result", "package main\n\n" + imp + "func startEdition() { edition.Load(get(), \"\", false) }\n"},
		{"through an alias of the import", "package main\n\nimport ed \"" + editionImportPath + "\"\n\nfunc startEdition(scored catalog.Scored) { ed.Load(scored.Catalog, \"\", false) }\n"},
	} {
		if v, _ := loadCallViolations(map[string]string{"cmd/scoreboard/edition.go": c[1]}); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c[0])
		}
	}
}
