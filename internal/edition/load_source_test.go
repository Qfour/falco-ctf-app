package edition_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ADR-0056 D8 (iii) and D19 A2b, fixed by reading the sources (ADR-0033 D6 does the
// same for the flags file): the answers table has ONE door.
//
//   - edition.NewJudge is called by edition.Load (internal/edition/load.go, func
//     Load) and by practiceJudge (the practice mode's Judge, A4a-2, same file), and by
//     nothing else in a non-test file;
//   - practiceJudge is called by edition.Load and by nothing else, and only inside the
//     body of an `if` whose condition has `!eventMode` (TestPracticeJudgeIsOnlyReached
//     OutsideTheEventMode): in the event mode no Judge is made from the practice
//     answers (D8 (iii), V36);
//   - edition.Parse is called by checkAnswersData (the one function that Parses and Checks
//     the bytes of an answers table: ADR-0056 D20, A4e-1, and A4e-3a, which moved it out of
//     loadChecked so that the renderer's self check goes through it too) and by loadPractice,
//     the unexported reader of the practice answers (A4a-1), in the same file; edition.Check
//     is called by checkAnswersData and by practiceJudge, and by nothing else: the table the
//     scoreboard starts with, the table the validator accepts and the table the renderer
//     writes are held to the same Check;
//   - checkAnswersData is called by loadChecked (load.go) and by RenderEvent
//     (internal/edition/eventrender.go: step 4 of D20's `edition render`), once each, and by
//     nothing else;
//   - loadChecked is called by edition.Load (the start-up) and by LoadEventTable (the
//     validator's door), and by nothing else; loadPractice is called by checkAnswersData (T6
//     in the event mode) and by practiceJudge and by nothing else, so the practice answers
//     have one reader and it has two callers;
//   - readPracticeFiles, the reader of the practice editions' bundles and templates, is
//     called by LoadEventTable only: the start-up path reads none of it (A4c-2);
//   - LoadEventTable is called by CheckEvent (internal/edition/checkevent.go, func CheckEvent:
//     step 2 of D20's `edition check`, A4e-2) and by nothing else, once;
//   - CheckEvent and WriteDigestsFile are called by the `edition check` command and by nothing
//     else: cmd/scoreboard/editioncmd.go, func runEditionCheck, once each. THIS test is the one
//     place that holds who calls them, where and how many times (doorViolations and
//     wantDoorCounts). cmd/scoreboard/editioncmd_source_test.go holds the rest of the command's
//     structure only: main's first statement, the server's files not naming the subcommand, the
//     command's imports, and that only the command names the types of the check's surface
//     (CheckInput, CheckReport, InputError);
//   - RenderEvent (ADR-0056 D20, V78, A4e-3a) is called by the `edition render` command and by
//     nothing else: cmd/scoreboard/editioncmd.go, func runEditionRender, once;
//   - RenderPracticeEdition (D20, V78, A4e-3b) is called by the `edition render --practice`
//     command and by nothing else: cmd/scoreboard/editioncmd.go, func runEditionRenderPractice,
//     once;
//   - edition.Load is called by cmd/scoreboard, exactly once, and by nothing else;
//   - load.go holds no PracticeSet literal (TestLoadHasNoPracticeLiteral).
//
// A second reader of the table would be a second place where the practice answers
// could be read in the event mode, or where a value is parsed without Check.

const editionImportPath = "github.com/Qfour/falco-ctf-app/internal/edition"

// doorGuarded are the names of this package that only the door may use.
var doorGuarded = []string{"Parse", "NewJudge", "Load", "loadPractice", "practiceJudge", "loadChecked", "LoadEventTable", "Check", "readPracticeFiles", "CheckEvent", "WriteDigestsFile", "checkAnswersData", "RenderEvent", "RenderPracticeEdition"}

// doorUse is one reference to a guarded name: the file (slash path from the repo
// root), the enclosing function ("" outside any function), the name, and whether
// the reference is the function of a call expression (call) or something else, such
// as `var f = edition.Load`: a value carried around would make the door a name that
// can be used anywhere, so only a call expression is the door.
type doorUse struct {
	file string
	fn   string
	name string
	call bool
}

// doorUses lists the references to Parse, NewJudge and Load in one non-test file.
// A reference is a qualified one (edition.X, through whatever name the file imports
// the package under), or, in a file of the package itself, a bare name. A dot import
// of the package is reported as a (non-call) use of every guarded name.
func doorUses(file, src string) ([]doorUse, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		return nil, err
	}
	inPackage := f.Name.Name == "edition" && strings.HasPrefix(file, "internal/edition/")
	local := ""
	var uses []doorUse
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != editionImportPath {
			continue
		}
		switch {
		case imp.Name == nil:
			local = "edition"
		case imp.Name.Name == ".":
			for _, n := range doorGuarded {
				uses = append(uses, doorUse{file: file, name: n})
			}
		case imp.Name.Name != "_":
			local = imp.Name.Name
		}
	}
	fn := ""
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			// A call whose function is a guarded name is recorded as a call; every
			// other reference (below) is not.
			name := ""
			switch fun := x.Fun.(type) {
			case *ast.SelectorExpr:
				if id, ok := fun.X.(*ast.Ident); ok && local != "" && id.Name == local && slices.Contains(doorGuarded, fun.Sel.Name) {
					name = fun.Sel.Name
				}
			case *ast.Ident:
				if inPackage && slices.Contains(doorGuarded, fun.Name) {
					name = fun.Name
				}
			}
			if name == "" {
				return true
			}
			uses = append(uses, doorUse{file: file, fn: fn, name: name, call: true})
			for _, a := range x.Args {
				ast.Inspect(a, visit)
			}
			return false
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && slices.Contains(doorGuarded, x.Sel.Name) {
				uses = append(uses, doorUse{file: file, fn: fn, name: x.Sel.Name})
			}
			// A selector's own Sel is a field or method name, not a bare identifier of
			// this package: look into X only.
			ast.Inspect(x.X, visit)
			return false
		case *ast.Ident:
			if inPackage && slices.Contains(doorGuarded, x.Name) {
				uses = append(uses, doorUse{file: file, fn: fn, name: x.Name})
			}
		}
		return true
	}
	for _, d := range f.Decls {
		fn = ""
		if fd, ok := d.(*ast.FuncDecl); ok {
			// The body only: the declared name (func Load) is not a use of it.
			fn = fd.Name.Name
			if fd.Body != nil {
				ast.Inspect(fd.Body, visit)
			}
			continue
		}
		ast.Inspect(d, visit)
	}
	return uses, nil
}

// doorViolations judges the uses of every non-test file of the program (the map is
// slash path -> source) against the rule above, and reports what it found: the
// violations, and how many allowed calls there were, by "name@enclosing function"
// (the positive side of the check: a scan that finds nothing is not a pass).
func doorViolations(files map[string]string) (violations []string, counts map[string]int) {
	counts = map[string]int{}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		uses, err := doorUses(p, files[p])
		if err != nil {
			violations = append(violations, p+": does not parse: "+err.Error())
			continue
		}
		for _, u := range uses {
			where := p
			if u.fn != "" {
				where += " (func " + u.fn + ")"
			}
			switch u.name {
			case "Parse":
				// checkAnswersData (the bytes of an answers table, which loadChecked and the
				// renderer's self check give it), and loadPractice (the practice answers, A4a-1).
				if p != "internal/edition/load.go" || (u.fn != "checkAnswersData" && u.fn != "loadPractice") || !u.call {
					violations = append(violations, where+": Parse is used outside a call in checkAnswersData or loadPractice")
					continue
				}
				counts["Parse@"+u.fn]++
			case "Check":
				// One Check for the table the scoreboard starts with, the one the validator
				// accepts and the one the renderer writes: checkAnswersData's, and the practice
				// mode's (practiceJudge).
				if p != "internal/edition/load.go" || (u.fn != "checkAnswersData" && u.fn != "practiceJudge") || !u.call {
					violations = append(violations, where+": Check is used outside a call in checkAnswersData or practiceJudge")
					continue
				}
				counts["Check@"+u.fn]++
			case "checkAnswersData":
				// The two that hand it bytes: loadChecked (a file it read) and the renderer's self
				// check (the table it is about to write, A4e-3a).
				okCaller := (p == "internal/edition/load.go" && u.fn == "loadChecked") || (p == "internal/edition/eventrender.go" && u.fn == "RenderEvent")
				if !okCaller || !u.call {
					violations = append(violations, where+": checkAnswersData is used outside a call in loadChecked (load.go) or RenderEvent (eventrender.go)")
					continue
				}
				counts["checkAnswersData@"+u.fn]++
			case "RenderEvent":
				// The renderer's entrance: the `edition render` command's function, as a call,
				// once (counted below).
				if p != "cmd/scoreboard/editioncmd.go" || u.fn != "runEditionRender" || !u.call {
					violations = append(violations, where+": RenderEvent is used outside a call in runEditionRender of cmd/scoreboard/editioncmd.go (the `edition render` command is its one caller)")
					continue
				}
				counts["RenderEvent@runEditionRender"]++
			case "RenderPracticeEdition":
				// The practice edition's entrance: the `edition render --practice` command's
				// function, as a call, once (counted below).
				if p != "cmd/scoreboard/editioncmd.go" || u.fn != "runEditionRenderPractice" || !u.call {
					violations = append(violations, where+": RenderPracticeEdition is used outside a call in runEditionRenderPractice of cmd/scoreboard/editioncmd.go (the `edition render --practice` command is its one caller)")
					continue
				}
				counts["RenderPracticeEdition@runEditionRenderPractice"]++
			case "loadChecked":
				// The two doors that read an answers file: the start-up's Load and the validator's
				// LoadEventTable.
				if p != "internal/edition/load.go" || (u.fn != "Load" && u.fn != "LoadEventTable") || !u.call {
					violations = append(violations, where+": loadChecked is used outside a call in edition.Load or LoadEventTable")
					continue
				}
				counts["loadChecked@"+u.fn]++
			case "readPracticeFiles":
				// The validator's path only: the start-up opens no bundle and no template.
				if p != "internal/edition/load.go" || u.fn != "LoadEventTable" || !u.call {
					violations = append(violations, where+": readPracticeFiles is used outside a call in LoadEventTable (the start-up path reads no bundle and no template)")
					continue
				}
				counts["readPracticeFiles@LoadEventTable"]++
			case "LoadEventTable":
				// The validator's door: CheckEvent's step 2, and nothing else (the command
				// calls CheckEvent, not this).
				if p != "internal/edition/checkevent.go" || u.fn != "CheckEvent" || !u.call {
					violations = append(violations, where+": LoadEventTable is used outside a call in CheckEvent (D20: the command calls CheckEvent, which is the one caller)")
					continue
				}
				counts["LoadEventTable@CheckEvent"]++
			case "CheckEvent", "WriteDigestsFile":
				// The validator's entrance and its one writer: the `edition check` command's
				// function, as a call, once each (counted below).
				if p != "cmd/scoreboard/editioncmd.go" || u.fn != "runEditionCheck" || !u.call {
					violations = append(violations, where+": "+u.name+" is used outside a call in runEditionCheck of cmd/scoreboard/editioncmd.go (the `edition check` command is its one caller)")
					continue
				}
				counts[u.name+"@runEditionCheck"]++
			case "NewJudge":
				// A Judge is made from the event table (Load) or, outside the event mode,
				// from the practice answers of the scope (practiceJudge): never from
				// loadPractice, the reader.
				if p != "internal/edition/load.go" || (u.fn != "Load" && u.fn != "practiceJudge") || !u.call {
					violations = append(violations, where+": NewJudge is used outside a call in edition.Load or practiceJudge")
					continue
				}
				counts["NewJudge@"+u.fn]++
			case "loadPractice":
				if p != "internal/edition/load.go" || (u.fn != "checkAnswersData" && u.fn != "practiceJudge") || !u.call {
					violations = append(violations, where+": loadPractice is used outside a call in checkAnswersData or practiceJudge (it is the one reader of the practice answers)")
					continue
				}
				counts["loadPractice@"+u.fn]++
			case "practiceJudge":
				// The practice mode's Judge: Load is its only caller (and the branch it is
				// called in is checked by practiceJudgeBranch).
				if p != "internal/edition/load.go" || u.fn != "Load" || !u.call {
					violations = append(violations, where+": practiceJudge is used outside a call in edition.Load")
					continue
				}
				counts["practiceJudge@Load"]++
			case "Load":
				if !strings.HasPrefix(p, "cmd/scoreboard/") {
					violations = append(violations, where+": edition.Load is used outside cmd/scoreboard")
					continue
				}
				if !u.call {
					violations = append(violations, where+": edition.Load is taken as a value; only a call expression is the door")
					continue
				}
				counts["Load@cmd/scoreboard"]++
			}
		}
	}
	if counts["Load@cmd/scoreboard"] > 1 {
		violations = append(violations, "cmd/scoreboard calls edition.Load more than once; the door is one call")
	}
	for _, name := range []string{"CheckEvent", "WriteDigestsFile"} {
		if counts[name+"@runEditionCheck"] > 1 {
			violations = append(violations, "runEditionCheck calls "+name+" more than once; the command is one call")
		}
	}
	if counts["RenderEvent@runEditionRender"] > 1 {
		violations = append(violations, "runEditionRender calls RenderEvent more than once; the command is one call")
	}
	if counts["RenderPracticeEdition@runEditionRenderPractice"] > 1 {
		violations = append(violations, "runEditionRenderPractice calls RenderPracticeEdition more than once; the command is one call")
	}
	for _, fn := range []string{"loadChecked", "RenderEvent"} {
		if counts["checkAnswersData@"+fn] > 1 {
			violations = append(violations, fn+" calls checkAnswersData more than once")
		}
	}
	return violations, counts
}

// nonTestSources reads every non-test .go file of cmd/ and internal/ (slash path from
// the repo root -> source).
func nonTestSources(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, root := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join("..", "..", root), func(path string, d fs.DirEntry, err error) error {
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
			rel, err := filepath.Rel(filepath.Join("..", ".."), path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 50 {
		t.Fatalf("read only %d non-test files; the walk is not seeing the tree", len(files))
	}
	return files
}

func TestAnswersTableHasOneDoor(t *testing.T) {
	files := nonTestSources(t)
	violations, counts := doorViolations(files)
	for _, v := range violations {
		t.Error(v)
	}
	// Positive: the door is there, once, and so is the practice reader. A scan that
	// finds nothing is not a pass.
	if !maps.Equal(counts, wantDoorCounts) {
		t.Errorf("calls found = %v, want %v", counts, wantDoorCounts)
	}
}

// wantDoorCounts is the whole of what the program may call: see the header.
// A4a-2 added NewJudge@practiceJudge, loadPractice@practiceJudge and
// practiceJudge@Load (the practice mode's Judge). A4e-1 moved the read of the answers file
// out of Load into loadChecked, which the validator's LoadEventTable shares: Parse@Load and
// loadPractice@Load became Parse@loadChecked and loadPractice@loadChecked, and the two
// Check calls, loadChecked@Load, loadChecked@LoadEventTable and readPracticeFiles@
// LoadEventTable are the new door. A4e-3a moved the Parse and the Check of the bytes of a table
// (and the read of the practice answers for T6) out of loadChecked into checkAnswersData, which
// loadChecked calls and the renderer's self check calls (Parse@loadChecked, Check@loadChecked and
// loadPractice@loadChecked became the three @checkAnswersData), and added the renderer's
// entrance, RenderEvent@runEditionRender. A4e-3b added the practice edition's entrance,
// RenderPracticeEdition@runEditionRenderPractice.
var wantDoorCounts = map[string]int{
	"Parse@checkAnswersData":           1,
	"Parse@loadPractice":               1,
	"Check@checkAnswersData":           1,
	"Check@practiceJudge":              1,
	"NewJudge@Load":                    1,
	"NewJudge@practiceJudge":           1,
	"loadChecked@Load":                 1,
	"loadChecked@LoadEventTable":       1,
	"checkAnswersData@loadChecked":     1,
	"checkAnswersData@RenderEvent":     1,
	"loadPractice@checkAnswersData":    1,
	"loadPractice@practiceJudge":       1,
	"practiceJudge@Load":               1,
	"readPracticeFiles@LoadEventTable": 1,
	"LoadEventTable@CheckEvent":        1,
	"CheckEvent@runEditionCheck":       1,
	"WriteDigestsFile@runEditionCheck": 1,
	"RenderEvent@runEditionRender":     1,
	"Load@cmd/scoreboard":              1,

	"RenderPracticeEdition@runEditionRenderPractice": 1,
}

// ADR-0056 D19 A4a-1 / V34: the Options that Load hands to Check carry the practice
// answers loadPractice read, never a literal PracticeSet (which would be "no practice
// answers" written by hand: the T6 that never refuses). The check is on the syntax of
// load.go: no composite literal of type PracticeSet anywhere in it.
func practiceLiterals(file, src string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, 0)
	if err != nil {
		return nil, err
	}
	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		switch ty := cl.Type.(type) {
		case *ast.Ident:
			if ty.Name == "PracticeSet" {
				found = append(found, "PracticeSet{...}")
			}
		case *ast.SelectorExpr:
			if ty.Sel.Name == "PracticeSet" {
				found = append(found, "edition.PracticeSet{...}")
			}
		}
		return true
	})
	return found, nil
}

func TestLoadHasNoPracticeLiteral(t *testing.T) {
	b, err := os.ReadFile("load.go")
	if err != nil {
		t.Fatal(err)
	}
	got, err := practiceLiterals("internal/edition/load.go", string(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("load.go holds a PracticeSet literal %v; the set comes from loadPractice", got)
	}
	// The scan itself: the old shape, and a qualified one, are seen; make() is not a literal.
	for name, src := range map[string]string{
		"the old shape":   "package edition\n\nvar o = Options{Practice: PracticeSet{}}\n",
		"a qualified one": "package x\n\nvar o = edition.Options{Practice: edition.PracticeSet{}}\n",
	} {
		if got, err := practiceLiterals("x.go", src); err != nil || len(got) != 1 {
			t.Errorf("%s: found %v (err %v), want one literal", name, got, err)
		}
	}
	if got, err := practiceLiterals("x.go", "package edition\n\nvar s = make(PracticeSet)\n"); err != nil || len(got) != 0 {
		t.Errorf("make(PracticeSet) was reported: %v (err %v)", got, err)
	}
}

// The scanner itself: a copy with one deliberate violation is reported, and the
// shape that is allowed is not.
func TestAnswersTableDoorScan_SeesAViolation(t *testing.T) {
	// The shape of load.go since A4e-3a: Load and LoadEventTable read the answers file through
	// loadChecked, which hands its bytes to checkAnswersData, which Parses them, reads the
	// practice answers and Checks; the practice mode's Judge is practiceJudge's; only
	// LoadEventTable reads the practice editions' files.
	const loadSrc = "package edition\n\n" +
		"func Load(eventMode bool) {\n\t_, _, _, _ = loadChecked(eventMode)\n\t_, _ = NewJudge(nil)\n\tif !eventMode {\n\t\t_, _ = practiceJudge()\n\t}\n}\n\n" +
		"func LoadEventTable() {\n\t_, _, _, _ = loadChecked(true)\n\t_, _ = readPracticeFiles(nil)\n}\n\n" +
		"func loadChecked(eventMode bool) (int, int, int, error) {\n\treturn checkAnswersData(nil, nil, eventMode)\n}\n\n" +
		"func checkAnswersData(s, d []int, eventMode bool) (int, int, int, error) {\n\t_, _ = Parse(nil)\n\t_, _ = loadPractice(\"\")\n\t_ = Check(nil)\n\treturn 0, 0, 0, nil\n}\n\n" +
		"func loadPractice(string) (int, error) {\n\t_, _ = Parse(nil)\n\treturn 0, nil\n}\n\n" +
		"func practiceJudge() (int, error) {\n\t_, _ = NewJudge(nil)\n\t_, _ = loadPractice(\"\")\n\t_ = Check(nil)\n\treturn 0, nil\n}\n"
	const mainSrc = "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc main() {\n\tedition.Load()\n}\n"
	// CheckEvent (A4e-2) is the validator's one caller of LoadEventTable.
	const eventSrc = "package edition\n\nfunc CheckEvent() {\n\t_, _, _ = LoadEventTable(nil, \"\")\n}\n"
	// RenderEvent (A4e-3a) holds the bytes of the table it is about to write to checkAnswersData.
	const renderEventSrc = "package edition\n\nfunc RenderEvent() {\n\t_, _, _, _ = checkAnswersData(nil, nil, true)\n}\n"
	// The `edition check` command calls CheckEvent and WriteDigestsFile, once each, the
	// `edition render` command calls RenderEvent, once, and `edition render --practice` calls
	// RenderPracticeEdition, once.
	const cmdSrc = "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionCheck() {\n\t_, _, _ = edition.CheckEvent(in)\n\t_ = edition.WriteDigestsFile(p, ev)\n}\n\nfunc runEditionRender() {\n\t_, _ = edition.RenderEvent(in)\n}\n\nfunc runEditionRenderPractice() {\n\t_, _ = edition.RenderPracticeEdition(c, id)\n}\n"
	good := map[string]string{"internal/edition/load.go": loadSrc, "internal/edition/checkevent.go": eventSrc, "internal/edition/eventrender.go": renderEventSrc, "cmd/scoreboard/edition.go": mainSrc, "cmd/scoreboard/editioncmd.go": cmdSrc}
	if v, c := doorViolations(good); len(v) != 0 || !maps.Equal(c, wantDoorCounts) {
		t.Fatalf("the allowed shape: violations %v, calls %v, want none and %v", v, c, wantDoorCounts)
	}

	cases := []struct {
		name string
		path string
		src  string
	}{
		{"Parse called by a package that imports edition", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { edition.Parse(nil) }\n"},
		{"NewJudge called through an alias", "internal/scoreboard/x.go", "package scoreboard\n\nimport ed \"" + editionImportPath + "\"\n\nfunc f() { ed.NewJudge(nil) }\n"},
		{"Load called outside cmd/scoreboard", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { edition.Load() }\n"},
		{"Load taken as a value in cmd/scoreboard", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.Load\n"},
		{"Load taken as a value elsewhere", "internal/scoreboard/y.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.Load\n"},
		{"Load called a second time in cmd/scoreboard", "cmd/scoreboard/y.go", mainSrc},
		{"Parse taken as a value in Load", "internal/edition/other.go", "package edition\n\nfunc Load() { f := Parse; _ = f }\n"},
		{"a dot import", "cmd/scoreboard/y.go", "package main\n\nimport . \"" + editionImportPath + "\"\n"},
		{"Parse called by another function of the package", "internal/edition/other.go", "package edition\n\nfunc other() { Parse(nil) }\n"},
		{"Parse called by Load in another file", "internal/edition/other.go", "package edition\n\nfunc Load() { Parse(nil) }\n"},
		{"Parse reached through a call chain", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _ = edition.Parse(nil).Seats() }\n"},
		// The practice reader (A4a-1): it may Parse, and nothing else may call it or make a Judge in it.
		{"NewJudge called by loadPractice", "internal/edition/load.go", "package edition\n\nfunc Load() {\n\t_, _ = loadPractice(\"\")\n}\n\nfunc loadPractice(string) (int, error) {\n\t_, _ = NewJudge(nil)\n\treturn 0, nil\n}\n"},
		{"loadPractice called by another function", "internal/edition/other.go", "package edition\n\nfunc other() { _, _ = loadPractice(\"\") }\n"},
		{"loadPractice taken as a value in Load", "internal/edition/other.go", "package edition\n\nfunc Load() { f := loadPractice; _ = f }\n"},
		{"Parse called by loadPractice in another file", "internal/edition/other.go", "package edition\n\nfunc loadPractice(string) { Parse(nil) }\n"},
		{"Parse called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _ = Parse(nil) }\n"},
		// The practice mode's Judge (A4a-2): Load alone calls practiceJudge; the Judge is
		// made in practiceJudge and in Load, in no third function; the reader has two callers.
		{"practiceJudge called by another function", "internal/edition/other.go", "package edition\n\nfunc other() { _, _ = practiceJudge() }\n"},
		{"practiceJudge called by Load in another file", "internal/edition/other.go", "package edition\n\nfunc Load() { _, _ = practiceJudge() }\n"},
		{"practiceJudge taken as a value in Load", "internal/edition/other.go", "package edition\n\nfunc Load() { f := practiceJudge; _ = f }\n"},
		{"NewJudge called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _ = NewJudge(nil) }\n"},
		{"loadPractice called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _ = loadPractice(\"\") }\n"},
		{"practiceJudge called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _ = practiceJudge() }\n"},
		// The one read of the answers file and the one Check (A4e-1, V54): the start-up and
		// the validator are held to the same function.
		{"Parse called by Load itself, not through loadChecked", "internal/edition/load.go", strings.Replace(loadSrc, "_, _, _, _ = loadChecked(eventMode)", "_, _ = Parse(nil)", 1)},
		{"Parse called by LoadEventTable itself", "internal/edition/load.go", strings.Replace(loadSrc, "_, _, _, _ = loadChecked(true)", "_, _ = Parse(nil)", 1)},
		{"Check called by Load itself", "internal/edition/load.go", strings.Replace(loadSrc, "_, _, _, _ = loadChecked(eventMode)", "_ = Check(nil)", 1)},
		{"Check called by LoadEventTable (a second Check for the validator)", "internal/edition/load.go", strings.Replace(loadSrc, "_, _, _, _ = loadChecked(true)", "_ = Check(nil)", 1)},
		{"Check called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _ = Check(nil) }\n"},
		{"Check called by another file of the package", "internal/edition/other.go", "package edition\n\nfunc other() { _ = Check(nil) }\n"},
		{"Check called by Load in another file", "internal/edition/other.go", "package edition\n\nfunc Load() { _ = Check(nil) }\n"},
		{"Check called by a package that imports edition", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _ = edition.Check(nil) }\n"},
		{"Check taken as a value", "internal/edition/other.go", "package edition\n\nvar f = Check\n"},
		{"loadChecked called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _, _, _ = loadChecked(true) }\n"},
		{"loadChecked called by another file of the package", "internal/edition/other.go", "package edition\n\nfunc other() { _, _, _, _ = loadChecked(true) }\n"},
		{"loadChecked taken as a value", "internal/edition/other.go", "package edition\n\nfunc Load() { f := loadChecked; _ = f }\n"},
		// The practice editions' files are the validator's path only.
		{"readPracticeFiles called by Load (the start-up reads no bundle)", "internal/edition/load.go", strings.Replace(loadSrc, "_, _, _, _ = loadChecked(eventMode)", "_, _, _, _ = loadChecked(eventMode)\n\t_, _ = readPracticeFiles(nil)", 1)},
		{"readPracticeFiles called by another function", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _ = readPracticeFiles(nil) }\n"},
		{"readPracticeFiles called from another file", "internal/edition/other.go", "package edition\n\nfunc LoadEventTable() { _, _ = readPracticeFiles(nil) }\n"},
		// LoadEventTable has one caller, CheckEvent.
		{"LoadEventTable called from cmd/scoreboard (the command calls CheckEvent)", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _, _, _ = edition.LoadEventTable(s, \"\") }\n"},
		// CheckEvent and WriteDigestsFile: the command's function only, once each.
		{"CheckEvent called from another file of cmd/scoreboard", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _, _, _ = edition.CheckEvent(in) }\n"},
		{"CheckEvent called twice by the command", "cmd/scoreboard/editioncmd.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionCheck() {\n\t_, _, _ = edition.CheckEvent(in)\n\t_, _, _ = edition.CheckEvent(in)\n\t_ = edition.WriteDigestsFile(p, ev)\n}\n"},
		{"CheckEvent called by another function of the command's file", "cmd/scoreboard/editioncmd.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionCheck() {\n\t_, _, _ = edition.CheckEvent(in)\n\t_ = edition.WriteDigestsFile(p, ev)\n}\n\nfunc other() { _, _, _ = edition.CheckEvent(in) }\n"},
		{"WriteDigestsFile called by another function of the command's file", "cmd/scoreboard/editioncmd.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionCheck() {\n\t_, _, _ = edition.CheckEvent(in)\n}\n\nfunc other() { _ = edition.WriteDigestsFile(p, ev) }\n"},
		{"CheckEvent called from the scoreboard's server", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _, _, _ = edition.CheckEvent(in) }\n"},
		{"CheckEvent called by another function of the package", "internal/edition/other.go", "package edition\n\nfunc other() { _, _, _ = CheckEvent(in) }\n"},
		{"CheckEvent taken as a value", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.CheckEvent\n"},
		{"WriteDigestsFile called from cmd/scoreboard", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _ = edition.WriteDigestsFile(p, ev) }\n"},
		{"WriteDigestsFile called by another function of the package", "internal/edition/other.go", "package edition\n\nfunc other() { _ = WriteDigestsFile(p, ev) }\n"},
		{"LoadEventTable called from the scoreboard's server", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _, _, _ = edition.LoadEventTable(s, \"\") }\n"},
		{"LoadEventTable called by another function of the package", "internal/edition/other.go", "package edition\n\nfunc other() { _, _, _ = LoadEventTable(s, \"\") }\n"},
		{"LoadEventTable taken as a value", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.LoadEventTable\n"},
		// The one Parse and Check of the bytes of a table (A4e-3a): checkAnswersData, which
		// loadChecked and RenderEvent call, once each.
		{"Parse called by loadChecked itself, not through checkAnswersData", "internal/edition/load.go", strings.Replace(loadSrc, "\treturn checkAnswersData(nil, nil, eventMode)\n", "\t_, _ = Parse(nil)\n\treturn 0, 0, 0, nil\n", 1)},
		{"Check called by loadChecked itself, not through checkAnswersData", "internal/edition/load.go", strings.Replace(loadSrc, "\treturn checkAnswersData(nil, nil, eventMode)\n", "\t_ = Check(nil)\n\treturn 0, 0, 0, nil\n", 1)},
		{"loadPractice called by loadChecked itself", "internal/edition/load.go", strings.Replace(loadSrc, "\treturn checkAnswersData(nil, nil, eventMode)\n", "\t_, _ = loadPractice(\"\")\n\treturn 0, 0, 0, nil\n", 1)},
		{"checkAnswersData called by a third function of load.go", "internal/edition/load.go", loadSrc + "\nfunc readMore() { _, _, _, _ = checkAnswersData(nil, nil, true) }\n"},
		{"checkAnswersData called by RenderEvent in another file", "internal/edition/other.go", "package edition\n\nfunc RenderEvent() { _, _, _, _ = checkAnswersData(nil, nil, true) }\n"},
		{"checkAnswersData called by another function of eventrender.go", "internal/edition/eventrender.go", renderEventSrc + "\nfunc other() { _, _, _, _ = checkAnswersData(nil, nil, true) }\n"},
		{"checkAnswersData called twice by RenderEvent", "internal/edition/eventrender.go", "package edition\n\nfunc RenderEvent() {\n\t_, _, _, _ = checkAnswersData(nil, nil, true)\n\t_, _, _, _ = checkAnswersData(nil, nil, true)\n}\n"},
		{"checkAnswersData taken as a value", "internal/edition/eventrender.go", "package edition\n\nfunc RenderEvent() { f := checkAnswersData; _ = f }\n"},
		// RenderEvent: the `edition render` command's function only, once (V78).
		{"RenderEvent called from another file of cmd/scoreboard", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionRender() { _, _ = edition.RenderEvent(in) }\n"},
		{"RenderEvent called twice by the command", "cmd/scoreboard/editioncmd.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionRender() {\n\t_, _ = edition.RenderEvent(in)\n\t_, _ = edition.RenderEvent(in)\n}\n"},
		{"RenderEvent called by the check command's function", "cmd/scoreboard/editioncmd.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionCheck() { _, _ = edition.RenderEvent(in) }\n"},
		{"RenderEvent taken as a value", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.RenderEvent\n"},
		{"RenderEvent called from the scoreboard's server", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _, _ = edition.RenderEvent(in) }\n"},
		{"RenderEvent called by another function of the package", "internal/edition/other.go", "package edition\n\nfunc other() { _, _ = RenderEvent(in) }\n"},
		// RenderPracticeEdition: the `edition render --practice` command's function only, once (V78).
		{"RenderPracticeEdition called from another file of cmd/scoreboard", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionRenderPractice() { _, _ = edition.RenderPracticeEdition(c, id) }\n"},
		{"RenderPracticeEdition called twice by the command", "cmd/scoreboard/editioncmd.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionRenderPractice() {\n\t_, _ = edition.RenderPracticeEdition(c, id)\n\t_, _ = edition.RenderPracticeEdition(c, id)\n}\n"},
		{"RenderPracticeEdition called by the event's render function", "cmd/scoreboard/editioncmd.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nfunc runEditionRender() { _, _ = edition.RenderPracticeEdition(c, id) }\n"},
		{"RenderPracticeEdition taken as a value", "cmd/scoreboard/y.go", "package main\n\nimport \"" + editionImportPath + "\"\n\nvar f = edition.RenderPracticeEdition\n"},
		{"RenderPracticeEdition called from the scoreboard's server", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _, _ = edition.RenderPracticeEdition(c, id) }\n"},
		{"RenderPracticeEdition called by another function of the package", "internal/edition/other.go", "package edition\n\nfunc other() { _, _ = RenderPracticeEdition(c, id) }\n"},
	}
	for _, c := range cases {
		files := map[string]string{"internal/edition/load.go": loadSrc, "cmd/scoreboard/edition.go": mainSrc, c.path: c.src}
		if v, _ := doorViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}

	// A method that is named Load or Parse on something else is not the door.
	other := "package scoreboard\n\nfunc f(x interface{ Load(); Parse() }) { x.Load(); x.Parse() }\n"
	if v, _ := doorViolations(map[string]string{"internal/scoreboard/x.go": other}); len(v) != 0 {
		t.Errorf("a method call on another type was reported: %v", v)
	}
}

// ADR-0056 D8 (iii) and D19 A4a-2 / V36: in the event mode no Judge is made from the
// practice answers. practiceJudge is the one function that does, so it may be reached
// from edition.Load only inside the body of an `if` whose condition cannot hold
// unless eventMode is false.

// impliesNotEventMode reports whether e cannot be true while eventMode is true:
// `!eventMode`, in parentheses or as an operand of &&. A condition that lets the
// branch be taken another way (an ||, a bare eventMode) does not count.
func impliesNotEventMode(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return impliesNotEventMode(x.X)
	case *ast.UnaryExpr:
		id, ok := x.X.(*ast.Ident)
		return x.Op == token.NOT && ok && id.Name == "eventMode"
	case *ast.BinaryExpr:
		return x.Op == token.LAND && (impliesNotEventMode(x.X) || impliesNotEventMode(x.Y))
	}
	return false
}

// practiceJudgeCalls counts the calls to practiceJudge in the body of func Load of
// src, and how many of them are not in the Body of an if that impliesNotEventMode
// (the Else of such an if is the event mode's side, so it is not guarded).
func practiceJudgeCalls(file, src string) (total, unguarded int, err error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, 0)
	if err != nil {
		return 0, 0, err
	}
	var load *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "Load" {
			load = fd
		}
	}
	if load == nil || load.Body == nil {
		return 0, 0, errors.New("func Load not found")
	}
	var walk func(n ast.Node, guarded bool)
	walk = func(n ast.Node, guarded bool) {
		ast.Inspect(n, func(x ast.Node) bool {
			switch x := x.(type) {
			case *ast.IfStmt:
				if x.Init != nil {
					walk(x.Init, guarded)
				}
				walk(x.Cond, guarded)
				walk(x.Body, guarded || impliesNotEventMode(x.Cond))
				if x.Else != nil {
					walk(x.Else, guarded)
				}
				return false
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "practiceJudge" {
					total++
					if !guarded {
						unguarded++
					}
				}
			}
			return true
		})
	}
	walk(load.Body, false)
	return total, unguarded, nil
}

func TestPracticeJudgeIsOnlyReachedOutsideTheEventMode(t *testing.T) {
	b, err := os.ReadFile("load.go")
	if err != nil {
		t.Fatal(err)
	}
	total, unguarded, err := practiceJudgeCalls("load.go", string(b))
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("func Load calls practiceJudge %d time(s), want exactly 1 (a scan that finds nothing is not a pass)", total)
	}
	if unguarded != 0 {
		t.Errorf("func Load calls practiceJudge %d time(s) outside an `if !eventMode` branch: in the event mode no Judge is made from the practice answers (D8 (iii))", unguarded)
	}

	// The scan itself: the allowed shapes pass, every other way to reach the call is seen.
	cases := []struct {
		name      string
		body      string
		total     int
		unguarded int
	}{
		{"the branch", "if !eventMode {\n\t\t_, _ = practiceJudge()\n\t}", 1, 0},
		{"the branch with another operand", "if !eventMode && x {\n\t\t_, _ = practiceJudge()\n\t}", 1, 0},
		{"the branch in parentheses", "if (!eventMode) {\n\t\t_, _ = practiceJudge()\n\t}", 1, 0},
		{"a nested if inside the branch", "if !eventMode {\n\t\tif x {\n\t\t\t_, _ = practiceJudge()\n\t\t}\n\t}", 1, 0},
		{"no condition", "_, _ = practiceJudge()", 1, 1},
		{"the else of the branch (the event mode)", "if !eventMode {\n\t\t_ = 1\n\t} else {\n\t\t_, _ = practiceJudge()\n\t}", 1, 1},
		{"the condition without the negation", "if eventMode {\n\t\t_, _ = practiceJudge()\n\t}", 1, 1},
		{"an or, which the event mode can satisfy", "if !eventMode || x {\n\t\t_, _ = practiceJudge()\n\t}", 1, 1},
		{"another variable", "if !x {\n\t\t_, _ = practiceJudge()\n\t}", 1, 1},
		{"no call at all", "_ = x", 0, 0},
	}
	for _, c := range cases {
		src := "package edition\n\nfunc Load(eventMode, x bool) {\n\t" + c.body + "\n}\n"
		gotTotal, gotUnguarded, err := practiceJudgeCalls("x.go", src)
		if err != nil || gotTotal != c.total || gotUnguarded != c.unguarded {
			t.Errorf("%s: total %d, unguarded %d, err %v; want %d and %d", c.name, gotTotal, gotUnguarded, err, c.total, c.unguarded)
		}
	}
	if _, _, err := practiceJudgeCalls("x.go", "package edition\n\nfunc other() {}\n"); err == nil {
		t.Error("a file with no func Load was not reported")
	}
}

// ADR-0056 D19 A4a-2 (review #630 R4#2): a Table is made in internal/edition/table.go
// only, by Parse and by joinPractice (which re-checks what Parse guarantees of a
// table: the run id and no repeated cell). Parse and NewJudge being called from one
// place does not cover a Table that is built by hand elsewhere, so the sources are
// scanned for the other ways to make one: a composite literal of the type, new(Table)
// and a `var t Table`, in package edition (bare name) and anywhere else through an
// import of it.

// tableMakers are the functions of table.go that may make a Table.
var tableMakers = []string{"Parse", "joinPractice"}

// tableMakes returns the enclosing function ("" outside any) of each place in src
// that makes a Table value.
func tableMakes(file, src string) ([]string, error) { return typeMakes(file, src, "Table") }

// typeMakes returns the enclosing function ("" outside any) of each place in src that makes
// a value of the type `name` of package edition: a composite literal, new(name) and a
// `var x name`, in package edition (bare name) and anywhere else through an import of it.
// A pointer type (`var x *name`, a parameter, a receiver) makes none. It is tableMakes's scan
// for any type (validator_door_source_test.go uses it for CheckedTable and CheckedBundles).
func typeMakes(file, src, name string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, 0)
	if err != nil {
		return nil, err
	}
	inPackage := f.Name.Name == "edition" && strings.HasPrefix(file, "internal/edition/")
	local := ""
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != editionImportPath {
			continue
		}
		switch {
		case imp.Name == nil:
			local = "edition"
		case imp.Name.Name == ".":
			out = append(out, "(dot import)")
		case imp.Name.Name != "_":
			local = imp.Name.Name
		}
	}
	isTable := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.Ident:
			return inPackage && x.Name == name
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			return ok && local != "" && id.Name == local && x.Sel.Name == name
		}
		return false
	}
	for _, d := range f.Decls {
		fn := ""
		if fd, ok := d.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
		}
		ast.Inspect(d, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if x.Type != nil && isTable(x.Type) {
					out = append(out, fn)
				}
			case *ast.ValueSpec:
				if x.Type != nil && isTable(x.Type) {
					out = append(out, fn)
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 && isTable(x.Args[0]) {
					out = append(out, fn)
				}
			}
			return true
		})
	}
	return out, nil
}

// tableViolations judges every non-test file (slash path -> source): a Table made
// anywhere but in table.go's tableMakers is a violation. counts is the positive side,
// by "function".
func tableViolations(files map[string]string) (violations []string, counts map[string]int) {
	counts = map[string]int{}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		fns, err := tableMakes(p, files[p])
		if err != nil {
			violations = append(violations, p+": does not parse: "+err.Error())
			continue
		}
		for _, fn := range fns {
			if p == "internal/edition/table.go" && slices.Contains(tableMakers, fn) {
				counts[fn]++
				continue
			}
			violations = append(violations, p+" (func "+fn+"): makes an edition.Table outside Parse and joinPractice in table.go")
		}
	}
	return violations, counts
}

func TestTableIsMadeOnlyInTableGo(t *testing.T) {
	violations, counts := tableViolations(nonTestSources(t))
	for _, v := range violations {
		t.Error(v)
	}
	// Positive: the two makers are there, once each. A scan that finds nothing is not a pass.
	if want := map[string]int{"Parse": 1, "joinPractice": 1}; !maps.Equal(counts, want) {
		t.Errorf("Table makers found = %v, want %v", counts, want)
	}

	// The scan itself: the allowed shape passes, every other way to make a Table is seen.
	const tableSrc = "package edition\n\nfunc Parse() *Table { return &Table{} }\n\nfunc joinPractice() *Table { return &Table{} }\n"
	good := map[string]string{"internal/edition/table.go": tableSrc}
	if v, c := tableViolations(good); len(v) != 0 || !maps.Equal(c, map[string]int{"Parse": 1, "joinPractice": 1}) {
		t.Fatalf("the allowed shape: violations %v, counts %v", v, c)
	}
	cases := []struct {
		name string
		path string
		src  string
	}{
		{"a literal in load.go", "internal/edition/load.go", "package edition\n\nfunc scopePracticeTable() *Table { return &Table{runID: PracticeRunID} }\n"},
		{"a literal in another function of table.go", "internal/edition/table.go", tableSrc + "\nfunc other() *Table { return &Table{} }\n"},
		{"a value literal", "internal/edition/load.go", "package edition\n\nfunc f() { _ = Table{} }\n"},
		{"new(Table)", "internal/edition/load.go", "package edition\n\nfunc f() { _ = new(Table) }\n"},
		{"var t Table in a function", "internal/edition/load.go", "package edition\n\nfunc f() { var t Table; _ = t }\n"},
		{"a package-level var of the type", "internal/edition/load.go", "package edition\n\nvar t Table\n"},
		{"a qualified literal elsewhere", "internal/scoreboard/x.go", "package scoreboard\n\nimport \"" + editionImportPath + "\"\n\nfunc f() { _ = edition.Table{} }\n"},
		{"a qualified literal through an alias", "internal/scoreboard/x.go", "package scoreboard\n\nimport ed \"" + editionImportPath + "\"\n\nfunc f() { _ = &ed.Table{} }\n"},
		{"a dot import", "internal/scoreboard/x.go", "package scoreboard\n\nimport . \"" + editionImportPath + "\"\n"},
	}
	for _, c := range cases {
		files := map[string]string{"internal/edition/table.go": tableSrc, c.path: c.src}
		if v, _ := tableViolations(files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
	// A Table type of another package, a method receiver and a parameter are not makers.
	other := "package contracttable\n\ntype Table struct{}\n\nfunc f(t *Table) *Table { return &Table{} }\n"
	if v, _ := tableViolations(map[string]string{"internal/contracttable/x.go": other}); len(v) != 0 {
		t.Errorf("another package's Table was reported: %v", v)
	}
	recv := "package edition\n\nfunc (Table) String() string { return \"\" }\n\nfunc g(t *Table) *Table { return t }\n"
	if v, _ := tableViolations(map[string]string{"internal/edition/judge.go": recv}); len(v) != 0 {
		t.Errorf("a receiver or a parameter of the type was reported: %v", v)
	}
}
