package contracttable

// ADR-0056 V82 (A4e-4), with V59 and the contract table's part of V92: the contract table's two
// rows of the second text of D16 (the event edition's check and render; the first cell of each
// holds "(ADR-0056 D16 " and "/ D20: CLI" or "/ D11: ") are what platform's P1b-2 and P1b-3 are
// written against, so every code span of them is held to the code that it describes:
//
//   - the subcommands and their arguments, the exit codes: cmd/scoreboard/editioncmd.go, read as
//     source (package main cannot be imported): the word of main.go's branch, the switch of
//     runEdition, the lists and the names that parseCheckArgs, parseRenderArgs and
//     parsePracticeArgs give readEditionArgs, and the four exit constants;
//   - the headers and the columns of the four files, the modes of the output: what a real
//     `edition render` of internal/edition/editiontest's event wrote, what `edition check`
//     accepted of it, and what WriteDigests wrote for the event it accepted (V59); the columns of
//     the answers table from WriteAnswers;
//   - the key's numbers: MinMasterKeyBytes and MaxKeyFileBytes; the names of the layouts:
//     practicelayout.go's constants.
//
// The set of the code spans is closed: a code span that none of these hold is red ("a code span
// with nothing to hold it is not put in the table", D20's division of the contract), and so is a
// code span of the form of stdout (V92: stdout is not a contract). The bundle row has no code span
// (nothing of app's code holds what it says), and that is held too. No row, or no code span, is red.
// The cases at the end change one side only (the row, the facts the code gave, or the source of
// cmd/scoreboard) and must each be red.

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

const (
	edCmdPath   = "cmd/scoreboard/editioncmd.go"
	edMainPath  = "cmd/scoreboard/main.go"
	edRowMarker = "(ADR-0056 D16 "
	edCLITag    = "/ D20: CLI"
	edBundleTag = "/ D11: "
)

// edGolden is the practice edition of the fixture's investigate challenge.
var edGolden = filepath.Join("..", "edition", "testdata", "render-golden", editiontest.CID)

// ---- the command, as cmd/scoreboard/editioncmd.go has it ----

// edArgs is one form of the command: the subcommand's word, the arguments that take a value (the
// one that may be given again among them) and the one argument that takes none.
type edArgs struct {
	word   string
	valued []string
	flag   string
}

func (a edArgs) names() []string { return append(slices.Clone(a.valued), a.flag) }

// edCLI is the command: main.go's word, the three forms and the exit codes (accepted, refused,
// usage, write failed, in that order).
type edCLI struct {
	edition                 string
	check, render, practice edArgs
	exits                   [4]int
}

// edSource is what one Go file declares at its top level, as far as this test reads it: string
// and integer constants of a literal, []string variables of string literals, and functions.
type edSource struct {
	strs  map[string]string
	ints  map[string]int
	lists map[string][]string
	funcs map[string]*ast.FuncDecl
}

func edParse(name, src string) (*edSource, error) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		return nil, err
	}
	s := &edSource{strs: map[string]string{}, ints: map[string]int{}, lists: map[string][]string{}, funcs: map[string]*ast.FuncDecl{}}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				s.funcs[d.Name.Name] = d
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Values) != len(vs.Names) {
					continue
				}
				for i, n := range vs.Names {
					s.add(d.Tok, n.Name, vs.Values[i])
				}
			}
		}
	}
	return s, nil
}

func (s *edSource) add(tok token.Token, name string, v ast.Expr) {
	switch x := v.(type) {
	case *ast.BasicLit:
		if tok != token.CONST {
			return
		}
		switch x.Kind {
		case token.STRING:
			if w, err := strconv.Unquote(x.Value); err == nil {
				s.strs[name] = w
			}
		case token.INT:
			if n, err := strconv.Atoi(x.Value); err == nil {
				s.ints[name] = n
			}
		}
	case *ast.CompositeLit:
		if tok != token.VAR {
			return
		}
		var words []string
		for _, e := range x.Elts {
			lit, ok := e.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return
			}
			w, err := strconv.Unquote(lit.Value)
			if err != nil {
				return
			}
			words = append(words, w)
		}
		s.lists[name] = words
	}
}

// constWord is the value of e when e is the name of a string constant of the file.
func (s *edSource) constWord(e ast.Expr) (string, error) {
	id, ok := e.(*ast.Ident)
	if !ok {
		return "", errors.New("is not the name of a constant")
	}
	w, ok := s.strs[id.Name]
	if !ok {
		return "", fmt.Errorf("%s is not a string constant of the file", id.Name)
	}
	return w, nil
}

// argsOf reads the one call readEditionArgs(args, list, repeated, flag) of the function fn: the
// list is a []string variable of the file, repeated the name of a constant or "" (none), and flag
// the name of a constant.
func (s *edSource) argsOf(fn string) (valued []string, flag string, err error) {
	d := s.funcs[fn]
	if d == nil || d.Body == nil {
		return nil, "", fmt.Errorf("func %s is not in %s", fn, edCmdPath)
	}
	var calls []*ast.CallExpr
	ast.Inspect(d.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "readEditionArgs" {
				calls = append(calls, c)
			}
		}
		return true
	})
	if len(calls) != 1 || len(calls[0].Args) != 4 {
		return nil, "", fmt.Errorf("func %s does not call readEditionArgs(args, list, repeated, flag) exactly once", fn)
	}
	a := calls[0].Args
	list, ok := a[1].(*ast.Ident)
	if !ok || s.lists[list.Name] == nil {
		return nil, "", fmt.Errorf("func %s does not give readEditionArgs a []string variable of the file", fn)
	}
	valued = slices.Clone(s.lists[list.Name])
	if lit, ok := a[2].(*ast.BasicLit); !ok || lit.Kind != token.STRING || lit.Value != `""` {
		rep, err := s.constWord(a[2])
		if err != nil {
			return nil, "", fmt.Errorf("func %s: the argument that may be given again %v", fn, err)
		}
		valued = append(valued, rep)
	}
	flag, err = s.constWord(a[3])
	if err != nil {
		return nil, "", fmt.Errorf("func %s: the argument that takes no value %v", fn, err)
	}
	return valued, flag, nil
}

// subcommands reads the switch of runEdition: the word of each case (a constant of the file) by
// the function its case returns the call of.
func (s *edSource) subcommands() (map[string]string, error) {
	d := s.funcs["runEdition"]
	if d == nil || d.Body == nil {
		return nil, fmt.Errorf("func runEdition is not in %s", edCmdPath)
	}
	words := map[string]string{}
	var problems []string
	switches := 0
	ast.Inspect(d.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		switches++
		for _, st := range sw.Body.List {
			cc, ok := st.(*ast.CaseClause)
			if !ok || len(cc.List) != 1 {
				problems = append(problems, "a case of the switch of runEdition is not one constant")
				continue
			}
			w, err := s.constWord(cc.List[0])
			if err != nil {
				problems = append(problems, "a case of the switch of runEdition "+err.Error())
				continue
			}
			handler := ""
			for _, b := range cc.Body {
				if r, ok := b.(*ast.ReturnStmt); ok && len(r.Results) == 1 {
					if c, ok := r.Results[0].(*ast.CallExpr); ok {
						if id, ok := c.Fun.(*ast.Ident); ok {
							handler = id.Name
						}
					}
				}
			}
			if handler == "" {
				problems = append(problems, "the case "+strconv.Quote(w)+" of runEdition returns the call of no function")
				continue
			}
			words[handler] = w
		}
		return true
	})
	if switches != 1 {
		return nil, fmt.Errorf("runEdition has %d switch statements, want 1", switches)
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}
	return words, nil
}

// edMainWord is the word of main.go's edition branch: the `if` whose body calls runEdition, and
// whose condition compares os.Args[1] with the word (`os.Args[1] == "<word>"`). There must be
// exactly one such comparison in such an `if`; a branch of another subcommand (an `if` that does
// not call runEdition) is not looked at.
func edMainWord(src string) (string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), edMainPath, src, 0)
	if err != nil {
		return "", err
	}
	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || !edCallsRunEdition(ifs.Body) {
			return true
		}
		found = append(found, edArgsWords(ifs.Cond)...)
		return true
	})
	if len(found) != 1 {
		return "", fmt.Errorf("%s has %d comparisons of os.Args[1] with a string in an if whose body calls runEdition, want 1 (the edition branch); if main.go's edition branch changed its shape, change this reader (edMainWord) with it: the word the contract table quotes is read from that branch", edMainPath, len(found))
	}
	return found[0], nil
}

// edCallsRunEdition reports whether the block calls runEdition.
func edCallsRunEdition(b *ast.BlockStmt) bool {
	calls := false
	ast.Inspect(b, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "runEdition" {
				calls = true
			}
		}
		return true
	})
	return calls
}

// edArgsWords are the strings that the expression compares os.Args[1] with (`os.Args[1] ==
// "<word>"`), wherever they are in it.
func edArgsWords(e ast.Expr) []string {
	var found []string
	ast.Inspect(e, func(n ast.Node) bool {
		b, ok := n.(*ast.BinaryExpr)
		if !ok || b.Op != token.EQL {
			return true
		}
		ix, ok := b.X.(*ast.IndexExpr)
		if !ok {
			return true
		}
		sel, ok := ix.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Args" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "os" {
			return true
		}
		if one, ok := ix.Index.(*ast.BasicLit); !ok || one.Value != "1" {
			return true
		}
		lit, ok := b.Y.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if w, err := strconv.Unquote(lit.Value); err == nil {
			found = append(found, w)
		}
		return true
	})
	return found
}

// edReadCLI reads the command from the sources of editioncmd.go and main.go.
func edReadCLI(cmdSrc, mainSrc string) (edCLI, error) {
	var c edCLI
	word, err := edMainWord(mainSrc)
	if err != nil {
		return c, err
	}
	c.edition = word
	s, err := edParse(edCmdPath, cmdSrc)
	if err != nil {
		return c, err
	}
	subs, err := s.subcommands()
	if err != nil {
		return c, err
	}
	checkWord, renderWord := subs["runEditionCheck"], subs["runEditionRender"]
	if len(subs) != 2 || checkWord == "" || renderWord == "" {
		return c, fmt.Errorf("runEdition's switch is %v, want one case for runEditionCheck and one for runEditionRender", subs)
	}
	for _, f := range []struct {
		fn   string
		word string
		into *edArgs
	}{
		{"parseCheckArgs", checkWord, &c.check},
		{"parseRenderArgs", renderWord, &c.render},
		{"parsePracticeArgs", renderWord, &c.practice},
	} {
		valued, flag, err := s.argsOf(f.fn)
		if err != nil {
			return c, err
		}
		*f.into = edArgs{word: f.word, valued: valued, flag: flag}
	}
	for i, name := range []string{"exitAccepted", "exitRefused", "exitUsage", "exitWriteFailed"} {
		v, ok := s.ints[name]
		if !ok {
			return c, fmt.Errorf("%s has no integer constant %s", edCmdPath, name)
		}
		c.exits[i] = v
	}
	return c, nil
}

// ---- the files, as a real render and check of the fixture's event wrote them ----

// edFiles are the code spans of the files: the headers and the columns (with the placeholders
// the row writes: <run id>, <fingerprint>, <TAB>), the key's numbers, the modes of the output and
// the names of the layouts.
type edFiles struct {
	seatsHeader    string
	answersHeader  string
	answersColumns string
	digestsHeader  string
	digestsColumns string
	record         [3]string
	keyDigits      int
	keyFileBytes   int
	outDir         fs.FileMode
	outFile        fs.FileMode
	digestsFile    fs.FileMode
	outAnswers     string
	outEvidence    string
	outRecord      string
	specFile       string
	templateFile   string
	practiceDir    string
}

func edLines(t *testing.T, what, text string) []string {
	t.Helper()
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("%s does not end with a newline", what)
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// edWithRunID is line with the run id at its end written as the placeholder <run id>.
func edWithRunID(t *testing.T, what, line, run string) string {
	t.Helper()
	head, ok := strings.CutSuffix(line, run)
	if !ok || len(run) != 32 {
		t.Fatalf("the first line of %s does not end with the run id of the render", what)
	}
	return head + "<run id>"
}

// edLabeled is a line `<label> TAB <value>` written as `<label><TAB><placeholder>`.
func edLabeled(t *testing.T, what, line, value, placeholder string) string {
	t.Helper()
	label, got, ok := strings.Cut(line, "\t")
	if !ok || got != value {
		t.Fatalf("a line of %s is not a label, a tab and the value the render reported", what)
	}
	return label + "<TAB>" + placeholder
}

// edColumns names the columns of line by the value each holds: byName maps a column's name to
// the value the writer was given for it, and every column must be exactly one of them.
func edColumns(t *testing.T, what, line string, byName map[string]string) string {
	t.Helper()
	fields := strings.Split(line, "\t")
	if len(fields) != len(byName) {
		t.Fatalf("a row of %s has %d columns, want %d", what, len(fields), len(byName))
	}
	var names []string
	for i, v := range fields {
		var hit []string
		for _, n := range slices.Sorted(maps.Keys(byName)) {
			if byName[n] == v {
				hit = append(hit, n)
			}
		}
		if len(hit) != 1 {
			t.Fatalf("column %d of a row of %s is %d of the named values, want 1", i+1, what, len(hit))
		}
		names = append(names, hit[0])
	}
	return strings.Join(names, "<TAB>")
}

func edPerm(t *testing.T, p string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// edReadFiles renders the fixture's event with edition.RenderEvent (what `edition render` calls),
// checks the output with edition.CheckEvent (what `edition check` calls), writes the digests of
// the accepted event, and reads the code spans of the files off what was written.
func edReadFiles(t *testing.T) edFiles {
	t.Helper()
	tree := editiontest.NewTree(t)
	seats := editiontest.Seats()
	tree.PlaceInputs(editiontest.Inputs{Golden: edGolden, Spec: editiontest.GoodSpec(), Template: editiontest.GoodTemplate(), Seats: seats})
	tree.PlaceKey(editiontest.KeyRel, editiontest.KeyText(), 0o600)
	rp := tree.RenderPaths()
	rendered, err := edition.RenderEvent(edition.RenderEventInput{
		Challenges:   rp.Challenges,
		ScenarioFile: rp.Scenario,
		FlagsFile:    rp.Flags,
		EditionRoot:  rp.EditionRoot,
		SeatsFile:    rp.Seats,
		NoPrevious:   true,
		KeyFile:      rp.Key,
		Out:          rp.Out,
	})
	if err != nil {
		t.Fatalf("the render of the fixture's event: %v", err)
	}
	p := tree.Paths()
	ev, _, err := edition.CheckEvent(edition.CheckInput{
		Challenges:       p.Challenges,
		ScenarioFile:     p.Scenario,
		FlagsFile:        p.Flags,
		AnswersFile:      filepath.Join(rp.Out, edition.EventAnswersFileName),
		RenderRecordFile: filepath.Join(rp.Out, edition.EventRenderRecordFileName),
		EvidenceRoot:     filepath.Join(rp.Out, edition.EventEvidenceDirName),
		SeatsFile:        p.Seats,
		EditionRoot:      p.EditionRoot,
		NoPrevious:       true,
		CorpusDirs:       []string{p.Corpus},
		DigestsOut:       p.DigestsOut,
	})
	if err != nil {
		t.Fatalf("the check of the render: %v", err)
	}
	if _, err := edition.WriteDigestsFile(p.DigestsOut, ev); err != nil {
		t.Fatalf("the digests file of the check: %v", err)
	}
	run := ev.RunID()
	if run != rendered.RunID() {
		t.Fatal("the check's run id is not the render's")
	}

	var f edFiles
	f.seatsHeader, _, _ = strings.Cut(tree.Read(editiontest.SeatsRel), "\n")

	answers := edLines(t, "the answers table", tree.Read(editiontest.RenderOutRel+"/"+edition.EventAnswersFileName))
	f.answersHeader = edWithRunID(t, "the answers table", answers[0], run)
	row := edition.AnswerRow{Seat: seats[0], CID: editiontest.CID, QID: "q1", Value: "placeholder-value"}
	var ab bytes.Buffer
	if err := edition.WriteAnswers(&ab, run, []edition.AnswerRow{row}); err != nil {
		t.Fatalf("WriteAnswers: %v", err)
	}
	written := edLines(t, "WriteAnswers' table", ab.String())
	if len(written) != 2 || written[0] != answers[0] {
		t.Fatal("WriteAnswers' table of one row is not the render's header and one row")
	}
	f.answersColumns = edColumns(t, "WriteAnswers' table", written[1], map[string]string{"seat": row.Seat, "cid": row.CID, "qid": row.QID, "value": row.Value})
	if len(answers) < 2 {
		t.Fatal("the render's answers table has no row")
	}
	for _, ln := range answers[1:] {
		if strings.Count(ln, "\t") != strings.Count(f.answersColumns, "<TAB>") {
			t.Fatal("a row of the render's answers table has another number of columns than WriteAnswers writes")
		}
	}

	var db bytes.Buffer
	if err := edition.WriteDigests(&db, ev); err != nil {
		t.Fatalf("WriteDigests: %v", err)
	}
	if tree.Read(editiontest.DigestsRel) != db.String() {
		t.Fatal("the digests file written to --digests-out is not WriteDigests' output")
	}
	digests := edLines(t, "the digests file", db.String())
	f.digestsHeader = edWithRunID(t, "the digests file", digests[0], run)
	rows := ev.Rows()
	if len(rows) == 0 || len(digests) != len(rows)+1 {
		t.Fatalf("the digests file has %d lines for %d rows", len(digests), len(rows))
	}
	for i, r := range rows {
		cols := edColumns(t, "the digests file", digests[i+1], map[string]string{"seat": r.Seat, "cid": r.CID, "digest": r.Digest})
		if i > 0 && cols != f.digestsColumns {
			t.Fatal("two rows of the digests file have their columns in another order")
		}
		f.digestsColumns = cols
	}

	record := edLines(t, "the render record", tree.Read(editiontest.RenderOutRel+"/"+edition.EventRenderRecordFileName))
	if len(record) != 3 {
		t.Fatalf("the render record has %d lines, want 3", len(record))
	}
	f.record = [3]string{
		record[0],
		edLabeled(t, "the render record", record[1], run, "<run id>"),
		edLabeled(t, "the render record", record[2], rendered.KeyFingerprint(), "<fingerprint>"),
	}

	f.keyDigits = 2 * edition.MinMasterKeyBytes
	f.keyFileBytes = edition.MaxKeyFileBytes

	f.outDir = edPerm(t, rp.Out)
	err = filepath.WalkDir(rp.Out, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		perm := info.Mode().Perm()
		switch {
		case info.IsDir():
			if perm != f.outDir {
				return fmt.Errorf("a directory under --out has the mode %#o, --out has %#o", perm, f.outDir)
			}
		case info.Mode().IsRegular():
			if f.outFile == 0 {
				f.outFile = perm
			} else if perm != f.outFile {
				return fmt.Errorf("two files under --out have the modes %#o and %#o", perm, f.outFile)
			}
		default:
			return errors.New("an entry under --out is neither a directory nor a regular file")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.outFile == 0 {
		t.Fatal("--out holds no file")
	}
	f.digestsFile = edPerm(t, p.DigestsOut)

	f.outAnswers = edition.EventAnswersFileName
	f.outEvidence = edition.EventEvidenceDirName + "/<seat>/<cid>/<file>"
	f.outRecord = edition.EventRenderRecordFileName
	f.specFile = "<cid>/" + edition.SpecFileName
	f.templateFile = "<cid>/" + edition.TemplateDirName + "/<file>"
	f.practiceDir = edition.EditionDirName + "/" + edition.PracticeDirName + "/"
	return f
}

// ---- the judgement ----

var (
	edSpanRe      = regexp.MustCompile("`([^`\n]*)`")
	edPlaceholder = regexp.MustCompile(`^<[a-z][a-z-]*>$`)
)

// edRows are the CLI row and the bundle row: exactly one each, and no other row of D16's second
// text.
func edRows(conventions string) (cli, bundle string, err error) {
	var c, b, other []string
	for _, r := range Rows(conventions) {
		cells := strings.SplitN(r, "|", 3)
		if len(cells) < 3 || !strings.Contains(cells[1], edRowMarker) {
			continue
		}
		switch {
		case strings.Contains(cells[1], edCLITag):
			c = append(c, r)
		case strings.Contains(cells[1], edBundleTag):
			b = append(b, r)
		default:
			other = append(other, r)
		}
	}
	if len(c) != 1 || len(b) != 1 || len(other) != 0 {
		return "", "", fmt.Errorf("the contract table has %d CLI rows, %d bundle rows and %d other rows of ADR-0056 D16's second text, want 1, 1 and 0", len(c), len(b), len(other))
	}
	return c[0], b[0], nil
}

// edSpans are the code spans of a row.
func edSpans(row string) ([]string, error) {
	if strings.Count(row, "`")%2 != 0 {
		return nil, errors.New("an odd number of backticks")
	}
	var out []string
	for _, m := range edSpanRe.FindAllStringSubmatch(row, -1) {
		out = append(out, m[1])
	}
	return out, nil
}

// edForm judges a code span that begins with main.go's word: a reference to a form (`edition
// check`, `edition render`, `edition render --practice`), which returns "", or the synopsis of a
// form, which returns "check", "render" or "practice". A synopsis is the form's words, then every
// argument of the form once, each followed by a placeholder <...> when it takes a value and by
// nothing when it takes none.
func edForm(span string, c edCLI) (string, error) {
	words := strings.Fields(span)
	if strings.Join(words, " ") != span {
		return "", fmt.Errorf("the code span %q is not words with one space between them", span)
	}
	if len(words) < 2 {
		return "", fmt.Errorf("the code span %q names no subcommand", span)
	}
	rest := words[2:]
	var kind string
	var a edArgs
	switch {
	case words[1] == c.check.word:
		kind, a = "check", c.check
	case words[1] == c.render.word && len(rest) > 0 && rest[0] == c.practice.flag:
		kind, a = "practice", c.practice
	case words[1] == c.render.word:
		kind, a = "render", c.render
	default:
		return "", fmt.Errorf("the code span %q names a subcommand that runEdition does not have", span)
	}
	if len(rest) == 0 || (kind == "practice" && len(rest) == 1) {
		return "", nil
	}
	var got []string
	for i, w := range rest {
		if strings.HasPrefix(w, "--") {
			got = append(got, w)
			takesValue := i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "--")
			if takesValue != (w != a.flag) {
				how := "without a value"
				if takesValue {
					how = "with a value"
				}
				return "", fmt.Errorf("the synopsis of %s writes %s %s, which is not how cmd/scoreboard reads it", kind, w, how)
			}
			continue
		}
		if !edPlaceholder.MatchString(w) || i == 0 || !strings.HasPrefix(rest[i-1], "--") {
			return "", fmt.Errorf("the synopsis of %s has %q, which is neither an argument nor the value of the one before it", kind, w)
		}
	}
	if want := sorted(a.names()); !slices.Equal(sorted(got), want) {
		return "", fmt.Errorf("the synopsis of %s names the arguments %q, cmd/scoreboard takes %q", kind, sorted(got), want)
	}
	return kind, nil
}

func edOctal(m fs.FileMode) string { return fmt.Sprintf("%04o", uint32(m)) }

// edRowMismatch is nil when the two rows hold exactly what the code has. It is the whole
// judgement of V82 on the conventions text and the facts the code gave.
func edRowMismatch(conventions string, c edCLI, f edFiles) error {
	cli, bundle, err := edRows(conventions)
	if err != nil {
		return err
	}
	spans, err := edSpans(cli)
	if err != nil {
		return fmt.Errorf("the CLI row has %v", err)
	}
	if len(spans) == 0 {
		return errors.New("the CLI row has no code span: nothing of it is held to the code")
	}
	bspans, err := edSpans(bundle)
	if err != nil {
		return fmt.Errorf("the bundle row has %v", err)
	}
	if len(bspans) != 0 {
		return fmt.Errorf("the bundle row has the code spans %q: it says it has none, and nothing of app's code holds them", bspans)
	}

	want := map[string]bool{}
	for _, s := range []string{
		f.seatsHeader, f.answersHeader, f.answersColumns, f.digestsHeader, f.digestsColumns,
		f.record[0], f.record[1], f.record[2],
		strconv.Itoa(f.keyDigits), strconv.Itoa(f.keyFileBytes),
		edOctal(f.outDir), edOctal(f.outFile), edOctal(f.digestsFile),
		f.outAnswers, f.outEvidence, f.outRecord, f.specFile, f.templateFile, f.practiceDir,
	} {
		want[s] = true
	}
	for _, e := range c.exits {
		want[strconv.Itoa(e)] = true
	}
	args := map[string]bool{}
	for _, a := range []edArgs{c.check, c.render, c.practice} {
		for _, n := range a.names() {
			args[n] = true
		}
	}

	var problems []string
	seen := map[string]bool{}
	forms := map[string]int{}
	for _, s := range spans {
		switch {
		case strings.Contains(s, "ok run=") || strings.HasPrefix(s, "ok "):
			problems = append(problems, fmt.Sprintf("the code span %q is the form of stdout, which is not a contract (V92)", s))
		case s == c.edition || strings.HasPrefix(s, c.edition+" "):
			kind, err := edForm(s, c)
			switch {
			case err != nil:
				problems = append(problems, err.Error())
			case kind != "":
				forms[kind]++
			}
		case strings.HasPrefix(s, "--"):
			if !args[s] {
				problems = append(problems, fmt.Sprintf("the code span %q is not an argument of a form of the command in %s", s, edCmdPath))
			}
		case want[s]:
			seen[s] = true
		default:
			problems = append(problems, fmt.Sprintf("the code span %q is held to nothing of app's code: write it as prose, or hold it here (V82)", s))
		}
	}
	for _, s := range slices.Sorted(maps.Keys(want)) {
		if !seen[s] {
			problems = append(problems, fmt.Sprintf("the CLI row does not quote `%s` as the code has it", s))
		}
	}
	for _, k := range []string{"check", "render", "practice"} {
		if forms[k] != 1 {
			problems = append(problems, fmt.Sprintf("the CLI row has %d synopses of %s, want 1", forms[k], k))
		}
	}
	for _, phrase := range []string{
		fmt.Sprintf("`%d`, `%d`, `%d`, `%d`", c.exits[0], c.exits[1], c.exits[2], c.exits[3]),
		fmt.Sprintf("`--out` (dir `%s`, file `%s`)", edOctal(f.outDir), edOctal(f.outFile)),
		fmt.Sprintf("`--digests-out` (file `%s`)", edOctal(f.digestsFile)),
	} {
		if !strings.Contains(cli, phrase) {
			problems = append(problems, "the CLI row does not say "+phrase+" (the exit codes in the order accepted, refused, usage, write failed; the modes of the two outputs)")
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

// ---- the tests ----

func TestEditionRows(t *testing.T) {
	conv := readRepoFile(t, Path)
	cmdSrc, mainSrc := readRepoFile(t, edCmdPath), readRepoFile(t, edMainPath)
	c, err := edReadCLI(cmdSrc, mainSrc)
	if err != nil {
		t.Fatalf("reading the command from cmd/scoreboard: %v", err)
	}
	f := edReadFiles(t)

	// (a) the rows hold what the code has.
	t.Run("the rows hold the code", func(t *testing.T) {
		if err := edRowMismatch(conv, c, f); err != nil {
			t.Fatal(err)
		}
	})

	// The reading itself is the values the ADR names (a reading that went wrong on both sides
	// the same way would pass the comparison above), and the row has the four exit codes and no
	// code span of stdout (V92).
	t.Run("the reading is the values of D20", func(t *testing.T) {
		if c.edition != "edition" || c.check.word != "check" || c.render.word != "render" || c.practice.word != "render" {
			t.Errorf("the words read are %q %q %q %q", c.edition, c.check.word, c.render.word, c.practice.word)
		}
		if c.check.flag != "--no-previous" || c.render.flag != "--no-previous" || c.practice.flag != "--practice" {
			t.Errorf("the arguments that take no value read are %q %q %q", c.check.flag, c.render.flag, c.practice.flag)
		}
		if len(c.check.valued) != 11 || !slices.Contains(c.check.valued, "--corpus") || !slices.Contains(c.check.valued, "--digests-out") {
			t.Errorf("the arguments of check read are %q", c.check.valued)
		}
		if len(c.render.valued) != 8 || !slices.Contains(c.render.valued, "--key-file") || !slices.Contains(c.render.valued, "--out") {
			t.Errorf("the arguments of render read are %q", c.render.valued)
		}
		if !slices.Equal(sorted(c.practice.valued), []string{"--challenges", "--cid"}) {
			t.Errorf("the arguments of render --practice read are %q", c.practice.valued)
		}
		// A branch of another subcommand in main.go (one that does not call runEdition) does not
		// change the word read, and a second comparison in the edition branch is refused.
		const branch = `if len(os.Args) > 1 && os.Args[1] == "edition" {`
		if n := strings.Count(mainSrc, branch); n != 1 {
			t.Fatalf("main.go has the edition branch %d times, want once: the cases below do not test what they say", n)
		}
		other := strings.Replace(mainSrc, branch, "if len(os.Args) > 1 && os.Args[1] == \"other\" {\n\t\treturn\n\t}\n\t"+branch, 1)
		if w, err := edMainWord(other); err != nil || w != "edition" {
			t.Errorf("with a branch of another subcommand, the word read is %q (%v), want edition", w, err)
		}
		twice := strings.Replace(mainSrc, branch, `if len(os.Args) > 1 && (os.Args[1] == "edition" || os.Args[1] == "editions") {`, 1)
		if _, err := edMainWord(twice); err == nil {
			t.Error("an edition branch with two words was read as one word")
		}
		if c.exits != [4]int{0, 1, 2, 3} {
			t.Errorf("the exit codes read are %v", c.exits)
		}
		if f.outDir != 0o700 || f.outFile != 0o600 || f.digestsFile != 0o600 {
			t.Errorf("the modes read are %#o %#o %#o", f.outDir, f.outFile, f.digestsFile)
		}
		if f.keyDigits != 64 || f.keyFileBytes != 4096 {
			t.Errorf("the key's numbers read are %d %d", f.keyDigits, f.keyFileBytes)
		}
		if f.answersColumns != "seat<TAB>cid<TAB>qid<TAB>value" || f.digestsColumns != "seat<TAB>cid<TAB>digest" {
			t.Errorf("the columns read are %q and %q", f.answersColumns, f.digestsColumns)
		}
		if f.record[1] != "run-id<TAB><run id>" || f.record[2] != "key-fingerprint<TAB><fingerprint>" {
			t.Errorf("the lines of the render record read are %q", f.record)
		}
		cli, _, err := edRows(conv)
		if err != nil {
			t.Fatal(err)
		}
		spans, _ := edSpans(cli)
		stdout := 0
		for _, s := range spans {
			if strings.Contains(s, "ok run=") {
				stdout++
			}
		}
		if stdout != 0 {
			t.Errorf("the CLI row has %d code spans of the form of stdout, want 0", stdout)
		}
		for _, code := range []string{"`0`", "`1`", "`2`", "`3`"} {
			if !strings.Contains(cli, code) {
				t.Errorf("the CLI row has no exit code %s", code)
			}
		}
	})

	// (c) The row changed, the code real: each is red.
	t.Run("a change of the row alone is red", func(t *testing.T) {
		cli, bundle, err := edRows(conv)
		if err != nil {
			t.Fatal(err)
		}
		in := func(row, old, repl string) string {
			t.Helper()
			if n := strings.Count(row, old); n != 1 {
				t.Fatalf("%q is in the row %d times, want once: the case would not change what it says", old, n)
			}
			return strings.Replace(conv, row, strings.Replace(row, old, repl, 1), 1)
		}
		for _, m := range []struct{ name, old, repl string }{
			{"the seats header", "`# falco-ctf seats v1`", "`# falco-ctf seats v2`"},
			{"the answers columns", "`seat<TAB>cid<TAB>qid<TAB>value`", "`seat<TAB>qid<TAB>cid<TAB>value`"},
			{"the digests header", "`# falco-ctf evidence-digests v1 run=<run id>`", "`# falco-ctf evidence-digests v1 run=<id>`"},
			{"the digests columns", "`seat<TAB>cid<TAB>digest`", "`cid<TAB>seat<TAB>digest`"},
			{"the fingerprint line", "`key-fingerprint<TAB><fingerprint>`", "`key-fingerprint <fingerprint>`"},
			{"the key's digits", "`64`", "`62`"},
			{"the key file's limit", "`4096`", "`4095`"},
			{"the order of the exit codes", "`0`, `1`, `2`, `3`", "`0`, `2`, `1`, `3`"},
			{"an exit code", "`2`, `3`", "`2`, `4`"},
			{"the mode of --out's directories", "(dir `0700`,", "(dir `0755`,"},
			{"the mode of --digests-out", "`--digests-out` (file `0600`)", "`--digests-out` (file `0644`)"},
			{"an argument dropped from the render synopsis", " --key-file <file>", ""},
			{"an argument added to the check synopsis", " --digests-out <file>`", " --digests-out <file> --force`"},
			{"the argument without a value given one", "--no-previous --corpus", "--no-previous <x> --corpus"},
			{"an argument added to the practice synopsis", "--cid <cid>`", "--cid <cid> --out <dir>`"},
			{"a subcommand renamed", "`edition check --challenges", "`edition verify --challenges"},
			{"a name of the output layout", "`render-record.tsv`", "`render-record.txt`"},
			{"the practice directory", "`edition/practice/`", "`edition/practise/`"},
			{"a code span written as prose", "`<cid>/edition.yaml`", "<cid>/edition.yaml"},
			{"the form of stdout as a code span", "`4096`", "`4096` `ok run=<run id>`"},
			{"an argument of docker as a code span", "`4096`", "`4096` `--user`"},
			{"a code span that nothing holds", "`4096`", "`4096` `:ro`"},
			{"an odd backtick", "`4096`", "`4096"},
			{"the CLI row's tag", edCLITag, "/ D20: CL1"},
		} {
			if err := edRowMismatch(in(cli, m.old, m.repl), c, f); err == nil {
				t.Errorf("%s: edRowMismatch accepted it", m.name)
			}
		}
		if err := edRowMismatch(in(bundle, "(type helm.sh/release.v1)", "(type `helm.sh/release.v1`)"), c, f); err == nil {
			t.Error("a code span in the bundle row: edRowMismatch accepted it")
		}
		if err := edRowMismatch(in(bundle, edBundleTag, "/ D1: "), c, f); err == nil {
			t.Error("the bundle row's tag: edRowMismatch accepted it")
		}
		if err := edRowMismatch(strings.Replace(conv, cli, cli+"\n"+cli, 1), c, f); err == nil {
			t.Error("a second CLI row: edRowMismatch accepted it")
		}
		if err := edRowMismatch("", c, f); err == nil {
			t.Error("an empty conventions text was accepted")
		}
	})

	// The facts changed, the row real: each is red.
	t.Run("a change of the code alone is red", func(t *testing.T) {
		for _, m := range []struct {
			name   string
			change func(c *edCLI, f *edFiles)
		}{
			{"main.go's word", func(c *edCLI, _ *edFiles) { c.edition = "editions" }},
			{"the check subcommand", func(c *edCLI, _ *edFiles) { c.check.word = "verify" }},
			{"an argument of render taken out", func(c *edCLI, _ *edFiles) {
				c.render.valued = slices.DeleteFunc(slices.Clone(c.render.valued), func(s string) bool { return s == "--key-file" })
			}},
			{"an argument of check added", func(c *edCLI, _ *edFiles) { c.check.valued = append(slices.Clone(c.check.valued), "--force") }},
			{"the practice argument renamed", func(c *edCLI, _ *edFiles) { c.practice.flag = "--practise" }},
			{"an exit code changed", func(c *edCLI, _ *edFiles) { c.exits[3] = 4 }},
			{"two exit codes swapped", func(c *edCLI, _ *edFiles) { c.exits[1], c.exits[2] = c.exits[2], c.exits[1] }},
			{"the seats header", func(_ *edCLI, f *edFiles) { f.seatsHeader += "x" }},
			{"the answers header", func(_ *edCLI, f *edFiles) { f.answersHeader = strings.Replace(f.answersHeader, "v1", "v2", 1) }},
			{"the answers columns", func(_ *edCLI, f *edFiles) { f.answersColumns = "seat<TAB>cid<TAB>value<TAB>qid" }},
			{"the digests header", func(_ *edCLI, f *edFiles) { f.digestsHeader = strings.Replace(f.digestsHeader, "v1", "v2", 1) }},
			{"the digests columns", func(_ *edCLI, f *edFiles) { f.digestsColumns = "seat<TAB>digest<TAB>cid" }},
			{"the render record's header", func(_ *edCLI, f *edFiles) { f.record[0] += "x" }},
			{"the render record's run id line", func(_ *edCLI, f *edFiles) { f.record[1] = "run<TAB><run id>" }},
			{"the key's digits", func(_ *edCLI, f *edFiles) { f.keyDigits = 62 }},
			{"the key file's limit", func(_ *edCLI, f *edFiles) { f.keyFileBytes = 8192 }},
			{"the mode of --out's directories", func(_ *edCLI, f *edFiles) { f.outDir = 0o755 }},
			{"the mode of --out's files", func(_ *edCLI, f *edFiles) { f.outFile = 0o644 }},
			{"the mode of --digests-out", func(_ *edCLI, f *edFiles) { f.digestsFile = 0o640 }},
			{"the answers file of --out", func(_ *edCLI, f *edFiles) { f.outAnswers = "answer.tsv" }},
			{"the evidence directory of --out", func(_ *edCLI, f *edFiles) { f.outEvidence = "bundles/<seat>/<cid>/<file>" }},
			{"the render record of --out", func(_ *edCLI, f *edFiles) { f.outRecord = "record.tsv" }},
			{"the spec file of an edition", func(_ *edCLI, f *edFiles) { f.specFile = "<cid>/spec.yaml" }},
			{"the template directory of an edition", func(_ *edCLI, f *edFiles) { f.templateFile = "<cid>/templates/<file>" }},
			{"the practice directory", func(_ *edCLI, f *edFiles) { f.practiceDir = "edition/public/" }},
		} {
			c2, f2 := c, f
			m.change(&c2, &f2)
			if err := edRowMismatch(conv, c2, f2); err == nil {
				t.Errorf("%s: edRowMismatch accepted it", m.name)
			}
		}
	})

	// The source of cmd/scoreboard changed, the row real: each is red (the reading refuses it,
	// or the row no longer matches what it reads).
	t.Run("a change of cmd/scoreboard's source alone is red", func(t *testing.T) {
		repl := func(src, old, with string) string {
			t.Helper()
			if n := strings.Count(src, old); n != 1 {
				t.Fatalf("%q is in the source %d times, want once: the case would not change what it says", old, n)
			}
			return strings.Replace(src, old, with, 1)
		}
		for _, m := range []struct {
			name          string
			cmdSrc, mainS string
		}{
			{"an argument of check renamed", repl(cmdSrc, `"--digests-out",`, `"--digest-out",`), mainSrc},
			{"an exit code changed", repl(cmdSrc, "exitWriteFailed = 3", "exitWriteFailed = 4"), mainSrc},
			{"the render subcommand renamed", repl(cmdSrc, `subcommandRender = "render"`, `subcommandRender = "draw"`), mainSrc},
			{"a case of a literal, not a constant", repl(cmdSrc, "case subcommandCheck:", `case "check":`), mainSrc},
			{"the repeated argument of check dropped", repl(cmdSrc, "readEditionArgs(args, checkFlags, corpusFlag, noPreviousFlag)", `readEditionArgs(args, checkFlags, "", noPreviousFlag)`), mainSrc},
			{"main.go's word", cmdSrc, repl(mainSrc, `os.Args[1] == "edition"`, `os.Args[1] == "editions"`)},
			{"no editioncmd.go", "", mainSrc},
			{"no main.go", cmdSrc, ""},
		} {
			c2, err := edReadCLI(m.cmdSrc, m.mainS)
			if err == nil && edRowMismatch(conv, c2, f) == nil {
				t.Errorf("%s: the source was read and the row still matched it", m.name)
			}
		}
	})
}
