package edition_test

// ADR-0056 D10 B12 and V98 (amendment 19, A4e-6): the digest of a scope and B12.
//
//   - the golden (testdata/scope-digest/cases.tsv): a scope of one id and of two, whose digests
//     were computed outside this code (printf and shasum on the input column). The test reads
//     the table three ways, as bundle_digest_test.go reads the table of D9, and holds that a
//     definition one byte off (the label, the LF after it, the LF after an id) misses it;
//   - the one definition: ScopeDigest is declared once, in scopedigest.go, the label is spelled
//     there alone, and the writer of the render record and CheckEvent each call it once (copies
//     of the sources that compute it another way are red);
//   - the render record of a render is v2, four lines, and its scope line is ScopeDigest of the
//     ids catalog.LoadScored returned, in their order;
//   - `edition check` refuses with B12, and nothing else, a scope that adds an evade challenge,
//     one that has the same challenges in another order, and one that leaves out an
//     investigate challenge of two (one is left, so step 1 runs, and B12 at step 1b stops the
//     check before the table: T4 and E2 are not reached);
//   - --all-challenges and the scenario of the same ids in the same order are one scope (both
//     ways);
//   - a render record of the first form, and a v2 one whose form is wrong, are a usage error
//     (exit 2) and not B12.
//
// The fixture is internal/edition/editiontest's; every value is a placeholder with no meaning.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

var scopeCaseDir = filepath.Join("testdata", "scope-digest")

// scopeLabel is the label as the ADR writes it: the reference of this test, not a copy of the
// implementation's constant (which is unexported).
const scopeLabel = "falco-ctf/edition/scope/v1"

// scopeCase is one row of cases.tsv.
type scopeCase struct {
	name   string
	digest string
	ids    []string
	input  string // the bytes, decoded from the printf spelling
}

func readScopeCases(t *testing.T) []scopeCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(scopeCaseDir, "cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []scopeCase
	seen := map[string]bool{}
	sizes := map[int]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 4 {
			t.Fatalf("cases.tsv:%d: want case<TAB>digest<TAB>ids<TAB>input, got %d columns", i+1, len(cols))
		}
		if !edition.ValidDigest(cols[1]) {
			t.Fatalf("cases.tsv:%d: the digest of %q is not 64 lower-case hex digits: it is computed from the input column with printf and shasum, never copied from ScopeDigest", i+1, cols[0])
		}
		input, err := printfBytes(cols[3])
		if err != nil {
			t.Fatalf("cases.tsv:%d: %v", i+1, err)
		}
		ids := strings.Split(cols[2], ",")
		for _, id := range ids {
			if !challengeid.Valid(id) {
				t.Fatalf("cases.tsv:%d: %q is not in the challenge id grammar", i+1, id)
			}
		}
		if seen[cols[0]] {
			t.Fatalf("cases.tsv:%d: case %q is listed twice", i+1, cols[0])
		}
		seen[cols[0]] = true
		sizes[len(ids)] = true
		cases = append(cases, scopeCase{name: cols[0], digest: cols[1], ids: ids, input: input})
	}
	if !sizes[1] || !sizes[2] {
		t.Fatalf("the table has no scope of one id or none of two (sizes %v): it is not being read", sizes)
	}
	return cases
}

// scopeVariant is a way to make the input of the digest. The reference is the definition of
// amendment 19; every other value is a deliberate mistake the table must catch.
type scopeVariant struct {
	label, afterLabel, afterID string
	joined                     bool // no LF after the last id: the ids joined by LF
}

var scopeReference = scopeVariant{label: scopeLabel, afterLabel: "\n", afterID: "\n"}

func scopeInputOf(ids []string, v scopeVariant) string {
	var b strings.Builder
	b.WriteString(v.label + v.afterLabel)
	for i, id := range ids {
		b.WriteString(id)
		if v.joined && i == len(ids)-1 {
			continue
		}
		b.WriteString(v.afterID)
	}
	return b.String()
}

func TestScopeDigest_Golden(t *testing.T) {
	cases := readScopeCases(t)
	byDigest := map[string]string{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sha256Hex(c.input); got != c.digest {
				t.Errorf("the digest column is not the sha256 of the input column: %s, want %s", got, c.digest)
			}
			if got := scopeInputOf(c.ids, scopeReference); got != c.input {
				t.Errorf("the input column is not what the definition makes of the ids:\n got %q\nwant %q", got, c.input)
			}
			if got := edition.ScopeDigest(c.ids); got != c.digest {
				t.Errorf("ScopeDigest = %s, want %s", got, c.digest)
			}
		})
		if other, dup := byDigest[c.digest]; dup {
			t.Errorf("cases %q and %q have the same digest", other, c.name)
		}
		byDigest[c.digest] = c.name
	}
	// The order is a part of the scope, and so is every id.
	a, b := []string{"91-synthetic-a", "92-synthetic-b"}, []string{"92-synthetic-b", "91-synthetic-a"}
	if edition.ScopeDigest(a) == edition.ScopeDigest(b) || edition.ScopeDigest(a) == edition.ScopeDigest(a[:1]) {
		t.Error("two scopes that differ by their order or by an id have one digest")
	}
	if d := edition.ScopeDigest(a); !edition.ValidDigest(d) {
		t.Errorf("ScopeDigest = %q, want 64 lower-case hex digits", d)
	}
}

// A definition one byte off misses every row of the table.
func TestScopeDigest_GoldenCatchesADriftedDefinition(t *testing.T) {
	cases := readScopeCases(t)
	for _, m := range []struct {
		name string
		v    scopeVariant
	}{
		{"one byte of the label changed", scopeVariant{label: "falco-ctf/edition/scope/v2", afterLabel: "\n", afterID: "\n"}},
		{"no LF after the label", scopeVariant{label: scopeLabel, afterLabel: "", afterID: "\n"}},
		{"a space for the LF after the label", scopeVariant{label: scopeLabel, afterLabel: " ", afterID: "\n"}},
		{"no LF after an id", scopeVariant{label: scopeLabel, afterLabel: "\n", afterID: ""}},
		{"the ids joined (no LF after the last id)", scopeVariant{label: scopeLabel, afterLabel: "\n", afterID: "\n", joined: true}},
		{"CR LF after an id", scopeVariant{label: scopeLabel, afterLabel: "\n", afterID: "\r\n"}},
	} {
		for _, c := range cases {
			if sha256Hex(scopeInputOf(c.ids, m.v)) == c.digest {
				t.Errorf("%s: case %q gives the table's digest under this mistake; the table does not catch it", m.name, c.name)
			}
		}
	}
}

// ---- the one definition, held by reading the sources ----

const (
	scopeDigestFile  = "internal/edition/scopedigest.go"
	scopeWriterFile  = "internal/edition/renderrecord.go"
	scopeCheckerFile = "internal/edition/checkevent.go"
	// scopeLabelStem is the part of the label that a second definition would spell.
	scopeLabelStem = "falco-ctf/edition/scope/"
)

// sdCount counts, in the body of the top-level func fn of the source, the identifiers named name
// (calls counts the calls of name only: an identifier, or the last name of a selector). found is
// false when the func is not there.
func sdCount(p, src, fn, name string, calls bool) (n int, found bool, err error) {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		return 0, false, err
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(x ast.Node) bool {
			switch x := x.(type) {
			case *ast.CallExpr:
				if !calls {
					return true
				}
				switch fun := x.Fun.(type) {
				case *ast.Ident:
					if fun.Name == name {
						n++
					}
				case *ast.SelectorExpr:
					if fun.Sel.Name == name {
						n++
					}
				}
			case *ast.Ident:
				if !calls && x.Name == name {
					n++
				}
			}
			return true
		})
		return n, true, nil
	}
	return 0, false, nil
}

// scopeDigestViolations judges the non-test sources (slash path -> source): ScopeDigest is
// declared once, in scopedigest.go, and its body takes the label; no other file spells the label;
// WriteRenderRecord and CheckEvent each call ScopeDigest once.
func scopeDigestViolations(files map[string]string) []string {
	var out []string
	defs := 0
	for _, p := range slices.Sorted(maps.Keys(files)) {
		src := files[p]
		if p != scopeDigestFile && strings.Contains(src, scopeLabelStem) {
			out = append(out, p+": spells the label of the scope digest, which "+scopeDigestFile+" alone defines")
		}
		if !isEditionPackageFile(p) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
		if err != nil {
			out = append(out, p+": does not parse: "+err.Error())
			continue
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "ScopeDigest" {
				defs++
				if p != scopeDigestFile {
					out = append(out, p+": declares ScopeDigest, which is "+scopeDigestFile+"'s")
				}
			}
		}
	}
	if defs != 1 {
		out = append(out, "ScopeDigest is declared "+strconv.Itoa(defs)+" time(s) in package edition, want once")
	}
	if n, found, err := sdCount(scopeDigestFile, files[scopeDigestFile], "ScopeDigest", "scopeDigestLabel", false); err != nil || !found || n != 1 {
		out = append(out, scopeDigestFile+": ScopeDigest does not take scopeDigestLabel exactly once")
	}
	for _, w := range []struct{ p, fn string }{{scopeWriterFile, "WriteRenderRecord"}, {scopeCheckerFile, "CheckEvent"}} {
		n, found, err := sdCount(w.p, files[w.p], w.fn, "ScopeDigest", true)
		switch {
		case err != nil:
			out = append(out, w.p+": does not parse: "+err.Error())
		case !found:
			out = append(out, w.p+": func "+w.fn+" is not found")
		case n != 1:
			out = append(out, w.p+": "+w.fn+" calls ScopeDigest "+strconv.Itoa(n)+" time(s), want once (the digest has one definition)")
		}
	}
	return out
}

func TestScopeDigestHasOneDefinitionThatTheWriterAndTheCheckCall(t *testing.T) {
	files := nonTestSources(t)
	for _, v := range scopeDigestViolations(files) {
		t.Error(v)
	}
	with := func(p, old, repl string) map[string]string {
		t.Helper()
		m := maps.Clone(files)
		m[p] = replaceOnce(t, files[p], old, repl)
		return m
	}
	added := func(p, src string) map[string]string {
		m := maps.Clone(files)
		m[p] = src
		return m
	}
	for _, c := range []struct {
		name  string
		files map[string]string
	}{
		{"the writer computes the digest with another function", with(scopeWriterFile, "ScopeDigest(scope)", "scopeDigestOwn(scope)")},
		{"the check computes the digest with another function", with(scopeCheckerFile, "ScopeDigest(scored.Order)", "scopeDigestOwn(scored.Order)")},
		{"the function does not take the label", with(scopeDigestFile, "[]byte(scopeDigestLabel + \"\\n\")", "[]byte(\"x\\n\")")},
		{"a second spelling of the label", added("internal/edition/scopecopy.go", "package edition\n\nconst scopeLabelCopy = \""+scopeLabel+"\"\n")},
		{"a second ScopeDigest in the package", added("internal/edition/scopecopy.go", "package edition\n\nfunc ScopeDigest(ids []string) string { return \"\" }\n")},
		{"no scopedigest.go", added(scopeDigestFile, "package edition\n")},
	} {
		if v := scopeDigestViolations(c.files); len(v) == 0 {
			t.Errorf("%s: no violation was reported", c.name)
		}
	}
}

// ---- B12 in `edition check` (V98) ----

// scopeExtraEvade is a second evade challenge the tree may hold, so that a scope can add an evade
// challenge or put two in another order (an evade challenge never comes after an investigate one).
const scopeExtraEvade = "00-extra"

// addExtraEvade puts scopeExtraEvade in the image's tree and its flag in the flags file (an
// entry for an evade challenge outside the scope is checked and not applied).
func (f *rfFix) addExtraEvade() {
	f.t.Helper()
	f.tree.Put(editiontest.ChallengesRel+"/"+scopeExtraEvade+"/falco-rule.yaml", "type: evade\nexpectedFlag: FALCO{dev-fixture-extra}\nforbiddenRules: [r2]\n")
	f.tree.Put(editiontest.FlagsRel, "flags:\n  "+editiontest.Evade+": "+editiontest.Flag+"\n  "+scopeExtraEvade+": FALCO{dev-fixture-02}\n")
}

// expectB12 runs the check and wants no event, a rule's refusal (not a usage error), and B12
// alone.
func expectB12(t *testing.T, what string, in edition.CheckInput) {
	t.Helper()
	ev, _, err := edition.CheckEvent(in)
	if ev != nil || err == nil {
		t.Fatalf("%s: event %v, err %v; want no event and B12", what, ev, err)
	}
	if isInputErr(err) {
		t.Fatalf("%s: a usage error (%v); want B12, a rule's refusal (exit 1)", what, err)
	}
	if got := cevRuleSet(err); !slices.Equal(got, []string{edition.RuleScope}) {
		t.Errorf("%s: the rules named are %v, want exactly [%s] (err: %v)", what, got, edition.RuleScope, err)
	}
}

// The render record of a render is v2, four lines, and its scope line is ScopeDigest of the
// ordered ids of LoadScored; the check of the output with the same scenario accepts it, and the
// same challenges in another order are B12.
func TestScopeB12_TheRecordHoldsTheScopeAndAnotherOrderIsRefused(t *testing.T) {
	f := newRfFix(t)
	f.addExtraEvade()
	order := []string{editiontest.Evade, scopeExtraEvade, editiontest.CID}
	f.in.ScenarioFile = f.tree.PutScenario(editiontest.ScenarioID, order...)
	if _, err := edition.RenderEvent(f.in); err != nil {
		t.Fatalf("RenderEvent: %v", err)
	}
	data, err := os.ReadFile(f.outFile(edition.EventRenderRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 4 || lines[0] != "# falco-ctf render-record v2" || !strings.HasPrefix(lines[1], "run-id\t") || !strings.HasPrefix(lines[2], "key-fingerprint\t") {
		t.Fatalf("the render record is %q, want the v2 header, the run id, the fingerprint and the scope", data)
	}
	scored, err := catalog.LoadScored(f.in.Challenges, f.in.ScenarioFile, f.in.FlagsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(scored.Order, order) {
		t.Fatalf("LoadScored's order is %v, want the scenario's %v", scored.Order, order)
	}
	if want := "scope\t" + edition.ScopeDigest(scored.Order); lines[3] != want {
		t.Errorf("the scope line is %q, want %q (ScopeDigest of LoadScored's order)", lines[3], want)
	}
	if lines[3] == "scope\t"+edition.ScopeDigest([]string{editiontest.Evade, editiontest.CID}) {
		t.Error("the scope line is the digest of the scope without the extra evade challenge")
	}

	if ev, _, err := edition.CheckEvent(f.checkInput()); err != nil || ev == nil {
		t.Fatalf("the check with the render's own scope = (%v, %v); want it accepted (the cases below would prove nothing)", ev, err)
	}
	in := f.checkInput()
	in.ScenarioFile = f.tree.PutScenario("swapped", scopeExtraEvade, editiontest.Evade, editiontest.CID)
	expectB12(t, "the same challenges in another order", in)
}

// A scope that adds an evade challenge only (no investigate challenge changes, so without B12 no
// rule of the table would see it) is B12.
func TestScopeB12_AnEvadeChallengeAdded(t *testing.T) {
	f := newRfFix(t)
	f.addExtraEvade()
	if _, err := edition.RenderEvent(f.in); err != nil {
		t.Fatalf("RenderEvent: %v", err)
	}
	if ev, _, err := edition.CheckEvent(f.checkInput()); err != nil || ev == nil {
		t.Fatalf("the check with the render's own scope = (%v, %v); want it accepted", ev, err)
	}
	in := f.checkInput()
	in.ScenarioFile = f.tree.PutScenario("plus-evade", editiontest.Evade, scopeExtraEvade, editiontest.CID)
	expectB12(t, "an evade challenge added", in)
}

// A scope that leaves out one investigate challenge of the two that were rendered is B12, at step
// 1b: the check's scope still has an investigate challenge (step 1 runs), and the table and the
// edition root, which hold the one left out, are not read (T4 and E2 are not reached).
func TestScopeB12_AnInvestigateChallengeLeftOut(t *testing.T) {
	const second = "02-demo"
	tree := editiontest.NewTree(t)
	seats := editiontest.Seats()
	tree.PlaceInputs(editiontest.Inputs{Golden: cevGold, Spec: editiontest.GoodSpec(), Template: editiontest.GoodTemplate(), Seats: seats})
	// The second investigate challenge: the first one's practice edition and journey, under its id.
	tree.CopyTree(cevGold, editiontest.ChallengesRel+"/"+second)
	for _, name := range []string{"answers.tsv", "digests.tsv"} {
		rel := editiontest.ChallengesRel + "/" + second + "/" + edition.EditionDirName + "/" + edition.PracticeDirName + "/" + name
		tree.Put(rel, strings.ReplaceAll(tree.Read(rel), "\t"+editiontest.CID+"\t", "\t"+second+"\t"))
	}
	tree.Put(editiontest.ChallengesRel+"/"+second+"/journey.yaml", strings.Replace(editiontest.Journey, "challengeId: "+editiontest.CID, "challengeId: "+second, 1))
	tree.Put(editiontest.EditionRootRel+"/"+second+"/"+edition.SpecFileName, editiontest.GoodSpec())
	tree.Put(editiontest.EditionRootRel+"/"+second+"/"+edition.TemplateDirName+"/"+editiontest.TemplateName, editiontest.GoodTemplate())
	tree.PutScenario(editiontest.ScenarioID, editiontest.Evade, editiontest.CID, second)

	// The render of the two (the renderer's own output, as checkevent_helpers_test.go makes it).
	p := tree.Paths()
	scored, err := catalog.LoadScored(p.Challenges, p.Scenario, p.Flags)
	if err != nil {
		t.Fatalf("catalog.LoadScored: %v", err)
	}
	scope := edition.ScopeOf(scored.Catalog)
	if len(scope) != 2 {
		t.Fatalf("the render's scope has %d investigate challenges, want 2: the case would not leave one in", len(scope))
	}
	key, err := edition.NewMasterKey(editiontest.KeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := edition.ParseSpec([]byte(editiontest.GoodSpec()))
	if err != nil {
		t.Fatal(err)
	}
	var rows []edition.AnswerRow
	for _, cid := range []string{editiontest.CID, second} {
		r, err := edition.Render(edition.RenderInput{
			CID:       cid,
			Questions: scope[cid],
			Spec:      spec,
			Template:  []edition.BundleFile{{Name: editiontest.TemplateName, Data: []byte(editiontest.GoodTemplate())}},
			Key:       key,
			Seats:     seats,
			Previous:  edition.NoPreviousSeats(),
		})
		if err != nil {
			t.Fatalf("Render of %s: %v", cid, err)
		}
		rows = append(rows, r.Rows...)
		for _, b := range r.Bundles {
			for _, file := range b.Files {
				tree.PlaceBundleFile(b.Seat, b.CID, file.Name, file.Data)
			}
		}
	}
	var table, record bytes.Buffer
	if err := edition.WriteAnswers(&table, runA, rows); err != nil {
		t.Fatal(err)
	}
	if err := edition.WriteRenderRecord(&record, runA, key, scored.Order); err != nil {
		t.Fatal(err)
	}
	tree.PlaceAnswers(table.String(), record.String())

	in := edition.CheckInput{
		Challenges:       p.Challenges,
		ScenarioFile:     tree.PutScenario("without-second", editiontest.Evade, editiontest.CID),
		FlagsFile:        p.Flags,
		AnswersFile:      p.Answers,
		RenderRecordFile: p.RenderRecord,
		EvidenceRoot:     p.Evidence,
		SeatsFile:        p.Seats,
		EditionRoot:      p.EditionRoot,
		NoPrevious:       true,
		CorpusDirs:       []string{p.Corpus},
		DigestsOut:       p.DigestsOut,
	}
	expectB12(t, "an investigate challenge left out", in)
}

// --all-challenges and the scenario of the same ids in the same order are one scope: a render with
// one and a check with the other pass, both ways.
func TestScopeB12_AllChallengesAndTheSameScenarioAreOneScope(t *testing.T) {
	f := newRfFix(t)
	p := f.tree.Paths()
	all, err := catalog.LoadScored(p.Challenges, "", p.Flags)
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := catalog.LoadScored(p.Challenges, p.Scenario, p.Flags)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(all.Order, narrow.Order) {
		t.Fatalf("the fixture's scenario %v is not the ids of every challenge in their order %v: the cases below would prove nothing", narrow.Order, all.Order)
	}

	f.in.ScenarioFile, f.in.AllChallenges = "", true
	if _, err := edition.RenderEvent(f.in); err != nil {
		t.Fatalf("RenderEvent with --all-challenges: %v", err)
	}
	if ev, _, err := edition.CheckEvent(f.checkInput()); err != nil || ev == nil {
		t.Errorf("render --all-challenges, check --scenario: (%v, %v); want it accepted", ev, err)
	}

	g := newRfFix(t)
	if _, err := edition.RenderEvent(g.in); err != nil {
		t.Fatalf("RenderEvent with --scenario: %v", err)
	}
	in := g.checkInput()
	in.ScenarioFile, in.AllChallenges = "", true
	if ev, _, err := edition.CheckEvent(in); err != nil || ev == nil {
		t.Errorf("render --scenario, check --all-challenges: (%v, %v); want it accepted", ev, err)
	}
}

// The first form of the render record, and a v2 one whose form is wrong, are a usage error (exit
// 2): the reader of step 1b does not go on to B12. The same set as platform's V99.
func TestScopeB12_AFormErrorOfTheRecordIsExit2AndNotB12(t *testing.T) {
	join := func(ls ...string) string { return strings.Join(ls, "\n") + "\n" }
	cases := map[string]func(l []string) string{
		"the first form (v1, three lines)": func(l []string) string { return join("# falco-ctf render-record v1", l[1], l[2]) },
		"v2 with no scope line":            func(l []string) string { return join(l[0], l[1], l[2]) },
		"five lines":                       func(l []string) string { return join(l[0], l[1], l[2], l[3], "extra") },
		"a scope of 63 digits":             func(l []string) string { return join(l[0], l[1], l[2], l[3][:len(l[3])-1]) },
		"an upper-case scope": func(l []string) string {
			return join(l[0], l[1], l[2], "scope\t"+strings.ToUpper(strings.TrimPrefix(l[3], "scope\t")))
		},
		"a scope that is not hex": func(l []string) string { return join(l[0], l[1], l[2], "scope\t"+strings.Repeat("z", 64)) },
		"another name for the scope": func(l []string) string {
			return join(l[0], l[1], l[2], "scope-digest"+strings.TrimPrefix(l[3], "scope"))
		},
		"the scope line twice": func(l []string) string { return join(l[0], l[1], l[2], l[3], l[3]) },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newGoodCevFix(t)
			lines := strings.Split(strings.TrimSuffix(f.read("render-record.tsv"), "\n"), "\n")
			if len(lines) != 4 || !strings.HasPrefix(lines[3], "scope\t") {
				t.Fatalf("the fixture's render record is %q, want the four lines of v2", lines)
			}
			f.put("render-record.tsv", mk(lines))
			err, report := f.refused(name)
			if !isInputErr(err) {
				t.Errorf("not a usage error (exit 2): %v", err)
			}
			if slices.Contains(cevRuleSet(err), edition.RuleScope) {
				t.Errorf("B12 was named for a record whose form is wrong: %v", err)
			}
			if report.OverlapRan {
				t.Error("B4 ran: the check went on past the render record")
			}
		})
	}
}
