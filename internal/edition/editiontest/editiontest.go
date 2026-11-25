// Package editiontest is the positive fixture of the event-edition commands (ADR-0056 D20,
// A4e-2d): an event for which every check of `edition check` passes, laid out on disk, minus
// what the renderer gives. Two test packages build it (internal/edition's checkevent tests and
// cmd/scoreboard's editioncmd tests) and the round trip of `edition render` (A4e-3) is the
// third, so the parts that do not depend on the renderer are here, once: the seats, the
// layout of the tree, the text of the inputs (the journey, the scenario, the flags file, the
// corpus, the event edition), the key's bytes and the paths of a good event.
//
// THIS PACKAGE NEVER CALLS THE RENDERER, and it never takes one as a value. What the renderer
// produces (the answers table, the render record, the files of each seat's bundle) is handed
// to it as text and bytes (PlaceAnswers, PlaceBundleFile); the call of the renderer stays in
// the _test.go file of each test package, which is what V78's closed list of callers
// (internal/edition/render_reach_test.go) is about. The package therefore names nothing the
// render files of internal/edition declare, and the test of that (V91,
// editiontest_source_test.go) reads this package's source.
//
// It is imported from _test.go files only: no non-test Go file of the module imports it (V91).
// It imports internal/edition for the two names of an edition's layout (SpecFileName and
// TemplateDirName: the layout has one definition, practicelayout.go) and nothing else of it, so
// package edition's own (internal) tests cannot import it; the external test package
// (edition_test) and cmd/scoreboard's tests can. It imports internal/catalog for the
// requirements block of the scenario it writes (catalog.DeriveRequirements, ADR-0055 S3a).
//
// Every value here is a placeholder with no meaning: no real flag, no real key, no real seat.
package editiontest

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/catalogtest"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// CID is the investigate challenge of the fixture.
const CID = "01-demo"

// Evade is the evade challenge of the fixture (a flags file needs one).
const Evade = "00-evade"

// Flag is the flag of the evade challenge in the fixture's flags file: a placeholder, in the
// form the public repository allows (FALCO{dev-...}), and not the evade challenge's default.
const Flag = "FALCO{dev-fixture-00}"

// TemplateName is the one template file of the event edition.
const TemplateName = "notes.txt"

// GoodNameWords is the number of words of the first answer slot's vocabulary of an accepted
// event, and GoodDecoys the decoys of each answer slot: B8 (b) needs 10 candidates per
// question, so 9 decoys and the answer.
const (
	GoodNameWords = 100

	GoodDecoys = 9
)

// The relative paths of an event in the fixture's tree (under Tree.Root, slash-separated).
const (
	// ChallengesRel is the image's challenges tree.
	ChallengesRel = "challenges"

	// ScenarioID is the fixture's scenario: the name of its directory (ADR-0055 D2).
	ScenarioID = "scenario"

	// ScenarioRel is the scenario file (PutScenario writes it and its module.yaml).
	ScenarioRel = ScenarioID + "/scenario.yaml"

	// FlagsRel is the flags file.
	FlagsRel = "flags/flags.yaml"

	// CorpusRel is the corpus directory.
	CorpusRel = "corpus"

	// EditionRootRel is the event editions' root.
	EditionRootRel = "edition-root"

	// SeatsRel is the seats file.
	SeatsRel = "seats.txt"

	// OutRel is the empty directory the digests file goes to.
	OutRel = "out"

	// DigestsRel is where the digests file of an accepted event goes (it does not exist yet).
	DigestsRel = "out/digests.tsv"

	// AnswersRel is the answers table.
	AnswersRel = "answers.tsv"

	// RenderRecordRel is the render record.
	RenderRecordRel = "render-record.tsv"

	// EvidenceRel is the root of the bundles, <seat>/<challenge>/<file> under it.
	EvidenceRel = "evidence"

	// KeyRel is the key file of `edition render` (A4e-3a): one line of hex, mode 0600.
	KeyRel = "key.hex"

	// PreviousSeatsRel is a previous seats file of `edition render` (--previous-seats).
	PreviousSeatsRel = "previous-seats.txt"

	// RenderOutRel is the --out of `edition render`, under the empty directory OutRel: it does
	// not exist until a render puts it there.
	RenderOutRel = "out/render"
)

// KeyText is the key file of the fixture's key (KeyBytes): its lower-case hex, one line.
func KeyText() string { return hex.EncodeToString(KeyBytes()) + "\n" }

// PlaceKey writes the key file at rel with the given text and the permission bits mode (set
// after the write, so the umask does not change them). A test of a key file of another form or
// mode gives its own text and mode.
func (tr *Tree) PlaceKey(rel, text string, mode fs.FileMode) {
	tr.T.Helper()
	tr.Put(rel, text)
	if err := os.Chmod(tr.Path(rel), mode); err != nil {
		tr.T.Fatal(err)
	}
}

// RenderPaths are the OS paths of the inputs and of the output of a good `edition render` of
// the fixture (PlaceInputs and PlaceKey(KeyRel, KeyText(), 0o600) lay them out).
type RenderPaths struct {
	Challenges, Scenario, Flags, EditionRoot, Seats, PreviousSeatsFile, Key, Out string
}

// RenderPaths is where the inputs of a good render are in the tree, and where its output goes.
func (tr *Tree) RenderPaths() RenderPaths {
	return RenderPaths{
		Challenges:        tr.Path(ChallengesRel),
		Scenario:          tr.Path(ScenarioRel),
		Flags:             tr.Path(FlagsRel),
		EditionRoot:       tr.Path(EditionRootRel),
		Seats:             tr.Path(SeatsRel),
		PreviousSeatsFile: tr.Path(PreviousSeatsRel),
		Key:               tr.Path(KeyRel),
		Out:               tr.Path(RenderOutRel),
	}
}

// EvadeRule is the falco-rule.yaml of the evade challenge: a placeholder flag, and a rule name.
const EvadeRule = "type: evade\nexpectedFlag: FALCO{dev-fixture}\nforbiddenRules: [r]\n"

// Journey is the journey.yaml of the investigate challenge: the prompts are placeholders, and
// the hint has words that no bundle holds.
const Journey = "challengeId: 01-demo\ntitle: Fixture\nbriefing: plain placeholder briefing of the fixture\n" +
	"hints:\n  - \"alpha bravo charlie delta echo foxtrot golf hotel india juliet\"\n" +
	"questions:\n" +
	"  - id: q1\n    prompt: \"first placeholder prompt\"\n" +
	"  - id: q2\n    prompt: \"second placeholder prompt\"\n" +
	"  - id: q3\n    prompt: \"third placeholder prompt\"\n" +
	"  - id: q4\n    prompt: \"fourth placeholder prompt\"\n" +
	"  - id: q5\n    prompt: \"fifth placeholder prompt\"\n"

// Seats is the three seats of the fixture, in the order of its seats file.
func Seats() []string { return []string{"seat-a", "seat-b", "seat-c"} }

// SeatsText is a seats file of the given seats.
func SeatsText(seats []string) string {
	return "# falco-ctf seats v1\n" + strings.Join(seats, "\n") + "\n"
}

// KeyBytes is the bytes of the fixture's master key: plainly a test key, and long enough for
// the key type that holds it. The caller makes the key; this package does not name the type.
func KeyBytes() []byte { return []byte(strings.Repeat("test-only-key-", 4)) }

// SpecText is the edition.yaml of the event edition: the first answer slot's vocabulary has
// nameWords words (its space is that number) and each answer slot has decoys decoys. The
// vocabulary, the time base, the fixed answer and the text are the event's own, so that no
// rule that compares an event with the practice edition (T6, B4) sees a copy.
func SpecText(nameWords, decoys int) string {
	words := make([]string, nameWords)
	for i := range words {
		words[i] = fmt.Sprintf("e%03d", i)
	}
	ten := func(p string) string {
		w := make([]string, 10)
		for i := range w {
			w[i] = fmt.Sprintf("%s%d", p, i)
		}
		return "[" + strings.Join(w, ", ") + "]"
	}
	var b strings.Builder
	b.WriteString("version: 1\ntime:\n  base: \"2001-01-01T00:00:00Z\"\nfixed:\n  q5: \"c2,c4\"\nslots:\n")
	fmt.Fprintf(&b, "  - name: who\n    role: answer\n    question: q1\n    decoys: %d\n    vocab:\n      - [%s]\n", decoys, strings.Join(words, ", "))
	fmt.Fprintf(&b, "  - name: where\n    role: answer\n    question: q2\n    decoys: %d\n    vocab:\n      - [srv]\n      - [y]\n      - %s\n      - %s\n      - %s\n", decoys, ten("d"), ten("e"), ten("f"))
	fmt.Fprintf(&b, "  - name: tag\n    role: answer\n    question: q3\n    decoys: %d\n", decoys)
	fmt.Fprintf(&b, "  - name: when\n    role: answer\n    question: q4\n    decoys: %d\n    window: {from: 0, to: 3600}\n", decoys)
	b.WriteString("  - name: other\n    role: filler\n    format: name\n    vocab:\n      - [n0, n1, n2]\n")
	// The time of each line of the groups of who, where and tag (when's lines are timed by their
	// own marks): one filler per line, all of one window after when's.
	for _, g := range Groups[:3] {
		for j := 0; j <= decoys; j++ {
			fmt.Fprintf(&b, "  - {name: %s-t%d, role: filler, format: timestamp, window: {from: 7200, to: 10800}}\n", g, j)
		}
	}
	// One block per group (ADR-0056 amendment 28, B17): blocks is the last key, so a case can add
	// an entry to its list.
	b.WriteString("blocks:\n")
	for _, g := range Groups {
		from, to := BlockLines(decoys, g)
		fmt.Fprintf(&b, "  - {file: %s, from: %d, to: %d}\n", TemplateName, from, to)
	}
	return b.String()
}

// Groups are the answer slots of the event edition, in the order of their blocks in the template.
var Groups = []string{"who", "where", "tag", "when"}

// BlockLines is the first and the last line (1-based) of the block of group g in TemplateText(decoys):
// the answer's line and one line of each decoy, after the template's first line.
func BlockLines(decoys int, g string) (int, int) {
	for i, s := range Groups {
		if s == g {
			from := 2 + i*(decoys+1)
			return from, from + decoys
		}
	}
	return 0, 0
}

// TimeField is the index of the time among the fields (strings.Fields) of a line of a block of
// TemplateText, in the template's text and in a bundle's.
const TimeField = 3

// TemplateText is the template of the event edition: the first line, then one block per answer
// slot (Groups, BlockLines) whose lines are the same but for their marks (B17): the answer's line
// and one line of each decoy, each with a time of its own (a filler, or the mark of when's group
// itself), the marks alone as tokens. A line of a filler ends it.
func TemplateText(decoys int) string {
	var b strings.Builder
	b.WriteString("fixture record, placeholder text only\n")
	for _, g := range Groups {
		for j := 0; j <= decoys; j++ {
			slot := g
			if j > 0 {
				slot = fmt.Sprintf("%s-d%d", g, j)
			}
			if g == "when" {
				fmt.Fprintf(&b, "when record at {{ctf:%s}}\n", slot)
				continue
			}
			fmt.Fprintf(&b, "%s record at {{ctf:%s-t%d}} holds {{ctf:%s}}\n", g, g, j, slot)
		}
	}
	b.WriteString("side-note = {{ctf:other}}\n")
	return b.String()
}

// GoodSpec is the edition.yaml of an accepted event.
func GoodSpec() string { return SpecText(GoodNameWords, GoodDecoys) }

// GoodTemplate is the template of an accepted event.
func GoodTemplate() string { return TemplateText(GoodDecoys) }

// Tree is one fixture on disk: a directory the test owns (t.TempDir()), and the testing.TB
// that a failure of the fixture is reported to.
type Tree struct {
	T    testing.TB
	Root string
}

// NewTree is an empty tree under t.TempDir(). It writes nothing to the repository.
func NewTree(t testing.TB) *Tree {
	t.Helper()
	return &Tree{T: t, Root: t.TempDir()}
}

// Path is the OS path of the slash-separated rel in the tree.
func (tr *Tree) Path(rel string) string { return filepath.Join(tr.Root, filepath.FromSlash(rel)) }

// Put writes the file rel (and the directories above it) with the content.
func (tr *Tree) Put(rel, content string) {
	tr.T.Helper()
	p := tr.Path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		tr.T.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		tr.T.Fatal(err)
	}
}

// PutScenario writes the scenario id of the challenges, in that order, at the root of the tree
// (id/scenario.yaml and the module.yaml it is generated from: catalog.LoadScenario takes
// nothing else, ADR-0055 S2c) and returns the scenario file's path. Its requirements block is
// the one the tree's challenges derive (scopeRequirements), so the challenges it lists are
// put in the tree first (a missing one fails the test).
func (tr *Tree) PutScenario(id string, challenges ...string) string {
	tr.T.Helper()
	return catalogtest.WriteScenarioWith(tr.T, tr.Root, id, tr.scopeRequirements(challenges), challenges...)
}

// scopeRequirements is the requirements block (ADR-0055 D6, S3a) that
// catalog.DeriveRequirements gives for the challenges of the tree's challenges directory that
// the scenario lists: the block the generator would write, which catalog.LoadScored compares
// the file's with. A tree that does not load, or a challenge the tree does not hold, fails the
// test (the fixture would otherwise write a block nothing derived). No caller needs the zero
// block today; a test of a scenario that names a missing challenge writes its file with
// catalogtest.WriteScenario (the zero block) explicitly.
func (tr *Tree) scopeRequirements(challenges []string) catalogtest.Requirements {
	tr.T.Helper()
	cat, err := catalog.Load(tr.Path(ChallengesRel))
	if err != nil {
		tr.T.Fatalf("PutScenario: the tree's challenges do not load (put them before the scenario): %v", err)
	}
	scope, err := cat.Restrict(challenges)
	if err != nil {
		tr.T.Fatalf("PutScenario: %v (put the challenges in the tree before the scenario)", err)
	}
	r := catalog.DeriveRequirements(scope)
	return catalogtest.Requirements{Answers: r.Answers, Detect: r.Detect, Exfil: r.Exfil, Rules: r.Rules}
}

// Read is the text of the file rel.
func (tr *Tree) Read(rel string) string {
	tr.T.Helper()
	b, err := os.ReadFile(tr.Path(rel))
	if err != nil {
		tr.T.Fatal(err)
	}
	return string(b)
}

// CopyTree copies the tree under the directory src (a path the test can open, such as one of
// internal/edition/testdata) to rel of the fixture.
func (tr *Tree) CopyTree(src, rel string) {
	tr.T.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sub, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		tr.Put(rel+"/"+filepath.ToSlash(sub), string(b))
		return nil
	})
	if err != nil {
		tr.T.Fatal(err)
	}
}

// Inputs is what an event is made of before the renderer runs.
type Inputs struct {
	// Golden is the directory of the practice edition of the investigate challenge
	// (internal/edition/testdata/render-golden/01-demo), as a path the test can open: it
	// becomes the image's tree for that challenge.
	Golden string

	// Spec and Template are the text of the event edition's edition.yaml and of its one
	// template file (TemplateName).
	Spec, Template string

	// Seats are the seats of the seats file.
	Seats []string
}

// PlaceInputs lays out the event up to the renderer's output: the image's tree (an evade
// challenge, the investigate challenge with its practice edition and its journey), the
// scenario, the flags file, the corpus, the event edition, the seats file and the empty
// output directory. The image's tree and the event edition are two editions of the same
// challenge, so that no rule that compares them sees a copy.
func (tr *Tree) PlaceInputs(in Inputs) {
	tr.T.Helper()
	tr.Put(ChallengesRel+"/"+Evade+"/falco-rule.yaml", EvadeRule)
	tr.CopyTree(in.Golden, ChallengesRel+"/"+CID)
	tr.Put(ChallengesRel+"/"+CID+"/journey.yaml", Journey)
	tr.PutScenario(ScenarioID, Evade, CID)
	tr.Put(FlagsRel, "flags:\n  "+Evade+": "+Flag+"\n")
	tr.Put(CorpusRel+"/public.txt", "placeholder text of the image's public files\n")
	tr.Put(EditionRootRel+"/"+CID+"/"+edition.SpecFileName, in.Spec)
	tr.Put(EditionRootRel+"/"+CID+"/"+edition.TemplateDirName+"/"+TemplateName, in.Template)
	tr.Put(SeatsRel, SeatsText(in.Seats))
	if err := os.MkdirAll(tr.Path(OutRel), 0o755); err != nil {
		tr.T.Fatal(err)
	}
}

// PlaceAnswers puts the answers table and the render record, as the text the renderer's
// writers gave, where the check reads them.
func (tr *Tree) PlaceAnswers(table, record string) {
	tr.T.Helper()
	tr.Put(AnswersRel, table)
	tr.Put(RenderRecordRel, record)
}

// PlaceBundleFile puts one file of the bundle of a seat's challenge, as the renderer gave it,
// under the evidence root.
func (tr *Tree) PlaceBundleFile(seat, cid, name string, data []byte) {
	tr.T.Helper()
	tr.Put(EvidenceRel+"/"+seat+"/"+cid+"/"+name, string(data))
}

// Paths are the OS paths of the inputs of a good event, as the check takes them.
type Paths struct {
	Challenges, Scenario, Flags, Answers, RenderRecord, Evidence, Seats, EditionRoot, Corpus, DigestsOut string
}

// Paths is where the inputs of a good event are in the tree.
func (tr *Tree) Paths() Paths {
	return Paths{
		Challenges:   tr.Path(ChallengesRel),
		Scenario:     tr.Path(ScenarioRel),
		Flags:        tr.Path(FlagsRel),
		Answers:      tr.Path(AnswersRel),
		RenderRecord: tr.Path(RenderRecordRel),
		Evidence:     tr.Path(EvidenceRel),
		Seats:        tr.Path(SeatsRel),
		EditionRoot:  tr.Path(EditionRootRel),
		Corpus:       tr.Path(CorpusRel),
		DigestsOut:   tr.Path(DigestsRel),
	}
}
