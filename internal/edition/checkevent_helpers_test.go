package edition_test

// The positive fixture of CheckEvent (ADR-0056 D20, V86): an event for which every check
// passes. It is NOT written by hand: the answers table, the bundles and the render record are
// the output of the renderer (edition.Render, WriteAnswers, WriteRenderRecord) run over a
// small edition with a key that is plainly a test key, so a case that breaks one rule changes
// one thing in a tree that is otherwise what a real render and its operator would give. Every
// value is a placeholder with no meaning.
//
// The image's tree (challenges/) is built from internal/edition/testdata/render-golden/01-demo
// (the practice edition) plus an evade challenge (a flags file needs one) and a journey.yaml
// (an investigate challenge needs one). The EVENT edition (edition-root/) is another edition
// of the same challenge, with its own vocabulary, time base, fixed answer and template text, so
// that no rule that compares an event with the practice edition (T6, B4) sees a copy.

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

const (
	cevEvade = "00-evade"
	cevFlag  = "FALCO{test-fixture-00}"
	cevGold  = "testdata/render-golden/01-demo"

	// cevJourney: the prompts are placeholders; the hint has words that no bundle holds.
	cevJourney = "challengeId: 01-demo\ntitle: Fixture\nbriefing: plain placeholder briefing of the fixture\n" +
		"hints:\n  - \"alpha bravo charlie delta echo foxtrot golf hotel india juliet\"\n" +
		"questions:\n" +
		"  - id: q1\n    prompt: \"first placeholder prompt\"\n" +
		"  - id: q2\n    prompt: \"second placeholder prompt\"\n" +
		"  - id: q3\n    prompt: \"third placeholder prompt\"\n" +
		"  - id: q4\n    prompt: \"fourth placeholder prompt\"\n" +
		"  - id: q5\n    prompt: \"fifth placeholder prompt\"\n"

	cevTemplateName = "notes.txt"
)

// cevOpts are the two knobs of the event edition that cases turn: the words of the name
// vocabulary of the first answer slot (its space is the number of words) and the decoys of
// each answer slot (B8 (b) needs 10 candidates per question, so 9 decoys and the answer).
type cevOpts struct {
	nameWords int
	decoys    int
}

// cevSpec is the edition.yaml of the event edition.
func cevSpec(o cevOpts) string {
	words := make([]string, o.nameWords)
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
	fmt.Fprintf(&b, "  - name: who\n    role: answer\n    question: q1\n    decoys: %d\n    vocab:\n      - [%s]\n", o.decoys, strings.Join(words, ", "))
	fmt.Fprintf(&b, "  - name: where\n    role: answer\n    question: q2\n    decoys: %d\n    vocab:\n      - [srv]\n      - [y]\n      - %s\n      - %s\n      - %s\n", o.decoys, ten("d"), ten("e"), ten("f"))
	fmt.Fprintf(&b, "  - name: tag\n    role: answer\n    question: q3\n    decoys: %d\n", o.decoys)
	fmt.Fprintf(&b, "  - name: when\n    role: answer\n    question: q4\n    decoys: %d\n    window: {from: 0, to: 3600}\n", o.decoys)
	b.WriteString("  - name: other\n    role: filler\n    format: name\n    vocab:\n      - [n0, n1, n2]\n")
	return b.String()
}

// cevTemplate is the template of the event edition: one line per slot, the mark alone as a
// token (a space before it, a line break after it).
func cevTemplate(decoys int) string {
	var b strings.Builder
	b.WriteString("fixture record, placeholder text only\n")
	for _, s := range []string{"who", "where", "tag", "when"} {
		fmt.Fprintf(&b, "%s-answer = {{ctf:%s}}\n", s, s)
		for j := 1; j <= decoys; j++ {
			fmt.Fprintf(&b, "%s-candidate-%d = {{ctf:%s-d%d}}\n", s, j, s, j)
		}
	}
	b.WriteString("side-note = {{ctf:other}}\n")
	return b.String()
}

// cevSeatsText is a seats file of the given seats.
func cevSeatsText(seats []string) string {
	return "# falco-ctf seats v1\n" + strings.Join(seats, "\n") + "\n"
}

// cevFix is one event: its paths (in is what CheckEvent is given), the answers the renderer
// drew (values: none may be in any message) and the key.
type cevFix struct {
	t       *testing.T
	root    string
	in      edition.CheckInput
	seats   []string
	key     edition.MasterKey
	values  []string
	answers map[string]string // "<seat>/<qid>" -> value
	spec    string
	tmpl    string
}

func (f *cevFix) path(rel string) string { return filepath.Join(f.root, filepath.FromSlash(rel)) }

func (f *cevFix) put(rel, content string) {
	f.t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *cevFix) read(rel string) string {
	f.t.Helper()
	b, err := os.ReadFile(f.path(rel))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

// rewrite replaces the file's text with fn's result.
func (f *cevFix) rewrite(rel string, fn func(string) string) {
	f.t.Helper()
	f.put(rel, fn(f.read(rel)))
}

// copyTree copies the tree under the testdata directory src to rel of the fixture.
func (f *cevFix) copyTree(src, rel string) {
	f.t.Helper()
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
		f.put(rel+"/"+filepath.ToSlash(sub), string(b))
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

// newCevFix builds the event: the image's tree, the event edition, and the renderer's output
// for three seats (seat-a, seat-b, seat-c), with run id runA. It writes nothing to the
// repository: everything is under t.TempDir().
func newCevFix(t *testing.T, o cevOpts) *cevFix {
	t.Helper()
	f := &cevFix{t: t, root: t.TempDir(), seats: []string{"seat-a", "seat-b", "seat-c"}, answers: map[string]string{}}
	f.spec, f.tmpl = cevSpec(o), cevTemplate(o.decoys)

	// the image's tree
	f.put("challenges/"+cevEvade+"/falco-rule.yaml", "type: evade\nexpectedFlag: FALCO{dev-fixture}\nforbiddenRules: [r]\n")
	f.copyTree(cevGold, "challenges/"+demoCID)
	f.put("challenges/"+demoCID+"/journey.yaml", cevJourney)
	f.put("scenario/scenario.yaml", "id: fixture\ntitle: Fixture\nchallenges: ["+cevEvade+", "+demoCID+"]\n")
	f.put("flags/flags.yaml", "flags:\n  "+cevEvade+": "+cevFlag+"\n")
	f.put("corpus/public.txt", "placeholder text of the image's public files\n")

	// the event edition, the seats and the key
	f.put("edition-root/"+demoCID+"/"+edition.SpecFileName, f.spec)
	f.put("edition-root/"+demoCID+"/"+edition.TemplateDirName+"/"+cevTemplateName, f.tmpl)
	f.put("seats.txt", cevSeatsText(f.seats))
	if err := os.MkdirAll(f.path("out"), 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := edition.NewMasterKey(bytes.Repeat([]byte("test-only-key-"), 4))
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	f.key = key

	// the renderer's output
	scored, err := catalog.LoadScored(f.path("challenges"), f.path("scenario/scenario.yaml"), f.path("flags/flags.yaml"))
	if err != nil {
		t.Fatalf("catalog.LoadScored: %v", err)
	}
	spec, err := edition.ParseSpec([]byte(f.spec))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	r, err := edition.Render(edition.RenderInput{
		CID:       demoCID,
		Questions: edition.ScopeOf(scored.Catalog)[demoCID],
		Spec:      spec,
		Template:  []edition.BundleFile{{Name: cevTemplateName, Data: []byte(f.tmpl)}},
		Key:       key,
		Seats:     f.seats,
		Previous:  edition.NoPreviousSeats(),
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var table, record bytes.Buffer
	if err := edition.WriteAnswers(&table, runA, r.Rows); err != nil {
		t.Fatalf("WriteAnswers: %v", err)
	}
	if err := edition.WriteRenderRecord(&record, runA, key); err != nil {
		t.Fatalf("WriteRenderRecord: %v", err)
	}
	f.put("answers.tsv", table.String())
	f.put("render-record.tsv", record.String())
	for _, b := range r.Bundles {
		for _, file := range b.Files {
			f.put("evidence/"+b.Seat+"/"+b.CID+"/"+file.Name, string(file.Data))
		}
	}
	for _, row := range r.Rows {
		f.values = append(f.values, row.Value)
		f.answers[row.Seat+"/"+row.QID] = row.Value
	}

	f.in = edition.CheckInput{
		Challenges:       f.path("challenges"),
		ScenarioFile:     f.path("scenario/scenario.yaml"),
		FlagsFile:        f.path("flags/flags.yaml"),
		AnswersFile:      f.path("answers.tsv"),
		RenderRecordFile: f.path("render-record.tsv"),
		EvidenceRoot:     f.path("evidence"),
		SeatsFile:        f.path("seats.txt"),
		EditionRoot:      f.path("edition-root"),
		NoPrevious:       true,
		CorpusDirs:       []string{f.path("corpus")},
		DigestsOut:       f.path("out/digests.tsv"),
	}
	return f
}

// newGoodCevFix is the event that every check accepts.
func newGoodCevFix(t *testing.T) *cevFix { return newCevFix(t, cevOpts{nameWords: 100, decoys: 9}) }

func (f *cevFix) check() (*edition.CheckedEvent, edition.CheckReport, error) {
	return edition.CheckEvent(f.in)
}

// noValue fails if a text holds a value of the render (an answer, a fixed answer).
func (f *cevFix) noValue(what string, texts ...string) {
	f.t.Helper()
	for _, text := range texts {
		for _, v := range f.values {
			if strings.Contains(text, v) {
				f.t.Errorf("%s: the text holds a value of the render (%q): %q", what, v, text)
			}
		}
	}
}

// refused runs the check and expects no event and an error; it returns the error and the
// report. The error's text holds no value of the render.
func (f *cevFix) refused(what string) (error, edition.CheckReport) {
	f.t.Helper()
	ev, report, err := f.check()
	if ev != nil || err == nil {
		f.t.Fatalf("%s: event %v, err %v; want no event and an error", what, ev, err)
	}
	f.noValue(what, err.Error(), fmt.Sprintf("%+v", err))
	return err, report
}

// isInputErr reports whether err is a usage error or an unreadable input (exit 2).
func isInputErr(err error) bool {
	var in *edition.InputError
	return errors.As(err, &in)
}

// cevRuleSet is every rule that a violation inside err names (an errors.Join, possibly wrapped
// one or more times), sorted and without repeats.
func cevRuleSet(err error) []string {
	var out []string
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, x := range j.Unwrap() {
				walk(x)
			}
			return
		}
		if v, ok := e.(*edition.Violation); ok {
			out = append(out, v.Rule)
			return
		}
		walk(errors.Unwrap(e))
	}
	walk(err)
	slices.Sort(out)
	return slices.Compact(out)
}

// seatsList is n generated seats (s001 ...), in order.
func seatsList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("s%03d", i+1)
	}
	return out
}
