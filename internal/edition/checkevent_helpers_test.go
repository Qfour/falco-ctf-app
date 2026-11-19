package edition_test

// The positive fixture of CheckEvent (ADR-0056 D20, V86): an event for which every check
// passes. It is NOT written by hand: the answers table, the bundles and the render record are
// the output of the renderer (edition.Render, WriteAnswers, WriteRenderRecord) run over a
// small edition with a key that is plainly a test key, so a case that breaks one rule changes
// one thing in a tree that is otherwise what a real render and its operator would give. Every
// value is a placeholder with no meaning.
//
// The tree the fixture is laid out in (the image's tree, the event edition, the seats, the
// corpus, the key's bytes) is internal/edition/editiontest's, which cmd/scoreboard's tests
// share (ADR-0056 A4e-2d, V91): that package never calls the renderer. The call of the
// renderer, and what is made of its output, stay here.
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
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

const (
	cevEvade        = editiontest.Evade
	cevGold         = "testdata/render-golden/01-demo"
	cevTemplateName = editiontest.TemplateName
)

// cevOpts are the two knobs of the event edition that cases turn: the words of the name
// vocabulary of the first answer slot (its space is the number of words) and the decoys of
// each answer slot (B8 (b) needs 10 candidates per question, so 9 decoys and the answer).
type cevOpts struct {
	nameWords int
	decoys    int
}

// cevSpec is the edition.yaml of the event edition.
func cevSpec(o cevOpts) string { return editiontest.SpecText(o.nameWords, o.decoys) }

// cevSeatsText is a seats file of the given seats.
func cevSeatsText(seats []string) string { return editiontest.SeatsText(seats) }

// cevFix is one event: its paths (in is what CheckEvent is given), the answers the renderer
// drew (values: none may be in any message) and the key.
type cevFix struct {
	t       *testing.T
	tree    *editiontest.Tree
	in      edition.CheckInput
	seats   []string
	key     edition.MasterKey
	scope   []string // the ordered ids of the render's scope (catalog.LoadScored's Order)
	values  []string
	answers map[string]string // "<seat>/<qid>" -> value
	spec    string
	tmpl    string
}

func (f *cevFix) path(rel string) string { return f.tree.Path(rel) }

func (f *cevFix) put(rel, content string) {
	f.t.Helper()
	f.tree.Put(rel, content)
}

func (f *cevFix) read(rel string) string {
	f.t.Helper()
	return f.tree.Read(rel)
}

// rewrite replaces the file's text with fn's result.
func (f *cevFix) rewrite(rel string, fn func(string) string) {
	f.t.Helper()
	f.put(rel, fn(f.read(rel)))
}

// newCevFix builds the event: the image's tree, the event edition, and the renderer's output
// for three seats (seat-a, seat-b, seat-c), with run id runA. It writes nothing to the
// repository: everything is under t.TempDir().
func newCevFix(t *testing.T, o cevOpts) *cevFix {
	t.Helper()
	f := &cevFix{t: t, tree: editiontest.NewTree(t), seats: editiontest.Seats(), answers: map[string]string{}}
	f.spec, f.tmpl = cevSpec(o), editiontest.TemplateText(o.decoys)

	// the image's tree, the event edition, the seats and the output directory
	f.tree.PlaceInputs(editiontest.Inputs{Golden: cevGold, Spec: f.spec, Template: f.tmpl, Seats: f.seats})
	key, err := edition.NewMasterKey(editiontest.KeyBytes())
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	f.key = key

	// the renderer's output
	p := f.tree.Paths()
	scored, err := catalog.LoadScored(p.Challenges, p.Scenario, p.Flags)
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
	f.scope = scored.Order
	if err := edition.WriteRenderRecord(&record, runA, key, f.scope); err != nil {
		t.Fatalf("WriteRenderRecord: %v", err)
	}
	f.tree.PlaceAnswers(table.String(), record.String())
	for _, b := range r.Bundles {
		for _, file := range b.Files {
			f.tree.PlaceBundleFile(b.Seat, b.CID, file.Name, file.Data)
		}
	}
	for _, row := range r.Rows {
		f.values = append(f.values, row.Value)
		f.answers[row.Seat+"/"+row.QID] = row.Value
	}

	f.in = edition.CheckInput{
		Challenges:       p.Challenges,
		ScenarioFile:     p.Scenario,
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
	return f
}

// newGoodCevFix is the event that every check accepts.
func newGoodCevFix(t *testing.T) *cevFix {
	return newCevFix(t, cevOpts{nameWords: editiontest.GoodNameWords, decoys: editiontest.GoodDecoys})
}

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
