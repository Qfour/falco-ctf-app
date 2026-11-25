package edition_test

// ADR-0056 B13 to B16 through CheckEvent (A7-x PR 3, the review's R2#2): an event of two
// investigate challenges, rendered with the test key, so that the wiring of step 7b
// (checkCrossChallenges: the catalog's declarations, the bundles of each challenge, the answers
// of the table) is what is tested, and not only CheckCrossChallenge on inputs made by hand. The
// first challenge is editiontest's (01-demo); the second (02-demo) has one per-seat name question,
// declares that it shares 01-demo's shared.log (B14) and 01-demo's timeline (B15), and has a
// practice edition of its own, rendered here with the public practice key. Every value is a
// placeholder.

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

const (
	ccB      = "02-demo"
	ccShared = "shared.log"
	ccPeers  = "peers.txt"
	// ccSharedText is the file both event templates have, byte for byte, with no mark. Its time
	// is outside 01-demo's answer window [00:00, 01:00).
	ccSharedText = "2001-01-01T01:30:00Z relay accepted the batch from the queue\n"

	// ccJourney is the journey.yaml of 02-demo: a hint of words no bundle holds, one prompt.
	ccJourney = "challengeId: " + ccB + "\ntitle: Fixture two\nbriefing: plain placeholder briefing of the second fixture\n" +
		"hints:\n  - \"kilo lima mike november oscar papa quebec romeo sierra tango\"\n" +
		"questions:\n  - id: q1\n    prompt: \"the placeholder prompt of the second fixture\"\n"
)

// ccOpts are the changes a case makes before the render: text added to the end of a challenge's
// own template file, and the shares declaration of 02-demo left out.
type ccOpts struct {
	aExtra, bExtra string
	noShares       bool
}

// ccRule is the falco-rule.yaml of 02-demo.
func ccRule(noShares bool) string {
	ev := "  evidence:\n    mountDir: /srv/evidence-b\n"
	if !noShares {
		ev += "    shares:\n      - with: " + editiontest.CID + "\n        file: " + ccShared + "\n"
	}
	ev += "    timeline: " + editiontest.CID + "\n"
	return "type: " + catalog.TypeInvestigate + "\ninvestigate:\n" + ev + "  questions:\n    - id: q1\n      format: name\n      attempts: 1\n"
}

// ccSpec is an edition.yaml of 02-demo: one answer slot of 9 decoys, a vocabulary of 100 words, its
// clues (editiontest.Clues of the prefix), the time and the key of each line of its group
// (fillers, after 01-demo's answer window), and the block of the group over the lines of file
// (B17, amendment 31's two-step shape).
func ccSpec(prefix, file string) string {
	words := make([]string, 100)
	for i := range words {
		words[i] = fmt.Sprintf("%s%03d", prefix, i)
	}
	var b strings.Builder
	b.WriteString("version: 1\ntime:\n  base: \"2001-01-01T00:00:00Z\"\nslots:\n")
	b.WriteString("  - name: peer\n    role: answer\n    question: q1\n    decoys: 9\n    clues: " + editiontest.Clues(prefix) + "\n    vocab:\n      - [" + strings.Join(words, ", ") + "]\n")
	for j := 0; j <= 9; j++ {
		fmt.Fprintf(&b, "  - {name: pt%d, role: filler, format: timestamp, window: {from: 10800, to: 14400}}\n", j)
		fmt.Fprintf(&b, "  - {name: pk%d, role: filler, format: name, vocab: [[ka, kb, kc]]}\n", j)
	}
	fmt.Fprintf(&b, "blocks:\n  - {file: %s, from: 1, to: 10}\n", file)
	return b.String()
}

// ccTemplate is a template file of 02-demo: the block of the group, one line per slot, the same
// but for the marks (lead, a time, the value, a key), then the clue line of each key (its clue
// columns editiontest.ClueTuple of the prefix).
func ccTemplate(lead, prefix string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s at {{ctf:pt0}} -> {{ctf:peer}} key {{ctf:pk0}}\n", lead)
	for j := 1; j <= 9; j++ {
		fmt.Fprintf(&b, "%s at {{ctf:pt%d}} -> {{ctf:peer-d%d}} key {{ctf:pk%d}}\n", lead, j, j, j)
	}
	for j := 0; j <= 9; j++ {
		w1, w2 := editiontest.ClueTuple(prefix, j)
		fmt.Fprintf(&b, "%s key {{ctf:pk%d}} from %s via %s\n", lead, j, w1, w2)
	}
	return b.String()
}

// ccFix is the event, and the answers the renderer drew: "<seat>/<cid>/<qid>" -> value.
type ccFix struct {
	*cevFix
	byCell map[string]string
}

func newCrossCevFix(t *testing.T, o ccOpts) *ccFix {
	t.Helper()
	f := &ccFix{cevFix: &cevFix{t: t, tree: editiontest.NewTree(t), seats: editiontest.Seats(), answers: map[string]string{}}, byCell: map[string]string{}}
	tr := f.tree
	f.spec = editiontest.GoodSpec()
	f.tmpl = editiontest.GoodTemplate() + o.aExtra
	tr.PlaceInputs(editiontest.Inputs{Golden: cevGold, Spec: f.spec, Template: f.tmpl, Seats: f.seats})
	tr.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.TemplateDirName+"/"+ccShared, ccSharedText)

	// The second challenge in the image's tree: its catalog entry, its journey and its practice
	// edition (rendered with the public practice key, as `make edition-practice` would).
	qs := []catalog.Question{{ID: "q1", Format: answerformat.Name, Attempts: 1}}
	img := editiontest.ChallengesRel + "/" + ccB
	tr.Put(img+"/falco-rule.yaml", ccRule(o.noShares))
	tr.Put(img+"/journey.yaml", ccJourney)
	pSpecText, pTmpl := ccSpec("p", "c.txt"), ccTemplate("v=", "p")
	pSpec, err := edition.ParseSpec([]byte(pSpecText))
	if err != nil {
		t.Fatalf("ParseSpec (practice of %s): %v", ccB, err)
	}
	pr, err := edition.RenderPractice(ccB, pSpec, qs, []edition.BundleFile{{Name: "c.txt", Data: []byte(pTmpl)}})
	if err != nil {
		t.Fatalf("RenderPractice (%s): %v", ccB, err)
	}
	pf, err := edition.PracticeOutput(pr)
	if err != nil {
		t.Fatalf("PracticeOutput (%s): %v", ccB, err)
	}
	ed := img + "/" + edition.EditionDirName
	tr.Put(ed+"/"+edition.SpecFileName, pSpecText)
	tr.Put(ed+"/"+edition.TemplateDirName+"/c.txt", pTmpl)
	pd := ed + "/" + edition.PracticeDirName
	tr.Put(pd+"/"+edition.PracticeAnswersFileName, string(pf.Answers))
	tr.Put(pd+"/"+edition.PracticeDigestsFileName, string(pf.Digests))
	for _, file := range pf.Evidence {
		tr.Put(pd+"/"+edition.PracticeEvidenceDirName+"/"+file.Name, string(file.Data))
	}
	tr.PutScenario(editiontest.ScenarioID, editiontest.Evade, editiontest.CID, ccB)

	// The event edition of the second challenge.
	bSpecText, bTmpl := ccSpec("r", ccPeers), ccTemplate("line of the peer list", "r")+o.bExtra
	tr.Put(editiontest.EditionRootRel+"/"+ccB+"/"+edition.SpecFileName, bSpecText)
	tr.Put(editiontest.EditionRootRel+"/"+ccB+"/"+edition.TemplateDirName+"/"+ccPeers, bTmpl)
	tr.Put(editiontest.EditionRootRel+"/"+ccB+"/"+edition.TemplateDirName+"/"+ccShared, ccSharedText)

	// The render of both, with the test key.
	key, err := edition.NewMasterKey(editiontest.KeyBytes())
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	f.key = key
	p := tr.Paths()
	scored, err := catalog.LoadScored(p.Challenges, p.Scenario, p.Flags)
	if err != nil {
		t.Fatalf("catalog.LoadScored: %v", err)
	}
	scope := edition.ScopeOf(scored.Catalog)
	var rows []edition.AnswerRow
	for _, c := range []struct {
		cid, spec string
		files     []edition.BundleFile
	}{
		{editiontest.CID, f.spec, []edition.BundleFile{{Name: editiontest.TemplateName, Data: []byte(f.tmpl)}, {Name: ccShared, Data: []byte(ccSharedText)}}},
		{ccB, bSpecText, []edition.BundleFile{{Name: ccPeers, Data: []byte(bTmpl)}, {Name: ccShared, Data: []byte(ccSharedText)}}},
	} {
		spec, err := edition.ParseSpec([]byte(c.spec))
		if err != nil {
			t.Fatalf("ParseSpec (%s): %v", c.cid, err)
		}
		r, err := edition.Render(edition.RenderInput{
			CID:       c.cid,
			Questions: scope[c.cid],
			Spec:      spec,
			Template:  c.files,
			Key:       key,
			Seats:     f.seats,
			Previous:  edition.NoPreviousSeats(),
		})
		if err != nil {
			t.Fatalf("Render (%s): %v", c.cid, err)
		}
		for _, b := range r.Bundles {
			for _, file := range b.Files {
				tr.PlaceBundleFile(b.Seat, b.CID, file.Name, file.Data)
			}
		}
		rows = append(rows, r.Rows...)
	}
	var table, record bytes.Buffer
	if err := edition.WriteAnswers(&table, runA, rows); err != nil {
		t.Fatalf("WriteAnswers: %v", err)
	}
	f.scope = scored.Order
	if err := edition.WriteRenderRecord(&record, runA, key, f.scope); err != nil {
		t.Fatalf("WriteRenderRecord: %v", err)
	}
	tr.PlaceAnswers(table.String(), record.String())
	for _, row := range rows {
		f.values = append(f.values, row.Value)
		f.byCell[row.Seat+"/"+row.CID+"/"+row.QID] = row.Value
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

// (1) The event of two challenges that every rule accepts.
func TestCheckEvent_TwoInvestigateChallengesAreAccepted(t *testing.T) {
	f := newCrossCevFix(t, ccOpts{})
	ev, _, err := f.check()
	if err != nil || ev == nil {
		t.Fatalf("the event of two investigate challenges is refused: %v", err)
	}
	if ev.Challenges() != 2 {
		t.Errorf("%d challenges were checked, want 2", ev.Challenges())
	}
}

// (2) to (5): one change each, refused by its rule through CheckEvent.
func TestCheckEvent_CrossChallengeRulesAreWired(t *testing.T) {
	cases := []struct {
		name  string
		rule  string
		opts  ccOpts
		after func(f *ccFix)
	}{
		{"a literal time in 02-demo's template that 01-demo's does not have", edition.RuleCrossTimeline, ccOpts{bExtra: "checked at 2001-01-01T02:00:00Z\n"}, nil},
		{"the shares declaration of 02-demo removed", edition.RuleCrossShare, ccOpts{noShares: true}, nil},
		{"a per-seat answer of 01-demo in 02-demo's bundle of the same seat", edition.RuleCrossAnswer, ccOpts{}, func(f *ccFix) {
			v := f.byCell["seat-a/"+editiontest.CID+"/q1"]
			if v == "" {
				f.t.Fatal("no answer of 01-demo q1 for seat-a")
			}
			rel := editiontest.EvidenceRel + "/seat-a/" + ccB + "/" + ccPeers
			f.put(rel, f.read(rel)+"remark "+v+"\n")
		}},
		{"a literal time in 01-demo's answer window", edition.RuleCrossWindow, ccOpts{aExtra: "audit 2001-01-01T00:30:00Z\n"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCrossCevFix(t, c.opts)
			if c.after != nil {
				c.after(f)
			}
			err, _ := f.refused(c.name)
			if got := cevRuleSet(err); !slices.Contains(got, c.rule) {
				t.Errorf("rules %v, want %s among them: %v", got, c.rule, err)
			}
		})
	}
}
