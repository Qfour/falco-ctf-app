package edition_test

// ADR-0056 D12 and amendment 9, D19 A4d-2 (V11's mechanism, V67): the practice edition of a
// challenge is a golden. render(edition.yaml, template, the key `practice`, the seat *) is
// compared, byte for byte, with the practice/ the challenge commits:
//
//	challenges/<cid>/edition/{edition.yaml, template/<file>, practice/{answers.tsv, digests.tsv, evidence/<file>}}
//
// Two checks use it:
//
//   - the FIXTURE, internal/edition/testdata/render-golden/: a small challenge with an
//     edition of placeholders, there to run the mechanism before any real challenge has an
//     edition (TestGolden_FixtureMatchesItsPracticeDir);
//   - the REAL tree, challenges/: every investigate challenge that has an edition/ is
//     compared (TestGolden_EveryEditionOfTheImageMatchesItsPracticeDir). ADR-0056 A7 put the
//     first one there (50-nimbus-desk-triage), and the test requires at least one since.
//
// The expected files of the fixture are HMAC outputs, which nobody writes by hand: they are
// written by a test, once, and committed. The update is
//
//	FALCO_EDITION_GOLDEN_UPDATE=1 go test ./internal/edition -run TestGolden_WriteTheFixture -count=1
//
// (in the test image, with the repository's files where the test reads them) and writes
// internal/edition/testdata/render-golden/01-demo/edition/practice/. Until it has run,
// TestGolden_FixtureMatchesItsPracticeDir fails and says so: it is never skipped.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

// The names of the layout are the package's (practicelayout.go: the one definition), not a
// copy of them: goldenEditionDir and goldenPracticeDir are its names, and the rest of the
// layout is used by name below.
const (
	goldenUpdateEnv   = "FALCO_EDITION_GOLDEN_UPDATE"
	goldenFixtureDir  = "testdata/render-golden"
	goldenRealDir     = "../../challenges"
	goldenEditionDir  = edition.EditionDirName
	goldenPracticeDir = edition.PracticeDirName
)

// goldenInputs are edition/edition.yaml (parsed) and the files of edition/template/ of the
// challenge ch of the tree at treeDir.
func goldenInputs(t *testing.T, treeDir string, ch catalog.Challenge) (*edition.Spec, []edition.BundleFile) {
	t.Helper()
	ed := filepath.Join(treeDir, ch.Dir(), goldenEditionDir)
	raw, err := os.ReadFile(filepath.Join(ed, edition.SpecFileName))
	if err != nil {
		t.Fatalf("%s: %v", ch.ID, err)
	}
	spec, err := edition.ParseSpec(raw)
	if err != nil {
		t.Fatalf("%s: edition.yaml: %v", ch.ID, err)
	}
	entries, err := os.ReadDir(filepath.Join(ed, edition.TemplateDirName))
	if err != nil {
		t.Fatalf("%s: %s/: %v", ch.ID, edition.TemplateDirName, err)
	}
	var files []edition.BundleFile
	for _, e := range entries {
		if !e.Type().IsRegular() {
			t.Fatalf("%s: %s/%s is not a regular file (the template is flat)", ch.ID, edition.TemplateDirName, e.Name())
		}
		data, err := os.ReadFile(filepath.Join(ed, edition.TemplateDirName, e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", ch.ID, err)
		}
		files = append(files, edition.BundleFile{Name: e.Name(), Data: data})
	}
	return spec, files
}

// goldenRendered is the practice render of the challenge ch.
func goldenRendered(t *testing.T, treeDir string, ch catalog.Challenge) *edition.Rendered {
	t.Helper()
	spec, files := goldenInputs(t, treeDir, ch)
	r, err := edition.RenderPractice(ch.ID, spec, ch.Investigate.Questions, files)
	if err != nil {
		t.Fatalf("%s: RenderPractice: %v", ch.ID, err)
	}
	return r
}

// goldenRender is the files of practice/ that the renderer gives for the challenge ch.
func goldenRender(t *testing.T, treeDir string, ch catalog.Challenge) *edition.PracticeFiles {
	t.Helper()
	pf, err := edition.PracticeOutput(goldenRendered(t, treeDir, ch))
	if err != nil {
		t.Fatalf("%s: PracticeOutput: %v", ch.ID, err)
	}
	return pf
}

// goldenOnDisk is the practice/ that the challenge at editionDir commits.
func goldenOnDisk(editionDir string) (*edition.PracticeFiles, error) {
	pdir := filepath.Join(editionDir, goldenPracticeDir)
	answers, err := os.ReadFile(filepath.Join(pdir, edition.PracticeAnswersFileName))
	if err != nil {
		return nil, err
	}
	digests, err := os.ReadFile(filepath.Join(pdir, edition.PracticeDigestsFileName))
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(pdir, edition.PracticeEvidenceDirName))
	if err != nil {
		return nil, err
	}
	pf := &edition.PracticeFiles{Answers: answers, Digests: digests}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("%s/%s is not a regular file", edition.PracticeEvidenceDirName, e.Name())
		}
		data, err := os.ReadFile(filepath.Join(pdir, edition.PracticeEvidenceDirName, e.Name()))
		if err != nil {
			return nil, err
		}
		pf.Evidence = append(pf.Evidence, edition.BundleFile{Name: e.Name(), Data: data})
	}
	return pf, nil
}

// goldenDiff is how got differs from want: the files that differ, are missing or are extra.
// It names files and never prints a byte (V67: one hand-edited file is red).
func goldenDiff(want, got *edition.PracticeFiles) []string {
	var out []string
	if !bytes.Equal(want.Answers, got.Answers) {
		out = append(out, edition.PracticeAnswersFileName+" differs")
	}
	if !bytes.Equal(want.Digests, got.Digests) {
		out = append(out, edition.PracticeDigestsFileName+" differs")
	}
	index := func(files []edition.BundleFile) map[string][]byte {
		m := make(map[string][]byte, len(files))
		for _, f := range files {
			m[f.Name] = f.Data
		}
		return m
	}
	w, g := index(want.Evidence), index(got.Evidence)
	for name, data := range w {
		switch gd, ok := g[name]; {
		case !ok:
			out = append(out, edition.PracticeEvidenceDirName+"/"+name+" is missing")
		case !bytes.Equal(data, gd):
			out = append(out, edition.PracticeEvidenceDirName+"/"+name+" differs")
		}
	}
	for name := range g {
		if _, ok := w[name]; !ok {
			out = append(out, edition.PracticeEvidenceDirName+"/"+name+" is not rendered")
		}
	}
	slices.Sort(out)
	return out
}

func goldenFixture(t *testing.T) catalog.Challenge {
	t.Helper()
	cat, err := catalog.Load(goldenFixtureDir)
	if err != nil {
		t.Fatalf("catalog.Load(%s): %v", goldenFixtureDir, err)
	}
	ch, ok := cat[demoCID]
	if !ok || ch.Type != catalog.TypeInvestigate || ch.Investigate == nil {
		t.Fatalf("the fixture challenge %s is not an investigate challenge of %s", demoCID, goldenFixtureDir)
	}
	return ch
}

// V11 / V67 on the fixture: what is committed is what the renderer gives.
func TestGolden_FixtureMatchesItsPracticeDir(t *testing.T) {
	if os.Getenv(goldenUpdateEnv) == "1" {
		t.Skip("the update is running (TestGolden_WriteTheFixture)")
	}
	ch := goldenFixture(t)
	want := goldenRender(t, goldenFixtureDir, ch)
	got, err := goldenOnDisk(filepath.Join(goldenFixtureDir, ch.Dir(), goldenEditionDir))
	if err != nil {
		t.Fatalf("the committed practice/ of the fixture cannot be read (%v). It is made once by the update of render_golden_test.go: %s=1 go test ./internal/edition -run TestGolden_WriteTheFixture -count=1 (the CoS runs it)", err, goldenUpdateEnv)
	}
	if d := goldenDiff(want, got); len(d) != 0 {
		t.Errorf("the committed practice/ is not what the renderer gives: %v (rerun the update if the change is meant)", d)
	}
}

// The fixture's practice/ is also what the scoreboard's practice mode accepts: Load reads it
// (Parse, then Check with the event mode off, every question answered), and the Judge made
// of it says correct to each answer the renderer wrote, for any seat.
func TestGolden_FixtureIsAPracticeEditionTheScoreboardLoads(t *testing.T) {
	if os.Getenv(goldenUpdateEnv) == "1" {
		t.Skip("the update is running (TestGolden_WriteTheFixture)")
	}
	cat, err := catalog.Load(goldenFixtureDir)
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	j, runID, err := edition.Load(scoredOf(t, cat, goldenFixtureDir), "", false)
	if err != nil || j == nil || runID != edition.PracticeRunID {
		t.Fatalf("Load = %v, %q, %v; want a judge and the practice run id (is practice/ committed? see the header)", j, runID, err)
	}
	ch := goldenFixture(t)
	rows := goldenRendered(t, goldenFixtureDir, ch).Rows
	// The fixture's questions are q1 .. q5, and every one has a row (the fixed one too).
	if len(rows) != len(ch.Investigate.Questions) {
		t.Fatalf("%d rows for %d questions", len(rows), len(ch.Investigate.Questions))
	}
	for _, row := range rows {
		if ok, known := j.Match("seat-x", ch.ID, row.QID, row.Value); !ok || !known {
			t.Errorf("question %s: Match = %v, %v; want the rendered answer to be correct", row.QID, ok, known)
		}
		if ok, _ := j.Match("seat-x", ch.ID, row.QID, row.Value+"x"); ok {
			t.Errorf("question %s: another value was correct", row.QID)
		}
	}
}

// V67: a comparison that cannot tell a hand-edited file is no golden. Each change to a copy
// of the rendered files, in turn, is seen; the copy itself is not.
func TestGolden_DiffSeesAHandEditedCopy(t *testing.T) {
	ch := goldenFixture(t)
	want := goldenRender(t, goldenFixtureDir, ch)
	if len(want.Evidence) < 2 {
		t.Fatalf("the fixture renders %d evidence files, want at least 2", len(want.Evidence))
	}
	clone := func() *edition.PracticeFiles {
		c := &edition.PracticeFiles{Answers: slices.Clone(want.Answers), Digests: slices.Clone(want.Digests)}
		for _, f := range want.Evidence {
			c.Evidence = append(c.Evidence, edition.BundleFile{Name: f.Name, Data: slices.Clone(f.Data)})
		}
		return c
	}
	if d := goldenDiff(want, clone()); len(d) != 0 {
		t.Fatalf("an identical copy differs: %v", d)
	}
	flip := func(b []byte) { b[len(b)/2] ^= 1 }
	cases := []struct {
		name   string
		change func(c *edition.PracticeFiles)
		want   string
	}{
		{"a byte of answers.tsv", func(c *edition.PracticeFiles) { flip(c.Answers) }, edition.PracticeAnswersFileName + " differs"},
		{"a byte of digests.tsv", func(c *edition.PracticeFiles) { flip(c.Digests) }, edition.PracticeDigestsFileName + " differs"},
		{"a byte of an evidence file", func(c *edition.PracticeFiles) { flip(c.Evidence[0].Data) }, edition.PracticeEvidenceDirName + "/" + want.Evidence[0].Name + " differs"},
		{"an evidence file removed", func(c *edition.PracticeFiles) { c.Evidence = c.Evidence[1:] }, edition.PracticeEvidenceDirName + "/" + want.Evidence[0].Name + " is missing"},
		{"an evidence file added", func(c *edition.PracticeFiles) {
			c.Evidence = append(c.Evidence, edition.BundleFile{Name: "extra.txt", Data: []byte("x")})
		}, edition.PracticeEvidenceDirName + "/extra.txt is not rendered"},
		{"an evidence file renamed", func(c *edition.PracticeFiles) { c.Evidence[0].Name = "renamed.txt" }, edition.PracticeEvidenceDirName + "/renamed.txt is not rendered"},
	}
	for _, c := range cases {
		got := clone()
		c.change(got)
		d := goldenDiff(want, got)
		if !slices.Contains(d, c.want) {
			t.Errorf("%s: the diff is %v, want it to hold %q", c.name, d, c.want)
		}
	}
	// The diff names files only.
	got := clone()
	flip(got.Evidence[0].Data)
	for _, line := range goldenDiff(want, got) {
		if strings.Contains(line, string(want.Evidence[0].Data[:8])) {
			t.Errorf("the diff holds a byte of a file: %q", line)
		}
	}
}

// The update: writes practice/ of the fixture. It is skipped unless FALCO_EDITION_GOLDEN_UPDATE
// is 1, and writes nowhere but under testdata/render-golden/.
func TestGolden_WriteTheFixture(t *testing.T) {
	if os.Getenv(goldenUpdateEnv) != "1" {
		t.Skipf("set %s=1 to write the practice/ of the fixture (see the header of this file)", goldenUpdateEnv)
	}
	ch := goldenFixture(t)
	pf := goldenRender(t, goldenFixtureDir, ch)
	pdir := filepath.Join(goldenFixtureDir, ch.Dir(), goldenEditionDir, goldenPracticeDir)
	if !strings.HasPrefix(filepath.ToSlash(pdir), "testdata/render-golden/") {
		t.Fatalf("refusing to write %s: it is not under testdata/render-golden/", pdir)
	}
	if err := os.RemoveAll(pdir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pdir, edition.PracticeEvidenceDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path string, data []byte) {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(pdir, edition.PracticeAnswersFileName), pf.Answers)
	write(filepath.Join(pdir, edition.PracticeDigestsFileName), pf.Digests)
	for _, f := range pf.Evidence {
		write(filepath.Join(pdir, edition.PracticeEvidenceDirName, f.Name), f.Data)
	}
	t.Logf("wrote %s: answers.tsv, digests.tsv and %d evidence files", pdir, len(pf.Evidence))
}

// practiceRendered is the files of practice/ that edition.yaml and template/ of the challenge
// ch of the tree at treeDir render (ParseSpec, RenderPractice, PracticeOutput), as an error and
// not a test failure, so that practiceStale can report every challenge.
func practiceRendered(treeDir string, ch catalog.Challenge) (*edition.PracticeFiles, error) {
	ed := filepath.Join(treeDir, ch.Dir(), goldenEditionDir)
	raw, err := os.ReadFile(filepath.Join(ed, edition.SpecFileName))
	if err != nil {
		return nil, err
	}
	spec, err := edition.ParseSpec(raw)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(ed, edition.TemplateDirName))
	if err != nil {
		return nil, err
	}
	var files []edition.BundleFile
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("%s/%s is not a regular file (the template is flat)", edition.TemplateDirName, e.Name())
		}
		data, err := os.ReadFile(filepath.Join(ed, edition.TemplateDirName, e.Name()))
		if err != nil {
			return nil, err
		}
		files = append(files, edition.BundleFile{Name: e.Name(), Data: data})
	}
	r, err := edition.RenderPractice(ch.ID, spec, ch.Investigate.Questions, files)
	if err != nil {
		return nil, err
	}
	return edition.PracticeOutput(r)
}

// practiceStale compares, for every challenge of the tree at treeDir that has an edition/, the
// committed practice/ with what its edition.yaml and template/ render, byte for byte (the set of
// the files and their content: goldenDiff). compared is how many challenges have an edition/;
// stale has one line per challenge whose practice/ is not the render (or that cannot be
// rendered, or that has an edition/ and is not an investigate challenge), and the line says what
// to run. err is a tree that cannot be read at all.
func practiceStale(treeDir string) (compared int, stale []string, err error) {
	cat, err := catalog.Load(treeDir)
	if err != nil {
		return 0, nil, err
	}
	for _, id := range cat.IDs() {
		ch := cat[id]
		editionDir := filepath.Join(treeDir, ch.Dir(), goldenEditionDir)
		if _, err := os.Lstat(editionDir); err != nil {
			if os.IsNotExist(err) {
				continue // a challenge with no edition: TestPracticeEditions_EveryInvestigateChallengeHasOne's
			}
			return compared, stale, err
		}
		compared++
		run := " (run `make edition-practice CID=" + id + "` and commit its practice/)"
		if ch.Type != catalog.TypeInvestigate || ch.Investigate == nil {
			stale = append(stale, id+": has an edition/ and is not an investigate challenge")
			continue
		}
		want, err := practiceRendered(treeDir, ch)
		if err != nil {
			stale = append(stale, id+": edition.yaml and template/ do not render: "+err.Error())
			continue
		}
		got, err := goldenOnDisk(editionDir)
		if err != nil {
			stale = append(stale, id+": the committed practice/ cannot be read ("+err.Error()+")"+run)
			continue
		}
		if d := goldenDiff(want, got); len(d) != 0 {
			stale = append(stale, id+": the committed practice/ is not what edition.yaml and template/ render: "+strings.Join(d, ", ")+run)
		}
	}
	return compared, stale, nil
}

// V11 / V67 on the real tree, and #658 (R4#2): practice/ is a generated file that is committed,
// so an edition.yaml or a template/ changed without `make edition-practice` is red here (in
// `make test`, the required check). Every challenge under challenges/ that has an edition/ is
// compared. Until ADR-0056 A7 the tree had none and this compared 0 editions; A7 put the first
// challenge in (50-nimbus-desk-triage) and flipped this to "at least one" (V47 does the same for
// the practice answers).
func TestGolden_EveryEditionOfTheImageMatchesItsPracticeDir(t *testing.T) {
	cat, err := catalog.Load(goldenRealDir)
	if err != nil {
		t.Fatalf("catalog.Load(%s): %v", goldenRealDir, err)
	}
	if len(cat) == 0 {
		t.Fatalf("catalog.Load(%s) found no challenge: the path is wrong", goldenRealDir)
	}
	compared, stale, err := practiceStale(goldenRealDir)
	if err != nil {
		t.Fatalf("the tree %s cannot be read: %v", goldenRealDir, err)
	}
	for _, s := range stale {
		t.Error(s)
	}
	if compared < 1 {
		t.Errorf("no practice edition of the real tree was compared: ADR-0056 A7 put the first investigate challenge with an edition/ in %s", goldenRealDir)
	}
	t.Logf("%d practice editions of the real tree were compared", compared)
}

// The comparison of the real tree can fail: on a copy of the golden fixture's challenge, the
// committed practice/ is accepted as it is, and a template with one more line, or a practice/
// that is gone, is reported with what to run.
func TestGolden_TheStalenessCheckSeesAStalePracticeDir(t *testing.T) {
	ch := goldenFixture(t)
	tplRel := "challenges/" + ch.Dir() + "/" + goldenEditionDir + "/" + edition.TemplateDirName
	fresh := func() *editiontest.Tree {
		tree := editiontest.NewTree(t)
		tree.CopyTree(goldenFixtureDir, "challenges")
		return tree
	}

	tree := fresh()
	compared, stale, err := practiceStale(tree.Path("challenges"))
	if err != nil || compared != 1 || len(stale) != 0 {
		t.Fatalf("a copy of the fixture: compared %d, stale %v, err %v; want 1, none, nil", compared, stale, err)
	}

	tree = fresh()
	entries, err := os.ReadDir(tree.Path(tplRel))
	if err != nil || len(entries) == 0 {
		t.Fatalf("the template of the copy: %v, %v", entries, err)
	}
	name := tplRel + "/" + entries[0].Name()
	tree.Put(name, tree.Read(name)+"x\n")
	compared, stale, err = practiceStale(tree.Path("challenges"))
	if err != nil || compared != 1 || len(stale) != 1 || !strings.Contains(stale[0], "make edition-practice CID="+ch.ID) {
		t.Errorf("a template with one more line: compared %d, stale %v, err %v; want one line that says to run make edition-practice", compared, stale, err)
	}

	tree = fresh()
	if err := os.RemoveAll(tree.Path("challenges/" + ch.Dir() + "/" + goldenEditionDir + "/" + goldenPracticeDir)); err != nil {
		t.Fatal(err)
	}
	if _, stale, err = practiceStale(tree.Path("challenges")); err != nil || len(stale) != 1 || !strings.Contains(stale[0], "make edition-practice CID="+ch.ID) {
		t.Errorf("no practice/: stale %v, err %v; want one line that says to run make edition-practice", stale, err)
	}
}
