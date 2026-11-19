package edition_test

// ADR-0056 D20 `edition render` (the event's), D19 A4e-3a: RenderEvent. V80 (the output is what
// `edition check` accepts, the modes of the tree, the run id, the render record, the refusals
// that write nothing, the guard of --out, the key file), V92 (the output that cannot be put in
// place: exit 3 and its names) and the second render with more seats (U2). The fixture is
// internal/edition/editiontest's (the image's tree, the event edition, the seats, the key): the
// render is RenderEvent's own, and nothing here calls the renderer. Every value is a
// placeholder with no meaning.

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/edition/editiontest"
)

// rfFix is one event laid out for a render: the tree and the input of a good render.
type rfFix struct {
	t    *testing.T
	tree *editiontest.Tree
	in   edition.RenderEventInput
}

func newRfFix(t *testing.T) *rfFix {
	t.Helper()
	tree := editiontest.NewTree(t)
	tree.PlaceInputs(editiontest.Inputs{Golden: cevGold, Spec: editiontest.GoodSpec(), Template: editiontest.GoodTemplate(), Seats: editiontest.Seats()})
	tree.PlaceKey(editiontest.KeyRel, editiontest.KeyText(), 0o600)
	p := tree.RenderPaths()
	return &rfFix{t: t, tree: tree, in: edition.RenderEventInput{
		Challenges:   p.Challenges,
		ScenarioFile: p.Scenario,
		FlagsFile:    p.Flags,
		EditionRoot:  p.EditionRoot,
		SeatsFile:    p.Seats,
		NoPrevious:   true,
		KeyFile:      p.Key,
		Out:          p.Out,
	}}
}

// outFile is the path of a file of the render's output.
func (f *rfFix) outFile(rel string) string { return filepath.Join(f.in.Out, filepath.FromSlash(rel)) }

// nothingWritten fails unless --out does not exist, the fixture's output directory holds
// nothing, and the directory of --out (when there is one) holds no temporary tree of it.
func (f *rfFix) nothingWritten(what string) {
	f.t.Helper()
	if _, err := os.Lstat(f.in.Out); !errors.Is(err, fs.ErrNotExist) {
		f.t.Errorf("%s: --out is there (%v), want nothing", what, err)
	}
	if names := listNames(f.t, f.tree.Path(editiontest.OutRel)); len(names) != 0 {
		f.t.Errorf("%s: the output directory holds %v, want nothing", what, names)
	}
	if list, err := os.ReadDir(filepath.Dir(f.in.Out)); err == nil {
		for _, e := range list {
			if strings.HasPrefix(e.Name(), "."+filepath.Base(f.in.Out)+".tmp-") {
				f.t.Errorf("%s: a temporary tree %s is left beside --out", what, e.Name())
			}
		}
	}
}

// checkInput is the input of `edition check` of the render's output, the first check.
func (f *rfFix) checkInput() edition.CheckInput {
	p := f.tree.Paths()
	return edition.CheckInput{
		Challenges:       p.Challenges,
		ScenarioFile:     p.Scenario,
		FlagsFile:        p.Flags,
		AnswersFile:      f.outFile(edition.EventAnswersFileName),
		RenderRecordFile: f.outFile(edition.EventRenderRecordFileName),
		EvidenceRoot:     f.outFile(edition.EventEvidenceDirName),
		SeatsFile:        p.Seats,
		EditionRoot:      p.EditionRoot,
		NoPrevious:       true,
		CorpusDirs:       []string{p.Corpus},
		DigestsOut:       p.DigestsOut,
	}
}

// answerValues is the values of the answers table of the output (the 4th column).
func (f *rfFix) answerValues() []string {
	f.t.Helper()
	data, err := os.ReadFile(f.outFile(edition.EventAnswersFileName))
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, ln := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")[1:] {
		cols := strings.Split(ln, "\t")
		if len(cols) != 4 {
			f.t.Fatalf("a row of the answers table has %d columns", len(cols))
		}
		out = append(out, cols[3])
	}
	if len(out) == 0 {
		f.t.Fatal("the answers table has no row")
	}
	return out
}

// treeOf is every file under root (slash-relative) with its bytes.
func treeOf(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// V80: the output of a render is what `edition check` accepts (the first check), it has the
// three parts of D20 and no digests file, the render record is D20's four lines (v2) with the run
// id and the scope digest, and nothing in the error-free path names a value.
func TestRenderEvent_TheOutputIsWhatEditionCheckAccepts(t *testing.T) {
	f := newRfFix(t)
	ev, err := edition.RenderEvent(f.in)
	if err != nil || ev == nil {
		t.Fatalf("RenderEvent = (%v, %v); want the event", ev, err)
	}
	if len(ev.RunID()) != 32 || ev.RunID() == edition.PracticeRunID || ev.Seats() != 3 || ev.Challenges() != 1 || !edition.ValidDigest(ev.KeyFingerprint()) {
		t.Errorf("event = run %q, %d seats, %d challenges, fingerprint %q", ev.RunID(), ev.Seats(), ev.Challenges(), ev.KeyFingerprint())
	}
	if names := listNames(t, f.in.Out); !slices.Equal(names, []string{edition.EventAnswersFileName, edition.EventEvidenceDirName, edition.EventRenderRecordFileName}) {
		t.Errorf("--out holds %v; want the answers table, the evidence and the render record, and no digests file", names)
	}
	if names := listNames(t, filepath.Dir(f.in.Out)); !slices.Equal(names, []string{filepath.Base(f.in.Out)}) {
		t.Errorf("the directory of --out holds %v; want --out only (no temporary left)", names)
	}
	record, err := os.ReadFile(f.outFile(edition.EventRenderRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	scope := edition.ScopeDigest([]string{editiontest.Evade, editiontest.CID}) // the fixture's scenario, in its order
	if want := "# falco-ctf render-record v2\nrun-id\t" + ev.RunID() + "\nkey-fingerprint\t" + ev.KeyFingerprint() + "\nscope\t" + scope + "\n"; string(record) != want {
		t.Errorf("the render record is %q, want %q", record, want)
	}
	values := f.answerValues()
	for _, v := range values {
		if strings.Contains(string(record), v) {
			t.Errorf("the render record holds a value of the render (%q)", v)
		}
	}
	if strings.Contains(string(record), strings.TrimSuffix(editiontest.KeyText(), "\n")) {
		t.Error("the render record holds the key")
	}

	checked, _, err := edition.CheckEvent(f.checkInput())
	if err != nil || checked == nil {
		t.Fatalf("CheckEvent of the render's output = (%v, %v); want it accepted", checked, err)
	}
	if checked.RunID() != ev.RunID() || checked.Seats() != 3 || checked.Challenges() != 1 {
		t.Errorf("the checked event is run %q, %d seats, %d challenges; want the render's", checked.RunID(), checked.Seats(), checked.Challenges())
	}
}

// V80: the run id is not all zeros, and two renders of the same input have two run ids (and the
// same bundles: the values do not depend on the run id).
func TestRenderEvent_TheRunIDIsNewEachTime(t *testing.T) {
	f := newRfFix(t)
	first, err := edition.RenderEvent(f.in)
	if err != nil {
		t.Fatal(err)
	}
	firstTree := treeOf(t, f.outFile(edition.EventEvidenceDirName))
	second := f.in
	second.Out = f.tree.Path(editiontest.OutRel + "/again")
	again, err := edition.RenderEvent(second)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID() == again.RunID() || first.RunID() == edition.PracticeRunID || again.RunID() == edition.PracticeRunID {
		t.Errorf("run ids %q and %q; want two different ones, neither all zeros", first.RunID(), again.RunID())
	}
	if againTree := treeOf(t, filepath.Join(second.Out, edition.EventEvidenceDirName)); !maps.Equal(firstTree, againTree) {
		t.Error("two renders of the same input have different bundles")
	}
}

// V80: the modes of the output are 0700 for every directory and 0600 for every file, under the
// umask 022 and the umask 077.
func TestRenderEvent_TheModesOfTheOutput(t *testing.T) {
	for _, mask := range []int{0o022, 0o077} {
		f := newRfFix(t)
		old := syscall.Umask(mask)
		_, err := edition.RenderEvent(f.in)
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("umask %#o: %v", mask, err)
		}
		n := 0
		err = filepath.WalkDir(f.in.Out, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := os.Lstat(p)
			if err != nil {
				return err
			}
			want := fs.FileMode(0o600)
			if info.IsDir() {
				want = 0o700
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				t.Errorf("umask %#o: %s is neither a directory nor a regular file", mask, p)
			}
			if info.Mode().Perm() != want {
				t.Errorf("umask %#o: %s has mode %#o, want %#o", mask, p, info.Mode().Perm(), want)
			}
			n++
			return nil
		})
		if err != nil || n < 8 {
			t.Errorf("umask %#o: walked %d entries (%v), want the whole tree", mask, n, err)
		}
	}
}

// U2 and V80: a second render with a seat added at the end, given the first seat list as the
// previous one, keeps the bundle of every earlier seat byte for byte.
func TestRenderEvent_ASecondRenderWithASeatMoreKeepsTheEarlierBundles(t *testing.T) {
	f := newRfFix(t)
	if _, err := edition.RenderEvent(f.in); err != nil {
		t.Fatal(err)
	}
	first := treeOf(t, f.outFile(edition.EventEvidenceDirName))
	f.tree.Put(editiontest.PreviousSeatsRel, f.tree.Read(editiontest.SeatsRel))
	f.tree.Put("seats-more.txt", editiontest.SeatsText(append(editiontest.Seats(), "seat-d")))
	second := f.in
	second.SeatsFile = f.tree.Path("seats-more.txt")
	second.NoPrevious = false
	second.PreviousSeatsFile = f.tree.Path(editiontest.PreviousSeatsRel)
	second.Out = f.tree.Path(editiontest.OutRel + "/second")
	ev, err := edition.RenderEvent(second)
	if err != nil || ev.Seats() != 4 {
		t.Fatalf("the second render = (%v, %v); want 4 seats", ev, err)
	}
	now := treeOf(t, filepath.Join(second.Out, edition.EventEvidenceDirName))
	for rel, data := range first {
		if now[rel] != data {
			t.Errorf("the bundle file %s of an earlier seat changed", rel)
		}
	}
	if len(now) <= len(first) {
		t.Errorf("the second render has %d files, want more than the first's %d (the new seat's)", len(now), len(first))
	}
}

// renderRefusal is one way to break the input of a good render.
type renderRefusal struct {
	name  string
	brk   func(f *rfFix)
	input bool   // an *InputError (exit 2); otherwise a rule's refusal (exit 1)
	rule  string // the rule a refusal names ("" for an *InputError)
}

// V80: every refusal writes nothing at --out and leaves nothing beside it, names no value and
// is of its kind: an *InputError for an input that is missing, unreadable or not in its form
// (the key's form and mode included) and for the guard of --out, a rule's *Violation otherwise.
func TestRenderEvent_EveryRefusalWritesNothing(t *testing.T) {
	keyRel := editiontest.KeyRel
	hexKey := strings.TrimSuffix(editiontest.KeyText(), "\n")
	cases := []renderRefusal{
		// the key file
		{"no key file", func(f *rfFix) { f.in.KeyFile = f.tree.Path("no-such-key") }, true, ""},
		{"a key of 63 hex digits", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey[:63]+"\n", 0o600) }, true, ""},
		{"a key of 62 hex digits (31 bytes)", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey[:62]+"\n", 0o600) }, true, ""},
		{"a key that is not hex", func(f *rfFix) { f.tree.PlaceKey(keyRel, strings.Repeat("zz", 40)+"\n", 0o600) }, true, ""},
		{"a key in upper-case hex", func(f *rfFix) { f.tree.PlaceKey(keyRel, strings.ToUpper(hexKey)+"\n", 0o600) }, true, ""},
		{"a key of two lines", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey+"\n"+hexKey+"\n", 0o600) }, true, ""},
		{"a key with no final newline", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey, 0o600) }, true, ""},
		// D20 / amendment 14: lower-case hex on one line and one final LF, nothing else.
		{"a key that ends with CRLF", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey+"\r\n", 0o600) }, true, ""},
		{"a key with an empty second line", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey+"\n\n", 0o600) }, true, ""},
		{"a key with a second line of text", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey+"\nsecond line\n", 0o600) }, true, ""},
		{"a key with a space before it", func(f *rfFix) { f.tree.PlaceKey(keyRel, " "+hexKey+"\n", 0o600) }, true, ""},
		{"a key with a space after it", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey+" \n", 0o600) }, true, ""},
		{"a key with a tab after it", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey+"\t\n", 0o600) }, true, ""},
		{"an empty key file", func(f *rfFix) { f.tree.PlaceKey(keyRel, "", 0o600) }, true, ""},
		{"a key of mode 0644", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey+"\n", 0o644) }, true, ""},
		{"a key of mode 0640", func(f *rfFix) { f.tree.PlaceKey(keyRel, hexKey+"\n", 0o640) }, true, ""},
		{"a key that is a link", func(f *rfFix) {
			if err := os.Symlink(f.tree.Path(keyRel), f.tree.Path("key-link")); err != nil {
				f.t.Fatal(err)
			}
			f.in.KeyFile = f.tree.Path("key-link")
		}, true, ""},
		// the previous seats
		{"both a previous seats file and --no-previous", func(f *rfFix) { f.in.PreviousSeatsFile = f.tree.Path(editiontest.SeatsRel) }, true, ""},
		{"neither a previous seats file nor --no-previous", func(f *rfFix) { f.in.NoPrevious = false }, true, ""},
		{"a previous seats file of the header alone", func(f *rfFix) {
			f.tree.Put(editiontest.PreviousSeatsRel, "# falco-ctf seats v1\n")
			f.in.NoPrevious, f.in.PreviousSeatsFile = false, f.tree.Path(editiontest.PreviousSeatsRel)
		}, true, ""},
		{"a seat list that does not extend the previous one", func(f *rfFix) {
			f.tree.Put(editiontest.PreviousSeatsRel, editiontest.SeatsText([]string{"seat-b", "seat-a"}))
			f.in.NoPrevious, f.in.PreviousSeatsFile = false, f.tree.Path(editiontest.PreviousSeatsRel)
		}, false, "E3"},
		// the guard of --out
		{existingOut, func(f *rfFix) {
			if err := os.Mkdir(f.in.Out, 0o700); err != nil {
				f.t.Fatal(err)
			}
		}, true, ""},
		{"an --out whose directory does not exist", func(f *rfFix) { f.in.Out = f.tree.Path(editiontest.OutRel + "/missing/render") }, true, ""},
		{"an --out in a git worktree (a .git directory above it)", func(f *rfFix) {
			if err := os.Mkdir(f.tree.Path(".git"), 0o755); err != nil {
				f.t.Fatal(err)
			}
		}, true, ""},
		{"an --out in a git worktree (a .git file above it, as a linked worktree has)", func(f *rfFix) { f.tree.Put(".git", "gitdir: elsewhere\n") }, true, ""},
		{"an --out whose directory is a link into a git worktree", func(f *rfFix) {
			f.tree.Put("repo/.git", "gitdir: elsewhere\n")
			if err := os.Mkdir(f.tree.Path("repo/sub"), 0o755); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink(f.tree.Path("repo/sub"), f.tree.Path("outside")); err != nil {
				f.t.Fatal(err)
			}
			f.in.Out = f.tree.Path("outside/render")
		}, true, ""},
		{"an --out inside the challenges tree", func(f *rfFix) { f.in.Out = f.tree.Path(editiontest.ChallengesRel + "/render") }, true, ""},
		// the edition root
		{"an extra challenge directory in the edition root", func(f *rfFix) { f.tree.Put(editiontest.EditionRootRel+"/02-other/edition.yaml", "x\n") }, false, "E2"},
		{"no directory for the challenge in the edition root", func(f *rfFix) {
			if err := os.RemoveAll(f.tree.Path(editiontest.EditionRootRel + "/" + editiontest.CID)); err != nil {
				f.t.Fatal(err)
			}
		}, false, "E2"},
		{"a file named like a challenge id in the edition root", func(f *rfFix) { f.tree.Put(editiontest.EditionRootRel+"/02-other", "x\n") }, true, ""},
		{"the challenge's entry of the edition root is a link to its directory", func(f *rfFix) {
			dir := f.tree.Path(editiontest.EditionRootRel + "/" + editiontest.CID)
			if err := os.Rename(dir, f.tree.Path("real-edition")); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink(f.tree.Path("real-edition"), dir); err != nil {
				f.t.Fatal(err)
			}
		}, true, ""},
		// the rules
		{"E2: decoys below K", func(f *rfFix) {
			f.tree.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.SpecFileName, editiontest.SpecText(editiontest.GoodNameWords, 3))
		}, false, "E2"},
		{"B8 (a2): 51 seats for a space of 100 (the renderer's rule, E3)", func(f *rfFix) {
			f.tree.Put(editiontest.SeatsRel, editiontest.SeatsText(seatsList(51)))
		}, false, "E3"},
		{"E3: a mark of a slot that edition.yaml does not declare", func(f *rfFix) {
			f.tree.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.TemplateDirName+"/"+editiontest.TemplateName, editiontest.GoodTemplate()+"extra = {{ctf:undeclared}}\n")
		}, false, "E3"},
		{"the self check, B8 (b): 4 decoys give 5 candidates, D3 (b) needs 10", func(f *rfFix) {
			f.tree.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.SpecFileName, editiontest.SpecText(editiontest.GoodNameWords, 4))
			f.tree.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.TemplateDirName+"/"+editiontest.TemplateName, editiontest.TemplateText(4))
		}, false, "B8"},
		// The self check of the answers table (checkAnswersData: Parse and Check in the event
		// mode, with the practice answers): the fixed answer of q5 is the one the practice edition
		// publishes (render-golden's c1,c3). Only T6 refuses it: nothing before the self check
		// compares an event with the practice edition.
		{"the self check, T6: the fixed answer is the practice edition's", func(f *rfFix) {
			f.tree.Put(editiontest.EditionRootRel+"/"+editiontest.CID+"/"+edition.SpecFileName, strings.Replace(editiontest.GoodSpec(), `q5: "c2,c4"`, `q5: "c1,c3"`, 1))
		}, false, "T6"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRfFix(t)
			c.brk(f)
			ev, err := edition.RenderEvent(f.in)
			if ev != nil || err == nil {
				t.Fatalf("RenderEvent = (%v, %v); want no event and an error", ev, err)
			}
			if got := isInputErr(err); got != c.input {
				t.Errorf("err = %v; an *InputError: %v, want %v", err, got, c.input)
			}
			if c.rule != "" && !slices.Contains(cevRuleSet(err), c.rule) {
				t.Errorf("err = %v; want the rule %s named", err, c.rule)
			}
			if strings.Contains(err.Error(), hexKey[:16]) {
				t.Errorf("the error holds the key: %v", err)
			}
			if c.name == existingOut {
				// the --out that was there is left as it was, and nothing is beside it
				if names := listNames(t, f.in.Out); len(names) != 0 {
					t.Errorf("the existing --out was written into: %v", names)
				}
				if names := listNames(t, f.tree.Path(editiontest.OutRel)); !slices.Equal(names, []string{filepath.Base(f.in.Out)}) {
					t.Errorf("the output directory holds %v, want the existing --out only", names)
				}
				return
			}
			f.nothingWritten(c.name)
		})
	}
}

// existingOut is the name of the case of an --out that is there before the render.
const existingOut = "an --out that exists"

// V80, the edges: a key of exactly 2 x MinMasterKeyBytes hex digits is accepted, and one of
// 2 x MinMasterKeyBytes - 2 is not (the refusal's case above); a key file at the limit of its
// size is read, one byte over it is refused; a .git right in the directory of --out (not only
// above it) is refused.
func TestRenderEvent_TheEdgesOfTheKeyAndOfTheGuard(t *testing.T) {
	hexKey := strings.TrimSuffix(editiontest.KeyText(), "\n")
	if len(hexKey) < 2*edition.MinMasterKeyBytes {
		t.Fatalf("the fixture's key has %d hex digits, fewer than the edge", len(hexKey))
	}
	f := newRfFix(t)
	f.tree.PlaceKey(editiontest.KeyRel, hexKey[:2*edition.MinMasterKeyBytes]+"\n", 0o600)
	if ev, err := edition.RenderEvent(f.in); err != nil || ev == nil {
		t.Errorf("a key of exactly %d hex digits: (%v, %v), want it rendered", 2*edition.MinMasterKeyBytes, ev, err)
	}

	// The limit of the file is 4 KiB. The digits are an even number, so the largest file of a
	// good form under it is 4094 digits and a newline (4095 bytes), and the next one, 4096 digits
	// and a newline (4097 bytes), is over it.
	f = newRfFix(t)
	f.tree.PlaceKey(editiontest.KeyRel, strings.Repeat("ab", 2047)+"\n", 0o600)
	if ev, err := edition.RenderEvent(f.in); err != nil || ev == nil {
		t.Errorf("a key file of 4095 bytes: (%v, %v), want it rendered", ev, err)
	}
	f = newRfFix(t)
	f.tree.PlaceKey(editiontest.KeyRel, strings.Repeat("ab", 2048)+"\n", 0o600)
	if ev, err := edition.RenderEvent(f.in); ev != nil || !isInputErr(err) || !strings.Contains(err.Error(), "larger than its limit") {
		t.Errorf("a key file of 4097 bytes: (%v, %v), want an *InputError of its size", ev, err)
	}
	f.nothingWritten("a key file over its limit")

	f = newRfFix(t)
	f.tree.Put(editiontest.OutRel+"/.git", "gitdir: elsewhere\n")
	if ev, err := edition.RenderEvent(f.in); ev != nil || !isInputErr(err) || !strings.Contains(err.Error(), "git worktree") {
		t.Errorf("a .git in the directory of --out: (%v, %v), want an *InputError of the guard", ev, err)
	}
	if _, err := os.Lstat(f.in.Out); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("--out is there after the refusal: %v", err)
	}
	if names := listNames(t, f.tree.Path(editiontest.OutRel)); !slices.Equal(names, []string{".git"}) {
		t.Errorf("the directory of --out holds %v, want the .git only", names)
	}
}

// V80: an E3 of the SECOND challenge refuses the render as a whole: the output of the first,
// which rendered, is not written either. The image's tree gets a second investigate challenge
// (02-demo: the first's questions, a journey of its own, no practice edition) and the edition
// root an edition of it whose template has a mark that edition.yaml does not declare.
func TestRenderEvent_AnE3OfTheSecondChallengeWritesNothing(t *testing.T) {
	f := newRfFix(t)
	const second = "02-demo"
	rule, err := os.ReadFile(filepath.Join(cevGold, "falco-rule.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	f.tree.Put(editiontest.ChallengesRel+"/"+second+"/falco-rule.yaml", strings.Replace(string(rule), "/opt/ctf/evidence", "/opt/ctf/evidence-two", 1))
	f.tree.Put(editiontest.ChallengesRel+"/"+second+"/journey.yaml", strings.Replace(editiontest.Journey, "challengeId: "+editiontest.CID, "challengeId: "+second, 1))
	f.tree.Put(editiontest.ScenarioRel, "id: fixture\ntitle: Fixture\nchallenges: ["+editiontest.Evade+", "+editiontest.CID+", "+second+"]\n")
	f.tree.Put(editiontest.EditionRootRel+"/"+second+"/"+edition.SpecFileName, editiontest.GoodSpec())
	f.tree.Put(editiontest.EditionRootRel+"/"+second+"/"+edition.TemplateDirName+"/"+editiontest.TemplateName, editiontest.GoodTemplate()+"extra = {{ctf:undeclared}}\n")

	ev, err := edition.RenderEvent(f.in)
	if ev != nil || err == nil || isInputErr(err) {
		t.Fatalf("RenderEvent = (%v, %v); want a rule's refusal", ev, err)
	}
	if !slices.Equal(cevRuleSet(err), []string{"E3"}) || !strings.Contains(err.Error(), "cid="+second) {
		t.Errorf("err = %v; want E3 of %s only", err, second)
	}
	f.nothingWritten("an E3 of the second challenge")

	// The same tree with the second challenge's template fixed renders both (the fixture is a
	// scope the renderer accepts, so the refusal above is the template's).
	f.tree.Put(editiontest.EditionRootRel+"/"+second+"/"+edition.TemplateDirName+"/"+editiontest.TemplateName, editiontest.GoodTemplate())
	if ev, err := edition.RenderEvent(f.in); err != nil || ev.Challenges() != 2 {
		t.Fatalf("the fixed tree: (%v, %v); want both challenges rendered", ev, err)
	}
}

// V92: the output that cannot be put in place after every check passed is an *OutputError
// (exit 3) and --out is not made: a write that fails, and a rename (the commit point) that
// fails; with a RemoveAll that fails too, the temporary tree is listed by its name, and the
// same input given again renders.
func TestRenderEvent_AnOutputThatCannotBePutInPlace(t *testing.T) {
	for _, c := range []struct {
		step string
		err  error
	}{
		{edition.FaultWriteForTest, syscall.ENOSPC},
		{edition.FaultRenameForTest, syscall.EXDEV},
	} {
		f := newRfFix(t)
		edition.SetWriteFaultForTest(t, map[string]error{c.step: c.err})
		ev, err := edition.RenderEvent(f.in)
		var oe *edition.OutputError
		if ev != nil || !errors.As(err, &oe) || isInputErr(err) || !errors.Is(err, c.err) || len(oe.Left) != 0 {
			t.Errorf("%s fails: (%v, %v), want an *OutputError of %v and no name left", c.step, ev, err, c.err)
		}
		f.nothingWritten(c.step + " fails")
	}

	f := newRfFix(t)
	edition.SetWriteFaultForTest(t, map[string]error{edition.FaultWriteForTest: syscall.ENOSPC, edition.FaultRemoveAllForTest: syscall.EIO})
	_, err := edition.RenderEvent(f.in)
	var oe *edition.OutputError
	if !errors.As(err, &oe) || isInputErr(err) || len(oe.Left) != 1 {
		t.Fatalf("the write and the cleanup fail: %v, want an *OutputError with one name left", err)
	}
	if _, err := os.Lstat(f.in.Out); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("--out is there after a failure: %v", err)
	}
	names := listNames(t, filepath.Dir(f.in.Out))
	if len(names) != 1 || !strings.Contains(oe.Left[0], names[0]) {
		t.Errorf("the directory of --out holds %v and the error lists %v; want the one temporary tree", names, oe.Left)
	}
	edition.SetWriteFaultForTest(t, nil)
	if ev, err := edition.RenderEvent(f.in); err != nil || ev == nil {
		t.Fatalf("the same input again: (%v, %v), want it rendered", ev, err)
	}
}
