package edition_test

// ADR-0056 D10 B1, B3, B5, B6, B9 (B2 is bundle_test.go's) and V3: one case, one defect,
// and the rule that must name it. The table is baseRows (helpers_test.go): two seats, one
// investigate challenge, per-seat questions `who` (a name) and `hx` (a hexid), and a
// choice-set `pick` that is the same for every seat. The bundle of each seat holds its two
// per-seat answers; every value is the sentinel or a placeholder of no meaning.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// B3's FlagChallenges: the challenges that carry a flag are the ones with an ExpectedFlag
// (the evade ones), the same set Check's FlagValues come from.
func TestCountFlagChallenges(t *testing.T) {
	cat := catalog.Catalog{
		"01-a": {ID: "01-a", Type: catalog.TypeEvade, ExpectedFlag: "FALCO{dev-x}"},
		"02-b": {ID: "02-b", Type: catalog.TypeTrigger},
		"03-c": {ID: "03-c", Type: catalog.TypeInvestigate},
	}
	if got := edition.CountFlagChallenges(cat); got != 1 {
		t.Errorf("CountFlagChallenges = %d, want 1 (the evade challenge)", got)
	}
	if got := edition.CountFlagChallenges(catalog.Catalog{"02-b": cat["02-b"], "03-c": cat["03-c"]}); got != 0 {
		t.Errorf("CountFlagChallenges without an evade challenge = %d, want 0", got)
	}
}

const (
	notesA   = "seat-a/01-demo/notes.txt"
	notesB   = "seat-b/01-demo/notes.txt"
	hintText = "quartz walnut zebra giraffe lemon"
	eventFlg = "flagvalue-zzz-9"
)

// goodBundleFiles: each seat's bundle holds that seat's answers of `who` and `hx`.
func goodBundleFiles() map[string]string {
	return kv(
		notesA, "user: "+sentinel+"-a\nid: aaaaaaaaaaaa\nline 3\n",
		notesB, "user: "+sentinel+"-b\nid: bbbbbbbbbbbb\nline 3\n",
	)
}

func goodBundleInput(t *testing.T) edition.BundleInput {
	t.Helper()
	return edition.BundleInput{
		Table:      mustParse(t, render(runA, baseRows())),
		Scope:      demoScope,
		Seats:      []string{"seat-a", "seat-b"},
		FlagValues: []string{eventFlg},
		Hints:      []hintleak.Item{{Source: "01-demo hints[0]", Text: hintText}},
		Free:       []hintleak.Item{{Source: "01-demo briefing", Text: "plain words only"}},
		Corpus:     edition.Corpus{[]byte("nothing that is an answer")},
	}
}

func putFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckBundles_AcceptsAndGivesTheDigests(t *testing.T) {
	files := goodBundleFiles()
	in := goodBundleInput(t)
	rows, err := edition.CheckBundles(bundleTree(t, files), in)
	if err != nil {
		t.Fatalf("CheckBundles: %v", err)
	}
	digest := func(rel string) string {
		return edition.BundleDigest([]edition.BundleFile{{Name: "notes.txt", Data: []byte(files[rel])}})
	}
	want := []edition.DigestRow{
		{Seat: "seat-a", CID: demoCID, Digest: digest(notesA)},
		{Seat: "seat-b", CID: demoCID, Digest: digest(notesB)},
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows = %v, want %v", rows, want)
	}
	if err := edition.CheckDigestSet(rows, in.Seats, in.Scope); err != nil {
		t.Errorf("the rows are not the seats x the scope: %v", err)
	}
	var buf bytes.Buffer
	if err := edition.WriteDigests(&buf, runA, rows); err != nil {
		t.Fatal(err)
	}
	if id, got, err := edition.ParseDigests(buf.Bytes()); err != nil || id != runA || !slices.Equal(got, want) {
		t.Errorf("the digests file does not read back: (%q, %v, %v)", id, got, err)
	}
}

// Rules that hold in a case that is NOT a defect (the checks must not refuse more than the ADR).
func TestCheckBundles_AcceptsWhatTheRulesAllow(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		mutate func(in *edition.BundleInput)
	}{
		{"the answers are in two different files of the bundle", plus(goodBundleFiles(), kv(
			notesA, "user: "+sentinel+"-a\n",
			"seat-a/01-demo/ids.txt", "id: aaaaaaaaaaaa\n",
		)), nil},
		// the hint's text in a bundle passes when a text shown without paying carries it too
		{"a hint's text that is shown without paying", plus(goodBundleFiles(), kv(notesA, "user: "+sentinel+"-a\nid: aaaaaaaaaaaa\n"+hintText+"\n")), func(in *edition.BundleInput) {
			in.Free = append(in.Free, hintleak.Item{Source: "01-demo step", Text: hintText})
		}},
		{"no flag values when no challenge has a flag", goodBundleFiles(), func(in *edition.BundleInput) {
			in.FlagValues = nil
			in.FlagChallenges = 0
		}},
		{"a shared answer (choice-set) that is in the corpus", goodBundleFiles(), func(in *edition.BundleInput) {
			in.Corpus = edition.Corpus{[]byte("the shared answer ca,cb is public")}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := goodBundleInput(t)
			if c.mutate != nil {
				c.mutate(&in)
			}
			if _, err := edition.CheckBundles(bundleTree(t, c.files), in); err != nil {
				t.Errorf("a bundle that meets every rule was refused: %v", err)
			}
		})
	}
}

func TestCheckBundles_OneDefectNamesItsRule(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, root string, in *edition.BundleInput)
		want   string // the rule, and only this rule
		msg    string
	}{
		// B1
		{"a seat of the list has no bundle", func(t *testing.T, root string, in *edition.BundleInput) {
			if err := os.RemoveAll(filepath.Join(root, "seat-b")); err != nil {
				t.Fatal(err)
			}
		}, edition.RuleBundleSet, "has no bundle for this challenge"},
		{"a bundle directory with no file", func(t *testing.T, root string, in *edition.BundleInput) {
			if err := os.Remove(filepath.Join(root, filepath.FromSlash(notesB))); err != nil {
				t.Fatal(err)
			}
		}, edition.RuleBundleSet, "has no file"},
		{"a bundle of a seat that is not in the list", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, "seat-c/01-demo/notes.txt", "x")
		}, edition.RuleBundleSet, "a seat that is not in the seat list"},
		{"an empty directory of a seat that is not in the list", func(t *testing.T, root string, in *edition.BundleInput) {
			if err := os.Mkdir(filepath.Join(root, "seat-z"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, edition.RuleBundleSet, "a directory of a seat that is not in the seat list"},
		{"an empty string in the flag values", func(t *testing.T, root string, in *edition.BundleInput) {
			in.FlagValues = append(in.FlagValues, "")
		}, edition.RuleBundleFlag, "an empty string is in FlagValues"},
		{"no flag values although a challenge has a flag", func(t *testing.T, root string, in *edition.BundleInput) {
			in.FlagValues = nil
			in.FlagChallenges = 1
		}, edition.RuleBundleFlag, "flags were not supplied"},
		{"a bundle of a challenge that is not in the scope", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, "seat-a/02-other/notes.txt", "x")
		}, edition.RuleBundleSet, "not an investigate challenge of the scope"},
		{"a seat of the list that the table has not", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, "seat-c/01-demo/notes.txt", "x")
			in.Seats = append(in.Seats, "seat-c")
		}, edition.RuleBundleSet, "has no row in the answers table"},
		{"a seat of the table that the list has not", func(t *testing.T, root string, in *edition.BundleInput) {
			in.Seats = []string{"seat-a"}
		}, edition.RuleBundleSet, "a seat of the answers table is not in the seat list"},
		{"an empty seat list", func(t *testing.T, root string, in *edition.BundleInput) {
			in.Seats = nil
		}, edition.RuleBundleSet, "the seat list is empty"},
		{"a seat listed twice", func(t *testing.T, root string, in *edition.BundleInput) {
			in.Seats = []string{"seat-a", "seat-b", "seat-a"}
		}, edition.RuleBundleSet, "listed twice"},
		{"a seat of the list outside the grammar", func(t *testing.T, root string, in *edition.BundleInput) {
			in.Seats = append(in.Seats, "Seat_A")
		}, edition.RuleBundleSet, "outside the seat grammar"},
		// B2 (the reader's rules are bundle_test.go's; one case to show CheckBundles lists them)
		{"a file name outside the grammar", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, "seat-a/01-demo/Bad.txt", "x")
		}, edition.RuleBundleShape, "outside the grammar"},
		// B3
		{"a flag shape in a file", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, "seat-a/01-demo/more.txt", "x FALCO{dev-x} y")
		}, edition.RuleBundleFlag, "flag shape"},
		{"a lower-case flag opening in a file", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, "seat-a/01-demo/more.txt", "x falco{ y")
		}, edition.RuleBundleFlag, "flag shape"},
		{"a value of this event's flags in a file", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, "seat-a/01-demo/more.txt", "x "+eventFlg+" y")
		}, edition.RuleBundleFlag, "flag shape"},
		// B5
		{"hint-only text in a file", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, "seat-a/01-demo/more.txt", "before "+hintText+" after")
		}, edition.RuleBundleHint, "in a hint of the scope"},
		{"no hint to scan against", func(t *testing.T, root string, in *edition.BundleInput) {
			in.Hints = nil
		}, edition.RuleBundleHint, "could not run"},
		// B6
		{"the answer of a per-seat question is not in the bundle", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, notesB, "user: "+sentinel+"-b\nid: cccccccccccc\n")
		}, edition.RuleBundleAnswer, "does not appear in the bundle of its seat"},
		{"another seat's answer in the bundle is not the seat's own", func(t *testing.T, root string, in *edition.BundleInput) {
			putFile(t, root, notesB, "user: "+sentinel+"-a\nid: bbbbbbbbbbbb\n")
		}, edition.RuleBundleAnswer, "does not appear in the bundle of its seat"},
		// B9
		{"a per-seat answer that is in the corpus", func(t *testing.T, root string, in *edition.BundleInput) {
			in.Corpus = edition.Corpus{[]byte("public text aaaaaaaaaaaa public text")}
		}, edition.RuleBundleCorpus, "appears in a file of the image"},
		{"no corpus", func(t *testing.T, root string, in *edition.BundleInput) {
			in.Corpus = nil
		}, edition.RuleBundleCorpus, "B9 cannot run"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := bundleTree(t, goodBundleFiles())
			in := goodBundleInput(t)
			c.mutate(t, root, &in)
			rows, err := edition.CheckBundles(root, in)
			if err == nil {
				t.Fatal("no violation was reported")
			}
			if rows != nil {
				t.Errorf("digest rows were returned with a violation: %v", rows)
			}
			if got := rules(err); !slices.Equal(got, []string{c.want}) {
				t.Errorf("rules = %v, want only [%s]: %v", got, c.want, err)
			}
			if !strings.Contains(err.Error(), c.msg) {
				t.Errorf("the error does not hold %q: %v", c.msg, err)
			}
			noSecret(t, c.name, err)
			for _, bad := range []string{hintText, eventFlg, "FALCO{"} {
				if strings.Contains(err.Error(), bad) {
					t.Errorf("the error carries %q: %v", bad, err)
				}
			}
		})
	}
}

// A violation names where it is: the seat, the challenge, the question or the file.
func TestCheckBundles_ViolationsNameTheirPlace(t *testing.T) {
	root := bundleTree(t, goodBundleFiles())
	putFile(t, root, "seat-a/01-demo/more.txt", "x FALCO{dev-x} y")
	_, err := edition.CheckBundles(root, goodBundleInput(t))
	var v *edition.Violation
	if !errors.As(err, &v) {
		t.Fatalf("err = %v, want a violation", err)
	}
	if v.Rule != edition.RuleBundleFlag || v.Seat != "seat-a" || v.CID != demoCID || v.File != "more.txt" {
		t.Errorf("violation = %+v, want B3 at seat-a, %s, file more.txt", *v, demoCID)
	}
	if want := "B3: "; !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "seat=seat-a cid="+demoCID+" file=more.txt") {
		t.Errorf("message = %q", err.Error())
	}

	root = bundleTree(t, goodBundleFiles())
	putFile(t, root, notesB, "user: "+sentinel+"-b\nid: cccccccccccc\n")
	_, err = edition.CheckBundles(root, goodBundleInput(t))
	if !errors.As(err, &v) || v.Rule != edition.RuleBundleAnswer || v.Seat != "seat-b" || v.QID != "hx" {
		t.Errorf("violation = %+v (%v), want B6 at seat-b, question hx", v, err)
	}
}

// Several defects are listed together, in the order B2, B1, B3, B6, B5, B9: a first
// failure does not hide the others.
func TestCheckBundles_ListsEveryRuleInOrder(t *testing.T) {
	root := bundleTree(t, goodBundleFiles())
	// B2: a name outside the grammar. B3: a flag shape. B5: a hint's text.
	putFile(t, root, "seat-a/01-demo/Bad.txt", "x")
	putFile(t, root, "seat-a/01-demo/more.txt", "x FALCO{dev-x} y")
	putFile(t, root, "seat-a/01-demo/hint.txt", hintText)
	// B1: a seat of the list with no bundle.
	if err := os.RemoveAll(filepath.Join(root, "seat-b")); err != nil {
		t.Fatal(err)
	}
	// B9: a per-seat answer that is in the corpus.
	in := goodBundleInput(t)
	in.Corpus = edition.Corpus{[]byte("aaaaaaaaaaaa")}
	_, err := edition.CheckBundles(root, in)
	if err == nil {
		t.Fatal("no violation was reported")
	}
	got := rules(err)
	if want := []string{"B1", "B2", "B3", "B5", "B9"}; !slices.Equal(got, want) {
		t.Fatalf("rules = %v, want %v: %v", got, want, err)
	}
	text := err.Error()
	last := -1
	for _, rule := range []string{"B2:", "B1:", "B3:", "B5:", "B9:"} {
		i := strings.Index(text, rule)
		if i < last {
			t.Errorf("%s is listed before an earlier rule (order B2, B1, B3, B6, B5, B9): %s", rule, text)
		}
		last = i
	}
}

// A tree with a file that ReadBundles did not read (over its limit) has a digest of the
// files that were read, which is not the digest of the tree: CheckBundles gives no row.
func TestCheckBundles_GivesNoDigestRowForATreeThatWasNotFullyRead(t *testing.T) {
	root := bundleTree(t, goodBundleFiles())
	putFile(t, root, "seat-a/01-demo/big.txt", repeat(edition.MaxBundleBytes+1))
	bs, readErr := edition.ReadBundles(root)
	if readErr == nil {
		t.Fatal("ReadBundles reported no violation for a file over the limit")
	}
	subset := bs.Get("seat-a", demoCID).Digest()
	rows, err := edition.CheckBundles(root, goodBundleInput(t))
	if err == nil || rows != nil {
		t.Fatalf("CheckBundles = (%v, %v), want no row and a violation", rows, err)
	}
	if got := rules(err); !slices.Equal(got, []string{edition.RuleBundleShape}) {
		t.Errorf("rules = %v, want only [B2]: %v", got, err)
	}
	// the digest ReadBundles gave is that of the files it read: the tree without the big file
	clean, err := edition.ReadBundles(bundleTree(t, goodBundleFiles()))
	if err != nil {
		t.Fatal(err)
	}
	if clean.Get("seat-a", demoCID).Digest() != subset {
		t.Error("the digest of a partly read bundle is not the digest of the files that were read")
	}
}

func TestCheckBundles_RefusesWhatItCannotRun(t *testing.T) {
	if _, err := edition.CheckBundles(bundleTree(t, goodBundleFiles()), edition.BundleInput{}); !errors.Is(err, edition.ErrTableMissing) {
		t.Errorf("a nil table: err = %v, want ErrTableMissing", err)
	}
	in := goodBundleInput(t)
	rows, err := edition.CheckBundles(filepath.Join(t.TempDir(), "missing"), in)
	var v *edition.Violation
	if err == nil || rows != nil || errors.As(err, &v) {
		t.Errorf("an unreadable root: (%v, %v), want an I/O error and no rows", rows, err)
	}
}

// B9's corpus: ReadCorpus reads what the image ships, and refuses what it cannot scan.
func TestReadCorpus(t *testing.T) {
	root := bundleTree(t, kv("a/one.txt", "first", "b/two.bin", "\xff\x00second"))
	corpus, err := edition.ReadCorpus(filepath.Join(root, "a"), filepath.Join(root, "b"))
	if err != nil || len(corpus) != 2 {
		t.Fatalf("ReadCorpus = (%d files, %v), want the two files", len(corpus), err)
	}
	if !bytes.Contains(corpus[1], []byte("second")) {
		t.Errorf("the binary file was not read as it is: %q", corpus[1])
	}
	// the real trees of the image: not empty
	shipped, err := edition.ReadCorpus(filepath.Join("..", "..", "challenges"), filepath.Join("..", "..", "scenarios"))
	if err != nil || len(shipped) < 50 {
		t.Errorf("the real challenges and scenarios: (%d files, %v), want a tree that is read", len(shipped), err)
	}

	cases := []struct {
		name string
		dirs func(t *testing.T) []string
	}{
		{"no directory", func(t *testing.T) []string { return nil }},
		{"a directory that does not exist", func(t *testing.T) []string { return []string{filepath.Join(t.TempDir(), "missing")} }},
		{"an empty directory", func(t *testing.T) []string { return []string{t.TempDir()} }},
		{"a link in the tree", func(t *testing.T) []string {
			d := bundleTree(t, kv("f", "x"))
			if err := os.Symlink("f", filepath.Join(d, "link")); err != nil {
				t.Fatal(err)
			}
			return []string{d}
		}},
	}
	for _, c := range cases {
		if got, err := edition.ReadCorpus(c.dirs(t)...); err == nil || got != nil {
			t.Errorf("%s: ReadCorpus = (%d files, %v), want an error", c.name, len(got), err)
		}
	}
}
