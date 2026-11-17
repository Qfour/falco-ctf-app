package edition

// ADR-0056 D19 A4c-2: the files of the practice editions (practicefiles.go) and the one
// decision about the start-up path. loadPractice finds where the practice editions are;
// readPracticeFiles reads their bundle and template as a bundle is read (B2); Load reads
// none of it. Every value is a placeholder.

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	practiceZeroRun  = "# falco-ctf answers v1 run=" + PracticeRunID + "\n"
	practiceGoodRows = practiceZeroRun + "*\t01-demo\twho\tpractice-who\n*\t01-demo\thx\taaaaaaaaaaaa\n"
	// contentSentinel is in the content of every file the refusal cases make bad: no error
	// may carry it.
	contentSentinel = "CONTENT-SENTINEL-zzzz"
)

// filesTree writes one investigate challenge per cid, with the files of entries (path
// under the challenge directory -> content), on top of its falco-rule.yaml.
func filesTree(t *testing.T, entries map[string]map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for cid, files := range entries {
		cdir := filepath.Join(dir, cid)
		filesWrite(t, filepath.Join(cdir, "falco-rule.yaml"), practiceFixtureYAML)
		for rel, content := range files {
			filesWrite(t, filepath.Join(cdir, filepath.FromSlash(rel)), content)
		}
	}
	return dir
}

func filesWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fileNames(files []BundleFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Name)
	}
	return out
}

func TestReadPracticeFiles_ReadsTheBundleAndTheTemplate(t *testing.T) {
	dir := filesTree(t, map[string]map[string]string{
		"01-demo": {
			"edition/practice/answers.tsv":        practiceGoodRows,
			"edition/practice/evidence/notes.txt": "bundle notes",
			"edition/practice/evidence/ids.txt":   "bundle ids",
			"edition/template/page.txt":           "template page",
		},
		// a template and no practice/ at all: the files that are there are read
		"02-bare": {"edition/template/only.txt": "template only"},
		// no edition/ at all
		"03-none": {},
	})
	_, _, dirs, err := loadPractice(treeScored(t, dir))
	if err != nil {
		t.Fatalf("loadPractice: %v", err)
	}
	if got := slices.Sorted(maps.Keys(dirs)); !slices.Equal(got, []string{"01-demo", "02-bare"}) {
		t.Fatalf("the practice directories are %v, want those of the two challenges that have an edition/", got)
	}
	if want := filepath.Join(dir, "01-demo", EditionDirName); dirs["01-demo"] != want {
		t.Errorf("the directory of 01-demo is %q, want %q", dirs["01-demo"], want)
	}

	files, err := readPracticeFiles(dirs)
	if err != nil {
		t.Fatalf("readPracticeFiles: %v", err)
	}
	if got := slices.Sorted(maps.Keys(files)); !slices.Equal(got, []string{"01-demo", "02-bare"}) {
		t.Fatalf("editions = %v, want 01-demo and 02-bare", got)
	}
	demo := files["01-demo"]
	if got := fileNames(demo.Evidence); !slices.Equal(got, []string{"ids.txt", "notes.txt"}) {
		t.Errorf("the bundle of 01-demo = %v, want ids.txt and notes.txt in byte order", got)
	}
	if string(demo.Evidence[1].Data) != "bundle notes" {
		t.Errorf("notes.txt holds %q", demo.Evidence[1].Data)
	}
	if got := fileNames(demo.Template); !slices.Equal(got, []string{"page.txt"}) || string(demo.Template[0].Data) != "template page" {
		t.Errorf("the template of 01-demo = %v", got)
	}
	bare := files["02-bare"]
	if bare.Evidence != nil || !slices.Equal(fileNames(bare.Template), []string{"only.txt"}) {
		t.Errorf("02-bare = %+v, want no bundle and the template only.txt", bare)
	}
	// the answers.tsv is not part of the bundle: it never reaches a seat
	for _, f := range demo.Evidence {
		if f.Name == PracticeAnswersFileName {
			t.Error("the answers table is in the practice bundle")
		}
	}
}

func TestReadPracticeFiles_NoneIsTheEmptyNonNilMap(t *testing.T) {
	for name, dirs := range map[string]practiceDirs{"nil": nil, "empty": {}} {
		files, err := readPracticeFiles(dirs)
		if err != nil || files == nil || len(files) != 0 {
			t.Errorf("%s: readPracticeFiles = (%#v, %v), want the empty non-nil map", name, files, err)
		}
	}
	dir := filesTree(t, map[string]map[string]string{"01-demo": {}})
	_, _, dirs, err := loadPractice(treeScored(t, dir))
	if err != nil || dirs == nil || len(dirs) != 0 {
		t.Errorf("a tree with no edition/: loadPractice's directories = (%#v, %v), want the empty non-nil map", dirs, err)
	}
}

// B2 applies to a practice edition's files as to a seat's bundle: a defect is an error that
// names the challenge, and never a content. The start-up path is not asked about it (the
// next test), so each case first shows that loadPractice accepts the tree.
func TestReadPracticeFiles_RefusesWhatB2Refuses(t *testing.T) {
	long := strings.Repeat("a", MaxBundleBytes) + contentSentinel
	base := func() map[string]string {
		return map[string]string{
			"edition/practice/answers.tsv":        practiceGoodRows,
			"edition/practice/evidence/notes.txt": "bundle notes",
			"edition/template/page.txt":           "template page",
		}
	}
	cases := []struct {
		name   string
		mutate func(t *testing.T, dir string, files map[string]string)
		want   string // in the error text
		rule   bool   // the error is a B2 violation
	}{
		{"a bundle file name outside the grammar", func(t *testing.T, dir string, f map[string]string) {
			f["edition/practice/evidence/Bad.txt"] = contentSentinel
		}, "outside the grammar", true},
		{"a template file name outside the grammar", func(t *testing.T, dir string, f map[string]string) {
			f["edition/template/Bad Name.txt"] = contentSentinel
		}, "outside the grammar", true},
		{"a directory inside the bundle", func(t *testing.T, dir string, f map[string]string) {
			f["edition/practice/evidence/sub/inner.txt"] = contentSentinel
		}, "flat", true},
		{"a file that is not UTF-8 in the template", func(t *testing.T, dir string, f map[string]string) {
			f["edition/template/raw.bin"] = "\xff\xfe" + contentSentinel
		}, "not valid UTF-8", true},
		{"a file over the limit in the bundle", func(t *testing.T, dir string, f map[string]string) {
			f["edition/practice/evidence/big.txt"] = long
		}, "larger than the limit", true},
		{"a link in the template", func(t *testing.T, dir string, f map[string]string) {
			// made after the tree: the link points at a file that holds the sentinel
			filesWrite(t, filepath.Join(dir, "outside.txt"), contentSentinel)
		}, "regular files only", true},
		{"evidence that is a file, not a directory", func(t *testing.T, dir string, f map[string]string) {
			delete(f, "edition/practice/evidence/notes.txt")
			f["edition/practice/evidence"] = contentSentinel
		}, "is not a directory", false},
		{"template that is a file, not a directory", func(t *testing.T, dir string, f map[string]string) {
			delete(f, "edition/template/page.txt")
			f["edition/template"] = contentSentinel
		}, "is not a directory", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := base()
			dir := t.TempDir()
			c.mutate(t, dir, files)
			// not filesTree: the link case needs dir before the tree is written
			cdir := filepath.Join(dir, "01-demo")
			filesWrite(t, filepath.Join(cdir, "falco-rule.yaml"), practiceFixtureYAML)
			for rel, content := range files {
				filesWrite(t, filepath.Join(cdir, filepath.FromSlash(rel)), content)
			}
			if c.name == "a link in the template" {
				if err := os.Symlink(filepath.Join(dir, "outside.txt"), filepath.Join(cdir, "edition", "template", "link.txt")); err != nil {
					t.Fatal(err)
				}
			}
			_, _, dirs, err := loadPractice(treeScored(t, dir))
			if err != nil {
				t.Fatalf("loadPractice refused the tree: %v (the start-up path must not look at the bundle or the template)", err)
			}
			got, err := readPracticeFiles(dirs)
			if err == nil {
				t.Fatalf("readPracticeFiles accepted the tree: %v", got)
			}
			if got != nil {
				t.Errorf("readPracticeFiles returned files with an error: %v", got)
			}
			if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "01-demo") {
				t.Errorf("the error does not say %q about 01-demo: %v", c.want, err)
			}
			var v *Violation
			if c.rule && (!errors.As(err, &v) || v.Rule != RuleBundleShape) {
				t.Errorf("err = %v, want a B2 violation", err)
			}
			if strings.Contains(err.Error(), contentSentinel) {
				t.Errorf("the error carries a content: %v", err)
			}
		})
	}
}

// The decision of A4c-2 about the start-up path (the task's item 3): the practice mode's
// Load reads the answers only. A challenge whose bundle and template are broken still gets
// its Judge, because a scoreboard has no use for them; they are B4's input, read by the
// validator's path alone.
func TestLoad_PracticeModeDoesNotReadTheBundleOrTheTemplate(t *testing.T) {
	dir := filesTree(t, map[string]map[string]string{
		"01-demo": {
			"edition/practice/answers.tsv":           practiceGoodRows,
			"edition/practice/evidence/Bad Name.txt": contentSentinel,
			"edition/practice/evidence/sub/x.txt":    contentSentinel,
			"edition/template/raw.bin":               "\xff\xfe" + contentSentinel,
		},
	})
	if _, err := readPracticeFilesOf(t, dir); err == nil {
		t.Fatal("the fixture is not broken: readPracticeFiles accepted it")
	}
	j, runID, err := Load(treeScored(t, dir), "", false)
	if err != nil || j == nil || runID != PracticeRunID {
		t.Fatalf("Load = (%v, %q, %v), want the practice Judge: a broken bundle or template must not stop a scoreboard", j, runID, err)
	}
}

func readPracticeFilesOf(t *testing.T, dir string) (practiceFiles, error) {
	t.Helper()
	_, _, dirs, err := loadPractice(treeScored(t, dir))
	if err != nil {
		t.Fatalf("loadPractice: %v", err)
	}
	return readPracticeFiles(dirs)
}
