package edition_test

// ADR-0056 D9 and V16 (Go side): the canonical digest of a bundle, held to the shared
// case table testdata/bundle-digest. deploy-user.sh (A5c) runs the same table, so the
// two implementations cannot drift without one of them going red.
//
// The first digest of the table is not trusted because this test computed it. Each row
// carries the exact bytes the digest is the sha256 of (the `input` column), and the
// digests in the table were made with `printf '<input>' | shasum -a 256`, which uses
// none of the code under test. The test reads the table three ways: the digest column is
// the sha256 of the input column; the input column is what the definition makes of the
// case's directory (rebuilt here, independently of edition.BundleDigest); and
// edition.BundleDigest of the directory is the digest column.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

var digestCaseDir = filepath.Join("testdata", "bundle-digest")

// digestCase is one row of cases.tsv and the files of its directory.
type digestCase struct {
	id     string
	digest string
	input  string // the bytes, decoded from the printf spelling
	files  []edition.BundleFile
}

// printfBytes decodes the two escapes the table uses. A backslash left over is an error:
// the table's spelling is closed, so a typo is red, not a different byte.
func printfBytes(s string) (string, error) {
	out := strings.NewReplacer(`\x00`, "\x00", `\n`, "\n").Replace(s)
	if strings.Contains(out, `\`) {
		return "", errors.New("an escape other than \\x00 and \\n")
	}
	return out, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// caseFiles reads the flat directory of a case. A case without a directory is the empty
// bundle, and only `empty` may be one (a typo in a case id must not read as an empty bundle).
func caseFiles(t *testing.T, id string) []edition.BundleFile {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(digestCaseDir, id))
	if errors.Is(err, fs.ErrNotExist) {
		if id != "empty" {
			t.Fatalf("case %q has no directory; only `empty` is the empty bundle", id)
		}
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var files []edition.BundleFile
	for _, e := range entries {
		if !e.Type().IsRegular() {
			t.Fatalf("case %q: %q is not a regular file (a case directory is flat)", id, e.Name())
		}
		data, err := os.ReadFile(filepath.Join(digestCaseDir, id, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, edition.BundleFile{Name: e.Name(), Data: data})
	}
	return files
}

func readDigestCases(t *testing.T) []digestCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(digestCaseDir, "cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []digestCase
	seen := map[string]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 2 || len(cols) > 3 {
			t.Fatalf("cases.tsv:%d: want case<TAB>digest[<TAB>input], got %d columns", i+1, len(cols))
		}
		input := ""
		if len(cols) == 3 {
			input = cols[2]
		}
		decoded, err := printfBytes(input)
		if err != nil {
			t.Fatalf("cases.tsv:%d: %v", i+1, err)
		}
		if seen[cols[0]] {
			t.Fatalf("cases.tsv:%d: case %q is listed twice", i+1, cols[0])
		}
		seen[cols[0]] = true
		cases = append(cases, digestCase{id: cols[0], digest: cols[1], input: decoded, files: caseFiles(t, cols[0])})
	}
	// Non-vacuity, and every directory is a case (a directory nobody runs proves nothing).
	if len(cases) < 9 {
		t.Fatalf("read %d cases, want at least 9: the table is not being read", len(cases))
	}
	entries, err := os.ReadDir(digestCaseDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() && !seen[e.Name()] {
			t.Errorf("directory %q is not a case of cases.tsv", e.Name())
		}
	}
	return cases
}

// digestVariant is a way to compute a digest's input. The reference is the definition of
// D9; every other value is a deliberate mistake the table must catch.
type digestVariant struct {
	order      func([]edition.BundleFile)
	sep, term  string
	upperHex   bool
	rawContent bool
}

func byteOrder(files []edition.BundleFile) {
	sort.SliceStable(files, func(i, j int) bool { return files[i].Name < files[j].Name })
}

var referenceVariant = digestVariant{order: byteOrder, sep: "\x00", term: "\n"}

// digestInputOf is the input of the digest of files under variant v.
func digestInputOf(files []edition.BundleFile, v digestVariant) string {
	ordered := slices.Clone(files)
	v.order(ordered)
	var b strings.Builder
	for _, f := range ordered {
		h := sha256Hex(string(f.Data))
		switch {
		case v.rawContent:
			h = string(f.Data)
		case v.upperHex:
			h = strings.ToUpper(h)
		}
		b.WriteString(f.Name + v.sep + h + v.term)
	}
	return b.String()
}

func TestBundleDigest_SharedCaseTable(t *testing.T) {
	cases := readDigestCases(t)
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			if got := sha256Hex(c.input); got != c.digest {
				t.Errorf("the digest column is not the sha256 of the input column: %s, want %s", got, c.digest)
			}
			if got := digestInputOf(c.files, referenceVariant); got != c.input {
				t.Errorf("the input column is not what D9 makes of the directory:\n got %q\nwant %q", got, c.input)
			}
			if got := edition.BundleDigest(c.files); got != c.digest {
				t.Errorf("BundleDigest = %s, want %s", got, c.digest)
			}
			if got := (&edition.Bundle{Files: c.files}).Digest(); got != c.digest {
				t.Errorf("Bundle.Digest = %s, want %s", got, c.digest)
			}
		})
	}
	// The cases that differ by one byte (a name, a content byte, the pairing of names and
	// contents) are different digests: every digest of the table is its own.
	byDigest := map[string]string{}
	for _, c := range cases {
		if other, dup := byDigest[c.digest]; dup {
			t.Errorf("cases %q and %q have the same digest %s", other, c.id, c.digest)
		}
		byDigest[c.digest] = c.id
	}
	if empty := sha256Hex(""); byDigest[empty] != "empty" {
		t.Errorf("the empty bundle is the sha256 of no bytes (%s); the table has it under %q", empty, byDigest[empty])
	}
}

// The digest does not depend on the order the files are given in, and does not reorder
// the caller's slice.
func TestBundleDigest_IsIndependentOfTheOrderOfTheFiles(t *testing.T) {
	for _, c := range readDigestCases(t) {
		if len(c.files) < 2 {
			continue
		}
		reversed := slices.Clone(c.files)
		slices.Reverse(reversed)
		before := slices.Clone(reversed)
		if got := edition.BundleDigest(reversed); got != c.digest {
			t.Errorf("%s: files given in reverse order: %s, want %s", c.id, got, c.digest)
		}
		if !slices.EqualFunc(reversed, before, func(a, b edition.BundleFile) bool { return a.Name == b.Name }) {
			t.Errorf("%s: BundleDigest reordered the caller's slice", c.id)
		}
	}
}

// The table must be able to fail: each variant below is one mistake an implementation
// could make (a missing separator, a different terminator, the wrong order, a content that
// is not hashed). For the cases where the mistake changes the bytes at all, the digest
// the variant gives is not the table's.
func TestBundleDigest_TableCatchesADriftedDefinition(t *testing.T) {
	cases := readDigestCases(t)
	// a locale-style sort: it compares the names with the punctuation left out.
	letters := func(s string) string {
		return strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return -1
		}, s)
	}
	variants := []struct {
		name       string
		v          digestVariant
		mustDiffer func(c digestCase) bool
	}{
		{"no NUL between the name and the hash", digestVariant{order: byteOrder, sep: "", term: "\n"}, func(c digestCase) bool { return len(c.files) > 0 }},
		{"a space for the NUL", digestVariant{order: byteOrder, sep: " ", term: "\n"}, func(c digestCase) bool { return len(c.files) > 0 }},
		{"no LF after an entry", digestVariant{order: byteOrder, sep: "\x00", term: ""}, func(c digestCase) bool { return len(c.files) > 0 }},
		{"CR LF after an entry", digestVariant{order: byteOrder, sep: "\x00", term: "\r\n"}, func(c digestCase) bool { return len(c.files) > 0 }},
		{"an upper-case hash", digestVariant{order: byteOrder, sep: "\x00", term: "\n", upperHex: true}, func(c digestCase) bool { return len(c.files) > 0 }},
		{"the content in place of its hash", digestVariant{order: byteOrder, sep: "\x00", term: "\n", rawContent: true}, func(c digestCase) bool { return len(c.files) > 0 }},
		{"the files in reverse order", digestVariant{order: func(f []edition.BundleFile) { slices.Reverse(f) }, sep: "\x00", term: "\n"}, func(c digestCase) bool { return len(c.files) > 1 }},
		{"a sort that ignores punctuation", digestVariant{order: func(f []edition.BundleFile) {
			sort.SliceStable(f, func(i, j int) bool { return letters(f[i].Name) < letters(f[j].Name) })
		}, sep: "\x00", term: "\n"}, func(c digestCase) bool { return c.id == "byte-order" }},
	}
	for _, m := range variants {
		caught := 0
		for _, c := range cases {
			differs := sha256Hex(digestInputOf(c.files, m.v)) != c.digest
			if differs {
				caught++
			}
			if m.mustDiffer(c) && !differs {
				t.Errorf("%s: case %q gives the table's digest under this mistake; the table does not catch it there", m.name, c.id)
			}
		}
		if caught == 0 {
			t.Errorf("%s: no case of the table catches it", m.name)
		}
	}
}

// The reader and the digest agree: a case's files, read from a <seat>/<cid>/ tree by
// ReadBundles, have the table's digest.
func TestBundleDigest_ReadBundlesGivesTheTablesDigest(t *testing.T) {
	for _, c := range readDigestCases(t) {
		if len(c.files) == 0 {
			continue
		}
		files := map[string]string{}
		for _, f := range c.files {
			files[onePath+f.Name] = string(f.Data)
		}
		bs, err := edition.ReadBundles(bundleTree(t, files))
		if err != nil {
			t.Errorf("%s: %v", c.id, err)
			continue
		}
		if b := bs.Get("seat-a", "01-demo"); b == nil || b.Digest() != c.digest {
			t.Errorf("%s: the bundle ReadBundles read does not have the digest %s", c.id, c.digest)
		}
	}
}
