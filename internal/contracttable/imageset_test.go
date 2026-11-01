package contracttable

// ADR-WS-0010 D8: platform's release scan gate (scripts/lib/release-scan.sh) reads
// the Makefile's `IMAGES :=` line as the set of images a release builds, scans and
// pushes. That is a cross-repo contract (the conventions' "Image naming" row), so
// the line is held here in two ways:
//
//  1. its FORM is the one platform reads (one line, `:=`, no continuation, no
//     trailing comment): MakefileImages is an error, never a best-effort set;
//  2. its CONTENT is the 8 images of Hard Invariant I5, and the brace list of the
//     Image naming row says the same 8 (one definition each, compared both ways).
//
// A missing file or row FAILS, never skips (Makefile and the conventions file are in
// the Docker test context: Dockerfile.test copies the tree, .dockerignore keeps both).

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("%s: %v (is it in the test build context?)", rel, err)
	}
	return string(b)
}

// i5Images reads the image list of the Hard Invariant I5 row:
// "| I5 | 全 8 イメージ (a / b / c ...) を ...".
func i5Images(t *testing.T, conventions string) []string {
	t.Helper()
	var row string
	for _, ln := range strings.Split(conventions, "\n") {
		if strings.HasPrefix(ln, "| I5 |") {
			row = ln
			break
		}
	}
	if row == "" {
		t.Fatal("the conventions file has no `| I5 |` row")
	}
	m := regexp.MustCompile(`全 (\d+) イメージ \(([^)]*)\)`).FindStringSubmatch(row)
	if m == nil {
		t.Fatalf("the I5 row has no \"全 N イメージ (a / b ...)\" list: %.120s", row)
	}
	var names []string
	for _, n := range strings.Split(m[2], "/") {
		names = append(names, strings.TrimSpace(n))
	}
	if n, err := strconv.Atoi(m[1]); err != nil || n != len(names) {
		t.Fatalf("the I5 row says %s images but lists %d: %q", m[1], len(names), names)
	}
	return names
}

// namingImages reads the brace list of the Image naming row of the contract table:
// "falco-ctf-{a,b,c}:<git-sha>".
func namingImages(t *testing.T, conventions string) []string {
	t.Helper()
	row := RowWhere(conventions, func(r string) bool { return strings.HasPrefix(r, "| Image naming") })
	if row == "" {
		t.Fatal("the contract table has no `| Image naming` row")
	}
	m := regexp.MustCompile(`falco-ctf-\{([^}]*)\}`).FindStringSubmatch(row)
	if m == nil {
		t.Fatalf("the Image naming row has no falco-ctf-{...} list: %.120s", row)
	}
	return strings.Split(m[1], ",")
}

func sorted(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

func TestMakefileIMAGES_IsTheI5SetInTheFormPlatformReads(t *testing.T) {
	images, err := MakefileImages(readRepoFile(t, MakefilePath))
	if err != nil {
		t.Fatalf("Makefile IMAGES: %v", err)
	}
	conventions := readRepoFile(t, Path)
	i5 := i5Images(t, conventions)
	if !slices.Equal(sorted(images), sorted(i5)) {
		t.Errorf("Makefile IMAGES = %q, but Hard Invariant I5 lists %q (both directions must match)", images, i5)
	}
	naming := namingImages(t, conventions)
	if !slices.Equal(sorted(naming), sorted(i5)) {
		t.Errorf("the Image naming row lists %q, but Hard Invariant I5 lists %q", naming, i5)
	}
	row := RowWhere(conventions, func(r string) bool { return strings.HasPrefix(r, "| Image naming") })
	if !strings.Contains(row, "IMAGES :=") || !strings.Contains(row, "release-scan.sh") {
		t.Errorf("the Image naming row no longer says that platform's release scan gate reads the Makefile `IMAGES :=` line (ADR-WS-0010 D8): %.200s", row)
	}
}

const eight = "scoreboard auth-policy collector ttyd ttyd-proxy challenge docs detect-grader"

func TestMakefileImages_Form(t *testing.T) {
	cases := []struct {
		name     string
		makefile string
		want     []string // nil = must be an error
	}{
		{"the one-line form", "A := b\nIMAGES       := " + eight + "\nB := c\n", strings.Fields(eight)},
		{"a comment line above is not the definition", "# IMAGES := evil\nIMAGES := a b\n", []string{"a", "b"}},
		{"no definition", "A := b\n", nil},
		{"a continuation line", "IMAGES := scoreboard auth-policy \\\n\tcollector ttyd\n", nil},
		{"a continuation with a space after the backslash", "IMAGES := scoreboard \\ \n\tcollector\n", nil},
		{"a trailing comment", "IMAGES := scoreboard auth-policy # the rest\n", nil},
		{"a second definition by +=", "IMAGES := scoreboard\nIMAGES += ttyd\n", nil},
		{"a second definition by :=", "IMAGES := scoreboard\nIMAGES := ttyd\n", nil},
		{"= instead of :=", "IMAGES = scoreboard\n", nil},
		{"?= instead of :=", "IMAGES ?= scoreboard\n", nil},
		{"a make variable in the list", "IMAGES := scoreboard $(OTHER)\n", nil},
		{"an empty list", "IMAGES :=\n", nil},
		{"CRLF line ending", "IMAGES := a b\r\n", []string{"a", "b"}},
	}
	for _, c := range cases {
		got, err := MakefileImages(c.makefile)
		switch {
		case c.want == nil && err == nil:
			t.Errorf("%s: want an error, got the set %q", c.name, got)
		case c.want != nil && err != nil:
			t.Errorf("%s: unexpected error: %v", c.name, err)
		case c.want != nil && !slices.Equal(got, c.want):
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// The comparison with I5 is two-way: a dropped image and an added image are both red.
func TestMakefileIMAGES_ComparisonIsTwoWay(t *testing.T) {
	i5 := strings.Fields(eight)
	for name, line := range map[string]string{
		"an image dropped": "IMAGES := scoreboard auth-policy collector ttyd ttyd-proxy challenge docs",
		"an image added":   "IMAGES := " + eight + " extra",
		"an image renamed": "IMAGES := scoreboard auth-policy collector ttyd ttyd-proxy challenge docs grader",
	} {
		got, err := MakefileImages(line + "\n")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if slices.Equal(sorted(got), sorted(i5)) {
			t.Errorf("%s: the set still equals I5's, so the real-tree comparison could not tell", name)
		}
	}
}
