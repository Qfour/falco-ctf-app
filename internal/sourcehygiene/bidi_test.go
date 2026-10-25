package sourcehygiene

// app#501 (#480, #478 review-5x R1#1, #489): no tracked text file may hold a raw
// bidirectional control character. "Trojan Source" (CVE-2021-42574) uses
// U+202A-U+202E (LRE RLE PDF LRO RLO) and U+2066-U+2069 (LRI RLI FSI PDI) so that
// what a reviewer sees in a diff differs from what the compiler, the YAML parser
// or an AI agent that reads the file receives. This repo handles U+202E as attack
// DATA in many tests and fixtures; every one of them writes it as an escape, and
// only the escape is allowed. A raw character is allowed solely where
// testdata/bidi-allowlist.txt names the file (a closed set, one reason per line).
//
// This is a Go test, not a script: `make test` is the required check `test`.
// In that check the tree is the Docker build context (Dockerfile.test copies it;
// .dockerignore leaves out .git), so the file set is "git ls-files" where there is
// a .git and "every file on disk" where there is not (hintleak does the same).
// "Tracked file" in the Docker path therefore means every file of the build
// context. scripts/check-build-context.sh (flag-guard) proves that set equals
// `git ls-files`; canaryFiles is the in-test tripwire for the same thing. If the
// test is red on an UNTRACKED file in your working tree (it is in the context
// although git ignores it), delete the file or exclude it in .dockerignore.
//
// Scope: the nine code points above. U+200E / U+200F (LRM / RLM) are not in the
// set: they only set the direction of neutral characters, cannot embed or
// override a run, and are the legitimate way to write Arabic / Hebrew prose; the
// tree has none today and the set is one table (bidiControls) if that changes.
// What is scanned: every regular file except those whose extension is in
// binaryExt, a closed set (a raw byte sequence inside a font is chance, not an
// attack). A NUL byte does NOT make a file binary: an attacker can put one in a
// .md or .yaml to skip a "has a NUL" test. A file outside binaryExt that holds a
// NUL is scanned all the same and is also a problem ("cannot decide"); a new
// binary format must be added to binaryExt with a reason. Invalid UTF-8 does NOT
// exempt a file either: the search is on bytes. Symlinks and submodules are not
// followed.

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

const allowlistFile = "internal/sourcehygiene/testdata/bidi-allowlist.txt"

// canaryFiles must be among the scanned files of the real tree. They are the
// files whose absence means the test is looking at less than the repo: a build
// context that dropped a directory, or a walk that listed nothing. One per
// directory that .dockerignore once excluded.
var canaryFiles = []string{
	"go.mod",
	"internal/sourcehygiene/bidi_test.go",
	allowlistFile,
	".github/workflows/ci.yaml",
	".claude/agents/architect.md",
	".claude/commands/commit.md",
	".claude/rules/dev-flow.md",
	".claude/skills/falco-go/SKILL.md",
	".claude/settings.json",
}

// binaryExt is the closed set of file extensions that are binary and not
// scanned, each with its reason. Adding one needs the same review as an
// allowlist line.
var binaryExt = map[string]string{
	".woff2": "WOFF2 font (compressed bytes; a 3-byte match is chance)",
	// Not tracked: `helm dependency build` writes charts/*/charts/*.tgz, and
	// Dockerfile.test runs it after COPY, before this test. git ignores them.
	".tgz": "helm dependency archive (untracked build output present in the Docker path)",
}

// bidiControls is the one list of what is forbidden raw.
var bidiControls = map[rune]string{
	0x202A: "LEFT-TO-RIGHT EMBEDDING",
	0x202B: "RIGHT-TO-LEFT EMBEDDING",
	0x202C: "POP DIRECTIONAL FORMATTING",
	0x202D: "LEFT-TO-RIGHT OVERRIDE",
	0x202E: "RIGHT-TO-LEFT OVERRIDE",
	0x2066: "LEFT-TO-RIGHT ISOLATE",
	0x2067: "RIGHT-TO-LEFT ISOLATE",
	0x2068: "FIRST STRONG ISOLATE",
	0x2069: "POP DIRECTIONAL ISOLATE",
}

type finding struct {
	line, col int // 1-based; col counts characters (an invalid byte counts as one)
	cp        rune
}

func (f finding) String() string {
	return fmt.Sprintf("%d:%d U+%04X %s", f.line, f.col, f.cp, bidiControls[f.cp])
}

// isBinary: the extension is in binaryExt. Not the content: see the header.
func isBinary(rel string) bool {
	_, ok := binaryExt[strings.ToLower(filepath.Ext(rel))]
	return ok
}

// scanBytes finds the raw controls in data. It searches bytes, not decoded
// runes, so a file that is not valid UTF-8 is scanned all the same: U+202x is
// E2 80 AA..AE and U+206x is E2 81 A6..A9.
func scanBytes(data []byte) []finding {
	var out []finding
	line, lineStart := 1, 0
	for i := 0; i < len(data); i++ {
		switch {
		case data[i] == '\n':
			line++
			lineStart = i + 1
		case data[i] == 0xE2 && i+2 < len(data):
			cp, w := utf8.DecodeRune(data[i:])
			if _, bad := bidiControls[cp]; bad && w == 3 {
				out = append(out, finding{line, utf8.RuneCount(data[lineStart:i]) + 1, cp})
				i += 2
			}
		}
	}
	return out
}

// parseAllowlist reads the closed list: <path>\t<reason>, # comments, blank lines.
func parseAllowlist(text string) (map[string]string, error) {
	allow := map[string]string{}
	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, reason, ok := strings.Cut(line, "\t")
		where := fmt.Sprintf("%s:%d", allowlistFile, n+1)
		switch {
		case !ok:
			return nil, fmt.Errorf("%s: want <path><TAB><reason>, got %q", where, line)
		case strings.TrimSpace(reason) == "":
			return nil, fmt.Errorf("%s: %q has no reason", where, p)
		case p == "" || p != strings.TrimSpace(p) || strings.ContainsAny(p, `*?[]{}\`) ||
			filepath.ToSlash(filepath.Clean(p)) != p || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "../") || p == ".":
			return nil, fmt.Errorf("%s: %q is not an exact, clean, slash-separated file path (no glob, no directory)", where, p)
		}
		if _, dup := allow[p]; dup {
			return nil, fmt.Errorf("%s: %q is listed twice", where, p)
		}
		allow[p] = strings.TrimSpace(reason)
	}
	return allow, nil
}

// listFiles returns the repo-relative, slash-separated files to scan: git ls-files
// in a checkout, every file on disk otherwise.
func listFiles(root string) ([]string, error) {
	var out []string
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		cmd := exec.Command("git", "-C", root, "-c", "core.quotepath=off", "ls-files", "-z")
		b, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git ls-files: %w", err)
		}
		for _, p := range bytes.Split(b, []byte{0}) {
			if len(p) > 0 {
				out = append(out, string(p))
			}
		}
	} else {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				rel, _ := filepath.Rel(root, p)
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", root, err)
		}
	}
	sort.Strings(out)
	return out, nil
}

type report struct {
	problems []string
	scanned  map[string]bool // text files that were read and scanned
	binary   []string        // regular files with a binaryExt extension, not scanned
	skipped  []string        // not regular (symlink, submodule) or absent from disk
}

// checkTree scans root against allow. Every problem is a line "<path>:<line>:<col>
// U+XXXX NAME ..." or a sentence naming the allowlist entry; none is empty.
func checkTree(root string, allow map[string]string) (*report, error) {
	files, err := listFiles(root)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no file listed under " + root + ": a scan of nothing proves nothing")
	}
	r := &report{scanned: map[string]bool{}}
	hit := map[string]bool{} // allowlisted files that did hold a raw character
	for _, rel := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		fi, err := os.Lstat(abs)
		if errors.Is(err, fs.ErrNotExist) || (err == nil && !fi.Mode().IsRegular()) {
			r.skipped = append(r.skipped, rel)
			continue
		}
		if err != nil {
			return nil, err
		}
		if isBinary(rel) {
			r.binary = append(r.binary, rel)
			continue
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil, err
		}
		r.scanned[rel] = true
		if bytes.IndexByte(data, 0) >= 0 {
			r.problems = append(r.problems, fmt.Sprintf("%s: holds a NUL byte but its extension is not in binaryExt, so it cannot be told from a text file that hides something (remove the NUL, or add the extension to binaryExt with a reason)", rel))
		}
		found := scanBytes(data)
		if len(found) == 0 {
			continue
		}
		if _, ok := allow[rel]; ok {
			hit[rel] = true
			continue
		}
		for _, f := range found {
			r.problems = append(r.problems, fmt.Sprintf("%s:%s: raw bidi control (write it as an escape such as \\u%04x; an exception needs a reviewed line in %s)", rel, f, f.cp, allowlistFile))
		}
	}
	var dead []string
	for p := range allow {
		if !hit[p] {
			dead = append(dead, p)
		}
	}
	sort.Strings(dead)
	for _, p := range dead {
		why := "the file holds no raw bidi character"
		switch {
		case slices.Contains(r.binary, p):
			why = "the file has a binaryExt extension and is not scanned"
		case !r.scanned[p]:
			why = "the file is not a tracked regular file"
		}
		r.problems = append(r.problems, fmt.Sprintf("%s: dead allowlist entry %q: %s; delete the line", allowlistFile, p, why))
	}
	return r, nil
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving the repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root not found at %s: %v", root, err)
	}
	return root
}

// TestTrackedFilesHoldNoRawBidiControl is the gate.
func TestTrackedFilesHoldNoRawBidiControl(t *testing.T) {
	root := repoRoot(t)
	text, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(allowlistFile)))
	if err != nil {
		t.Fatalf("the allowlist is unreadable (it must exist, even with no entry): %v", err)
	}
	allow, err := parseAllowlist(string(text))
	if err != nil {
		t.Fatal(err)
	}
	r, err := checkTree(root, allow)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range canaryFiles {
		if !r.scanned[c] {
			t.Errorf("canary %s was not scanned: the file set is smaller than the repo (a .dockerignore line, a wrong root, or a failed listing)", c)
		}
	}
	for _, p := range r.problems {
		t.Error(p)
	}
	t.Logf("scanned %d text files; %d binary (not scanned); %d not regular or absent; %d allowlist entries",
		len(r.scanned), len(r.binary), len(r.skipped), len(allow))
}

// ---- selftest: the checks run on planted trees ----------------------------

// raw builds the characters at run time: this file stays free of them.
func raw(cp rune) string { return string(cp) }

func plant(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		abs := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCheckTree_PlantedTrees(t *testing.T) {
	rlo := raw(0x202E)
	tests := []struct {
		name  string
		files map[string]string
		allow map[string]string
		want  []string // each must be a substring of some problem; none: no problem at all
	}{
		{
			name:  "a raw RLO in a file that is not listed is red, with path line col and code point",
			files: map[string]string{"a/b.go": "package a\n// x" + rlo + "y\n", "ok.txt": "fine\n"},
			want:  []string{"a/b.go:2:5 U+202E RIGHT-TO-LEFT OVERRIDE"},
		},
		{
			name:  "the same file listed with a reason is green",
			files: map[string]string{"a/b.go": "package a\n// x" + rlo + "y\n"},
			allow: map[string]string{"a/b.go": "attack fixture"},
		},
		{
			name:  "a listed file holding no raw character is a dead entry",
			files: map[string]string{"a/b.go": "package a\n"},
			allow: map[string]string{"a/b.go": "attack fixture"},
			want:  []string{`dead allowlist entry "a/b.go": the file holds no raw bidi character`},
		},
		{
			name:  "a listed file that is not in the tree is a dead entry",
			files: map[string]string{"ok.txt": "fine\n"},
			allow: map[string]string{"gone.txt": "attack fixture"},
			want:  []string{`dead allowlist entry "gone.txt": the file is not a tracked regular file`},
		},
		{
			name:  "a listed binaryExt file is a dead entry (such a file is not scanned)",
			files: map[string]string{"font.woff2": "\x00" + rlo},
			allow: map[string]string{"font.woff2": "attack fixture"},
			want:  []string{`dead allowlist entry "font.woff2": the file has a binaryExt extension`},
		},
		{
			name: "escapes of every kind are green",
			files: map[string]string{
				"esc.go":   `s := "\u202e" + "\xe2\x80\xae" + "\U0000202E"` + "\n",
				"esc.yaml": `name: "\u202E x"` + "\n",
				"esc.tsv":  "user{U+202E}1\treject\n",
				"esc.md":   "U+202E, &#x202e; and &#8238;\n",
			},
		},
		{
			name: "a binaryExt file is not scanned, whatever its case",
			files: map[string]string{
				"font.woff2": "\x00\x01" + rlo + "\x02",
				"Font.WOFF2": "\x00\x01" + rlo + "\x02",
			},
		},
		{
			name:  "a NUL does not make a .md binary: the raw RLO is found and the NUL is a problem",
			files: map[string]string{"hide.md": "a\x00b\n" + rlo + "\n"},
			want:  []string{"hide.md:2:1 U+202E", "hide.md: holds a NUL byte but its extension is not in binaryExt"},
		},
		{
			name:  "a NUL file outside binaryExt is a problem even with no bidi character",
			files: map[string]string{"blob.bin": "\x00\x01\x02"},
			want:  []string{"blob.bin: holds a NUL byte but its extension is not in binaryExt"},
		},
		{
			name:  "invalid UTF-8 elsewhere in the file does not switch the check off",
			files: map[string]string{"bad.txt": "\xff\xfe broken\n" + rlo + "\n"},
			want:  []string{"bad.txt:2:1 U+202E"},
		},
		{
			name:  "the column counts characters, not bytes",
			files: map[string]string{"ja.md": "ab\nあい" + rlo + "\n"},
			want:  []string{"ja.md:2:3 U+202E"},
		},
		{
			name:  "a second hit on the same file is reported too",
			files: map[string]string{"two.md": rlo + "a" + raw(0x2066) + "\n"},
			want:  []string{"two.md:1:1 U+202E", "two.md:1:3 U+2066"},
		},
		{
			name:  "LRM RLM and the neighbours of the two ranges are not in the set",
			files: map[string]string{"near.md": raw(0x200E) + raw(0x200F) + raw(0x2029) + raw(0x202F) + raw(0x2065) + raw(0x206A) + "\n"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := checkTree(plant(t, tc.files), tc.allow)
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(r.problems, "\n")
			if len(tc.want) == 0 && len(r.problems) != 0 {
				t.Fatalf("want no problem, got:\n%s", joined)
			}
			for _, w := range tc.want {
				if !strings.Contains(joined, w) {
					t.Errorf("want a problem containing %q, got:\n%s", w, joined)
				}
			}
		})
	}
}

func TestScanBytes_EveryControlAndOnlyThose(t *testing.T) {
	for cp := rune(0x2000); cp <= 0x206F; cp++ {
		_, forbidden := bidiControls[cp]
		got := scanBytes([]byte("a" + string(cp) + "b"))
		if forbidden && (len(got) != 1 || got[0].cp != cp || got[0].col != 2) {
			t.Errorf("U+%04X is forbidden but scanBytes gave %v", cp, got)
		}
		if !forbidden && len(got) != 0 {
			t.Errorf("U+%04X is not forbidden but scanBytes gave %v", cp, got)
		}
	}
	if len(bidiControls) != 9 {
		t.Errorf("the set is U+202A-202E and U+2066-2069 (nine); got %d", len(bidiControls))
	}
}

func TestCheckTree_ASymlinkIsNotFollowed(t *testing.T) {
	root := plant(t, map[string]string{"real.txt": "x" + raw(0x202E)})
	outside := plant(t, map[string]string{"target.txt": raw(0x202E)})
	if err := os.Symlink(filepath.Join(outside, "target.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	r, err := checkTree(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.problems) != 1 || !strings.HasPrefix(r.problems[0], "real.txt:") {
		t.Errorf("only real.txt is scanned, got %v", r.problems)
	}
	if len(r.skipped) != 1 || r.skipped[0] != "link.txt" {
		t.Errorf("link.txt is skipped, got %v", r.skipped)
	}
}

func TestCheckTree_AnEmptyListingIsAnError(t *testing.T) {
	if _, err := checkTree(t.TempDir(), nil); err == nil {
		t.Fatal("a scan of an empty directory must be an error, not a pass")
	}
}

func TestParseAllowlist(t *testing.T) {
	good, err := parseAllowlist("# c\n\na/b.txt\tattack fixture: the RLO is the payload\nc.go\tx\n")
	if err != nil || len(good) != 2 || good["a/b.txt"] == "" {
		t.Fatalf("good list: %v %v", good, err)
	}
	bad := map[string]string{
		"no TAB":            "a/b.txt attack fixture\n",
		"empty reason":      "a/b.txt\t \n",
		"glob":              "a/*.txt\treason\n",
		"directory":         "a/\treason\n",
		"absolute":          "/a/b.txt\treason\n",
		"parent":            "../a.txt\treason\n",
		"not clean":         "a//b.txt\treason\n",
		"dot-slash":         "./a.txt\treason\n",
		"backslash":         "a\\b.txt\treason\n",
		"leading space":     " a.txt\treason\n",
		"duplicate":         "a.txt\tr\na.txt\tr2\n",
		"indented comment":  "  # x\n",
		"empty path":        "\treason\n",
		"braces":            "a{b,c}.txt\treason\n",
		"bracket":           "a[0].txt\treason\n",
		"question":          "a?.txt\treason\n",
		"dot":               ".\treason\n",
		"trailing space":    "a.txt \treason\n",
		"carriage-return-x": "a.txt\r\n",
	}
	for name, text := range bad {
		if _, err := parseAllowlist(text); err == nil {
			t.Errorf("%s: %q must be rejected", name, text)
		}
	}
}
