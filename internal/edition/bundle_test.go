package edition_test

// ADR-0056 D10 B2 and D19 A4b: the bundle reader. Every file content here is the
// sentinel or a placeholder of no meaning; a message must never carry a byte of it.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// kv makes a tree from alternating path, content arguments (slash path under the
// root). A map literal would need gofmt's column alignment; this does not.
func kv(pairs ...string) map[string]string {
	if len(pairs)%2 != 0 {
		panic("kv: an odd number of arguments")
	}
	out := make(map[string]string, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out[pairs[i]] = pairs[i+1]
	}
	return out
}

// plus is a copy of base with the files of extra added.
func plus(base map[string]string, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// bundleTree writes files (slash path under the root -> content) into a fresh
// directory and returns it.
func bundleTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// onePath is the one bundle most cases put a file in.
const onePath = "seat-a/01-demo/"

// repeat is a file content of n bytes of no meaning.
func repeat(n int) string { return strings.Repeat("a", n) }

// manyFiles is n one-byte bundle files, f00 ..., under prefix.
func manyFiles(prefix string, n int) map[string]string {
	out := map[string]string{}
	for i := 0; i < n; i++ {
		out[fmt.Sprintf("%sf%02d", prefix, i)] = "x"
	}
	return out
}

// seatBundles is seat-a with n challenges (01-a, 02-b, ...), each holding one file of
// size bytes.
func seatBundles(n, size int) map[string]string {
	out := map[string]string{}
	for i := 0; i < n; i++ {
		out[fmt.Sprintf("seat-a/%02d-%c/f", i+1, 'a'+i)] = repeat(size)
	}
	return out
}

func TestValidFileName(t *testing.T) {
	// c, not a or b: a file name that a message shows must not collide with a fixture's table value.
	long63 := strings.Repeat("c", 63)
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"a", true}, {"0", true}, {"notes.txt", true}, {"a-b", true}, {"a_b", true}, {"a..b", true}, {"9.log", true},
		{long63, true},
		{"", false}, {".a", false}, {"..a", false}, {"..", false}, {"-a", false}, {"_a", false}, {"A", false}, {"a B", false},
		{"a/b", false}, {"a,b", false}, {long63 + "a", false}, {"\xc3\xa9", false}, {"a\n", false}, {"a\x00b", false},
	} {
		if got := edition.ValidFileName(c.name); got != c.ok {
			t.Errorf("ValidFileName(%q) = %v, want %v", c.name, got, c.ok)
		}
	}
}

func TestReadBundles_ReadsInByteOrder(t *testing.T) {
	root := bundleTree(t, kv(
		"seat-b/01-demo/zz", "1",
		"seat-a/02-other/x", "2",
		"seat-a/01-demo/ab", "3",
		"seat-a/01-demo/a0", "4",
		"seat-a/01-demo/a-b", "5",
		"seat-a/01-demo/a.b", "6",
		"seat-a/01-demo/notes.t", "7",
	))
	bs, err := edition.ReadBundles(root)
	if err != nil {
		t.Fatalf("ReadBundles: %v", err)
	}
	var keys []string
	for _, b := range bs.All() {
		keys = append(keys, b.Seat+"/"+b.CID)
	}
	if want := []string{"seat-a/01-demo", "seat-a/02-other", "seat-b/01-demo"}; !slices.Equal(keys, want) {
		t.Errorf("bundles = %v, want %v (byte order of seat, then cid)", keys, want)
	}
	b := bs.Get("seat-a", "01-demo")
	if b == nil {
		t.Fatal("Get(seat-a, 01-demo) = nil")
	}
	var names []string
	for _, f := range b.Files {
		names = append(names, f.Name)
	}
	if want := []string{"a-b", "a.b", "a0", "ab", "notes.t"}; !slices.Equal(names, want) {
		t.Fatalf("files = %v, want %v (byte order: - 0x2d, . 0x2e, 0 0x30, b 0x62)", names, want)
	}
	if string(b.Files[3].Data) != "3" {
		t.Errorf("content of ab = %q, want %q", b.Files[3].Data, "3")
	}
	if bs.Get("seat-a", "03-none") != nil || bs.Get("seat-z", "01-demo") != nil {
		t.Error("Get returned a bundle for a pair that is not in the tree")
	}
	// One tree, one answer: a second read gives the same digests.
	again, err := edition.ReadBundles(root)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range bs.All() {
		if got := again.All()[i].Digest(); got != b.Digest() {
			t.Errorf("bundle %d: digest %s on the second read, %s on the first", i, got, b.Digest())
		}
	}
}

func TestReadBundles_RootThatIsNotAReadableDirectoryIsNotAViolation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	aFile := filepath.Join(bundleTree(t, kv("f", "x")), "f")
	for name, root := range map[string]string{"missing": missing, "a file": aFile} {
		bs, err := edition.ReadBundles(root)
		if err == nil || bs != nil {
			t.Errorf("%s: got (%v, %v), want (nil, an error)", name, bs, err)
			continue
		}
		var v *edition.Violation
		if errors.As(err, &v) {
			t.Errorf("%s: an unreadable root is an I/O error, not a rule violation: %v", name, err)
		}
	}
	empty, err := edition.ReadBundles(t.TempDir())
	if err != nil || empty == nil || len(empty.All()) != 0 {
		t.Errorf("an empty root: got (%v, %v), want no bundle and no error (B1 says what is missing)", empty, err)
	}
}

func TestReadBundles_B2(t *testing.T) {
	good := kv(onePath+"notes.txt", "line "+sentinel+"\n")
	cases := []struct {
		name  string
		files map[string]string
		after func(t *testing.T, root string)
		want  string
	}{
		{"a link in a bundle", good, func(t *testing.T, root string) {
			if err := os.Symlink("notes.txt", filepath.Join(root, "seat-a", "01-demo", "link")); err != nil {
				t.Fatal(err)
			}
		}, "regular files only"},
		{"a link to a directory in place of a seat", good, func(t *testing.T, root string) {
			if err := os.Symlink(t.TempDir(), filepath.Join(root, "seat-b")); err != nil {
				t.Fatal(err)
			}
		}, "seat entry of the evidence root is not a directory"},
		{"a link to a directory in place of a challenge", good, func(t *testing.T, root string) {
			if err := os.Symlink(t.TempDir(), filepath.Join(root, "seat-a", "02-link")); err != nil {
				t.Fatal(err)
			}
		}, "challenge entry of a seat directory is not a directory"},
		{"a directory in a bundle", plus(good, kv(onePath+"sub/x", sentinel)), nil, "flat"},
		{"a dot-file name", plus(good, kv(onePath+".hidden", sentinel)), nil, "grammar"},
		{"a name starting with a dash", plus(good, kv(onePath+"-x", sentinel)), nil, "grammar"},
		{"a name starting with two dots", plus(good, kv(onePath+"..a", sentinel)), nil, "grammar"},
		{"an upper-case name", plus(good, kv(onePath+"A.txt", sentinel)), nil, "grammar"},
		{"a name with a space", plus(good, kv(onePath+"a b", sentinel)), nil, "grammar"},
		{"a name with a comma", plus(good, kv(onePath+"a,b", sentinel)), nil, "grammar"},
		{"a non-ASCII name", plus(good, kv(onePath+"\xc3\xa9.txt", sentinel)), nil, "grammar"},
		{"a 64-character name", plus(good, kv(onePath+strings.Repeat("c", 64), sentinel)), nil, "grammar"},
		{"a file that is not UTF-8", plus(good, kv(onePath+"bin", sentinel+"\xff")), nil, "not valid UTF-8"},
		{"a zero-width space in a file", plus(good, kv(onePath+"z", "a\xe2\x80\x8bb "+sentinel)), nil, "invisible"},
		{"a bidi control in a file", plus(good, kv(onePath+"z", "a\xe2\x80\xaeb "+sentinel)), nil, "invisible"},
		{"a file of 512 KiB + 1 byte", plus(good, kv(onePath+"big", repeat(512<<10+1))), nil, "larger than the limit of a bundle"},
		{"two files of 300 KiB", plus(good, kv(onePath+"p", repeat(300<<10), onePath+"q", repeat(300<<10))), nil, "bundle is larger than its limit"},
		{"65 files", manyFiles(onePath, 65), nil, "limit is 64 files"},
		{"a seat directory named like no seat", plus(good, kv("Seat_A/01-demo/x", sentinel)), nil, "not named like a seat"},
		{"a stray file in the root", plus(good, kv("stray.txt", sentinel)), nil, "not named like a seat"},
		{"a file named like a seat in the root", plus(good, kv("seat-b", sentinel)), nil, "seat entry of the evidence root is not a directory"},
		{"a challenge directory named like no id", plus(good, kv("seat-a/bad/x", sentinel)), nil, "not named like a challenge id"},
		{"a file named like a challenge id in a seat", plus(good, kv("seat-a/02-file", sentinel)), nil, "challenge entry of a seat directory is not a directory"},
		{"the bundles of one seat over 2 MiB together", seatBundles(5, 500<<10), nil, "bundles of this seat are larger than their limit together"},
		{"the bundles of one seat at 2 MiB + 1 byte", plus(seatBundles(4, 512<<10), kv("seat-a/05-e/f", "x")), nil, "bundles of this seat are larger than their limit together"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := bundleTree(t, c.files)
			if c.after != nil {
				c.after(t, root)
			}
			bs, err := edition.ReadBundles(root)
			if bs == nil {
				t.Fatalf("a readable root gave no Bundles: %v", err)
			}
			if err == nil {
				t.Fatal("no violation was reported")
			}
			if got := rules(err); !slices.Equal(got, []string{edition.RuleBundleShape}) {
				t.Errorf("rules = %v, want [B2]: %v", got, err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error does not hold %q: %v", c.want, err)
			}
			noSecret(t, c.name, err)
			if strings.ContainsAny(err.Error(), "\xe2\x80\x8b\xe2\x80\xae\x00") {
				t.Errorf("the error carries a raw invisible byte: %q", err.Error())
			}
		})
	}
}

// The limits are exact: the limit itself passes (one byte more is B2's, above).
func TestReadBundles_LimitsPassAtTheLimit(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
	}{
		{"64 files", manyFiles(onePath, 64)},
		{"a file of 512 KiB", kv(onePath+"big", repeat(512<<10))},
		{"a bundle of 512 KiB in two files", kv(onePath+"p", repeat(256<<10), onePath+"q", repeat(256<<10))},
		{"the bundles of a seat at 2 MiB", seatBundles(4, 512<<10)},
	} {
		t.Run(c.name, func(t *testing.T) {
			bs, err := edition.ReadBundles(bundleTree(t, c.files))
			if err != nil || bs == nil {
				t.Errorf("ReadBundles: (%v, %v), want no violation at the limit", bs, err)
			}
		})
	}
}

// A seat's 2 MiB is per seat: two seats of 2 MiB each pass.
func TestReadBundles_SeatLimitIsPerSeat(t *testing.T) {
	files := seatBundles(4, 512<<10)
	for k, v := range seatBundles(4, 512<<10) {
		files["seat-b"+strings.TrimPrefix(k, "seat-a")] = v
	}
	if _, err := edition.ReadBundles(bundleTree(t, files)); err != nil {
		t.Errorf("two seats of 2 MiB each: %v", err)
	}
}

// Two seats that are each over 2 MiB are two violations, one per seat (not one for the
// tree, and not one per bundle).
func TestReadBundles_SeatLimitIsReportedOncePerSeat(t *testing.T) {
	files := seatBundles(5, 500<<10)
	for k, v := range seatBundles(5, 500<<10) {
		files["seat-b"+strings.TrimPrefix(k, "seat-a")] = v
	}
	_, err := edition.ReadBundles(bundleTree(t, files))
	if err == nil {
		t.Fatal("no violation was reported")
	}
	if got := strings.Count(err.Error(), "bundles of this seat are larger than their limit together"); got != 2 {
		t.Errorf("%d violations of the seat limit, want 2 (one per seat): %v", got, err)
	}
	if got := rules(err); !slices.Equal(got, []string{edition.RuleBundleShape}) {
		t.Errorf("rules = %v, want only [B2]: %v", got, err)
	}
	for _, seat := range []string{"seat=seat-a", "seat=seat-b"} {
		if !strings.Contains(err.Error(), seat) {
			t.Errorf("the error does not name %s: %v", seat, err)
		}
	}
}

// The list of violations is bounded like Check's: 20 listed, the rest counted.
func TestReadBundles_ListIsBounded(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 25; i++ {
		files[fmt.Sprintf("%sBAD%02d", onePath, i)] = sentinel
	}
	_, err := edition.ReadBundles(bundleTree(t, files))
	if err == nil {
		t.Fatal("no violation was reported")
	}
	if !strings.Contains(err.Error(), "5 further violations are not listed") {
		t.Errorf("25 violations should list 20 and count 5: %v", err)
	}
	if got := strings.Count(err.Error(), "B2:"); got != 20 {
		t.Errorf("%d violations are listed, want 20", got)
	}
}

// A content violation does not drop the file: the caller still checks it. A bundle with no
// file is kept (B1 reports it).
func TestReadBundles_KeepsWhatItReported(t *testing.T) {
	root := bundleTree(t, kv(onePath+"bin", "a\xffb", "seat-b/01-demo/x", "ok"))
	if err := os.MkdirAll(filepath.Join(root, "seat-c", "01-demo"), 0o755); err != nil {
		t.Fatal(err)
	}
	bs, err := edition.ReadBundles(root)
	if err == nil {
		t.Fatal("no violation was reported for a file that is not UTF-8")
	}
	if b := bs.Get("seat-a", "01-demo"); b == nil || len(b.Files) != 1 {
		t.Errorf("the file with a content violation was dropped: %+v", b)
	}
	if b := bs.Get("seat-c", "01-demo"); b == nil || len(b.Files) != 0 {
		t.Errorf("an empty bundle directory: %+v, want a bundle with no file", b)
	}
}
