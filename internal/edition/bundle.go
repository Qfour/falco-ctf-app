package edition

// bundle.go is the evidence-bundle side of the validator (ADR-0056 D9, D10 B2, D11,
// D19 A4b): the reader of a tree of bundles, the one grammar of a bundle's file names,
// and the canonical digest of a bundle. Like the rest of this package it names an
// identifier (seat, cid, file name) in a message and never a byte of a file's content.
//
// The tree the validator reads is  <root>/<seat>/<cid>/<file>  : a bundle is the files
// of ONE (seat, challenge) pair (D11: one Secret per challenge, so the unit of a
// digest, of the size limits and of a Secret is the pair). Nothing here is reachable
// from the scoreboard's HTTP side; the caller is the validator (A4e).

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/sourcehygiene"
)

const (
	// NamePattern is D10 B2's grammar of a bundle's file name: lower-case, at most 63
	// characters, never starting with `.` or `-` (so never `..`). It is the ONE
	// definition in Go. Three copies exist in other languages and are held equal to it
	// (and challengeid.Pattern to theirs) by evidence_grammar_test.go (ADR-0056 V52):
	// the two `regexMatch` literals of the chart's ctf-user.evidence.check that take a
	// challenge id, the one that takes a file name, and gen-values.sh's
	// EVIDENCE_NAME_RE.
	NamePattern = `^[a-z0-9][a-z0-9._-]{0,62}$`

	// MaxBundleFiles is the most files one bundle (one seat, one challenge) holds (B2).
	MaxBundleFiles = 64
	// MaxBundleBytes is the most bytes one bundle holds, summed over its files (B2,
	// D11: also a Kubernetes Secret's size per challenge).
	MaxBundleBytes = 512 << 10
	// MaxSeatBytes is the most bytes the bundles of ONE seat hold, summed over every
	// challenge (D11: half of plant-seed's sizeLimit of 4 MiB). deploy-user counts the
	// same, per seat, before it touches a cluster.
	MaxSeatBytes = 2 << 20

	// maxShownName bounds how much of an out-of-grammar entry name a message shows.
	maxShownName = 48
)

// RuleBundleShape is the rule name of D10 B2, which ReadBundles applies (the other
// bundle rules are in bundlecheck.go).
const RuleBundleShape = "B2"

var nameRE = regexp.MustCompile(NamePattern)

// ValidFileName reports whether name is a bundle file name (B2).
func ValidFileName(name string) bool { return nameRE.MatchString(name) }

// BundleFile is one file of a bundle. Name is the bare file name.
type BundleFile struct {
	Name string
	Data []byte
}

// Bundle is the files of one (seat, challenge) pair, in byte order of their names.
type Bundle struct {
	Seat  string
	CID   string
	Files []BundleFile
}

// Digest is the canonical digest of the bundle (BundleDigest). Of a bundle that
// ReadBundles returned with a non-nil error it is the digest of the files that were read
// (a file over a limit or of a refused kind is not among them): never use it as a digest
// of the tree.
func (b *Bundle) Digest() string { return BundleDigest(b.Files) }

// BundleDigest is the one definition of a bundle's digest (ADR-0056 D9). Sort the
// files by name, byte order. For each file append  name + NUL + hex(sha256(content))
// + LF  (the hex is lower-case). The digest is the lower-case hex of the sha256 of
// that sequence; a bundle with no file is the sha256 of the empty sequence.
//
// The names are distinct and in the B2 grammar (a directory's entries, read by
// ReadBundles): neither NUL nor LF can occur in one, and the content enters as a fixed
// width hash, so the sequence cannot be read two ways. The function does not check the
// names; it sorts a copy, so the order of files does not matter. deploy-user.sh holds
// the one other implementation, and both run the shared case table
// testdata/bundle-digest (V16).
func BundleDigest(files []BundleFile) string {
	sorted := slices.Clone(files)
	slices.SortStableFunc(sorted, func(a, b BundleFile) int { return strings.Compare(a.Name, b.Name) })
	h := sha256.New()
	for _, f := range sorted {
		sum := sha256.Sum256(f.Data)
		_, _ = io.WriteString(h, f.Name)
		_, _ = h.Write([]byte{0})
		_, _ = io.WriteString(h, hex.EncodeToString(sum[:]))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Bundles is every bundle ReadBundles read, by (seat, challenge).
type Bundles struct {
	list  []*Bundle
	index map[cell]*Bundle
	seats []string
}

// Seats is every seat directory of the tree (a directory named like a seat), in byte
// order, whether or not it holds a bundle: an empty seat directory is a seat of the tree
// that B1 holds to the seat list.
func (bs *Bundles) Seats() []string { return bs.seats }

// All is every bundle, in byte order of (seat, cid).
func (bs *Bundles) All() []*Bundle { return bs.list }

// Get is the bundle of (seat, cid), or nil.
func (bs *Bundles) Get(seat, cid string) *Bundle { return bs.index[cell{seat: seat, cid: cid}] }

// ReadBundles reads the tree <root>/<seat>/<cid>/<file> and applies D10 B2 to it. The
// order of everything it reads and reports is the byte order of the names (os.ReadDir's
// order), so one tree gives one answer.
//
// B2 refused: an entry of the root that is not a directory named like a seat
// (identity.ValidSeat), an entry of a seat directory that is not a directory named like
// a challenge id (challengeid.Valid), and in a bundle anything but a regular file: a
// link, a directory (a bundle is flat) or a special file; a name outside NamePattern;
// more than MaxBundleFiles entries; a file or a bundle over MaxBundleBytes; the bundles
// of one seat over MaxSeatBytes together; a file that is not valid UTF-8 or that holds a
// rune sourcehygiene.Hidden reports. A limit is exact: the limit itself passes, one byte
// more is refused. A file over a limit is not read.
//
// The result is a non-nil *Bundles and an errors.Join of *Violation (at most
// maxViolations listed, the rest counted) when the tree is readable, nil error when it
// holds none; a root that cannot be read at all is (nil, error). A file with a content
// violation is kept in the result (the caller still checks it) and so is a bundle that
// holds no file: whether a bundle is complete is B1's, not B2's. When the error is not
// nil the digests of the Bundles are of a subset (the files that were not read are
// missing): they are not written to a digests file and not compared with one. The tree is the
// validator's own input, not a participant's: the checks are of a tree that was made
// wrong, not of one that is under attack while it is read.
func ReadBundles(root string) (*Bundles, error) {
	var c collector
	bs, err := readBundles(root, &c)
	if err != nil {
		return nil, err
	}
	return bs, c.err()
}

// readBundles is ReadBundles with the caller's collector, so that CheckBundles lists
// B2 together with its other rules under one bound.
func readBundles(root string, c *collector) (*Bundles, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("edition: evidence root: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("edition: evidence root is not a directory")
	}
	seatEntries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("edition: evidence root: %w", err)
	}
	out := &Bundles{index: make(map[cell]*Bundle)}
	for _, se := range seatEntries {
		seat := se.Name()
		if !identity.ValidSeat(seat) {
			c.add(entryViolation("an entry of the evidence root is not named like a seat (ADR-0042)", "", "", seat))
			continue
		}
		if !se.IsDir() {
			c.add(entryViolation("a seat entry of the evidence root is not a directory (a link or a file is refused)", seat, "", ""))
			continue
		}
		cidEntries, err := os.ReadDir(filepath.Join(root, seat))
		if err != nil {
			c.add(entryViolation("a seat directory cannot be read", seat, "", ""))
			continue
		}
		out.seats = append(out.seats, seat)
		budget := &seatBudget{}
		for _, ce := range cidEntries {
			cid := ce.Name()
			if !challengeid.Valid(cid) {
				c.add(entryViolation("an entry of a seat directory is not named like a challenge id", seat, "", cid))
				continue
			}
			if !ce.IsDir() {
				c.add(entryViolation("a challenge entry of a seat directory is not a directory (a link or a file is refused)", seat, cid, ""))
				continue
			}
			b := readBundleDir(filepath.Join(root, seat, cid), seat, cid, budget, c)
			out.list = append(out.list, b)
			out.index[cell{seat: seat, cid: cid}] = b
		}
	}
	sort.SliceStable(out.list, func(i, j int) bool {
		a, b := out.list[i], out.list[j]
		if a.Seat != b.Seat {
			return a.Seat < b.Seat
		}
		return a.CID < b.CID
	})
	return out, nil
}

// seatBudget is the bytes the bundles of one seat hold so far, and whether the
// MaxSeatBytes violation of that seat was reported already (once per seat).
type seatBudget struct {
	bytes int
	over  bool
}

// readBundleDir is the files of one bundle directory (see ReadBundles for the rules).
func readBundleDir(dir, seat, cid string, budget *seatBudget, c *collector) *Bundle {
	b := &Bundle{Seat: seat, CID: cid}
	report := func(msg, file string) { c.add(entryViolation(msg, seat, cid, file)) }
	entries, err := os.ReadDir(dir)
	if err != nil {
		report("the bundle directory cannot be read", "")
		return b
	}
	if len(entries) > MaxBundleFiles {
		report(fmt.Sprintf("the bundle has %d entries; the limit is %d files", len(entries), MaxBundleFiles), "")
		return b
	}
	bundleBytes, overBundle := 0, false
	for _, e := range entries {
		name := e.Name()
		info, err := e.Info()
		switch {
		case err != nil:
			report("a bundle entry cannot be read", name)
			continue
		case info.IsDir():
			report("a bundle is flat: a directory inside it is refused", name)
			continue
		case !info.Mode().IsRegular():
			report("a bundle holds regular files only: a link or a special file is refused", name)
			continue
		case !ValidFileName(name):
			report("the file name is outside the grammar "+NamePattern, name)
			continue
		case info.Size() > MaxBundleBytes:
			report("the file is larger than the limit of a bundle (512 KiB)", name)
			continue
		}
		bundleBytes += int(info.Size())
		budget.bytes += int(info.Size())
		if bundleBytes > MaxBundleBytes {
			if !overBundle {
				overBundle = true
				report("the bundle is larger than its limit (512 KiB)", "")
			}
			continue
		}
		if budget.bytes > MaxSeatBytes {
			if !budget.over {
				budget.over = true
				report("the bundles of this seat are larger than their limit together (2 MiB)", "")
			}
			continue
		}
		data, err := readCapped(filepath.Join(dir, name), MaxBundleBytes)
		if err != nil {
			report("the file cannot be read", name)
			continue
		}
		if !utf8.Valid(data) {
			report("the file is not valid UTF-8", name)
		} else if found := sourcehygiene.Hidden(data); len(found) > 0 {
			v := entryViolation("the file holds an invisible or bidi control character", seat, cid, name)
			v.Line = found[0].Line
			c.add(v)
		}
		b.Files = append(b.Files, BundleFile{Name: name, Data: data})
	}
	return b
}

// readCapped reads path, refusing a file of more than limit bytes (it never holds
// more than limit+1 in memory). The file is opened by openRegular (safeopen.go): a link, a
// file that is not a regular one and a file that was swapped after it was looked at are
// refused (ADR-0056 V57). It is the one reader of the files of a bundle, of a template and of
// the corpus.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file is larger than its limit")
	}
	return data, nil
}

// entryViolation is a B2 violation about an entry of the tree. seat and cid are named
// when they are in their grammar; file is the entry name, shown in the grammar or quoted.
func entryViolation(msg, seat, cid, file string) *Violation {
	return newBundleViolation(RuleBundleShape, msg, cell{seat: seat, cid: cid}, file)
}

// newBundleViolation is newViolation with a file (or entry) name. A name in the B2
// grammar is shown as it is; any other is shown quoted in ASCII and cut short, so a
// message never carries an invisible or bidi character from a file name.
func newBundleViolation(rule, msg string, c cell, file string) *Violation {
	v := newViolation(rule, msg, 0, c, nil)
	v.File = shownName(file)
	return v
}

func shownName(s string) string {
	if s == "" || ValidFileName(s) {
		return s
	}
	suffix := ""
	if len(s) > maxShownName {
		s, suffix = s[:maxShownName], "..."
	}
	return strconv.QuoteToASCII(s) + suffix
}
