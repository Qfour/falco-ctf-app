package edition

// bundlecheck.go is the validator's side of the bundles (ADR-0056 D10 B1, B2, B3, B5,
// B6, B9; D19 A4b). The rules that need a bundle are checked here because the
// scoreboard has no bundle: it holds the answers table only (D10, last paragraph). B4
// (the practice editions), B7 and B8 (the renderer's vocabulary, the decoys) are later
// stages, and the `edition check` command that calls CheckBundles is A4e.
//
// Like Check, nothing here returns, formats or logs a table value or a byte of a
// bundle: a violation names a rule, a seat, a challenge, a question, a file name.

import (
	"bytes"
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/sourcehygiene"
)

// The rule a bundle Violation belongs to (ADR-0056 D10). B2's is RuleBundleShape, in
// bundle.go with the reader that applies it.
const (
	RuleBundleSet    = "B1"
	RuleBundleFlag   = "B3"
	RuleBundleHint   = "B5"
	RuleBundleAnswer = "B6"
	RuleBundleCorpus = "B9"
)

// BundleInput is what the bundle checks need besides the tree.
type BundleInput struct {
	// Table is the parsed answers table (Parse, then Check, by the caller: a table
	// that Check refused is not given here). B6 and B9 read its per-seat values.
	Table *Table
	// Scope is the investigate challenges of the event (ScopeOf).
	Scope Scope
	// Seats is `--seats`: the roster plus the spare seats. B1 holds the table's seats
	// and the tree's seats equal to it.
	Seats []string
	// FlagValues are the values of this event's flags file (B3).
	FlagValues []string
	// Hints and Free are hintleak's inputs for the scope: every hint text, and the
	// texts a participant sees without paying (ADR-0026 D5-1; the questions' prompts
	// are Free items). The caller assembles them once; this package does not know
	// where they come from. B5 scans the files of the bundles against them.
	Hints []hintleak.Item
	Free  []hintleak.Item
	// Corpus is what B9 scans (ReadCorpus). Empty is refused: B9 would check nothing.
	Corpus Corpus
}

// CheckBundles reads the tree under root (<root>/<seat>/<cid>/<file>, ReadBundles) and
// applies D10 B1, B2, B3, B5, B6 and B9. It returns the digest of every bundle, in byte
// order of (seat, cid), only when every rule is met; otherwise it returns an
// errors.Join of *Violation, at most maxViolations listed in this order (the rest
// counted), and no rows. It does not stop at the first violation. A root that cannot be
// read is (nil, error) with no violation.
//
//   - B2: the tree's shape and limits (ReadBundles), in the order of the tree.
//   - B1: the seats of the table and of the tree are exactly `Seats`; every (seat,
//     challenge of the scope) has a bundle of at least one file and the tree has no other
//     bundle. (An empty directory is not a bundle: the chart refuses a bundle with no file
//     name, D11.)
//   - B3: no file holds a flag shape (catalog.MentionsFlag: FALCO{, its dev placeholders
//     and a flag regexp's matches) or one of FlagValues.
//   - B6: the answer of every per-seat question appears in a file of its own seat's
//     bundle (the least that shows the answer can be derived from it).
//   - B5: hintleak.Check over the files, as Targets, finds no 10-rune sequence that is in
//     a hint and in no free text (one violation per file, with the count). A hintleak
//     input it cannot scan (no hint) is a violation too: a scan of nothing proves nothing.
//   - B9: no per-seat answer appears in any file of the Corpus.
//
// The final guard re-checks the digests against Seats x the scope (CheckDigestSet, V48):
// B1 makes it unreachable, and it stays so that the one place that makes digests cannot
// make a set that deploy-user would refuse.
func CheckBundles(root string, in BundleInput) ([]DigestRow, error) {
	if in.Table == nil {
		return nil, ErrTableMissing
	}
	var c collector
	bundles, err := readBundles(root, &c)
	if err != nil {
		return nil, err
	}
	checkSeatSet(&c, in, bundles)
	checkBundleFlags(&c, in, bundles)
	checkAnswersInBundles(&c, in, bundles)
	checkBundleHints(&c, in, bundles)
	checkCorpus(&c, in)
	if err := c.err(); err != nil {
		return nil, err
	}
	rows := bundles.digestRows()
	if err := CheckDigestSet(rows, in.Seats, in.Scope); err != nil {
		return nil, err
	}
	return rows, nil
}

// digestRows is the digest of every bundle, in the order of All.
func (bs *Bundles) digestRows() []DigestRow {
	rows := make([]DigestRow, 0, len(bs.list))
	for _, b := range bs.list {
		rows = append(rows, DigestRow{Seat: b.Seat, CID: b.CID, Digest: b.Digest()})
	}
	return rows
}

// checkSeatSet is B1. A bundle with no file is reported here, as B1's "every (seat,
// investigate challenge of the scope) has a bundle" (an empty directory is not a bundle:
// the chart needs 1 to 64 names, D11). B2 only bounds the other side, at most 64 files.
func checkSeatSet(c *collector, in BundleInput, bundles *Bundles) {
	b1 := func(msg string, seat, cid string) {
		c.add(newViolation(RuleBundleSet, msg, 0, cell{seat: seat, cid: cid}, nil))
	}
	if len(in.Seats) == 0 {
		b1("the seat list is empty", "", "")
	}
	want := make(map[string]struct{}, len(in.Seats))
	for _, s := range in.Seats {
		if !identity.ValidSeat(s) {
			b1("a seat of the seat list is outside the seat grammar (ADR-0042)", s, "")
			continue
		}
		if _, dup := want[s]; dup {
			b1("a seat is listed twice in the seat list", s, "")
		}
		want[s] = struct{}{}
	}

	inTable := make(map[string]struct{})
	for _, s := range in.Table.Seats() {
		inTable[s] = struct{}{}
		if _, ok := want[s]; !ok {
			b1("a seat of the answers table is not in the seat list", s, "")
		}
	}
	seats := sortedKeys(want)
	for _, s := range seats {
		if _, ok := inTable[s]; !ok {
			b1("a seat of the seat list has no row in the answers table", s, "")
		}
	}

	for _, s := range seats {
		for _, cid := range in.Scope.sortedCIDs() {
			switch b := bundles.Get(s, cid); {
			case b == nil:
				b1("this seat has no bundle for this challenge", s, cid)
			case len(b.Files) == 0:
				b1("the bundle of this seat and challenge has no file", s, cid)
			}
		}
	}
	for _, b := range bundles.All() {
		if _, ok := want[b.Seat]; !ok {
			b1("the tree has a bundle of a seat that is not in the seat list", b.Seat, b.CID)
			continue
		}
		if _, ok := in.Scope[b.CID]; !ok {
			b1("the tree has a bundle of a challenge that is not an investigate challenge of the scope", b.Seat, b.CID)
		}
	}
}

// checkBundleFlags is B3.
func checkBundleFlags(c *collector, in BundleInput, bundles *Bundles) {
	for _, b := range bundles.All() {
		for _, f := range b.Files {
			text := string(f.Data)
			if catalog.MentionsFlag(text) || containsAny(text, in.FlagValues) {
				c.add(newBundleViolation(RuleBundleFlag, "the file holds a flag shape or a value of this event's flags", cell{seat: b.Seat, cid: b.CID}, f.Name))
			}
		}
	}
}

// checkAnswersInBundles is B6. A bundle with no file is B1's, not reported again here.
func checkAnswersInBundles(c *collector, in BundleInput, bundles *Bundles) {
	for _, b := range bundles.All() {
		if len(b.Files) == 0 {
			continue
		}
		for _, q := range in.Scope[b.CID] {
			if !answerformat.PerSeat(q.Format) {
				continue
			}
			k := cell{seat: b.Seat, cid: b.CID, qid: q.ID}
			i, ok := in.Table.index[k]
			if !ok {
				continue // no row for it: T4's (Check), not B6's
			}
			if !bundleHolds(b, in.Table.rows[i].value) {
				c.add(newViolation(RuleBundleAnswer, "the answer of a per-seat question does not appear in the bundle of its seat", 0, k, nil))
			}
		}
	}
}

// bundleHolds reports whether a file of b contains value.
func bundleHolds(b *Bundle, value string) bool {
	needle := []byte(value)
	for _, f := range b.Files {
		if bytes.Contains(f.Data, needle) {
			return true
		}
	}
	return false
}

// bundleFileRef names a file that was given to hintleak as a Target.
type bundleFileRef struct {
	seat, cid, name string
}

// checkBundleHints is B5. The files that are not valid UTF-8 or hold a hidden rune are
// not given to hintleak (it refuses the whole scan for one): B2 reported them already.
func checkBundleHints(c *collector, in BundleInput, bundles *Bundles) {
	var targets []hintleak.Item
	refs := make(map[string]bundleFileRef)
	for _, b := range bundles.All() {
		for _, f := range b.Files {
			if !utf8.Valid(f.Data) || len(sourcehygiene.Hidden(f.Data)) > 0 {
				continue
			}
			src := b.Seat + "/" + b.CID + "/" + f.Name
			refs[src] = bundleFileRef{seat: b.Seat, cid: b.CID, name: f.Name}
			targets = append(targets, hintleak.Item{Source: src, Text: string(f.Data)})
		}
	}
	if len(targets) == 0 {
		return // no file to scan: B1 and B2 report what is missing
	}
	vs, err := hintleak.Check(hintleak.Input{Hints: in.Hints, Free: in.Free, Targets: targets})
	if err != nil {
		v := newViolation(RuleBundleHint, "the hintleak scan of the bundles could not run", 0, cell{}, err)
		c.add(v)
		return
	}
	// hintleak.Check reports one (file, sequence) pair at a time, sorted by file: group
	// them into one violation per file. The sequence itself is never put in a message.
	count := make(map[string]int)
	var order []string
	for _, v := range vs {
		if count[v.Target] == 0 {
			order = append(order, v.Target)
		}
		count[v.Target]++
	}
	sort.Strings(order)
	for _, src := range order {
		ref := refs[src]
		msg := fmt.Sprintf("the file holds %d 10-rune sequence(s) that are in a hint of the scope and in no text shown without paying", count[src])
		c.add(newBundleViolation(RuleBundleHint, msg, cell{seat: ref.seat, cid: ref.cid}, ref.name))
	}
}

// checkCorpus is B9.
func checkCorpus(c *collector, in BundleInput) {
	if len(in.Corpus) == 0 {
		c.add(newViolation(RuleBundleCorpus, "the image's challenges and scenarios were not supplied, so B9 cannot run", 0, cell{}, nil))
		return
	}
	found := make(map[string]bool)
	for _, r := range in.Table.rows {
		q, ok := findQuestion(in.Scope[r.c.cid], r.c.qid)
		if !ok || !answerformat.PerSeat(q.Format) {
			continue
		}
		hit, seen := found[r.value]
		if !seen {
			hit = corpusHolds(in.Corpus, r.value)
			found[r.value] = hit
		}
		if hit {
			c.add(newViolation(RuleBundleCorpus, "a per-seat answer appears in a file of the image's challenges or scenarios", r.line, r.c, nil))
		}
	}
}

// corpusHolds reports whether a file of corpus contains value.
func corpusHolds(corpus Corpus, value string) bool {
	needle := []byte(value)
	for _, data := range corpus {
		if bytes.Contains(data, needle) {
			return true
		}
	}
	return false
}

// sortedCIDs is the challenge ids of s in byte order.
func (s Scope) sortedCIDs() []string {
	out := make([]string, 0, len(s))
	for cid := range s {
		out = append(out, cid)
	}
	sort.Strings(out)
	return out
}

// sortedKeys is the keys of set in byte order.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
