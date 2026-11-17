package edition

// practiceoverlap.go is D10 B4 (ADR-0056, D19 A4c-2): an event edition must not be a
// practice edition of the image with the values changed. A public edition is known to
// every participant, so an event bundle or an event template that is one of them, or
// mostly one of them, is a bundle whose structure is public (the reason editions are split
// at all, D8). Three things are compared with what the image publishes:
//
//   - digests: a file of an event bundle, or the bundle, has the digest of a file / a bundle
//     of a practice edition (the same digest definitions as D9: sha256 of a file, BundleDigest
//     of a bundle);
//   - answers: a practice edition's answer, of any format, appears in an event bundle. ADR-0056
//     D10 B4 does not restrict the formats; narrowing it is for an addendum to the ADR. A
//     per-seat format is searched in every spelling that grading accepts (answerformat.Fold);
//     the others have no fold and their normalised value is searched as it is (a short value
//     can be a false hit, which is on the refusing side);
//   - shingles: the 10-rune shingles (hintleak.GramRunes, cut from hintleak.Normalize, the
//     rule of ADR-0026 D5 itself) of an event bundle against those of each practice bundle
//     (1, the outputs), and of an event template against each practice template (2, with the
//     slot marks {{ctf:...}} removed first: a filler that differs per seat lowers (1) and
//     leaves (2) alone, so a copied public template is caught by (2) only). The overlap of
//     an event set S_event with a practice set S_practice is |S_event intersect S_practice| /
//     |S_event|, and it is refused at or above theta.
//
// The input is explicit (overlapInput): the event bundles, the practice editions' files
// (readPracticeFiles) and answers (loadPractice's PracticeSet), and the event templates. The
// function is not wired into CheckBundles here: A4e makes it a step of the validator, with
// these inputs carried by CheckedTable (M2) and the event templates read from --edition-dir.
// It writes nothing: the largest overlaps are RETURNED (OverlapReport) for the caller to
// print (the command prints numbers and challenge ids to stderr, never a byte of a file).
//
// Like the rest of this package a violation names a rule, a seat, a challenge, a file and
// the id of a practice edition, and a number; never a value or a byte of content.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// RuleBundlePractice is the rule name of D10 B4.
const RuleBundlePractice = "B4"

// OverlapTheta is theta of B4 (D10, CISO 2026-11-16, provisional): an event bundle or
// template whose shingle overlap with a practice edition is at or above it is refused.
// practiceoverlap_internal_test.go pins the value (V19) and its boundary; changing it is the CISO's
// decision after the first event's measurements (Signpost 6), and changes this constant and
// that pin together.
const OverlapTheta = 0.5

// markFault is the first `{{ctf:` of a template that is not a mark (slotmark.go, ScanMarks:
// the one definition of the grammar of a mark): the file it is in and its line. B4 refuses
// such a template; it neither leaves the text in nor takes it out. It holds no content.
type markFault struct {
	file string
	line int
}

// markViolation is B4's violation for a markFault: the rule, a sentence, the line, and the
// name of the file as the bundle rules show a name (never a byte of the template).
func markViolation(msg string, c cell, f *markFault) *Violation {
	v := newViolation(RuleBundlePractice, msg, f.line, c, nil)
	v.File = shownName(f.file)
	return v
}

// OverlapPair is the largest overlap of one comparison and the pair it is of.
type OverlapPair struct {
	// Rate is |S_event intersect S_practice| / |S_event| of the pair with the largest rate,
	// 0 when nothing overlaps (or nothing was compared).
	Rate float64
	// Event is what the rate is of: "<seat>/<cid>" for the outputs, "<cid>" for the
	// templates. Practice is the id of the practice edition it was compared with. Both are
	// empty when Rate is 0.
	Event    string
	Practice string
	// Compared is how many (event, practice edition) pairs were compared.
	Compared int
}

// OverlapReport is what B4 measured: for the caller to print as numbers and ids. It holds
// no content.
type OverlapReport struct {
	// Output is (1), the event bundles against the practice bundles.
	Output OverlapPair
	// Template is (2), the event templates against the practice templates.
	Template OverlapPair
}

// overlapInput is B4's input besides the event bundles.
type overlapInput struct {
	// Practice is the files of the image's practice editions (readPracticeFiles). nil is
	// "not supplied" and a refusal. An empty map, or editions with no bundle / no template,
	// is a refusal too whenever there is an event bundle / template to compare: B4 compared
	// nothing, which is not "no overlap". An image with no investigate challenge has no event
	// edition either, and the caller (A4e) does not call B4 for it.
	Practice practiceFiles
	// Answers is the practice editions' answers (loadPractice's PracticeSet). nil is "not
	// supplied": the answers part of B4 cannot run, and that is a refusal.
	Answers PracticeSet
	// Templates is the event edition's template files, by challenge id. None at all is a
	// refusal (the comparison (2) would compare nothing); so is a challenge that has a
	// bundle and no entry here, and a challenge whose files have no 10-rune shingle left
	// once the slot marks are removed.
	Templates map[string][]BundleFile
}

// checkPracticeOverlap applies B4 to the event bundles with the given theta (the caller
// passes OverlapTheta; the parameter is what lets a test show the refusal of an unset one).
// A theta that is not in (0, 1] (zero, negative, NaN, above 1) is a violation, and no
// overlap is then compared with it: a threshold that is not set never accepts. Everything
// else is still checked and the report still filled.
//
// Violations, in this order: those of the inputs, then for each bundle in the order of
// Bundles.All the digest, the answer and the output overlap, then for each event template
// in byte order of its challenge id the template overlap. A bundle with no file is B1's,
// not reported here. An event set with no shingle (every file is shorter than 10 runes
// once the whitespace is out, or a template is all marks) is a violation, not a rate of
// 0 / 0: nothing can be said of it, and fail-closed is a refusal.
func checkPracticeOverlap(c *collector, bundles *Bundles, in overlapInput, theta float64) OverlapReport {
	var rep OverlapReport
	b4 := func(msg, seat, cid string) {
		c.add(newViolation(RuleBundlePractice, msg, 0, cell{seat: seat, cid: cid}, nil))
	}

	thetaSet := theta > 0 && theta <= 1 // false for NaN
	if !thetaSet {
		b4("the overlap threshold theta is not a number in (0, 1], so B4 cannot decide (it refuses and does not skip)", "", "")
	}
	if in.Practice == nil {
		b4("the practice editions' files were not supplied, so B4 cannot run", "", "")
		return rep
	}
	if bundles == nil {
		b4("no event bundle was supplied, so B4 has nothing to compare", "", "")
		return rep
	}
	if in.Answers == nil {
		b4("the practice answers were not supplied, so the answer part of B4 cannot run", "", "")
	} else {
		checkEmptyPracticeAnswers(c, in.Answers)
	}
	nBundles := 0 // how many bundles have a file; withFiles is the challenges of those
	withFiles := make(map[string]struct{})
	for _, b := range bundles.All() {
		if len(b.Files) > 0 {
			withFiles[b.CID] = struct{}{}
			nBundles++
		}
	}
	if len(in.Templates) == 0 {
		b4("no event template was supplied, so the template overlap (2) of B4 cannot run", "", "")
	} else {
		// every challenge that has a bundle needs its template: a challenge that is not in
		// Templates would be skipped without a word, and a copied template would pass
		for _, cid := range slices.Sorted(maps.Keys(withFiles)) {
			if _, ok := in.Templates[cid]; !ok {
				b4("no event template was supplied for this challenge, so its template overlap (2) cannot be computed", "", cid)
			}
		}
	}

	// What the image publishes, in byte order of the practice challenge id (a digest that
	// two editions share is named after the first).
	fileDigests := make(map[string]string)   // sha256 hex of a practice evidence file -> edition id
	bundleDigests := make(map[string]string) // BundleDigest of a practice bundle -> edition id
	outputs, templates := newShingleIndex(), newShingleIndex()
	for _, pid := range slices.Sorted(maps.Keys(in.Practice)) {
		ed := in.Practice[pid]
		if ed == nil {
			continue
		}
		if len(ed.Evidence) > 0 {
			setOnce(bundleDigests, BundleDigest(ed.Evidence), pid)
			for _, f := range ed.Evidence {
				setOnce(fileDigests, fileDigest(f.Data), pid)
			}
			set, _ := shingleSet(ed.Evidence, false) // no marks are read in an output: no fault
			outputs.add(pid, set)
		}
		if len(ed.Template) > 0 {
			set, fault := shingleSet(ed.Template, true)
			if fault != nil {
				// A practice template (a public file of the image) that the lexer cannot read is
				// not indexed, and not compared by a guess: B4 refuses it.
				c.add(markViolation("a template of practice edition "+practiceRef(pid)+" holds a "+MarkOpen+" that is not a mark, so B4 cannot read it", cell{}, fault))
			} else {
				templates.add(pid, set)
			}
		}
	}
	// Fail-closed: an event side with nothing to compare it with is not a pass. No practice
	// edition (or none with a bundle / a template) makes (1) / (2) compare nothing, and that
	// must not read as "no overlap". Whether to call B4 at all for an image with no
	// investigate challenge is the caller's decision (A4e), not this function's.
	if nBundles > 0 && len(outputs.ids) == 0 {
		b4("no practice edition has a bundle, so the output overlap (1) of B4 compared nothing", "", "")
	}
	if len(in.Templates) > 0 && len(templates.ids) == 0 {
		b4("no practice edition has a template, so the template overlap (2) of B4 compared nothing", "", "")
	}

	for _, b := range bundles.All() {
		if len(b.Files) == 0 {
			continue
		}
		where := cell{seat: b.Seat, cid: b.CID}

		// the digests
		if pid, ok := bundleDigests[b.Digest()]; ok {
			b4("the digest of the bundle is the digest of the bundle of practice edition "+practiceRef(pid), b.Seat, b.CID)
		} else {
			for _, f := range b.Files {
				if pid, ok := fileDigests[fileDigest(f.Data)]; ok {
					c.add(newBundleViolation(RuleBundlePractice, "the digest of the file is the digest of a file of the bundle of practice edition "+practiceRef(pid), where, f.Name))
					break
				}
			}
		}

		// the answers
		if in.Answers != nil {
			hit, err := holdsPracticeAnswer(b, in.Answers)
			switch {
			case err != nil:
				c.add(newViolation(RuleBundlePractice, "a bundle could not be folded for a practice answer, so B4 cannot run on it", 0, where, err))
			case hit:
				b4("an answer of a practice edition appears in the bundle", b.Seat, b.CID)
			}
		}

		// the shingles, (1)
		set, _ := shingleSet(b.Files, false) // no marks are read in an output: no fault
		if len(set) == 0 {
			b4("the bundle has no 10-rune sequence, so its overlap with the practice editions cannot be computed", b.Seat, b.CID)
			continue
		}
		rate, pid := outputs.best(set)
		rep.Output.Compared += len(outputs.ids)
		if rate > rep.Output.Rate {
			rep.Output.Rate, rep.Output.Event, rep.Output.Practice = rate, b.Seat+"/"+b.CID, pid
		}
		if thetaSet && rate >= theta {
			b4(overlapMessage("the 10-rune shingle overlap (outputs) of the bundle with practice edition", pid, rate, theta), b.Seat, b.CID)
		}
	}

	// the shingles, (2)
	for _, cid := range slices.Sorted(maps.Keys(in.Templates)) {
		files := in.Templates[cid]
		if len(files) == 0 {
			b4("the event template of this challenge has no file, so its overlap with the practice templates cannot be computed", "", cid)
			continue
		}
		set, fault := shingleSet(files, true)
		if fault != nil {
			// The event template reached the validator as it is (the validator does not trust
			// the renderer): a `{{ctf:` that is not a mark is a refusal, not text to shingle.
			c.add(markViolation("the event template of this challenge holds a "+MarkOpen+" that is not a mark, so its overlap with the practice templates cannot be computed", cell{cid: cid}, fault))
			continue
		}
		if len(set) == 0 {
			b4("the event template of this challenge has no 10-rune sequence outside its slot marks, so its overlap with the practice templates cannot be computed", "", cid)
			continue
		}
		rate, pid := templates.best(set)
		rep.Template.Compared += len(templates.ids)
		if rate > rep.Template.Rate {
			rep.Template.Rate, rep.Template.Event, rep.Template.Practice = rate, cid, pid
		}
		if thetaSet && rate >= theta {
			b4(overlapMessage("the 10-rune shingle overlap (templates) of the event template with the template of practice edition", pid, rate, theta), "", cid)
		}
	}
	return rep
}

// overlapMessage is a violation's sentence for an overlap: the id of a practice edition
// and two numbers, nothing of any content.
func overlapMessage(what, pid string, rate, theta float64) string {
	return fmt.Sprintf("%s %s is %.3f, at or above theta %.3f", what, practiceRef(pid), rate, theta)
}

// practiceRef is a practice edition's id as a message names it: only an id inside the
// challenge-id grammar (the ids come from the catalog, which holds them to it).
func practiceRef(pid string) string {
	if challengeid.Valid(pid) {
		return pid
	}
	return "(an id outside the challenge-id grammar)"
}

func fileDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// setOnce records k -> v unless k is there already.
func setOnce(m map[string]string, k, v string) {
	if _, ok := m[k]; !ok {
		m[k] = v
	}
}

// holdsPracticeAnswer reports whether a file of b holds an answer of a practice edition,
// of any format (ADR-0056 D10 B4 does not restrict the formats). The answer, in its
// normalised form, is searched in the file as a substring. For a format that varies per seat
// the file is folded first (answerformat.Fold), so every spelling that grading accepts is
// found; a format that does not (technique, choice-set, sequence) has no fold, and its
// normalised value is searched in the file as it is. A short value of such a format can be a
// false hit in free text; that is on the refusing side, and narrowing it is for an addendum
// to the ADR, not for this function. An empty value is skipped here (it would match every
// file); checkEmptyPracticeAnswers refuses it once, as an input defect.
//
// The error is Fold's, and only a per-seat format reaches Fold: it is ErrNoFold only for a
// per-seat format that has no fold, which internal/catalog/answerformat/fold_test.go (TestFold_IsDefinedForExactlyThePerSeatFormats: every per-seat format has one) makes
// unreachable today. It stays a returned error so that a format added without a fold is a
// refusal and not a silent skip.
func holdsPracticeAnswer(b *Bundle, answers PracticeSet) (bool, error) {
	for _, format := range slices.Sorted(maps.Keys(answers)) {
		perSeat := answerformat.PerSeat(format)
		for _, f := range b.Files {
			text := f.Data
			if perSeat {
				folded, err := answerformat.Fold(format, f.Data)
				if err != nil {
					return false, err
				}
				text = folded
			}
			for v := range answers[format] {
				if v != "" && bytes.Contains(text, []byte(v)) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// checkEmptyPracticeAnswers refuses an empty practice answer, once: loadPractice's values
// are canonical and so never empty, and an empty one would mean the answers were not read
// as they should be (fail-closed: B4 cannot say that no practice answer is in a bundle).
func checkEmptyPracticeAnswers(c *collector, answers PracticeSet) {
	for _, format := range slices.Sorted(maps.Keys(answers)) {
		if _, empty := answers[format][""]; empty {
			c.add(newViolation(RuleBundlePractice, "a practice answer is empty, so the answer part of B4 cannot look for it", 0, cell{}, nil))
			return
		}
	}
}

// shingleSet is the distinct 10-rune shingles of the files, each file cut by itself (a run
// that straddles two files is in neither, as in hintleak.Check). With stripMarks the slot
// marks are taken out first, and the file is read by the lexer of the marks (ScanMarks, the
// one definition of a mark): the literal parts are joined and what the marks were is gone.
// A `{{ctf:` that is not a mark makes the whole call fail (nil set and the first fault, in
// the order of files): a template that cannot be read is never shingled with the text left
// in or with the text guessed out. Without stripMarks the files are not scanned, and the
// fault is always nil. The windows are hintleak's (hintleak.Normalize, then windows of
// hintleak.GramRunes runes): there is no second definition of what a run of runes is, only
// this loop over its result. The loop cuts the windows the way hintleak's gramSet does; a
// parity test that ties the two together is for the next change to hintleak.
func shingleSet(files []BundleFile, stripMarks bool) (map[string]struct{}, *markFault) {
	set := make(map[string]struct{})
	for _, f := range files {
		text := string(f.Data)
		if stripMarks {
			parts, err := ScanMarks(f.Data)
			if err != nil {
				// A MarkError is the only error ScanMarks returns; without its line the fault
				// is still a fault (line 0 is "not known").
				var me *MarkError
				line := 0
				if errors.As(err, &me) {
					line = me.Line
				}
				return nil, &markFault{file: f.Name, line: line}
			}
			var lits []byte
			for _, p := range parts {
				lits = append(lits, p.Lit...)
			}
			text = string(lits)
		}
		runes := hintleak.Normalize(text)
		for i := 0; i+hintleak.GramRunes <= len(runes); i++ {
			set[string(runes[i:i+hintleak.GramRunes])] = struct{}{}
		}
	}
	return set, nil
}

// shingleIndex maps a shingle to the practice editions that hold it, so that the overlap of
// one event set with every practice edition is one pass over the event set.
type shingleIndex struct {
	ids  []string         // the practice editions that were added, in the order they were
	gram map[string][]int // shingle -> indexes into ids
}

func newShingleIndex() *shingleIndex { return &shingleIndex{gram: make(map[string][]int)} }

// add records the shingles of practice edition id.
func (x *shingleIndex) add(id string, set map[string]struct{}) {
	i := len(x.ids)
	x.ids = append(x.ids, id)
	for g := range set {
		x.gram[g] = append(x.gram[g], i)
	}
}

// best is the largest |set intersect S_practice| / |set| over the practice editions, and the
// id of the edition it is of (the first one added when two are equal). It is 0 and "" when
// set is empty, no edition was added, or nothing overlaps.
func (x *shingleIndex) best(set map[string]struct{}) (float64, string) {
	if len(set) == 0 || len(x.ids) == 0 {
		return 0, ""
	}
	counts := make([]int, len(x.ids))
	for g := range set {
		for _, i := range x.gram[g] {
			counts[i]++
		}
	}
	bestIndex, bestCount := -1, 0
	for i, n := range counts {
		if n > bestCount {
			bestIndex, bestCount = i, n
		}
	}
	if bestIndex < 0 {
		return 0, ""
	}
	return float64(bestCount) / float64(len(set)), x.ids[bestIndex]
}
