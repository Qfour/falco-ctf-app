package edition

// crosschallenge.go is D10 B13 to B16 (ADR-0056 amendment 26, with the limits of amendment 28;
// D19 A7-x, PR 3): the rules between the investigate challenges of one scope. D1 (ii) and the
// rules of a bundle (B1 to B12) look at one challenge at a time; these look at two.
//
//   - B13: for one seat, a per-seat answer of challenge X is in no file of the bundle of another
//     challenge Y of the scope, for every ordered pair (X, Y). The value is searched as B6 searches
//     it (bundleHolds: the normalised value as a substring), in the file folded for the answer's
//     format first (answerformat.Fold, as B9 folds a corpus: a name is not folded, a hexid's
//     capitals, a path's runs of slashes and a timestamp's +00:00 are), so every spelling that
//     grading accepts is found. Grading tells a name's capitals apart, so a copy of a name in
//     other capitals is not an accepted spelling and is not caught here (E2 does not hold a name's
//     vocabulary to lower case): the review's. Only the value is compared: a leak that can be derived (a table
//     of correspondences) is the review's (amendment 28).
//   - B14: a file that two templates have in common is declared in the public catalog
//     (catalog.Evidence.Shares, on either side). A declared pair is the same bytes in both
//     templates, and neither holds a slot mark. A pair of files of two challenges that is not
//     declared is refused when its bytes are the same, or when the 10-rune shingle overlap of the
//     two files, with the marks taken out (shingleSet, the sets of B4's (2)), is at or above
//     OverlapTheta in either direction (amendment 28: a copy one byte off). Every pair of files
//     counts, whatever their names, so a copy cannot pass under another name.
//   - B15: when Y declares the timeline of X (catalog.Evidence.Timeline), every literal time of
//     Y's template is a literal time of X's template, as a string. A literal time is a word (B7's
//     TOKEN, templateTokens) outside every mark that is a timestamp word (isTimestampWord: RFC
//     3339, UTC, at second precision). A time written otherwise is not one (amendment 28: it is
//     the review's to keep such a time out of a record the timeline depends on).
//   - B16: no literal time of a challenge's template, nor of the template of a challenge it shares
//     a timeline with (either side of a declaration of B15), lies in the window
//     [time.base + from, time.base + to) of one of its answer slots.
//
// A declaration that names a challenge outside the scope is not compared, and is not a refusal:
// that challenge is not played in the event, and no seat has a bundle of it (B1 refuses a bundle of
// a challenge that is not an investigate challenge of the scope), so there is no second bundle for
// a value, a file or a time to be shared with. The rules between the challenges that ARE in the
// scope are applied in full whatever is declared (an undeclared pair of B14 is refused). A
// declaration that names a challenge the catalog does not have, or one that is not an
// investigate challenge, is refused when the catalog is loaded (catalog.checkEvidencePartners),
// so the declaration is never left unchecked. The one function is applied to an event (CheckEvent: the event's templates, the
// answers table and the bundles) and to the practice editions of the image (the tests: the
// committed templates, the practice answers and bundles, seat *).
//
// Like the rest of the validator it holds no key, draws nothing and does not reach the renderer
// (render_reach_test.go). It is given the plaintext answers (SeatAnswers, which prints as a fixed
// string), so who may call it is fixed (crosschallenge_source_test.go). A violation names a rule,
// a seat, a challenge, a question, a slot, a file, a line and the id of the other challenge and
// of its file; never a value, a time or a byte of a file.

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

// The rules of D10 between the investigate challenges of a scope (amendment 26).
const (
	RuleCrossAnswer   = "B13"
	RuleCrossShare    = "B14"
	RuleCrossTimeline = "B15"
	RuleCrossWindow   = "B16"
)

// CrossChallenge is one investigate challenge of a scope as B13 to B16 read it.
type CrossChallenge struct {
	// Questions are the catalog's questions of the challenge (B13 reads the per-seat ones).
	Questions []catalog.Question
	// Evidence is the catalog's evidence block: Shares (B14) and Timeline (B15, B16).
	Evidence catalog.Evidence
	// Spec is the challenge's edition.yaml as ParseSpec read it (B16: time.base and the windows
	// of the answer slots).
	Spec *Spec
	// Template is the files of the edition's template (B14, B15, B16).
	Template []BundleFile
	// Bundles are the challenge's bundles, one per seat (B13 looks in them for the answers of
	// the other challenges of the same seat).
	Bundles []*Bundle
	// Answers is the answers table's value of each seat and question of the challenge (B13).
	Answers SeatAnswers
}

// CrossReport is what B13 to B16 compared, for a caller (a test) to hold to "not nothing". It
// holds counts only.
type CrossReport struct {
	// AnswerPairs is how many (seat, X, Y) B13 compared: the answers of X of a seat with the
	// bundle of Y of the same seat.
	AnswerPairs int
	// Shared is how many declared pairs of files B14 held to their declaration, and FilePairs
	// how many pairs of files of two challenges it compared as not declared.
	Shared    int
	FilePairs int
	// Timelines is how many declarations of B15 (both challenges in the scope) were held.
	Timelines int
	// Windows is how many windows of answer slots B16 looked into.
	Windows int
}

// CheckCrossChallenge applies B13 to B16 to the investigate challenges of one scope (challenge
// id -> its inputs). It returns what it compared, and nil or an errors.Join of *Violation (at most
// maxViolations listed: an input that is missing or cannot be read, then B13, B14, B15 and B16,
// each in byte order of the challenge ids). No challenge at all is a refusal (the rules would
// compare nothing); one challenge has no pair, and B16 is still applied to it.
func CheckCrossChallenge(chs map[string]*CrossChallenge) (CrossReport, error) {
	var rep CrossReport
	var c collector
	var ids []string
	for _, id := range slices.Sorted(maps.Keys(chs)) {
		if chs[id] == nil {
			c.add(newViolation(RuleCrossAnswer, "a challenge of the scope was given without its inputs, so B13 to B16 cannot run on it", 0, cell{cid: id}, nil))
			continue
		}
		ids = append(ids, id)
	}
	if len(chs) == 0 {
		c.add(newViolation(RuleCrossAnswer, "no challenge was given, so B13 to B16 compare nothing", 0, cell{}, nil))
	}
	// The literal times of every template, read once (B15 and B16). A template that the lexer of
	// the marks refuses has none that can be known: it is refused, and left out of B15 and B16.
	lits := make(map[string][]literalTime, len(ids))
	for _, id := range ids {
		l, bad := literalTimes(chs[id].Template)
		if bad != "" {
			c.add(newBundleViolation(RuleCrossWindow, "the template has a "+MarkOpen+" that is not a mark, so its literal times cannot be read (B15 and B16 cannot run on it)", cell{cid: id}, bad))
			continue
		}
		lits[id] = l
	}
	checkCrossAnswers(&c, &rep, ids, chs)
	checkCrossShares(&c, &rep, ids, chs)
	checkCrossTimelines(&c, &rep, ids, chs, lits)
	checkCrossWindows(&c, &rep, ids, chs, lits)
	return rep, c.err()
}

// checkCrossAnswers is B13. A seat of X that Y has no bundle for is B1's, and a question of X
// that has no answer of the seat is T4's: neither is reported here. B13 that compared nothing
// while there are two challenges is a refusal.
func checkCrossAnswers(c *collector, rep *CrossReport, ids []string, chs map[string]*CrossChallenge) {
	for _, y := range ids {
		for _, b := range chs[y].Bundles {
			if b == nil || b.CID != y {
				c.add(newViolation(RuleCrossAnswer, "a bundle given for this challenge is missing or is of another challenge, so B13 cannot trust the bundles of it", 0, cell{cid: y}, nil))
				break
			}
		}
	}
	for _, x := range ids {
		X := chs[x]
		for _, y := range ids {
			if y == x {
				continue
			}
			bySeat := make(map[string]*Bundle, len(chs[y].Bundles))
			for _, b := range chs[y].Bundles {
				if b != nil && b.CID == y {
					bySeat[b.Seat] = b
				}
			}
			for _, seat := range slices.Sorted(maps.Keys(X.Answers)) {
				b := bySeat[seat]
				if b == nil {
					continue
				}
				rep.AnswerPairs++
				for _, q := range X.Questions {
					if !answerformat.PerSeat(q.Format) {
						continue
					}
					v, ok := X.Answers[seat][q.ID]
					if !ok {
						continue
					}
					where := cell{seat: seat, cid: x, qid: q.ID}
					if v == "" {
						c.add(newViolation(RuleCrossAnswer, "an answer is empty, so B13 cannot look for it", 0, where, nil))
						continue
					}
					file, err := foldedHolder(b, q.Format, v)
					switch {
					case err != nil:
						c.add(newViolation(RuleCrossAnswer, "a file of the bundle of challenge "+practiceRef(y)+" cannot be folded for the answer's format, so B13 cannot run on it", 0, where, err))
					case file != "":
						c.add(newBundleViolation(RuleCrossAnswer, "a per-seat answer of this challenge appears in a file of the bundle of challenge "+practiceRef(y)+" of the same seat", where, file))
					}
				}
			}
		}
	}
	if len(ids) >= 2 && rep.AnswerPairs == 0 {
		c.add(newViolation(RuleCrossAnswer, "no seat has both the answers of one challenge and the bundle of another, so B13 compared nothing", 0, cell{}, nil))
	}
}

// foldedHolder is the name of the first file of b that, folded for format (answerformat.Fold),
// holds value, or "". The error is Fold's: only a per-seat format reaches it, and every one has a
// fold (answerformat's fold_test.go), so it is a refusal and never a silent skip.
func foldedHolder(b *Bundle, format, value string) (string, error) {
	needle := []byte(value)
	for _, f := range b.Files {
		folded, err := answerformat.Fold(format, f.Data)
		if err != nil {
			return "", err
		}
		if bytes.Contains(folded, needle) {
			return f.Name, nil
		}
	}
	return "", nil
}

// sharedPair is a declared pair of B14: the file of that name of the templates of challenges a
// and b, a before b in byte order.
type sharedPair struct {
	a, b, file string
}

func newSharedPair(x, y, file string) sharedPair {
	if y < x {
		x, y = y, x
	}
	return sharedPair{a: x, b: y, file: file}
}

// checkCrossShares is B14.
func checkCrossShares(c *collector, rep *CrossReport, ids []string, chs map[string]*CrossChallenge) {
	declared := make(map[sharedPair]bool)
	for _, y := range ids {
		for i, s := range chs[y].Evidence.Shares {
			if !ValidFileName(s.File) {
				v := newViolation(RuleCrossShare, "a declared shared file is outside B2's grammar of a bundle's file name "+NamePattern, 0, cell{cid: y}, nil)
				v.At = fmt.Sprintf("investigate.evidence.shares[%d].file", i)
				c.add(v)
				continue
			}
			if !slices.Contains(ids, s.With) || s.With == y {
				// A challenge outside the scope: no seat has a bundle of it (B1), so there is no
				// second side (see the header). The catalog refused a challenge it does not have.
				continue
			}
			declared[newSharedPair(y, s.With, s.File)] = true
		}
	}

	// The declared pairs: the same bytes on both sides, and no mark in either.
	pairs := slices.SortedFunc(maps.Keys(declared), func(p, q sharedPair) int {
		switch {
		case p.a != q.a:
			return strings.Compare(p.a, q.a)
		case p.b != q.b:
			return strings.Compare(p.b, q.b)
		}
		return strings.Compare(p.file, q.file)
	})
	for _, p := range pairs {
		rep.Shared++
		fa, fb := templateFile(chs[p.a].Template, p.file), templateFile(chs[p.b].Template, p.file)
		for _, side := range []struct {
			cid, other string
			f          *BundleFile
		}{{p.a, p.b, fa}, {p.b, p.a, fb}} {
			switch {
			case side.f == nil:
				c.add(newBundleViolation(RuleCrossShare, "a file declared as shared with challenge "+practiceRef(side.other)+" is not a file of the template of this challenge", cell{cid: side.cid}, p.file))
			case holdsMark(side.f.Data):
				c.add(newBundleViolation(RuleCrossShare, "a file declared as shared with challenge "+practiceRef(side.other)+" holds a slot mark (or a "+MarkOpen+" that is not one): its rendered values would differ between the two challenges", cell{cid: side.cid}, p.file))
			}
		}
		if fa != nil && fb != nil && !bytes.Equal(fa.Data, fb.Data) {
			c.add(newBundleViolation(RuleCrossShare, "a file declared as shared with challenge "+practiceRef(p.a)+" is not the same bytes in the two templates", cell{cid: p.b}, p.file))
		}
	}

	// The pairs that are not declared: neither the same bytes nor a near copy. The shingle sets
	// are B4's (shingleSet, marks taken out), each file by itself, made once.
	type fileShingles struct {
		set   map[string]struct{}
		fault bool
	}
	sets := make(map[string][]fileShingles, len(ids))
	for _, id := range ids {
		for _, f := range chs[id].Template {
			set, fault := shingleSet([]BundleFile{f}, true)
			sets[id] = append(sets[id], fileShingles{set: set, fault: fault != nil})
		}
	}
	for i, a := range ids {
		for _, b := range ids[i+1:] {
			for ia, fa := range chs[a].Template {
				for ib, fb := range chs[b].Template {
					if fa.Name == fb.Name && declared[newSharedPair(a, b, fa.Name)] {
						continue
					}
					rep.FilePairs++
					where := cell{cid: b}
					if bytes.Equal(fa.Data, fb.Data) {
						c.add(newBundleViolation(RuleCrossShare, "this file of the template is byte for byte file "+shownName(fa.Name)+" of the template of challenge "+practiceRef(a)+", and the pair is not declared (investigate.evidence.shares)", where, fb.Name))
						continue
					}
					sa, sb := sets[a][ia], sets[b][ib]
					if sa.fault || sb.fault {
						c.add(newBundleViolation(RuleCrossShare, "this file of the template, or file "+shownName(fa.Name)+" of the template of challenge "+practiceRef(a)+", has a "+MarkOpen+" that is not a mark, so their overlap cannot be computed", where, fb.Name))
						continue
					}
					rate := max(shingleOverlap(sa.set, sb.set), shingleOverlap(sb.set, sa.set))
					if rate >= OverlapTheta {
						c.add(newBundleViolation(RuleCrossShare, fmt.Sprintf("the 10-rune shingle overlap of this file of the template with file %s of the template of challenge %s is %.3f, at or above theta %.3f, and the pair is not declared (a declared pair is the same bytes)", shownName(fa.Name), practiceRef(a), rate, OverlapTheta), where, fb.Name))
					}
				}
			}
		}
	}
}

// templateFile is the file of the template named name, or nil.
func templateFile(template []BundleFile, name string) *BundleFile {
	for i := range template {
		if template[i].Name == name {
			return &template[i]
		}
	}
	return nil
}

// holdsMark reports whether data holds a slot mark, or a `{{ctf:` that is not one (ScanMarks, the
// one lexer of the marks: a text with no mark is one part).
func holdsMark(data []byte) bool {
	parts, err := ScanMarks(data)
	return err != nil || len(parts) > 1
}

// shingleOverlap is |s intersect o| / |s| (B4's measure, with s the side it is of), 0 when s is
// empty.
func shingleOverlap(s, o map[string]struct{}) float64 {
	if len(s) == 0 {
		return 0
	}
	n := 0
	for g := range s {
		if _, ok := o[g]; ok {
			n++
		}
	}
	return float64(n) / float64(len(s))
}

// literalTime is one literal time of a template: the word, the instant, and where it is.
type literalTime struct {
	word string
	at   time.Time
	file string
	line int
}

// literalTimes is the literal times of a template: every word (templateTokens) outside every mark
// that is a timestamp word, with its file and line. A file the lexer of the marks refuses makes
// the call fail: its name is returned (and no times), since the times of that file are not known.
func literalTimes(template []BundleFile) ([]literalTime, string) {
	var out []literalTime
	for _, f := range template {
		if _, err := ScanMarks(f.Data); err != nil {
			return nil, f.Name
		}
		for li, line := range templateLines(f.Data) {
			toks, err := templateTokens(line)
			if err != nil {
				return nil, f.Name
			}
			for _, t := range toks {
				if len(t.slots) != 0 || !isTimestampWord(t.lit) {
					continue
				}
				// A timestamp word is answerformat's canonical RFC 3339 form, which time.Parse
				// reads; a word it does not read is a fault, not a time to leave out.
				at, err := time.Parse(time.RFC3339, string(t.lit))
				if err != nil {
					return nil, f.Name
				}
				out = append(out, literalTime{word: string(t.lit), at: at, file: f.Name, line: li + 1})
			}
		}
	}
	return out, ""
}

// checkCrossTimelines is B15. A challenge whose template could not be read is refused already
// (CheckCrossChallenge) and is not compared.
func checkCrossTimelines(c *collector, rep *CrossReport, ids []string, chs map[string]*CrossChallenge, lits map[string][]literalTime) {
	for _, y := range ids {
		x := chs[y].Evidence.Timeline
		if x == "" || x == y || !slices.Contains(ids, x) {
			continue
		}
		ly, okY := lits[y]
		lx, okX := lits[x]
		if !okY || !okX {
			continue
		}
		rep.Timelines++
		have := make(map[string]struct{}, len(lx))
		for _, t := range lx {
			have[t.word] = struct{}{}
		}
		for _, t := range ly {
			if _, ok := have[t.word]; ok {
				continue
			}
			v := newBundleViolation(RuleCrossTimeline, "a literal time of the template is not a literal time of the template of challenge "+practiceRef(x)+", whose timeline this challenge declares it shares (investigate.evidence.timeline; a time of this challenge only is a slot)", cell{cid: y}, t.file)
			v.Line = t.line
			c.add(v)
		}
	}
}

// timelinePartners is, for every challenge, the challenges of the scope it shares a timeline with
// (either side of a declaration of B15), itself first.
func timelinePartners(ids []string, chs map[string]*CrossChallenge) map[string][]string {
	out := make(map[string][]string, len(ids))
	add := func(a, b string) {
		if !slices.Contains(out[a], b) {
			out[a] = append(out[a], b)
		}
	}
	for _, id := range ids {
		add(id, id)
	}
	for _, y := range ids {
		x := chs[y].Evidence.Timeline
		if x == "" || x == y || !slices.Contains(ids, x) {
			continue
		}
		add(y, x)
		add(x, y)
	}
	return out
}

// checkCrossWindows is B16.
func checkCrossWindows(c *collector, rep *CrossReport, ids []string, chs map[string]*CrossChallenge, lits map[string][]literalTime) {
	partners := timelinePartners(ids, chs)
	for _, id := range ids {
		spec := chs[id].Spec
		if spec == nil {
			c.add(newViolation(RuleCrossWindow, "the challenge's edition.yaml was not given, so B16 cannot run on it", 0, cell{cid: id}, nil))
			continue
		}
		var base time.Time
		baseRead := false
		for i := range spec.Slots {
			sl := &spec.Slots[i]
			w := sl.Window
			if sl.Role != RoleAnswer || w == nil || w.From == nil || w.To == nil {
				continue
			}
			if !baseRead {
				b, err := time.Parse(time.RFC3339, spec.Time.Base)
				if err != nil {
					c.add(newSpecViolation(RuleCrossWindow, "time.base cannot be read, so the answer windows of B16 are not known", 0, id, "", "", "time.base", nil))
					break
				}
				base, baseRead = b, true
			}
			rep.Windows++
			for _, p := range partners[id] {
				for _, t := range lits[p] {
					d := t.at.Unix() - base.Unix()
					if d < *w.From || d >= *w.To {
						continue
					}
					of := "this challenge"
					if p != id {
						of = "challenge " + practiceRef(p) + " (which shares this challenge's timeline)"
					}
					v := newSpecViolation(RuleCrossWindow, "a literal time of the template of "+of+" lies in the answer window of this slot (a time of the window is a filler slot)", t.line, id, sl.Question, sl.Name, "", nil)
					v.File = shownName(t.file)
					c.add(v)
				}
			}
		}
	}
}
