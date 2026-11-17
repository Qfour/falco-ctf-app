package edition

// spread.go is the output half of two rules that look at what a render made, not at
// edition.yaml (ADR-0056 D10 B7 and B8 (b), D12, D3 (b), amendment 10, D19 A4d-2c): B7,
// "a seat's bundle holds enough decoys that look like the answer", and B8 (b), "a seat's
// bundle holds enough candidates of a question's format". The inputs are the bundles
// themselves (and, for B7, the template and the spec, which say where the decoys are), so
// the same two functions run on a render in the tests and, once the bundles are read from
// disk, in the validator (A4e; no caller yet). Neither applies to a practice edition (the
// seat *, which is public): the seat grammar refuses it here, so a caller that passes one
// gets a refusal and not a pass.
//
// This file is NOT a part of the renderer (it is not named render*.go, and
// render_reach_test.go does not count it as one): the validator does not trust the renderer,
// so what it calls holds no key and no answer. It reads the bundles and the template, takes the
// positions from slotmark.go (LayoutOf) and the formats from answerformat, and refers to
// nothing that render*.go declares (MasterKey, Render, the random source). A source test
// (spread_source_test.go) fixes that.
//
// A TOKEN is the unit both rules count: a maximal run of the bytes a value of the
// per-seat formats is made of, [A-Za-z0-9._:/-] (a name, a path, a hexid and a timestamp
// are all runs of these). Everything else, whatever it is, separates two tokens. This
// definition is the ADR's amendment 10 (D10 B7); isTokenByte (slotmark.go) is the one place
// that spells it. A token FITS a question when answerformat.Canonical accepts it for the question's
// format and params, which is also the form the answers table holds.
//
// B8 (b), D3 (b): per seat and per-seat question, the number of DISTINCT tokens in the
// seat's bundle that fit the question is at least R x attempts (R = 10, the CISO's
// decision). The count is the attacker's: whatever fits is a thing to try, whether the
// template meant it as a decoy or not. A name fits plain words too, so for a name the
// count is on the generous side (Signpost 13).
//
// B7, D12, amendment 10 (as revised): the renderer gives every position of every seat a value
// of its own (U2), and B7 does not trust it: it checks, per seat, that the positions of the
// answer's decoys hold K values that fit (O(seats x bundle)), and, per position of an
// answer or a decoy, that no two seats hold the same token (O(seats x slots)). Together
// they make "every pair of seats differs at K positions that could hold the answer" a
// checked property; the pair-wise comparison itself stays in the renderer's tests. The
// positions are found in the template: slotmark.go's LayoutOf gives the index of the token
// of each mark, and a template with each mark replaced by one token byte has the same
// tokens, in the same number, as every bundle rendered from it (a value is a run of token
// bytes). A mark of an answer or a decoy that is not a token of its own (a byte glued to it)
// cannot be located, and is a violation here as it is E3 in the renderer. A bundle that
// does not have the template's files and number of tokens was not made from the template and
// cannot be read by position: a violation too (fail-closed), left out of the part between
// seats.
//
// Nothing here names a value: a violation names a rule, a seat, a challenge, a question, a
// slot, a file and a position's number, never a token or a byte of a file.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
)

const (
	// RuleDecoySpread is D10 B7. (B8 (b) is RuleVocabSpace, as B8 (a).)
	RuleDecoySpread = "B7"
	// CandidateFactor is R of D3 (b): a seat's bundle holds at least R x attempts distinct
	// tokens of the format of each per-seat question (CISO, 2026-11-16).
	CandidateFactor = 10
)

// SpreadSeat is the output of one challenge for one seat: the files of its bundle.
type SpreadSeat struct {
	Seat  string
	Files []BundleFile
}

// fileTokens is the tokens of one file, in order.
func fileTokens(data []byte) []string {
	spans := tokenSpans(data)
	out := make([]string, len(spans))
	for i, sp := range spans {
		out[i] = string(data[sp[0]:sp[1]])
	}
	return out
}

// fitsFormat reports whether the token (not empty) is a value of the question's format in
// normalised form. The first tests only keep the regular expressions of answerformat for
// the tokens that can fit: they do not decide anything Canonical would not.
func fitsFormat(q catalog.Question, tok string) bool {
	switch q.Format {
	case answerformat.Path:
		if tok[0] != '/' {
			return false
		}
	case answerformat.HexID:
		if q.Params.Length == nil || len(tok) != *q.Params.Length {
			return false
		}
	case answerformat.Timestamp:
		if len(tok) != len("2000-01-01T00:00:00Z") {
			return false
		}
	}
	return answerformat.Canonical(q.Format, q.Params, tok) == nil
}

// spreadSeat is a SpreadSeat read once: its files in byte order of the names, and the tokens
// of each.
type spreadSeat struct {
	seat   string
	names  []string
	tokens [][]string
}

func (s *spreadSeat) distinct() map[string]struct{} {
	out := make(map[string]struct{})
	for _, toks := range s.tokens {
		for _, tok := range toks {
			out[tok] = struct{}{}
		}
	}
	return out
}

func spreadViolation(rule, msg, seat, cid, qid string) *Violation {
	return newViolation(rule, msg, 0, cell{seat: seat, cid: cid, qid: qid}, nil)
}

// prepareSpread reads the seats and picks the per-seat questions (the formats that can vary
// per seat). It refuses what the two rules cannot be run on: no seat, a seat outside the
// seat grammar (the practice seat * too) or repeated, no per-seat question, and a per-seat
// question whose attempts are outside 1..answerformat.MaxAttempts (a floor of 0 would pass
// anything). The seats are read in byte order of their names, so which seat of two that
// share a token is named does not depend on the order the caller listed them in.
func prepareSpread(cid string, qs []catalog.Question, seats []SpreadSeat) ([]spreadSeat, []catalog.Question, error) {
	if !challengeid.Valid(cid) {
		return nil, nil, newViolation(RuleDecoySpread, "cid is not a challenge id", 0, cell{}, nil)
	}
	if len(seats) == 0 {
		return nil, nil, newViolation(RuleDecoySpread, "there is no seat to check", 0, cell{cid: cid}, nil)
	}
	var per []catalog.Question
	for _, q := range qs {
		if answerformat.PerSeat(q.Format) {
			per = append(per, q)
		}
	}
	if len(per) == 0 {
		return nil, nil, newViolation(RuleDecoySpread, "the challenge has no question that can vary per seat", 0, cell{cid: cid}, nil)
	}
	var c collector
	for _, q := range per {
		if q.Attempts < 1 || q.Attempts > answerformat.MaxAttempts {
			c.add(spreadViolation(RuleDecoySpread, "the attempts of the question are outside 1..MaxAttempts, so K and R x attempts cannot be set", "", cid, q.ID))
		}
	}
	sorted := slices.Clone(seats)
	slices.SortStableFunc(sorted, func(a, b SpreadSeat) int { return strings.Compare(a.Seat, b.Seat) })
	out := make([]spreadSeat, 0, len(sorted))
	seen := make(map[string]struct{}, len(sorted))
	for _, s := range sorted {
		if !identity.ValidSeat(s.Seat) {
			c.add(spreadViolation(RuleDecoySpread, "a seat is outside the seat grammar (ADR-0042); a practice edition is not checked", s.Seat, cid, ""))
			continue
		}
		if _, dup := seen[s.Seat]; dup {
			c.add(spreadViolation(RuleDecoySpread, "a seat is listed twice", s.Seat, cid, ""))
			continue
		}
		seen[s.Seat] = struct{}{}
		files := slices.Clone(s.Files)
		slices.SortStableFunc(files, func(a, b BundleFile) int { return strings.Compare(a.Name, b.Name) })
		rs := spreadSeat{seat: s.Seat}
		for _, f := range files {
			rs.names = append(rs.names, f.Name)
			rs.tokens = append(rs.tokens, fileTokens(f.Data))
		}
		out = append(out, rs)
	}
	if err := c.err(); err != nil {
		return nil, nil, err
	}
	return out, per, nil
}

// CheckOutputSpace is D10 B8 (b), D3 (b): see the header. It lists every seat and question
// that is short (bounded like Check's list), with the number of tokens it has and the
// number it needs.
func CheckOutputSpace(cid string, qs []catalog.Question, seats []SpreadSeat) error {
	prep, per, err := prepareSpread(cid, qs, seats)
	if err != nil {
		return err
	}
	var c collector
	for i := range prep {
		s := &prep[i]
		distinct := s.distinct()
		for _, q := range per {
			need := CandidateFactor * q.Attempts
			n := 0
			for tok := range distinct {
				if fitsFormat(q, tok) {
					n++
					if n >= need {
						break
					}
				}
			}
			if n < need {
				c.add(spreadViolation(RuleVocabSpace,
					fmt.Sprintf("the bundle holds %d distinct tokens of the format of the question; D3 (b) needs %d (%d x attempts)", n, need, CandidateFactor),
					s.seat, cid, q.ID))
			}
		}
	}
	return c.err()
}

// slotPosition is where a mark of an answer slot or of a decoy is in a template: the file (by
// index in byte order of the names, and its name), the index of the token, the slot and the
// question it belongs to, and whether the mark is a decoy's (otherwise the answer's).
type slotPosition struct {
	file     int
	fileName string
	token    int
	slot     string
	qid      string
	decoy    bool
}

// templateLayout is the files of a template (byte order of the names), the number of tokens
// of each once every mark is one token byte, and the positions of the marks of the answers
// and the decoys (a filler is not located: it is not assigned). It reads the positions with
// LayoutOf, the lexer the renderer's E3 uses, and refuses a template in which a mark of an
// answer or a decoy is not a token of its own, or a mark names a slot that edition.yaml does
// not declare: the validator does not trust the renderer to have refused them.
func templateLayout(spec *Spec, template []BundleFile) (names []string, counts []int, positions []slotPosition, err error) {
	type located struct {
		qid    string
		decoy  bool
		filler bool
	}
	slotOf := make(map[string]located, len(spec.Slots)+len(spec.ImpliedDecoys))
	for _, sl := range spec.Slots {
		if sl.Role == RoleAnswer {
			slotOf[sl.Name] = located{qid: sl.Question}
		} else {
			slotOf[sl.Name] = located{filler: true}
		}
	}
	for _, d := range spec.ImpliedDecoys {
		slotOf[d.Name] = located{qid: d.Question, decoy: true}
	}
	files := slices.Clone(template)
	slices.SortStableFunc(files, func(a, b BundleFile) int { return strings.Compare(a.Name, b.Name) })
	for fi, f := range files {
		layout, layoutErr := LayoutOf(f.Data)
		if layoutErr != nil {
			return nil, nil, nil, newBundleViolation(RuleDecoySpread, "the template has a mark outside the grammar, so its positions cannot be located", cell{}, f.Name)
		}
		for _, m := range layout.Marks {
			s, ok := slotOf[m.Slot]
			if !ok {
				return nil, nil, nil, newBundleViolation(RuleDecoySpread, "the template has a mark of a slot that edition.yaml does not declare, so its positions cannot be located", cell{}, f.Name)
			}
			if s.filler {
				continue
			}
			if !m.Alone {
				return nil, nil, nil, newBundleViolation(RuleDecoySpread, "the mark of an answer or a decoy is not a token of its own, so its position cannot be located", cell{}, f.Name)
			}
			positions = append(positions, slotPosition{file: fi, fileName: f.Name, token: m.Token, slot: m.Slot, qid: s.qid, decoy: s.decoy})
		}
		names = append(names, f.Name)
		counts = append(counts, layout.Tokens)
	}
	return names, counts, positions, nil
}

// CheckDecoySpread is the output half of D10 B7: see the header. Two things, both found by
// position (the token of a file at the index the template says):
//
//   - per seat and per-seat question: the DISTINCT tokens at the positions of the question's
//     decoys that fit the question are at least K = DecoyK(attempts) (a decoy that repeats
//     another one in the seat is not another candidate to try);
//   - per position of an answer or a decoy: no two seats hold the same token. The validator
//     does not trust the renderer's assignment, so it checks what the assignment is for. A
//     filler is not looked at. With one seat there is no pair and this part is empty (no one
//     to collude with, so not a fail-open); the per-seat part is checked all the same.
//
// spec must be a Spec that ParseSpec returned (a Spec made by hand is refused). A bundle whose
// files or number of tokens differ from the template's cannot be read by position and is a
// violation, and is left out of the second part. It lists every seat and question that is
// short, bounded like Check's list. The cost is O(seats x bundle).
func CheckDecoySpread(cid string, spec *Spec, qs []catalog.Question, template []BundleFile, seats []SpreadSeat) error {
	prep, per, err := prepareSpread(cid, qs, seats)
	if err != nil {
		return err
	}
	if spec == nil || !spec.parsed {
		return newViolation(RuleDecoySpread, "the spec is missing or did not come from ParseSpec, so the decoys cannot be located", 0, cell{cid: cid}, nil)
	}
	names, counts, positions, err := templateLayout(spec, template)
	if err != nil {
		return err
	}
	var c collector
	// held[i] is the tokens the seats so far hold at positions[i].
	held := make([]map[string]struct{}, len(positions))
	for i := range held {
		held[i] = make(map[string]struct{})
	}
	for i := range prep {
		s := &prep[i]
		if !slices.Equal(s.names, names) || !sameCounts(s.tokens, counts) {
			c.add(spreadViolation(RuleDecoySpread, "the bundle of the seat does not have the template's layout (its files or the number of tokens in a file differ), so its positions cannot be located", s.seat, cid, ""))
			continue
		}
		for _, q := range per {
			got := make(map[string]struct{})
			for _, p := range positions {
				if p.qid != q.ID || !p.decoy {
					continue
				}
				if tok := s.tokens[p.file][p.token]; fitsFormat(q, tok) {
					got[tok] = struct{}{}
				}
			}
			if k := DecoyK(q.Attempts); len(got) < k {
				c.add(spreadViolation(RuleDecoySpread,
					fmt.Sprintf("the bundle holds %d distinct decoy tokens of the format of the question; B7 needs K = %d", len(got), k),
					s.seat, cid, q.ID))
			}
		}
		for pi, p := range positions {
			tok := s.tokens[p.file][p.token]
			if _, dup := held[pi][tok]; dup {
				v := spreadViolation(RuleDecoySpread,
					fmt.Sprintf("an earlier seat holds the same token at token %d of the file, a position of an answer or a decoy, so a comparison of the two bundles does not show where the answer is", p.token),
					s.seat, cid, p.qid)
				if answerformat.ValidID(p.slot) {
					v.Slot = p.slot
				}
				v.File = shownName(p.fileName)
				c.add(v)
				continue
			}
			held[pi][tok] = struct{}{}
		}
	}
	return c.err()
}

// sameCounts reports whether each file has the number of tokens the template says.
func sameCounts(tokens [][]string, counts []int) bool {
	if len(tokens) != len(counts) {
		return false
	}
	for i := range tokens {
		if len(tokens[i]) != counts[i] {
			return false
		}
	}
	return true
}
