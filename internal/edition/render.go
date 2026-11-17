package edition

// render.go is the renderer of an edition (ADR-0056 D12 and its amendments 8 and 9, D19
// A4d-2): from an edition.yaml, the challenge's questions, the template files, a master key
// and a list of seats it makes, for every seat, the bundle of the evidence files and the
// rows of that seat in the answers table.
//
// The renderer is PURE, as the rest of this package: it reads no file, writes none, reads
// no environment and no clock, and logs nothing. The caller (the CLI of A4e) reads the
// inputs and writes the outputs. Everything the renderer holds is the event's secret (the
// answers; the key): a Violation names a rule, a seat, a challenge, a slot, a template
// file and a line, never a value, a word of a vocabulary or a byte of the key (D13), and a
// MasterKey prints as a fixed string under every fmt verb and under encoding/json.
//
// What a seat gets (D12): every slot is drawn from the stream of (key, seat, challenge,
// slot) (renderdrbg.go), a name or a path from its vocabulary, a hexid of the question's
// params.length (a filler's `length`), a timestamp from time.base and the slot's window,
// and every value is checked to be answerformat.Canonical, which is the form the answers
// table holds and the grader compares with. An answer slot and its implied decoys are
// drawn to be pairwise different within a seat: the decoy is "the same kind of thing" and
// never the answer itself.
//
// The seats are an ORDERED list, appended to and never reordered (ADR-0056 amendment 10,
// U2), and are rendered in that order, which is what makes the values of two seats
// different: for every slot of an answer group (the answer and each decoy) the renderer
// remembers the values the earlier seats got at that position, and a draw that is one of
// them is thrown away and the next of the same stream is taken. So a position has one
// value in each seat (T8 holds by construction, and so does B7), a seat's values depend on
// the seats BEFORE it in the list and on nothing after, and a seat added at the end changes
// no value of the others. Reordering the list changes the values of the seats that move
// behind another. A filler is not assigned: two seats may share one. The price is a space
// of at least 2 x the number of seats at each position (B8 (a)): a smaller one is E3, and
// so is a draw that cannot be made within maxDistinctTries.
//
// The marks of a template and the rules that refuse a template are rendertemplate.go; their
// lexer is slotmark.go (the one definition, shared with B4 and not a part of the renderer).
//
// Reach (D9, D13): the renderer is not a part of the scoreboard's HTTP side. Every file of
// this stage is named render*.go, and render_reach_test.go fixes by reading the sources
// that nothing outside those files, and no file of cmd/ or internal/ outside this
// package, refers to what they declare (A4e adds the one caller, the `edition render` command
// of cmd/scoreboard; `edition check` does not call the renderer).

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
)

// RuleSpecRender is D10 E3 (ADR-0056 amendment 10): the renderer's refusals. The key, the
// seats, a template that does not fit edition.yaml (an undeclared mark, a slot no mark
// uses, a mark left after the render), a space too small to give each seat its own value,
// a value that cannot be drawn. A message holds no value and no key.
const RuleSpecRender = "E3"

const (
	// MinMasterKeyBytes is the shortest key an event is rendered with (amendment 10).
	MinMasterKeyBytes = 32

	// practiceKeyText is the public key of a practice edition (D12). It is a constant of
	// the program on purpose: a practice edition is the same output for everyone.
	practiceKeyText = "practice"

	// maxDistinctTries is how many values a slot may draw to find one that is not taken
	// by the others of its group or by the earlier seats at its position. With a space of
	// at least 2 x the number of seats (and 100 x attempts), a try fails with a
	// probability of at most about 1/2 + 21/100, so 1000 in a row is not a thing that
	// happens; a space that makes it happen is E3, not a loop.
	maxDistinctTries = 1000
)

// MasterKey is the key every value of an event is drawn from (D12). It lives in the
// platform's sops and is read by the render command only (D13); here it is the one type
// that carries it, so that it cannot reach a message by accident: it has no accessor and
// prints as a fixed string under every fmt verb and under encoding/json.
type MasterKey struct{ key []byte }

// NewMasterKey is the key of the bytes given (copied). A key of fewer than
// MinMasterKeyBytes bytes is refused, and so are the bytes of the public practice key (an
// event is never rendered with it). The errors name no byte of the key.
func NewMasterKey(key []byte) (MasterKey, error) {
	if len(key) < MinMasterKeyBytes {
		return MasterKey{}, fmt.Errorf("edition: the master key is shorter than %d bytes", MinMasterKeyBytes)
	}
	k := MasterKey{key: bytes.Clone(key)}
	if k.isPractice() {
		return MasterKey{}, errors.New("edition: the master key is the public practice key")
	}
	return k, nil
}

// PracticeMasterKey is the public key `practice` of a practice edition (D12, D8).
func PracticeMasterKey() MasterKey { return MasterKey{key: []byte(practiceKeyText)} }

// isPractice reports whether the key is the public one (a constant-time comparison).
func (k MasterKey) isPractice() bool { return hmac.Equal(k.key, []byte(practiceKeyText)) }

const redactedKey = "edition.MasterKey{redacted}"

// Format, String, GoString and MarshalJSON make a MasterKey print as a fixed string
// under every fmt verb and under encoding/json (value receivers, so a copy does too).
func (MasterKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedKey) }

// String: see Format.
func (MasterKey) String() string { return redactedKey }

// GoString: see Format.
func (MasterKey) GoString() string { return redactedKey }

// MarshalJSON: see Format.
func (MasterKey) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedKey + `"`), nil }

// RenderInput is what Render needs for one challenge.
type RenderInput struct {
	// CID is the challenge id; Questions are its questions (catalog order), the ones
	// Spec.CheckQuestions holds the spec to.
	CID       string
	Questions []catalog.Question
	// Spec is a parsed edition.yaml (ParseSpec). A Spec made by hand is refused.
	Spec *Spec
	// Template is the files of template/: the name (B2's grammar) and the bytes, with
	// the marks `{{ctf:<slot>}}`. Their order does not matter.
	Template []BundleFile
	// Key is the master key; Seats are the seats to render (ADR-0042's grammar, no
	// repeat), in the order of the list: the roster plus the spare seats, appended to and
	// never reordered (U2, see the header). There is no run id here: the values do not
	// depend on it (a run id only ties a table to its digests).
	Key   MasterKey
	Seats []string
	// Previous is the seat list of the last render of this event, which Seats must extend
	// at its end (E3 otherwise: a reorder, a removal or an insertion would change the
	// values of the seats behind it). It is REQUIRED: the zero value is "not given" and
	// refused, and the first render says so with NoPreviousSeats.
	Previous PreviousSeats
}

// PreviousSeats is the seat list of the previous render, or the statement that there is
// none. It is a type of its own, not a nil slice, so that a caller that forgot the argument
// (the zero value) is refused instead of passing as a first render: the first render has to
// be written down, and the only way to write it down is NoPreviousSeats (the command's
// `--no-previous`), as edition.yaml's `version` has to be written (Spec.VersionDeclared). A
// previous list that is empty is not a first render but a list that was lost (a file cut
// short), so it is "not given" (PreviousSeatsOf).
type PreviousSeats struct {
	given bool
	seats []string
}

// NoPreviousSeats is the first render of an event: there is no previous list. It is the only
// way to say so.
func NoPreviousSeats() PreviousSeats { return PreviousSeats{given: true} }

// PreviousSeatsOf is the previous render's seat list (copied). An empty list is NOT the first
// render: it is the zero value, "not given", and Render refuses it (E3; ADR-0056 D20,
// V74), so that a seat list that was cut short is never read as "there was none". The first
// render is NoPreviousSeats and nothing else.
func PreviousSeatsOf(seats []string) PreviousSeats {
	if len(seats) == 0 {
		return PreviousSeats{}
	}
	return PreviousSeats{given: true, seats: slices.Clone(seats)}
}

// AnswerRow is one row of the answers table: the plaintext answer of a seat to a
// question. It is the renderer's output and the secret of the event: hold it as long as
// it takes to write the table, like a Table.
type AnswerRow struct {
	Seat  string
	CID   string
	QID   string
	Value string
}

// Rendered is the output of one challenge: the bundle of every seat and the answer rows
// (the answer slots of every seat, and `fixed` for every seat), both in the order of the
// seat list the render was given.
type Rendered struct {
	Bundles []*Bundle
	Rows    []AnswerRow
}

// Render renders the edition of one challenge for the seats of in. It first holds the
// spec to the challenge's questions (Spec.CheckQuestions, E2 and B8 (a); its violations
// are returned as they are) and the template to the spec (rendertemplate.go), and then
// draws every slot of every seat. It returns a Rendered, or an error that is a *Violation
// (or an errors.Join of them) and holds no value and no key.
//
// The seats are rendered in the order of in.Seats, which is not changed (see the header). An
// event is never rendered with the public practice key (the key of RenderPractice), and
// never for the seat * (the practice seat); a render that fails returns no output. All of
// these are E3.
func Render(in RenderInput) (*Rendered, error) {
	switch {
	case len(in.Key.key) == 0:
		return nil, newViolation(RuleSpecRender, "the master key is missing", 0, cell{}, nil)
	case in.Key.isPractice():
		return nil, newViolation(RuleSpecRender, "an event is not rendered with the public practice key", 0, cell{}, nil)
	case len(in.Seats) == 0:
		return nil, newViolation(RuleSpecRender, "there is no seat to render", 0, cell{}, nil)
	}
	seen := make(map[string]struct{}, len(in.Seats))
	for _, seat := range in.Seats {
		if !identity.ValidSeat(seat) {
			return nil, newViolation(RuleSpecRender, "a seat is outside the seat grammar (ADR-0042), and * is the practice seat", 0, cell{seat: seat}, nil)
		}
		if _, dup := seen[seat]; dup {
			return nil, newViolation(RuleSpecRender, "a seat is listed twice", 0, cell{seat: seat}, nil)
		}
		seen[seat] = struct{}{}
	}
	if !in.Previous.given {
		return nil, newViolation(RuleSpecRender, "the previous seat list is not given (the first render says so with NoPreviousSeats)", 0, cell{}, nil)
	}
	prev := in.Previous.seats
	for i, seat := range prev {
		if !identity.ValidSeat(seat) {
			return nil, newViolation(RuleSpecRender, "a seat of the previous list is outside the seat grammar (ADR-0042)", 0, cell{seat: seat}, nil)
		}
		if slices.Contains(prev[:i], seat) {
			return nil, newViolation(RuleSpecRender, "a seat is listed twice in the previous list", 0, cell{seat: seat}, nil)
		}
	}
	if len(prev) > len(in.Seats) || !slices.Equal(prev, in.Seats[:len(prev)]) {
		return nil, newViolation(RuleSpecRender, "the seat list does not extend the previous list at its end (a reorder, a removal or an insertion would change the values of the seats behind it)", 0, cell{}, nil)
	}
	return render(in)
}

// RenderPractice renders the practice edition of a challenge (D12, D8): the public key
// `practice` and the one seat `*`, so the output is the same for everyone. Its output is
// what practice/ of the challenge holds, and what V67 compares with it.
func RenderPractice(cid string, spec *Spec, qs []catalog.Question, template []BundleFile) (*Rendered, error) {
	return render(RenderInput{
		CID: cid, Questions: qs, Spec: spec, Template: template,
		Key: PracticeMasterKey(), Seats: []string{AnySeat},
	})
}

// renderSlot is one slot of an edition as the renderer draws it: a slot of the file, or a
// decoy, which is a copy of its answer slot (format, params, vocabulary, window and
// question: the sameness of D12 holds by construction).
type renderSlot struct {
	name   string
	format string
	params answerformat.Params
	vocab  [][]string
	from   int64 // the window of a timestamp slot, in seconds from time.base
	to     int64
	// group is the name of the answer slot, for an answer slot and its decoys (their
	// values are drawn to differ); empty for a filler.
	group string
}

func render(in RenderInput) (*Rendered, error) {
	if !challengeid.Valid(in.CID) {
		return nil, newViolation(RuleSpecRender, "cid is not a challenge id", 0, cell{}, nil)
	}
	if in.Spec == nil || in.Spec.Version != SpecVersion || !in.Spec.parsed {
		return nil, newViolation(RuleSpecRender, "the spec did not come from ParseSpec", 0, cell{cid: in.CID}, nil)
	}
	if err := in.Spec.CheckQuestions(in.CID, in.Questions); err != nil {
		return nil, err
	}
	// B8 (a2), before anything is drawn: a space below 2 x the seats is E3, whatever the key.
	if err := in.Spec.CheckSeatSpace(in.CID, in.Questions, len(in.Seats), RuleSpecRender); err != nil {
		return nil, err
	}
	slots, err := renderSlots(in.CID, in.Spec, in.Questions)
	if err != nil {
		return nil, err
	}
	tmpl, err := compileTemplate(in.CID, in.Template, slots)
	if err != nil {
		return nil, err
	}
	var base time.Time
	if in.Spec.Time.Base != "" {
		if base, err = time.Parse(time.RFC3339, in.Spec.Time.Base); err != nil {
			return nil, newViolation(RuleSpecRender, "time.base is not an RFC 3339 time", 0, cell{cid: in.CID}, nil)
		}
	}
	// earlier[slot] is the values the seats before this one got at that position (U2). A
	// seat's draws read it and add to it, so a seat depends on the seats before it only.
	earlier := make(map[string]map[string]struct{}, len(slots))
	out := &Rendered{}
	for _, seat := range in.Seats {
		values, err := drawSeat(in, slots, base, seat, earlier)
		if err != nil {
			return nil, err
		}
		files, err := tmpl.fill(in.CID, seat, values)
		if err != nil {
			return nil, err
		}
		out.Bundles = append(out.Bundles, &Bundle{Seat: seat, CID: in.CID, Files: files})
		out.Rows = append(out.Rows, seatRows(in.Spec, in.CID, seat, values)...)
	}
	return out, nil
}

// renderSlots is the slots of spec in the order of the file, and then the implied decoys.
// Every answer slot comes before its decoys, so a group is drawn answer first.
func renderSlots(cid string, spec *Spec, qs []catalog.Question) ([]*renderSlot, error) {
	bad := func(msg, slot string) error {
		v := newViolation(RuleSpecRender, msg, 0, cell{cid: cid}, nil)
		if answerformat.ValidID(slot) {
			v.Slot = slot
		}
		return v
	}
	var out []*renderSlot
	byName := make(map[string]*renderSlot, len(spec.Slots))
	for i := range spec.Slots {
		sl := &spec.Slots[i]
		rs := &renderSlot{name: sl.Name, vocab: sl.Vocab}
		switch sl.Role {
		case RoleAnswer:
			q, ok := findQuestion(qs, sl.Question)
			if !ok {
				return nil, bad("an answer slot names a question the challenge does not have", sl.Name)
			}
			rs.format, rs.params, rs.group = q.Format, q.Params, sl.Name
		case RoleFiller:
			rs.format = sl.Format
			if sl.Format == answerformat.HexID {
				rs.params = answerformat.Params{Length: sl.Length}
			}
		default:
			return nil, bad("a slot has no role (the spec did not come from ParseSpec)", sl.Name)
		}
		if sl.Window != nil {
			if sl.Window.From == nil || sl.Window.To == nil {
				return nil, bad("a window needs from and to", sl.Name)
			}
			rs.from, rs.to = *sl.Window.From, *sl.Window.To
			if sl.Role == RoleFiller {
				width := rs.to - rs.from
				rs.params = answerformat.Params{WindowSeconds: &width}
			}
		}
		if rs.format == answerformat.Timestamp && rs.to <= rs.from {
			return nil, bad("a timestamp slot has no window", sl.Name)
		}
		if (rs.format == answerformat.Name || rs.format == answerformat.Path) && !hasWords(rs.vocab) {
			return nil, bad("a name or path slot has no vocabulary", sl.Name)
		}
		out = append(out, rs)
		byName[rs.name] = rs
	}
	for i := range spec.ImpliedDecoys {
		dc := &spec.ImpliedDecoys[i]
		ans, ok := byName[dc.DecoyOf]
		if !ok || ans.group != dc.DecoyOf {
			return nil, bad("a decoy has no answer slot (the spec did not come from ParseSpec)", dc.Name)
		}
		cp := *ans
		cp.name = dc.Name
		out = append(out, &cp)
	}
	return out, nil
}

// hasWords reports whether every list of vocab holds a word, and there is a list.
func hasWords(vocab [][]string) bool {
	if len(vocab) == 0 {
		return false
	}
	for _, words := range vocab {
		if len(words) == 0 {
			return false
		}
	}
	return true
}

// drawSeat is the value of every slot for one seat, by slot name. The slots of a group
// (an answer slot and its decoys) are drawn to differ from each other, and each of them to
// differ from the values the seats before this one got at the same position (earlier, which
// it adds this seat's values to). A filler is drawn as it comes.
func drawSeat(in RenderInput, slots []*renderSlot, base time.Time, seat string, earlier map[string]map[string]struct{}) (map[string]string, error) {
	values := make(map[string]string, len(slots))
	taken := make(map[string]map[string]struct{})
	for _, s := range slots {
		var seen, before map[string]struct{}
		if s.group != "" {
			if taken[s.group] == nil {
				taken[s.group] = make(map[string]struct{})
			}
			seen = taken[s.group]
			if earlier[s.name] == nil {
				earlier[s.name] = make(map[string]struct{})
			}
			before = earlier[s.name]
		}
		v, err := s.drawDistinct(newDRBG(in.Key, seat, in.CID, s.name), base, seen, before)
		if err != nil {
			viol := newViolation(RuleSpecRender, "a value could not be drawn for the slot", 0, cell{seat: seat, cid: in.CID}, err)
			if answerformat.ValidID(s.name) {
				viol.Slot = s.name
			}
			return nil, viol
		}
		values[s.name] = v
	}
	return values, nil
}

// drawDistinct is a value of the slot that is in answerformat's normalised form and in
// neither seen (the values of the slot's group in this seat) nor before (the values the
// earlier seats got at this position); a nil map is empty. A draw that is in one is thrown
// away and the next of the slot's own stream is taken, at most maxDistinctTries times. The
// value is added to the maps that are not nil. An error describes the rule that failed,
// never the value.
func (s *renderSlot) drawDistinct(d *drbg, base time.Time, seen, before map[string]struct{}) (string, error) {
	for try := 0; try < maxDistinctTries; try++ {
		v, err := s.draw(d, base)
		if err != nil {
			return "", err
		}
		if err := answerformat.Canonical(s.format, s.params, v); err != nil {
			return "", err
		}
		if _, taken := seen[v]; taken {
			continue
		}
		if _, taken := before[v]; taken {
			continue
		}
		if seen != nil {
			seen[v] = struct{}{}
		}
		if before != nil {
			before[v] = struct{}{}
		}
		return v, nil
	}
	return "", errors.New("no value of the slot differs from the others of its group and from the earlier seats' (the space is too small for the seats)")
}

// draw is one value of the slot, uniform over the slot's space (D12): a name is a word, a
// path is a word of each position, a hexid is `length` lower-case hex digits (every digit
// a uniform nibble, so there is no choice to bias), a timestamp is a second of the
// half-open window after time.base.
func (s *renderSlot) draw(d *drbg, base time.Time) (string, error) {
	switch s.format {
	case answerformat.Name:
		i, err := d.below(uint64(len(s.vocab[0])))
		if err != nil {
			return "", err
		}
		return s.vocab[0][i], nil
	case answerformat.Path:
		var b strings.Builder
		for _, words := range s.vocab {
			i, err := d.below(uint64(len(words)))
			if err != nil {
				return "", err
			}
			b.WriteByte('/')
			b.WriteString(words[i])
		}
		return b.String(), nil
	case answerformat.HexID:
		if s.params.Length == nil {
			return "", errors.New("a hexid slot has no length")
		}
		n := *s.params.Length
		raw, err := d.bytes((n + 1) / 2)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(raw)[:n], nil
	case answerformat.Timestamp:
		off, err := d.below(uint64(s.to - s.from))
		if err != nil {
			return "", err
		}
		return time.Unix(base.Unix()+s.from+int64(off), 0).UTC().Format(time.RFC3339), nil
	}
	return "", errors.New("the slot has a format the renderer does not draw")
}

// seatRows is the rows of one seat in the answers table: the answer of every per-seat
// question, in the order of the slots, and then `fixed`, which is the same for every
// seat, in the order of the question ids.
func seatRows(spec *Spec, cid, seat string, values map[string]string) []AnswerRow {
	var rows []AnswerRow
	for i := range spec.Slots {
		if sl := &spec.Slots[i]; sl.Role == RoleAnswer {
			rows = append(rows, AnswerRow{Seat: seat, CID: cid, QID: sl.Question, Value: values[sl.Name]})
		}
	}
	qids := make([]string, 0, len(spec.Fixed))
	for qid := range spec.Fixed {
		qids = append(qids, qid)
	}
	sort.Strings(qids)
	for _, qid := range qids {
		rows = append(rows, AnswerRow{Seat: seat, CID: cid, QID: qid, Value: spec.Fixed[qid]})
	}
	return rows
}
