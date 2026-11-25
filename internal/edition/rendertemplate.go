package edition

// rendertemplate.go is the template of an edition (ADR-0056 D12, D19 A4d-2): the files of
// `template/`, the marks `{{ctf:<slot>}}` in them, and the rules that refuse a template
// that does not fit edition.yaml.
//
// A mark is  {{ctf:  a slot name (answerformat.IDPattern)  }}  and nothing else; what a
// mark is, is slotmark.go's (ScanMarks, the one lexer). The template is read ONCE, from
// left to right, into literal parts and marks; a render puts the values into the parts. A
// value is never read again, so it cannot make a mark of its own (and the formats have no
// `{` to make one with: still, fill refuses an output that holds a `{{ctf:`).
//
// A template is refused when (every failure is an E3 (RuleSpecRender) Violation; none holds a
// value, and the ones that are about a file name its file and, when there is one, its
// line):
//   - it has no file, more than MaxBundleFiles, a file whose name is outside B2's grammar
//     or is repeated, a file over MaxBundleBytes, one that is not UTF-8 or that holds a rune
//     sourcehygiene.Hidden reports (the output has to pass B2);
//   - a mark is outside the grammar;
//   - a mark names a slot edition.yaml does not declare (answer, filler or implied decoy);
//   - the mark of an answer or a decoy has a token byte next to it (a filler's may);
//   - a declared slot, a decoy included, is named by no mark in any file;
//   - a bundle that a seat gets is larger than MaxBundleBytes once the values are put in,
//     or holds a `{{ctf:` after it, or has a block whose lines cannot be put in the strict
//     order of their times (fill, orderBlocks).

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/sourcehygiene"
)

type tmplFile struct {
	name  string
	parts []TemplatePart
}

// compiledTemplate is a template that every rule above accepted, for one challenge, and the
// blocks of each of its files (blockForms; none for an edition without blocks).
type compiledTemplate struct {
	files  []tmplFile
	blocks map[string][]blockForm
}

// compileTemplate holds the files to the rules in the header and to the declared slots.
// It lists every failure it finds (bounded like Check's), the files in byte order of
// their names and then the unused slots in the order of slots.
func compileTemplate(cid string, files []BundleFile, slots []*renderSlot) (*compiledTemplate, error) {
	switch {
	case len(files) == 0:
		return nil, newViolation(RuleSpecRender, "the template has no file", 0, cell{cid: cid}, nil)
	case len(files) > MaxBundleFiles:
		return nil, newViolation(RuleSpecRender, fmt.Sprintf("the template has more than %d files", MaxBundleFiles), 0, cell{cid: cid}, nil)
	}
	declared := make(map[string]*renderSlot, len(slots))
	for _, s := range slots {
		declared[s.name] = s
	}
	sorted := slices.Clone(files)
	slices.SortStableFunc(sorted, func(a, b BundleFile) int { return strings.Compare(a.Name, b.Name) })

	var c collector
	used := make(map[string]struct{})
	ct := &compiledTemplate{}
	for i, f := range sorted {
		bad := func(msg string, line int) {
			v := newBundleViolation(RuleSpecRender, msg, cell{cid: cid}, f.Name)
			v.Line = line
			c.add(v)
		}
		switch {
		case !ValidFileName(f.Name):
			bad("the template file name is outside the grammar "+NamePattern, 0)
			continue
		case i > 0 && sorted[i-1].Name == f.Name:
			bad("two template files have this name", 0)
			continue
		case len(f.Data) > MaxBundleBytes:
			bad("the template file is larger than the limit of a bundle (512 KiB)", 0)
			continue
		case !utf8.Valid(f.Data):
			bad("the template file is not valid UTF-8", 0)
			continue
		}
		if found := sourcehygiene.Hidden(f.Data); len(found) > 0 {
			bad("the template file holds an invisible or bidi control character", found[0].Line)
			continue
		}
		parts, err := ScanMarks(f.Data)
		if err != nil {
			line := 0
			var me *MarkError
			if errors.As(err, &me) {
				line = me.Line
			}
			bad("a "+MarkOpen+" is not a mark of the grammar "+MarkOpen+"<slot>"+MarkClose, line)
			continue
		}
		for _, p := range parts {
			if p.Slot == "" {
				continue
			}
			if _, ok := declared[p.Slot]; !ok {
				v := newBundleViolation(RuleSpecRender, "a mark names a slot that edition.yaml does not declare", cell{cid: cid}, f.Name)
				v.Slot = p.Slot
				c.add(v)
				continue
			}
			used[p.Slot] = struct{}{}
		}
		// The mark of an answer or a decoy is a token of its own: B7 locates it by the index
		// of its token, and a byte glued to it would make the value another token.
		layout, err := LayoutOf(f.Data)
		if err != nil {
			continue // the same error was reported above
		}
		for _, m := range layout.Marks {
			if s, ok := declared[m.Slot]; ok && s.group != "" && !m.Alone {
				v := newBundleViolation(RuleSpecRender, "the mark of an answer or a decoy is not a token of its own (a token byte is next to it)", cell{cid: cid}, f.Name)
				v.Slot = m.Slot
				c.add(v)
			}
		}
		ct.files = append(ct.files, tmplFile{name: f.Name, parts: parts})
	}
	// A file that was refused has marks that are not counted: the unused slots are
	// listed only when every file was read, so they are not a consequence of another failure.
	if len(c.errs) == 0 {
		for _, s := range slots {
			if _, ok := used[s.name]; !ok {
				v := newViolation(RuleSpecRender, "a slot is named by no mark in any template file", 0, cell{cid: cid}, nil)
				if answerformat.ValidID(s.name) {
					v.Slot = s.name
				}
				c.add(v)
			}
		}
	}
	if err := c.err(); err != nil {
		return nil, err
	}
	return ct, nil
}

// fill is the files of the bundle of one seat: the parts with the value of each mark put
// in, and then the lines of each block in the order of their times (orderBlocks). A mark with
// no value, a block that cannot be ordered, a bundle over MaxBundleBytes and an output that
// holds a `{{ctf:` are refused (a mark must not survive the render).
func (ct *compiledTemplate) fill(cid, seat string, values map[string]string) ([]BundleFile, error) {
	out := make([]BundleFile, 0, len(ct.files))
	total := 0
	for _, f := range ct.files {
		var b bytes.Buffer
		for _, p := range f.parts {
			b.Write(p.Lit)
			if p.Slot == "" {
				continue
			}
			v, ok := values[p.Slot]
			if !ok {
				return nil, newViolation(RuleSpecRender, "a mark has no value", 0, cell{seat: seat, cid: cid}, errors.New("the slot was not drawn"))
			}
			b.WriteString(v)
		}
		data := b.Bytes()
		if forms := ct.blocks[f.name]; len(forms) > 0 {
			ordered, msg := orderBlocks(data, forms)
			if msg != "" {
				return nil, newBundleViolation(RuleSpecRender, "the lines of a block cannot be put in the order of their times: "+msg, cell{seat: seat, cid: cid}, f.name)
			}
			data = ordered
		}
		if bytes.Contains(data, []byte(MarkOpen)) {
			return nil, newBundleViolation(RuleSpecRender, "a "+MarkOpen+" is left in the output", cell{seat: seat, cid: cid}, f.name)
		}
		total += len(data)
		out = append(out, BundleFile{Name: f.name, Data: data})
	}
	if total > MaxBundleBytes {
		return nil, newViolation(RuleSpecRender, "the bundle of the seat is larger than the limit of a bundle (512 KiB)", 0, cell{seat: seat, cid: cid}, nil)
	}
	return out, nil
}

// orderBlocks is the order of the lines of a block (ADR-0056 amendment 28, as revised): after the
// marks are filled, the lines of each block of the file are put in the ascending order of their
// times (lineTime, the word E2 makes the value of each line's time slot). A line keeps its bytes,
// and the file keeps its line feeds: the lines are templateLines' (the text between line feeds),
// joined again with one, and the file ends with a line feed when it did. The order is strict: the
// draws keep the times of a block apart (r2), and two lines of one time are refused rather than
// left in the template's order, so a tie is never decided by the template (which is public). It
// returns the file, or why the block cannot be ordered (a message with no value).
func orderBlocks(data []byte, forms []blockForm) ([]byte, string) {
	lines := templateLines(data)
	for _, f := range forms {
		n := f.lines()
		if f.from+n > len(lines) {
			return nil, "the file has fewer lines than its block"
		}
		block := lines[f.from : f.from+n]
		times := make([]string, n)
		order := make([]int, n)
		for i, ln := range block {
			t, ok := lineTime(ln)
			if !ok {
				return nil, "a line of the block has no time"
			}
			times[i], order[i] = t, i
		}
		slices.SortStableFunc(order, func(a, b int) int { return strings.Compare(times[a], times[b]) })
		sorted := make([][]byte, n)
		for i, j := range order {
			if i > 0 && times[order[i-1]] == times[j] {
				return nil, "two lines of the block have one time"
			}
			sorted[i] = block[j]
		}
		copy(block, sorted)
	}
	out := bytes.Join(lines, []byte{'\n'})
	if len(data) > 0 && data[len(data)-1] == '\n' {
		out = append(out, '\n')
	}
	return out, ""
}
