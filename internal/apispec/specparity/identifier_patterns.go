package specparity

// ADR-0039 follow-up (app#440): the identifier grammars a spec repeats as
// `pattern` (a seat, a challenge id, a board id) each have ONE Go definition
// (identity.SeatPattern, challengeid.Pattern, board.IDPattern). This is the one
// mechanism that holds the spec side and the Go side equal, for every
// identifier alike: the set of every `pattern` value in the specs, against the
// table of Go grammars, compared as exact strings in both directions. There is
// no list of nodes, so a new node that carries one of the patterns needs no
// edit, and a pattern nobody defined in Go (a new copy, a typo) is a failure.
//
// Test-only by package placement, like the rest of this package.

import (
	"fmt"
	"sort"
)

// Grammar is one identifier's Go-side definition: a name for messages, the
// pattern string a spec must repeat, and WHERE it must be repeated: per spec
// file, exactly this many sites (nodes carrying the pattern). Exactly one is the
// norm: a spec writes a grammar once (a component, or the one inline copy a
// document that cannot $ref across files keeps), so a node that lost its pattern
// is a site that vanished and a new inline copy is a second site, both red,
// without a list of nodes.
type Grammar struct {
	Name    string
	Pattern string
	// Sites maps a spec file name to the exact number of nodes that carry
	// Pattern there. A spec not listed must carry none.
	Sites map[string]int
}

// PatternSites returns, for every `pattern` keyword with a string value
// anywhere in the document, the pointers that carry it, keyed by the value.
// A `pattern` that is a property NAME (a map value, not a string) is not one.
func (s *Spec) PatternSites() map[string][]string {
	out := map[string][]string{}
	var walk func(v any, ptr string)
	walk = func(v any, ptr string) {
		switch t := v.(type) {
		case map[string]any:
			if p, ok := t["pattern"].(string); ok {
				out[p] = append(out[p], ptr)
			}
			for k, ev := range t {
				walk(ev, childPointer(ptr, k))
			}
		case []any:
			for i, ev := range t {
				walk(ev, childPointer(ptr, fmt.Sprint(i)))
			}
		}
	}
	walk(s.raw, "")
	for _, ptrs := range out {
		sort.Strings(ptrs)
	}
	return out
}

// PatternParityViolations compares the patterns found in the specs (spec file
// name -> PatternSites) with the table of Go grammars: every spec pattern must
// be exactly one grammar's, every grammar must appear in at least one spec, the
// table's patterns must be distinct, and finding no pattern at all is a
// failure (an extraction that finds nothing proves nothing).
func PatternParityViolations(specs map[string]map[string][]string, grammars []Grammar) []string {
	var viol []string
	if len(grammars) == 0 {
		return []string{"the table of Go grammars is empty: the comparison would be vacuous"}
	}
	byPattern := map[string]string{}
	for _, g := range grammars {
		if g.Pattern == "" {
			viol = append(viol, fmt.Sprintf("grammar %q has an empty pattern", g.Name))
			continue
		}
		if prev, dup := byPattern[g.Pattern]; dup {
			viol = append(viol, fmt.Sprintf("grammars %q and %q have the same pattern %q: the table must name each grammar once", prev, g.Name, g.Pattern))
		}
		byPattern[g.Pattern] = g.Name
	}

	// Where each grammar must appear, exactly.
	for _, g := range grammars {
		if g.Pattern == "" {
			continue
		}
		if len(g.Sites) == 0 {
			viol = append(viol, fmt.Sprintf("grammar %q lists no expected site: say in which spec and how many times it is repeated", g.Name))
		}
		files := make([]string, 0, len(specs))
		for f := range specs {
			files = append(files, f)
		}
		for f := range g.Sites {
			if _, listed := specs[f]; !listed {
				files = append(files, f)
			}
		}
		sort.Strings(files)
		done := map[string]bool{}
		for _, f := range files {
			if done[f] {
				continue
			}
			done[f] = true
			got := specs[f][g.Pattern]
			if want := g.Sites[f]; len(got) != want {
				viol = append(viol, fmt.Sprintf("grammar %q (%q): %s has %d site(s) %v, want exactly %d: a node lost its pattern, a copy was added, or the pattern moved to another document", g.Name, g.Pattern, f, len(got), got, want))
			}
		}
	}

	total := 0
	seen := map[string]bool{}
	files := make([]string, 0, len(specs))
	for f := range specs {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		patterns := make([]string, 0, len(specs[f]))
		for p := range specs[f] {
			patterns = append(patterns, p)
		}
		sort.Strings(patterns)
		for _, p := range patterns {
			total += len(specs[f][p])
			if _, ok := byPattern[p]; ok {
				seen[p] = true
				continue
			}
			viol = append(viol, fmt.Sprintf("%s: pattern %q (at %s) is not the Go definition of any identifier grammar in the table: a typo or a one-character drift of an existing one, or a new grammar that needs its Go definition and a row", f, p, specs[f][p][0]))
		}
	}
	if total == 0 {
		viol = append(viol, "no `pattern` found in any spec: the extraction found nothing")
	}
	for _, g := range grammars {
		if !seen[g.Pattern] {
			viol = append(viol, fmt.Sprintf("grammar %q (%q) appears in no spec's `pattern`: the spec drifted from its Go definition, or the table lists a grammar no spec repeats", g.Name, g.Pattern))
		}
	}
	sort.Strings(viol)
	return viol
}
