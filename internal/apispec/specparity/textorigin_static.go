package specparity

// ADR-0039 S1b, D3 (d): the static rules between a word and where its node
// sits. They need to know, for each string node, whether an operation's
// request or response reaches it (following $ref into components, however
// long the chain) and, for a request, whether the operation may carry
// operator-chosen text.
//
//   - participant-opaque is promised never to be echoed: a node a response
//     reaches must not be opaque.
//   - operator text goes in a request only where the operation is an
//     operator-audience or internal one that the collector does not forward
//     (falcosidekick's webhook is the example). An operation a participant
//     can reach has no operator-chosen request field; this is what keeps
//     "operator" from being used to launder a participant's bytes as staff
//     text. NOTE the approximation: this is derived from audience and the
//     forward flag, not from who can really connect. auth-policy's /check-*
//     operations are `internal` and not forwarded, yet a participant's
//     browser reaches them through the ingress; so "operator" there is a
//     statement about the declaration, and widening what the request-side
//     operator nodes are is a D3 (g) pin question (ADR rev4), not decided here.
//   - `enum` if and only if the node has `enum` or `const`.
//   - participant-inline / participant-block are written INLINE: the string
//     schema sits at the property that uses it, never behind a `$ref` to a
//     shared definition (VP decision on review-5x 40). The portal derivation
//     (S2) matches participant text by the name of the property that uses it
//     and a pointer into a component would be invisible to a name rule.
//   - a participant-inline / -block node a response reaches is a NAMED
//     property (not items / additionalProperties / a parameter or header
//     schema / a combinator branch), and that use-site property name is not
//     reused, in responses, by a string node of another class.
//
// A component reached from both a request and a response is subject to both
// sides' rules. A component no operation reaches is subject to the enum rule
// only.

import (
	"fmt"
	"sort"
	"strings"
)

// operatorCapable reports whether an operation's request may carry
// `operator` text (ADR-0039 D2's operator row): an operator- or
// internal-audience operation, AND explicitly not forwarded by the
// collector. A missing or unreadable extension is NOT capable: fail-closed.
func operatorCapable(op map[string]any) bool {
	aud, _ := StringExt(op, "x-ctf-audience")
	fwd, ok := BoolExt(op, "x-ctf-collector-forward")
	return (aud == "operator" || aud == "internal") && ok && !fwd
}

// use is one place a string node is used from: the property that names the
// use site (when the node was entered through `properties`, possibly across
// $ref hops) and whether the node itself was reached through a `$ref`.
type use struct {
	ptr      string // the string node's defining pointer
	property string // use-site property name, "" when the node is not a named property
	viaRef   bool   // the string node itself is behind a `$ref` (a shared definition)
}

// reachSets is which string nodes the operations' responses and requests
// reach.
type reachSets struct {
	respUses       []use               // every use of a string node from a response (deduplicated, sorted)
	reqAny         map[string]bool     // pointers any request reaches (operator-capable operations too)
	respAny        map[string]bool     // pointers any response reaches
	reqParticipant map[string][]string // node pointer -> operations whose request reaches it and may not carry operator text
	reqViaRef      map[string]bool     // node pointer -> reached from a request through a `$ref` at the node itself
	respViaRef     map[string]bool     // the same for responses
}

// derefAll follows `$ref` (any #/components/<section>/<Name>) until the node
// is not a reference, returning the entry, its pointer and how many hops it
// took. A reference that does not resolve, or a cycle, returns (nil, "", n):
// TextOrigin reports the first; a cycle holds no string node.
func (s *Spec) derefAll(v any, ptr string) (any, string, int) {
	seen := map[string]bool{}
	hops := 0
	for {
		m, ok := asMap(v)
		if !ok {
			return v, ptr, hops
		}
		ref, ok := m["$ref"].(string)
		if !ok {
			return v, ptr, hops
		}
		if !s.refResolves(ref) || seen[ref] {
			return nil, "", hops
		}
		seen[ref] = true
		segs := strings.Split(ref[2:], "/")
		comp, _ := asMap(s.raw["components"])
		section, _ := asMap(comp[segs[1]])
		name := strings.ReplaceAll(strings.ReplaceAll(segs[2], "~1", "/"), "~0", "~")
		v, ptr = section[name], childPointer(childPointer("/components", segs[1]), name)
		hops++
	}
}

func (s *Spec) reachability() reachSets {
	rs := reachSets{
		reqAny: map[string]bool{}, respAny: map[string]bool{},
		reqParticipant: map[string][]string{}, reqViaRef: map[string]bool{}, respViaRef: map[string]bool{},
	}
	respUse := map[use]bool{}

	// schema descends one Schema Object, following $ref, calling visit for
	// each string node. property is the use-site name carried in from the
	// parent when this node was entered through `properties` (it survives
	// $ref hops); seen stops recursion.
	var schema func(v any, ptr, property string, seen map[string]bool, visit func(use))
	schema = func(v any, ptr, property string, seen map[string]bool, visit func(use)) {
		v, ptr, hops := s.derefAll(v, ptr)
		m, ok := asMap(v)
		if !ok {
			return
		}
		key := ptr + "\x00" + property
		if seen[key] {
			return
		}
		seen[key] = true
		if isStringType(m) {
			visit(use{ptr: ptr, property: property, viaRef: hops > 0})
		}
		for _, c := range schemaChildren(m) {
			name := ""
			if c.named {
				name = c.property
			}
			schema(c.node, childPtr(ptr, c), name, seen, visit)
		}
	}
	media := func(v any, ptr string, seen map[string]bool, visit func(use)) {
		v, ptr, _ = s.derefAll(v, ptr)
		m, ok := asMap(v)
		if !ok {
			return
		}
		if content, ok := asMap(m["content"]); ok {
			for _, mt := range sortedAnyKeys(content) {
				if mm, ok := asMap(content[mt]); ok {
					schema(mm["schema"], childPointer(childPointer(childPointer(ptr, "content"), mt), "schema"), "", seen, visit)
				}
			}
		}
	}
	parameter := func(v any, ptr string, seen map[string]bool, visit func(use)) {
		v, ptr, _ = s.derefAll(v, ptr)
		m, ok := asMap(v)
		if !ok {
			return
		}
		schema(m["schema"], childPointer(ptr, "schema"), "", seen, visit)
		media(m, ptr, seen, visit)
	}
	response := func(v any, ptr string, seen map[string]bool, visit func(use)) {
		v, ptr, _ = s.derefAll(v, ptr)
		media(v, ptr, seen, visit)
		if m, ok := asMap(v); ok {
			if hs, ok := asMap(m["headers"]); ok {
				for _, hk := range sortedAnyKeys(hs) {
					parameter(hs[hk], childPointer(childPointer(ptr, "headers"), hk), seen, visit)
				}
			}
		}
	}

	paths, _ := asMap(s.raw["paths"])
	for _, p := range sortedAnyKeys(paths) {
		item, ok := asMap(paths[p])
		if !ok {
			continue
		}
		pp := childPointer("/paths", p)
		for _, method := range sortedAnyKeys(item) {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}
			op, ok := asMap(item[method])
			if !ok {
				continue
			}
			opKey := strings.ToUpper(method) + " " + p
			op0 := childPointer(pp, method)
			capable := operatorCapable(op)

			reqVisit := func(u use) {
				rs.reqAny[u.ptr] = true
				if u.viaRef {
					rs.reqViaRef[u.ptr] = true
				}
				if capable {
					return
				}
				for _, k := range rs.reqParticipant[u.ptr] {
					if k == opKey {
						return
					}
				}
				rs.reqParticipant[u.ptr] = append(rs.reqParticipant[u.ptr], opKey)
			}
			reqSeen := map[string]bool{}
			for _, lp := range []struct {
				v   any
				ptr string
			}{{item["parameters"], childPointer(pp, "parameters")}, {op["parameters"], childPointer(op0, "parameters")}} {
				if list, ok := lp.v.([]any); ok {
					for i, el := range list {
						parameter(el, childPointer(lp.ptr, fmt.Sprint(i)), reqSeen, reqVisit)
					}
				}
			}
			media(op["requestBody"], childPointer(op0, "requestBody"), reqSeen, reqVisit)

			respSeen := map[string]bool{}
			if rm, ok := asMap(op["responses"]); ok {
				for _, code := range sortedAnyKeys(rm) {
					response(rm[code], childPointer(childPointer(op0, "responses"), code), respSeen, func(u use) {
						rs.respAny[u.ptr] = true
						if u.viaRef {
							rs.respViaRef[u.ptr] = true
						}
						respUse[u] = true
					})
				}
			}
		}
	}
	for u := range respUse {
		rs.respUses = append(rs.respUses, u)
	}
	sort.Slice(rs.respUses, func(i, j int) bool {
		a, b := rs.respUses[i], rs.respUses[j]
		if a.ptr != b.ptr {
			return a.ptr < b.ptr
		}
		if a.property != b.property {
			return a.property < b.property
		}
		return !a.viaRef && b.viaRef
	})
	for _, ops := range rs.reqParticipant {
		sort.Strings(ops)
	}
	return rs
}

func sortedAnyKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isParticipantText(word string) bool {
	return word == OriginParticipantInline || word == OriginParticipantBlock
}

// inlineNodesNotReached lists string nodes written inline under an operation
// (pointer under /paths/) that the reachability walk never visited from
// either side. It must be empty: the two walks share schemaChildren and the
// same entry points, so a non-empty answer means one of them was changed
// without the other and the (d) rules would silently skip those nodes.
func inlineNodesNotReached(nodes []StringNode, rs reachSets) []string {
	var out []string
	for _, n := range nodes {
		if strings.HasPrefix(n.Pointer, "/paths/") && !rs.reqAny[n.Pointer] && !rs.respAny[n.Pointer] {
			out = append(out, n.Pointer)
		}
	}
	return out
}

// staticRuleViolations checks D3 (d) for the already-walked string nodes.
// Nodes whose declaration is missing or outside the vocabulary are skipped
// here (TextOrigin reports them).
func (s *Spec) staticRuleViolations(nodes []StringNode) []string {
	var viol []string
	rs := s.reachability()

	for _, p := range inlineNodesNotReached(nodes, rs) {
		viol = append(viol, fmt.Sprintf("%s: an inline string node under /paths/ that the request/response reachability walk never visited (the walks disagree: the (d) rules would skip it)", p))
	}

	words := map[string]string{} // pointer -> word, valid declarations only
	hasEnum := map[string]bool{}
	for _, n := range nodes {
		word, ok := n.Raw.(string)
		if !ok || !inVocabulary(word) {
			continue
		}
		words[n.Pointer] = word
		hasEnum[n.Pointer] = n.HasEnum
		switch {
		case word == OriginEnum && !n.HasEnum:
			viol = append(viol, fmt.Sprintf("%s: declared `enum` but has neither `enum` nor `const` (the word names a closed set)", n.Pointer))
		case word != OriginEnum && n.HasEnum:
			viol = append(viol, fmt.Sprintf("%s: has `enum`/`const` but declares %q (a closed set is `enum`)", n.Pointer, word))
		}
	}

	for _, n := range nodes {
		word, ok := words[n.Pointer]
		if !ok {
			continue
		}
		if ops := rs.reqParticipant[n.Pointer]; word == OriginOperator && len(ops) > 0 {
			viol = append(viol, fmt.Sprintf("%s: `operator` text in the request of %s, which is not an operator/internal operation that the collector leaves unforwarded (a participant can reach it, so the bytes are not operator's)", n.Pointer, strings.Join(ops, ", ")))
		}
		if isParticipantText(word) && (rs.reqViaRef[n.Pointer] || rs.respViaRef[n.Pointer]) {
			viol = append(viol, fmt.Sprintf("%s: %q is referenced through a `$ref`; participant-inline / -block are written inline at the property that uses them (a shared definition hides the use-site name the portal derivation matches by)", n.Pointer, word))
		}
	}

	type named struct{ ptr, word string }
	byName := map[string][]named{}
	for _, u := range rs.respUses {
		word, ok := words[u.ptr]
		if !ok {
			continue
		}
		if word == OriginParticipantOpaque {
			viol = append(viol, fmt.Sprintf("%s: `participant-opaque` is reachable from a response (opaque is promised never to be echoed; if it is shown it is participant-inline or -block)", u.ptr))
		}
		if isParticipantText(word) && u.property == "" {
			viol = append(viol, fmt.Sprintf("%s: %q in a response must be a named property (not items / additionalProperties / a parameter or header schema / a combinator branch): the portal derivation finds participant text by property name", u.ptr, word))
		}
		if u.property != "" {
			byName[u.property] = append(byName[u.property], named{u.ptr, word})
		}
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		list := byName[name]
		participant := false
		classes := map[string]bool{}
		for _, e := range list {
			classes[e.word] = true
			if isParticipantText(e.word) {
				participant = true
			}
		}
		if !participant || len(classes) < 2 {
			continue
		}
		var ws []string
		for w := range classes {
			ws = append(ws, w)
		}
		sort.Strings(ws)
		seen := map[string]bool{}
		for _, e := range list {
			if seen[e.ptr] {
				continue
			}
			seen[e.ptr] = true
			viol = append(viol, fmt.Sprintf("%s: used from a response property named %q, which is a participant-text name there, but this node is declared %s (classes seen under that name: %s); the portal derivation matches by name, so use a different property name", e.ptr, name, e.word, strings.Join(ws, ", ")))
		}
	}
	return viol
}
