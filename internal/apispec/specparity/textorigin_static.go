package specparity

// ADR-0039 S1b, D3 (d): the static rules between a word and where its node
// sits. They need to know, for each string node, whether an operation's
// request or response reaches it (following $ref into components) and, for a
// request, whether the operation may carry operator-chosen text.
//
//   - participant-opaque is promised never to be echoed: a node a response
//     reaches must not be opaque.
//   - operator text goes in a request only where the operation's audience is
//     operator, or internal and not forwarded by the collector (falcosidekick's
//     webhook is the example). An operation a participant can reach has no
//     operator-chosen request field; this is what keeps "operator" from being
//     used to launder a participant's bytes as staff text.
//   - `enum` if and only if the node has `enum` or `const`.
//   - a participant-inline / participant-block node a response reaches is a
//     NAMED property (not items / additionalProperties / a parameter or
//     header schema): the portal's derivation (S2) finds participant text by
//     property name, so an unnamed one would be invisible to it.
//   - a participant-* property name is not reused, in responses, by a string
//     node of another class: the same derivation matches by name.
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
// `operator` text (ADR-0039 D2's operator row). A missing or unreadable
// extension is NOT capable: fail-closed.
func operatorCapable(op map[string]any) bool {
	aud, _ := StringExt(op, "x-ctf-audience")
	if aud == "operator" {
		return true
	}
	fwd, ok := BoolExt(op, "x-ctf-collector-forward")
	return aud == "internal" && ok && !fwd
}

// reachSets is which string nodes the operations' responses and (non
// operator-capable) requests reach.
type reachSets struct {
	resp           map[string]bool
	reqParticipant map[string][]string // node pointer -> operations whose request reaches it and may not carry operator text
}

// derefComponent follows a `$ref` of the shape #/components/<section>/<Name>
// to its entry, returning the entry and its pointer. Any other node is
// returned unchanged with the given pointer. An unresolvable $ref returns
// (nil, "") (TextOrigin reports it separately).
func (s *Spec) derefComponent(v any, ptr string) (any, string) {
	m, ok := asMap(v)
	if !ok {
		return v, ptr
	}
	ref, ok := m["$ref"].(string)
	if !ok {
		return v, ptr
	}
	if !s.refResolves(ref) {
		return nil, ""
	}
	segs := strings.Split(ref[2:], "/")
	comp, _ := asMap(s.raw["components"])
	section, _ := asMap(comp[segs[1]])
	name := strings.ReplaceAll(strings.ReplaceAll(segs[2], "~1", "/"), "~0", "~")
	return section[name], childPointer(childPointer("/components", segs[1]), name)
}

func (s *Spec) reachability() reachSets {
	rs := reachSets{resp: map[string]bool{}, reqParticipant: map[string][]string{}}

	// schema descends one Schema Object, following $ref, calling visit for
	// each string node. seen stops a recursive schema.
	var schema func(v any, ptr string, seen map[string]bool, visit func(string))
	schema = func(v any, ptr string, seen map[string]bool, visit func(string)) {
		v, ptr = s.derefComponent(v, ptr)
		m, ok := asMap(v)
		if !ok || seen[ptr] {
			return
		}
		seen[ptr] = true
		if isStringType(m) {
			visit(ptr)
		}
		if props, ok := asMap(m["properties"]); ok {
			for k, pv := range props {
				schema(pv, childPointer(childPointer(ptr, "properties"), k), seen, visit)
			}
		}
		for _, kw := range []string{"items", "additionalProperties"} {
			schema(m[kw], childPointer(ptr, kw), seen, visit)
		}
		for _, kw := range []string{"allOf", "anyOf", "oneOf"} {
			if list, ok := m[kw].([]any); ok {
				for i, el := range list {
					schema(el, childPointer(childPointer(ptr, kw), fmt.Sprint(i)), seen, visit)
				}
			}
		}
	}
	media := func(v any, ptr string, seen map[string]bool, visit func(string)) {
		v, ptr = s.derefComponent(v, ptr)
		m, ok := asMap(v)
		if !ok {
			return
		}
		if content, ok := asMap(m["content"]); ok {
			for mt, mv := range content {
				if mm, ok := asMap(mv); ok {
					schema(mm["schema"], childPointer(childPointer(childPointer(ptr, "content"), mt), "schema"), seen, visit)
				}
			}
		}
	}
	parameter := func(v any, ptr string, seen map[string]bool, visit func(string)) {
		v, ptr = s.derefComponent(v, ptr)
		m, ok := asMap(v)
		if !ok {
			return
		}
		schema(m["schema"], childPointer(ptr, "schema"), seen, visit)
		media(m, ptr, seen, visit)
	}
	response := func(v any, ptr string, seen map[string]bool, visit func(string)) {
		v, ptr = s.derefComponent(v, ptr)
		media(v, ptr, seen, visit)
		if m, ok := asMap(v); ok {
			if hs, ok := asMap(m["headers"]); ok {
				for hk, hv := range hs {
					parameter(hv, childPointer(childPointer(ptr, "headers"), hk), seen, visit)
				}
			}
		}
	}

	paths, _ := asMap(s.raw["paths"])
	for p, pv := range paths {
		item, ok := asMap(pv)
		if !ok {
			continue
		}
		pp := childPointer("/paths", p)
		for method, ov := range item {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}
			op, ok := asMap(ov)
			if !ok {
				continue
			}
			opKey := strings.ToUpper(method) + " " + p
			op0 := childPointer(pp, method)

			reqVisit := func(ptr string) {}
			if !operatorCapable(op) {
				reqVisit = func(ptr string) {
					for _, k := range rs.reqParticipant[ptr] {
						if k == opKey {
							return
						}
					}
					rs.reqParticipant[ptr] = append(rs.reqParticipant[ptr], opKey)
				}
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
				for code, rv := range rm {
					response(rv, childPointer(childPointer(op0, "responses"), code), respSeen, func(ptr string) { rs.resp[ptr] = true })
				}
			}
		}
	}
	for _, ops := range rs.reqParticipant {
		sort.Strings(ops)
	}
	return rs
}

// propertyName returns the property name when a node's pointer ends in
// /properties/<name> (unescaped), and false for any other position.
func propertyName(ptr string) (string, bool) {
	segs := strings.Split(ptr, "/")
	if len(segs) < 3 || segs[len(segs)-2] != "properties" {
		return "", false
	}
	return strings.ReplaceAll(strings.ReplaceAll(segs[len(segs)-1], "~1", "/"), "~0", "~"), true
}

func isParticipantText(word string) bool {
	return word == OriginParticipantInline || word == OriginParticipantBlock
}

// staticRuleViolations checks D3 (d) for the already-walked string nodes.
// Nodes whose declaration is missing or outside the vocabulary are skipped
// here (TextOrigin reports them).
func (s *Spec) staticRuleViolations(nodes []StringNode) []string {
	var viol []string
	rs := s.reachability()

	type named struct{ ptr, word string }
	byName := map[string][]named{}

	for _, n := range nodes {
		word, ok := n.Raw.(string)
		if !ok || !inVocabulary(word) {
			continue
		}
		switch {
		case word == OriginEnum && !n.HasEnum:
			viol = append(viol, fmt.Sprintf("%s: declared `enum` but has neither `enum` nor `const` (the word names a closed set)", n.Pointer))
		case word != OriginEnum && n.HasEnum:
			viol = append(viol, fmt.Sprintf("%s: has `enum`/`const` but declares %q (a closed set is `enum`)", n.Pointer, word))
		}

		if ops := rs.reqParticipant[n.Pointer]; word == OriginOperator && len(ops) > 0 {
			viol = append(viol, fmt.Sprintf("%s: `operator` text in the request of %s, which is neither operator-audience nor internal-and-not-forwarded (a participant can reach it, so the bytes are not operator's)", n.Pointer, strings.Join(ops, ", ")))
		}

		if !rs.resp[n.Pointer] {
			continue
		}
		if word == OriginParticipantOpaque {
			viol = append(viol, fmt.Sprintf("%s: `participant-opaque` is reachable from a response (opaque is promised never to be echoed; if it is shown it is participant-inline or -block)", n.Pointer))
		}
		name, isProp := propertyName(n.Pointer)
		if isParticipantText(word) && !isProp {
			viol = append(viol, fmt.Sprintf("%s: %q in a response must be a named property (not items / additionalProperties / a parameter or header schema): the portal derivation finds participant text by property name", n.Pointer, word))
		}
		if isProp {
			byName[name] = append(byName[name], named{n.Pointer, word})
		}
	}

	for name, list := range byName {
		participant := false
		words := map[string]bool{}
		for _, e := range list {
			words[e.word] = true
			if isParticipantText(e.word) {
				participant = true
			}
		}
		if !participant || len(words) < 2 {
			continue
		}
		var ws []string
		for w := range words {
			ws = append(ws, w)
		}
		sort.Strings(ws)
		for _, e := range list {
			viol = append(viol, fmt.Sprintf("%s: property name %q is a participant-text name in responses but is also declared %s there (classes seen: %s); the portal derivation matches by name, so use a different name", e.ptr, name, e.word, strings.Join(ws, ", ")))
		}
	}
	return viol
}
