package specparity

// ADR-0039 S1: the per-string-node `x-ctf-text-origin` declaration and the
// walker that finds every string Schema Object in a spec and checks it.
//
// Every Schema Object that says `type: string` (or a `type` list containing
// "string") must carry `x-ctf-text-origin: <one of six words>`: who can
// choose the bytes of this value, and how it is shown. The key is mandatory
// and has no default (ADR-0005's discipline: absent is a failure, never
// "false"), and there is no exclusion list: a string added without a
// classification turns `make test` red.
//
// This file is TEST-ONLY by package placement (see the package doc in
// spec.go and internal/apispec/dependency_boundary_test.go): nothing here is
// imported by a cmd/* binary's build.
//
// What S1 checks (ADR-0039 D3 (a)/(b)/(c)/(f)/(g) subset):
//
//   - every string node has the key, and the value is in the vocabulary;
//   - the key appears on no node that is not a string node (an object, a
//     $ref site, an operation);
//   - every $ref resolves inside the document (specparity's resolve() turns
//     an outside $ref into nil silently; here an unresolvable $ref is a
//     failure so a node cannot vanish from the check behind one);
//   - the structured walk (the places ADR-0039 C3 enumerates) reaches
//     exactly the string nodes a blind whole-document scan finds, so a new
//     location the walk does not know about fails instead of being skipped;
//   - a spec that yields zero string nodes is a failure, not a pass.
//
// What it deliberately does NOT do (later ADR-0039 stages): the static rules
// between a word and the node's shape (enum <=> enum/const, participant-* only
// as named response properties, ...), the collector-copy comparison, the
// portal gate, the route probes and the response-flow check.

import (
	"fmt"
	"sort"
	"strings"
)

// TextOriginKey is the schema-node extension this file is about.
const TextOriginKey = "x-ctf-text-origin"

// The six words of the vocabulary (ADR-0039 D2). Their meaning is written in
// docs/openapi-scoreboard.yaml's info.description and in the ADR; this slice
// is the ONLY machine definition of the set.
const (
	OriginParticipantInline = "participant-inline"
	OriginParticipantBlock  = "participant-block"
	OriginParticipantOpaque = "participant-opaque"
	OriginOperator          = "operator"
	OriginToken             = "token"
	OriginEnum              = "enum"
)

// TextOriginVocabulary is the closed set of values of TextOriginKey.
var TextOriginVocabulary = []string{
	OriginParticipantInline,
	OriginParticipantBlock,
	OriginParticipantOpaque,
	OriginOperator,
	OriginToken,
	OriginEnum,
}

func inVocabulary(word string) bool {
	for _, w := range TextOriginVocabulary {
		if w == word {
			return true
		}
	}
	return false
}

// StringNode is one string Schema Object found by the structured walk.
type StringNode struct {
	// Pointer is the JSON pointer of the node inside the document, e.g.
	// "/components/schemas/Me/properties/display_name".
	Pointer string
	// Raw is the node's value of TextOriginKey (nil when absent).
	Raw any
}

// TextOriginReport is the result of checking one spec.
type TextOriginReport struct {
	// Nodes is every string Schema Object the structured walk reached,
	// sorted by pointer.
	Nodes []StringNode
	// Counts maps each vocabulary word to the number of string nodes that
	// declare it. Every word of the vocabulary has an entry (possibly 0);
	// unknown or missing values are not counted anywhere (they are
	// Violations).
	Counts map[string]int
	// Violations is the sorted list of failures; empty means the spec is
	// fully and validly declared. Each line names a JSON pointer.
	Violations []string
}

// TextOrigin walks the spec and checks every string Schema Object.
func (s *Spec) TextOrigin() TextOriginReport {
	rep := TextOriginReport{Counts: map[string]int{}}
	for _, w := range TextOriginVocabulary {
		rep.Counts[w] = 0
	}
	var viol []string

	nodes := s.stringNodes()
	rep.Nodes = nodes
	if len(nodes) == 0 {
		viol = append(viol, "no string Schema Object found at all: the walk or the spec is broken (0 nodes must never read as \"nothing to declare\")")
	}

	walked := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		walked[n.Pointer] = true
		switch v := n.Raw.(type) {
		case nil:
			viol = append(viol, fmt.Sprintf("%s: string node without %s (declare who can choose its bytes: %s)", n.Pointer, TextOriginKey, strings.Join(TextOriginVocabulary, " | ")))
		case string:
			if !inVocabulary(v) {
				viol = append(viol, fmt.Sprintf("%s: %s: %q is not in the vocabulary (%s)", n.Pointer, TextOriginKey, v, strings.Join(TextOriginVocabulary, " | ")))
			} else {
				rep.Counts[v]++
			}
		default:
			viol = append(viol, fmt.Sprintf("%s: %s must be a string naming one of %s, got %T", n.Pointer, TextOriginKey, strings.Join(TextOriginVocabulary, " | "), v))
		}
	}

	// Cross-check the structured walk against a blind scan of the whole
	// document: any `type: string` map the walk did not reach, and any map
	// carrying the key that is not a string node, is a failure.
	scan := scanDocument(s.raw)
	for _, p := range scan.stringTyped {
		if !walked[p] {
			viol = append(viol, fmt.Sprintf("%s: a string Schema Object that the walk (components, parameters, request bodies, responses, headers -> properties/items/additionalProperties/allOf|anyOf|oneOf) does not reach: it would escape the declaration check; extend the walk", p))
		}
	}
	stringTyped := make(map[string]bool, len(scan.stringTyped))
	for _, p := range scan.stringTyped {
		stringTyped[p] = true
	}
	for _, p := range scan.originKeyed {
		if !stringTyped[p] {
			viol = append(viol, fmt.Sprintf("%s: %s on a node that is not a string Schema Object (it belongs on the definition with `type: string`, not on an object, a $ref site or an operation)", p, TextOriginKey))
		}
	}
	for _, r := range scan.refs {
		if !s.refResolves(r.ref) {
			viol = append(viol, fmt.Sprintf("%s: $ref %q does not resolve inside this document (an outside or missing target would let nodes vanish from the check)", r.pointer, r.ref))
		}
	}

	sort.Strings(viol)
	rep.Violations = viol
	return rep
}

// refResolves reports whether a "#/a/b/c" JSON-pointer $ref names an existing
// value in this document. Anything not starting with "#/" (an external file
// or URL) does not resolve here by design.
func (s *Spec) refResolves(ref string) bool {
	if !strings.HasPrefix(ref, "#/") {
		return false
	}
	var cur any = s.raw
	for _, seg := range strings.Split(ref[2:], "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		switch c := cur.(type) {
		case map[string]any:
			next, ok := c[seg]
			if !ok {
				return false
			}
			cur = next
		default:
			return false
		}
	}
	return cur != nil
}

func escapePointerSegment(seg string) string {
	return strings.ReplaceAll(strings.ReplaceAll(seg, "~", "~0"), "/", "~1")
}

func childPointer(parent, seg string) string { return parent + "/" + escapePointerSegment(seg) }

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// isStringType reports whether a Schema Object's `type` is "string" or a
// list containing "string" (OpenAPI 3.1: `type: [string, "null"]`).
func isStringType(m map[string]any) bool {
	switch t := m["type"].(type) {
	case string:
		return t == "string"
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && s == "string" {
				return true
			}
		}
	}
	return false
}

// stringNodes is the structured walk (ADR-0039 C3's counting rule): string
// Schema Objects under components.{schemas,parameters,responses,requestBodies,
// headers} and under every operation's (and path item's) inline parameters,
// requestBody and responses, descending through properties, items,
// additionalProperties and allOf|anyOf|oneOf. A `$ref` site is not a node.
func (s *Spec) stringNodes() []StringNode {
	var out []StringNode

	var schema func(v any, ptr string)
	schema = func(v any, ptr string) {
		m, ok := asMap(v)
		if !ok {
			return
		}
		if isStringType(m) {
			out = append(out, StringNode{Pointer: ptr, Raw: m[TextOriginKey]})
		}
		if props, ok := asMap(m["properties"]); ok {
			for k, pv := range props {
				schema(pv, childPointer(childPointer(ptr, "properties"), k))
			}
		}
		for _, kw := range []string{"items", "additionalProperties"} {
			if sub, ok := asMap(m[kw]); ok {
				schema(sub, childPointer(ptr, kw))
			}
		}
		for _, kw := range []string{"allOf", "anyOf", "oneOf"} {
			if list, ok := m[kw].([]any); ok {
				for i, el := range list {
					schema(el, childPointer(childPointer(ptr, kw), fmt.Sprint(i)))
				}
			}
		}
	}

	media := func(v any, ptr string) { // requestBody / response / requestBodies entry
		m, ok := asMap(v)
		if !ok {
			return
		}
		if content, ok := asMap(m["content"]); ok {
			for mt, mv := range content {
				if mm, ok := asMap(mv); ok {
					schema(mm["schema"], childPointer(childPointer(childPointer(ptr, "content"), mt), "schema"))
				}
			}
		}
	}
	parameter := func(v any, ptr string) { // parameter / header
		m, ok := asMap(v)
		if !ok {
			return
		}
		schema(m["schema"], childPointer(ptr, "schema"))
		media(m, ptr)
	}
	response := func(v any, ptr string) {
		media(v, ptr)
		if m, ok := asMap(v); ok {
			if hs, ok := asMap(m["headers"]); ok {
				for hk, hv := range hs {
					parameter(hv, childPointer(childPointer(ptr, "headers"), hk))
				}
			}
		}
	}
	each := func(v any, ptr string, fn func(any, string)) {
		if m, ok := asMap(v); ok {
			for k, ev := range m {
				fn(ev, childPointer(ptr, k))
			}
		}
	}
	parameterList := func(v any, ptr string) {
		if list, ok := v.([]any); ok {
			for i, el := range list {
				parameter(el, childPointer(ptr, fmt.Sprint(i)))
			}
		}
	}

	if comp, ok := asMap(s.raw["components"]); ok {
		base := "/components"
		each(comp["schemas"], childPointer(base, "schemas"), schema)
		each(comp["parameters"], childPointer(base, "parameters"), parameter)
		each(comp["responses"], childPointer(base, "responses"), response)
		each(comp["requestBodies"], childPointer(base, "requestBodies"), media)
		each(comp["headers"], childPointer(base, "headers"), parameter)
	}
	if paths, ok := asMap(s.raw["paths"]); ok {
		for p, pv := range paths {
			item, ok := asMap(pv)
			if !ok {
				continue
			}
			pp := childPointer("/paths", p)
			parameterList(item["parameters"], childPointer(pp, "parameters"))
			for method, ov := range item {
				if !httpMethods[strings.ToLower(method)] {
					continue
				}
				op, ok := asMap(ov)
				if !ok {
					continue
				}
				op0 := childPointer(pp, method)
				parameterList(op["parameters"], childPointer(op0, "parameters"))
				media(op["requestBody"], childPointer(op0, "requestBody"))
				each(op["responses"], childPointer(op0, "responses"), response)
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Pointer < out[j].Pointer })
	return out
}

type refSite struct{ pointer, ref string }

type documentScan struct {
	stringTyped []string  // maps with type string, anywhere in the document
	originKeyed []string  // maps carrying TextOriginKey, anywhere
	refs        []refSite // every `$ref` string, anywhere
}

// scanDocument is the blind whole-document scan the structured walk is
// checked against. It knows nothing about OpenAPI structure.
func scanDocument(root any) documentScan {
	var sc documentScan
	var walk func(v any, ptr string)
	walk = func(v any, ptr string) {
		switch t := v.(type) {
		case map[string]any:
			if isStringType(t) {
				sc.stringTyped = append(sc.stringTyped, ptr)
			}
			if _, ok := t[TextOriginKey]; ok {
				sc.originKeyed = append(sc.originKeyed, ptr)
			}
			if ref, ok := t["$ref"].(string); ok {
				sc.refs = append(sc.refs, refSite{pointer: ptr, ref: ref})
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
	walk(root, "")
	sort.Strings(sc.stringTyped)
	sort.Strings(sc.originKeyed)
	return sc
}
