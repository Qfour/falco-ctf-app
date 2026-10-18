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
//   - every $ref is a component reference of the shape
//     #/components/<section>/<Name> that exists in this document
//     (specparity's resolve() turns an outside $ref into nil silently; here
//     any other $ref is a failure so a node cannot vanish from the check
//     behind one), and by position: a Schema Object takes
//     #/components/schemas/<Name> only, a parameter #/components/parameters/,
//     a response #/components/responses/, a request body
//     #/components/requestBodies/, a header #/components/headers/;
//   - no mapping has a non-string key (yaml.v3 decodes an unquoted `200:`
//     as a map[any]any, which neither walk below descends into, so strings
//     under it would be unchecked: that is a failure, not a skip);
//   - the structured walk (the places ADR-0039 C3 enumerates) reaches
//     exactly the string nodes a blind whole-document scan finds, so a new
//     location the walk does not know about fails instead of being skipped;
//   - a spec that yields zero string nodes is a failure, not a pass.
//
// The guarantee is exactly that list. It is not "every string schema in the
// file is declared" for shapes the YAML decoder hands over as something other
// than map[string]any / []any: those are rejected, not interpreted.
//
// S1b (#454) adds, in textorigin_static.go and textorigin_forward.go: the
// static rules between a word and the node's shape (D3 (d): opaque never in a
// response, operator in a request only where D2 allows it, enum <=>
// enum/const, participant-* only as named response properties and those
// names not reused for another class), `type` on every enum/const (D3 (h)),
// and the collector's forward copy against its target (D3 (e)). A $ref takes
// no sibling keyword but description / summary, and participant-inline /
// -block are never behind a $ref (textorigin_static.go). Later stages
// (S2+) add the portal gate, the route probes and the response-flow check.

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
	// HasEnum is true when the node carries `enum` or `const`.
	HasEnum bool
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

	walk := s.walkSchemas()
	nodes := walk.nodes
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
	typeless := map[string]bool{}
	for _, p := range walk.typelessEnum {
		typeless[p] = true
	}
	for _, p := range scan.typelessEnum {
		typeless[p] = true
	}
	typelessList := make([]string, 0, len(typeless))
	for p := range typeless {
		typelessList = append(typelessList, p)
	}
	sort.Strings(typelessList)
	for _, p := range typelessList {
		viol = append(viol, fmt.Sprintf("%s: a Schema Object with enum/const and no `type` (ADR-0039 D3 (h)): it is no string node, so neither the declaration check nor the enum rule would see it; write `type`. (Anywhere in the document: a constraint position such as `not:` is no exception.)", p))
	}
	for _, r := range scan.refSiblings {
		viol = append(viol, fmt.Sprintf("%s: a $ref with sibling keywords %s (only description/summary may sit next to a $ref: the walks follow the $ref and would ignore the rest, and the two walks must read one meaning)", r.pointer, r.ref))
	}
	viol = append(viol, s.staticRuleViolations(nodes)...)
	for _, r := range walk.refs {
		if !refInSection(r.ref, r.section) {
			viol = append(viol, fmt.Sprintf("%s: a $ref in a %s position must be #/components/%s/<Name>, got %q (the derivations in later stages follow only that shape, like resolve())", r.pointer, componentSectionNoun[r.section], r.section, r.ref))
		}
	}
	for _, p := range scan.nonStringKeys {
		viol = append(viol, fmt.Sprintf("non-string mapping key at %s (quote it, e.g. \"200\":; the walk does not descend into such a mapping, so anything under it would go unchecked)", p))
	}
	for _, r := range scan.refs {
		if !s.refResolves(r.ref) {
			viol = append(viol, fmt.Sprintf("%s: $ref %q is not a reference to an existing #/components/<section>/<Name> in this document (an outside, missing or deeper target would let nodes vanish from the check)", r.pointer, r.ref))
		}
	}

	sort.Strings(viol)
	rep.Violations = viol
	return rep
}

// componentSections are the components sections a $ref may point into: the
// ones the structured walk below visits.
var componentSections = map[string]bool{
	"schemas": true, "parameters": true, "responses": true,
	"requestBodies": true, "headers": true,
}

// componentSectionNoun names the kind of object a section holds, for messages.
var componentSectionNoun = map[string]string{
	"schemas": "Schema Object", "parameters": "parameter", "responses": "response",
	"requestBodies": "request body", "headers": "header",
}

// refInSection reports whether ref is exactly #/components/<section>/<Name>
// (Name one non-empty segment). For "schemas" this is the same predicate
// resolve() (spec.go) follows, so the $ref shapes this check lets through
// are the ones the later derivations can walk.
func refInSection(ref, section string) bool {
	segs := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
	return strings.HasPrefix(ref, "#/") && len(segs) == 3 && segs[0] == "components" && segs[1] == section && segs[2] != ""
}

// refResolves reports whether ref is exactly #/components/<section>/<Name>
// (section in componentSections, Name one non-empty segment) and that entry
// exists in this document. Everything else (an external file or URL, a
// pointer into paths, a deeper pointer such as
// #/components/schemas/X/properties/y, an unknown section) is not resolved
// here by design: the walk visits components entries, so only a reference to
// one keeps a node inside the check.
func (s *Spec) refResolves(ref string) bool {
	if !strings.HasPrefix(ref, "#/") {
		return false
	}
	segs := strings.Split(ref[2:], "/")
	if len(segs) != 3 || segs[0] != "components" || !componentSections[segs[1]] || segs[2] == "" {
		return false
	}
	comp, ok := asMap(s.raw["components"])
	if !ok {
		return false
	}
	section, ok := asMap(comp[segs[1]])
	if !ok {
		return false
	}
	name := strings.ReplaceAll(strings.ReplaceAll(segs[2], "~1", "/"), "~0", "~")
	v, ok := section[name]
	return ok && v != nil
}

func escapePointerSegment(seg string) string {
	return strings.ReplaceAll(strings.ReplaceAll(seg, "~", "~0"), "/", "~1")
}

func childPointer(parent, seg string) string { return parent + "/" + escapePointerSegment(seg) }

// asMap returns v as a string-keyed mapping. A map[any]any (yaml.v3's result
// for a mapping with a non-string key) is deliberately NOT converted: it is
// reported by scanDocument as a violation instead of being interpreted.
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

// schemaChild is one child Schema Object of a Schema Object, found by
// schemaChildren. Every walker that descends into a Schema Object
// (walkSchemas, the reachability walk, the copy comparison) uses this one
// list, so a keyword added here is seen by all of them at once.
type schemaChild struct {
	segs     []string // keyword path below the parent, e.g. ["properties","name"], ["items"], ["allOf","0"]
	node     any
	property string // the property name, only when the child is entered through `properties`
	named    bool   // true exactly when property is meaningful
}

// schemaChildren lists m's child Schema Objects in a fixed order:
// properties/<name> (sorted), items, additionalProperties, allOf|anyOf|oneOf/<i>.
func schemaChildren(m map[string]any) []schemaChild {
	var out []schemaChild
	if props, ok := asMap(m["properties"]); ok {
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, schemaChild{segs: []string{"properties", k}, node: props[k], property: k, named: true})
		}
	}
	for _, kw := range []string{"items", "additionalProperties"} {
		if sub, ok := asMap(m[kw]); ok {
			out = append(out, schemaChild{segs: []string{kw}, node: sub})
		}
	}
	for _, kw := range []string{"allOf", "anyOf", "oneOf"} {
		if list, ok := m[kw].([]any); ok {
			for i, el := range list {
				out = append(out, schemaChild{segs: []string{kw, fmt.Sprint(i)}, node: el})
			}
		}
	}
	return out
}

// childPtr is ptr extended by a schemaChild's keyword path.
func childPtr(ptr string, c schemaChild) string {
	for _, seg := range c.segs {
		ptr = childPointer(ptr, seg)
	}
	return ptr
}

// stringNodes is the structured walk (ADR-0039 C3's counting rule): string
// Schema Objects under components.{schemas,parameters,responses,requestBodies,
// headers} and under every operation's (and path item's) inline parameters,
// requestBody and responses, descending through properties, items,
// additionalProperties and allOf|anyOf|oneOf. A `$ref` site is not a node.
func (s *Spec) stringNodes() []StringNode { return s.walkSchemas().nodes }

// positionedRef is a `$ref` found where the walk expects a Schema Object, a
// parameter, a response, a request body or a header: the section the
// reference must point into is fixed by that position.
type positionedRef struct{ pointer, ref, section string }

// schemaWalk is what the structured walk collects.
type schemaWalk struct {
	nodes []StringNode
	refs  []positionedRef
	// typelessEnum: Schema Objects with `enum` or `const` and no `type`
	// (ADR-0039 D3 (h)): they are no string node, so no declaration check
	// and no enum <=> enum/const rule would ever see them.
	typelessEnum []string
}

func hasKey(m map[string]any, k string) bool { _, ok := m[k]; return ok }

func (s *Spec) walkSchemas() schemaWalk {
	var w schemaWalk
	out := &w.nodes
	note := func(v any, ptr, section string) {
		if m, ok := asMap(v); ok {
			if ref, ok := m["$ref"].(string); ok {
				w.refs = append(w.refs, positionedRef{pointer: ptr, ref: ref, section: section})
			}
		}
	}

	var schema func(v any, ptr string)
	schema = func(v any, ptr string) {
		note(v, ptr, "schemas")
		m, ok := asMap(v)
		if !ok {
			return
		}
		hasEnum := hasKey(m, "enum") || hasKey(m, "const")
		if isStringType(m) {
			*out = append(*out, StringNode{Pointer: ptr, Raw: m[TextOriginKey], HasEnum: hasEnum})
		} else if hasEnum && !hasKey(m, "type") {
			w.typelessEnum = append(w.typelessEnum, ptr)
		}
		for _, c := range schemaChildren(m) {
			schema(c.node, childPtr(ptr, c))
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
	paramBody := func(v any, ptr string) { // parameter / header
		m, ok := asMap(v)
		if !ok {
			return
		}
		schema(m["schema"], childPointer(ptr, "schema"))
		media(m, ptr)
	}
	parameter := func(v any, ptr string) { note(v, ptr, "parameters"); paramBody(v, ptr) }
	header := func(v any, ptr string) { note(v, ptr, "headers"); paramBody(v, ptr) }
	requestBody := func(v any, ptr string) { note(v, ptr, "requestBodies"); media(v, ptr) }
	response := func(v any, ptr string) {
		note(v, ptr, "responses")
		media(v, ptr)
		if m, ok := asMap(v); ok {
			if hs, ok := asMap(m["headers"]); ok {
				for hk, hv := range hs {
					header(hv, childPointer(childPointer(ptr, "headers"), hk))
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
		each(comp["requestBodies"], childPointer(base, "requestBodies"), requestBody)
		each(comp["headers"], childPointer(base, "headers"), header)
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
				requestBody(op["requestBody"], childPointer(op0, "requestBody"))
				each(op["responses"], childPointer(op0, "responses"), response)
			}
		}
	}

	sort.Slice(w.nodes, func(i, j int) bool { return w.nodes[i].Pointer < w.nodes[j].Pointer })
	sort.Strings(w.typelessEnum)
	return w
}

type refSite struct{ pointer, ref string }

type documentScan struct {
	stringTyped []string  // maps with type string, anywhere in the document
	originKeyed []string  // maps carrying TextOriginKey, anywhere
	refs        []refSite // every `$ref` string, anywhere
	// refSiblings: $ref sites with a sibling key other than description /
	// summary; refSite.ref holds the sibling names, sorted.
	refSiblings []refSite
	// typelessEnum: maps with an `enum` list or a scalar `const` and no
	// `type`, anywhere (a property that is merely NAMED enum / const holds a
	// map, so it is not mistaken for the keyword).
	typelessEnum []string
	// pointers of mappings with a non-string key (map[any]any); not descended
	nonStringKeys []string
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
				var extra []string
				for k := range t {
					if k != "$ref" && k != "description" && k != "summary" {
						extra = append(extra, k)
					}
				}
				if len(extra) > 0 {
					sort.Strings(extra)
					sc.refSiblings = append(sc.refSiblings, refSite{pointer: ptr, ref: strings.Join(extra, ", ")})
				}
			}
			if !hasKey(t, "type") && !hasKey(t, "$ref") {
				_, enumList := t["enum"].([]any)
				c, hasConst := t["const"]
				_, constIsMap := c.(map[string]any)
				_, constIsList := c.([]any)
				if enumList || (hasConst && !constIsMap && !constIsList) {
					sc.typelessEnum = append(sc.typelessEnum, ptr)
				}
			}
			for k, ev := range t {
				walk(ev, childPointer(ptr, k))
			}
		case map[any]any:
			sc.nonStringKeys = append(sc.nonStringKeys, ptr)
		case []any:
			for i, ev := range t {
				walk(ev, childPointer(ptr, fmt.Sprint(i)))
			}
		}
	}
	walk(root, "")
	sort.Strings(sc.nonStringKeys)
	sort.Strings(sc.typelessEnum)
	sort.Slice(sc.refSiblings, func(i, j int) bool { return sc.refSiblings[i].pointer < sc.refSiblings[j].pointer })
	sort.Strings(sc.stringTyped)
	sort.Strings(sc.originKeyed)
	return sc
}
