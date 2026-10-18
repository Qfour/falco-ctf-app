package specparity

// ADR-0039 S1b, D3 (e): when a collector operation writes out a request
// schema for a route it forwards, that schema is a COPY of the scoreboard
// route's (a spec cannot $ref across documents: an outside $ref is a failure
// of D3 (c)). The collector forwards the body unchanged, so the target alone
// accepts or rejects it; a copy that accepts less or more than the target is a
// spec that lies. #433 found such a copy by hand (the target had a `pattern`
// the copy lacked).
//
// The pairing is the one the spec already declares: the collector operation's
// `x-ctf-forward-target` ("<METHOD> <path>" of the scoreboard operation), which
// CollectorForwardBijection (parity.go) already holds to a real forwarded
// operation. No second declaration is introduced.
//
// Compared, per string node, at the same position inside the request schema:
// the position set (both ways), the text-origin word, the keywords that decide
// acceptance (type, pattern, maxLength, minLength, format, enum, const), and
// whether the parent object lists the property in `required`. `description`
// and everything else is not compared. $ref is resolved before comparing.
// Parameters are not compared (the collector validates {cid} itself).

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// forwardCopyKeywords are the keywords that decide whether a string value is
// accepted (ADR-0039 D3 (e)).
var forwardCopyKeywords = []string{"type", "pattern", "maxLength", "minLength", "format", "enum", "const"}

type copyLeaf struct {
	word     any
	keywords map[string]any
	required bool
}

// requestJSONSchema returns an operation's application/json request schema.
// The request body may itself be a `$ref` (#/components/requestBodies/<Name>),
// which is resolved first. (nil, "") means the operation writes no schema:
// no request body, or an application/json media with no `schema` (the
// collector's submit says `application/json: {}`). A body that cannot be
// read, or a schema only under another media type, is a problem, never a
// silent "nothing to compare".
func (s *Spec) requestJSONSchema(op map[string]any) (map[string]any, string) {
	raw, present := op["requestBody"]
	if !present {
		return nil, ""
	}
	rb, _, _ := s.derefAll(raw, "")
	rbm, ok := asMap(rb)
	if !ok {
		return nil, "its requestBody is not readable (an unresolvable $ref or a non-mapping)"
	}
	content, _ := asMap(rbm["content"])
	if media, ok := asMap(content["application/json"]); ok {
		if _, has := media["schema"]; !has {
			return nil, ""
		}
		sch, ok := asMap(media["schema"])
		if !ok {
			return nil, "its application/json schema is not a mapping"
		}
		return sch, ""
	}
	for _, mt := range sortedAnyKeys(content) {
		if mm, ok := asMap(content[mt]); ok && hasKey(mm, "schema") {
			return nil, fmt.Sprintf("it writes a schema only under %s, not application/json (the comparison reads application/json)", mt)
		}
	}
	return nil, ""
}

// copyLeaves lists the string nodes of schema, keyed by their position
// relative to the schema root (properties/items/additionalProperties/
// allOf|anyOf|oneOf), resolving #/components/schemas/<Name> $refs. A problem
// (unresolvable ref, too deep) is returned instead of skipped.
func (s *Spec) copyLeaves(schema map[string]any) (leaves map[string]copyLeaf, problems []string) {
	leaves = map[string]copyLeaf{}
	var walk func(v any, rel string, required bool, onPath map[string]bool)
	walk = func(v any, rel string, required bool, onPath map[string]bool) {
		m, ok := asMap(v)
		if !ok {
			return
		}
		if ref, ok := m["$ref"].(string); ok {
			name, ok := schemaRefName(ref)
			if !ok || s.SchemaByName(name) == nil {
				problems = append(problems, fmt.Sprintf("%s: $ref %q does not name an existing #/components/schemas/<Name>", rel, ref))
				return
			}
			if onPath[name] {
				problems = append(problems, fmt.Sprintf("%s: recursive $ref %q: the copy comparison does not follow cycles", rel, ref))
				return
			}
			next := map[string]bool{name: true}
			for k := range onPath {
				next[k] = true
			}
			walk(s.SchemaByName(name), rel, required, next)
			return
		}
		if isStringType(m) {
			kw := map[string]any{}
			for _, k := range forwardCopyKeywords {
				if v, ok := m[k]; ok {
					kw[k] = v
				}
			}
			leaves[rel] = copyLeaf{word: m[TextOriginKey], keywords: kw, required: required}
		}
		reqd := map[string]bool{}
		if list, ok := m["required"].([]any); ok {
			for _, e := range list {
				if name, ok := e.(string); ok {
					reqd[name] = true
				}
			}
		}
		for _, c := range schemaChildren(m) {
			childRel := rel
			for _, seg := range c.segs {
				childRel += "/" + escapePointerSegment(seg)
			}
			walk(c.node, childRel, c.named && reqd[c.property], onPath)
		}
	}
	walk(schema, "", false, map[string]bool{})
	return leaves, problems
}

// CollectorCopyViolations compares, for every collector operation that
// forwards (x-ctf-collector-forward: true) and writes an application/json
// request schema, that schema against its x-ctf-forward-target's in target.
// compared is the number of string nodes compared (0 must be read by the
// caller as a broken check, not as agreement).
func CollectorCopyViolations(collector, target *Spec) (violations []string, compared int) {
	ops := collector.Operations()
	keys := make([]string, 0, len(ops))
	for k := range ops {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	targetOps := target.Operations()

	for _, key := range keys {
		op := ops[key]
		if fwd, ok := BoolExt(op, "x-ctf-collector-forward"); !ok || !fwd {
			continue
		}
		copySchema, problem := collector.requestJSONSchema(op)
		if problem != "" {
			violations = append(violations, fmt.Sprintf("collector %s: %s", key, problem))
			continue
		}
		if copySchema == nil {
			continue // the collector does not write the body out: nothing to copy
		}
		tkey, ok := StringExt(op, "x-ctf-forward-target")
		if !ok || tkey == "" {
			violations = append(violations, fmt.Sprintf("collector %s: writes a request schema but has no x-ctf-forward-target to compare it with", key))
			continue
		}
		top, ok := targetOps[tkey]
		if !ok {
			violations = append(violations, fmt.Sprintf("collector %s: x-ctf-forward-target %q is not an operation of the target spec", key, tkey))
			continue
		}
		tSchema, tproblem := target.requestJSONSchema(top)
		if tproblem != "" {
			violations = append(violations, fmt.Sprintf("collector %s: its target %s: %s", key, tkey, tproblem))
			continue
		}
		if tSchema == nil {
			violations = append(violations, fmt.Sprintf("collector %s: writes a request schema but its target %s has no application/json request schema", key, tkey))
			continue
		}

		cl, cp := collector.copyLeaves(copySchema)
		tl, tp := target.copyLeaves(tSchema)
		for _, p := range cp {
			violations = append(violations, fmt.Sprintf("collector %s requestBody%s", key, p))
		}
		for _, p := range tp {
			violations = append(violations, fmt.Sprintf("target %s requestBody%s", tkey, p))
		}

		rels := map[string]bool{}
		for r := range cl {
			rels[r] = true
		}
		for r := range tl {
			rels[r] = true
		}
		sorted := make([]string, 0, len(rels))
		for r := range rels {
			sorted = append(sorted, r)
		}
		sort.Strings(sorted)
		for _, r := range sorted {
			c, inC := cl[r]
			t, inT := tl[r]
			where := fmt.Sprintf("collector %s requestBody%s vs %s", key, r, tkey)
			switch {
			case !inT:
				violations = append(violations, fmt.Sprintf("%s: the copy has a string node the target does not", where))
				continue
			case !inC:
				violations = append(violations, fmt.Sprintf("%s: the target has a string node the copy lacks", where))
				continue
			}
			compared++
			if !reflect.DeepEqual(c.word, t.word) {
				violations = append(violations, fmt.Sprintf("%s: %s differs: copy %v, target %v", where, TextOriginKey, c.word, t.word))
			}
			for _, k := range forwardCopyKeywords {
				cv, cok := c.keywords[k]
				tv, tok := t.keywords[k]
				if cok != tok || !reflect.DeepEqual(cv, tv) {
					violations = append(violations, fmt.Sprintf("%s: %s differs: copy %s, target %s", where, k, describeKeyword(cv, cok), describeKeyword(tv, tok)))
				}
			}
			if c.required != t.required {
				violations = append(violations, fmt.Sprintf("%s: required differs: copy %v, target %v", where, c.required, t.required))
			}
		}
	}
	return violations, compared
}

func describeKeyword(v any, present bool) string {
	if !present {
		return "(absent)"
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

// schemaRefName returns Name for "#/components/schemas/<Name>", the only $ref
// shape a Schema Object position takes (refInSection, textorigin.go).
func schemaRefName(ref string) (string, bool) {
	if !refInSection(ref, "schemas") {
		return "", false
	}
	return strings.TrimPrefix(ref, "#/components/schemas/"), true
}
