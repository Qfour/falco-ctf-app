package apispec

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// httpMethods is the set of path-item keys this package treats as HTTP
// operations (as opposed to other path-item-level keys like "parameters" —
// none of docs/openapi-*.yaml currently use path-level "parameters", but the
// guard costs nothing and keeps Operations() honest if one is added later).
var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

// Spec is a minimally-parsed OpenAPI document: just enough structure for the
// ADR-0005 parity checks (route sets, x-ctf-* operation extensions, and
// properties/required on component schemas). It deliberately does NOT
// implement general OpenAPI 3.1 semantics (e.g. multi-branch oneOf/anyOf
// resolution, arbitrary $ref targets outside #/components/schemas) — only
// the subset docs/openapi-*.yaml actually uses. See ADR-0005 Verification's
// "この検査が見ないもの" for the explicit boundary.
type Spec struct {
	raw map[string]any
}

// LoadSpec reads and YAML-decodes an OpenAPI document at path. yaml.v3
// decodes YAML mappings into map[string]any (unlike yaml.v2's
// map[interface{}]interface{}), which is what makes the generic navigation
// below possible without per-field structs.
func LoadSpec(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spec %s: %w", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse spec %s: %w", path, err)
	}
	return &Spec{raw: raw}, nil
}

// Operations returns every operation in the document keyed by "METHOD
// /path" (method upper-cased), e.g. "GET /api/state". This key shape is
// exactly Route.MuxPattern()'s shape, so a spec's operation-key set compares
// directly against a route table's MuxPattern() set with no translation
// (ADR-0005 V1).
func (s *Spec) Operations() map[string]map[string]any {
	out := map[string]map[string]any{}
	paths, _ := s.raw["paths"].(map[string]any)
	for path, v := range paths {
		item, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for method, opv := range item {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}
			op, ok := opv.(map[string]any)
			if !ok {
				continue
			}
			key := strings.ToUpper(method) + " " + path
			out[key] = op
		}
	}
	return out
}

// OperationKeys returns the sorted "METHOD /path" set (for readable diff
// output).
func (s *Spec) OperationKeys() []string {
	keys := make([]string, 0, len(s.raw))
	for k := range s.Operations() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// StringExt reads a string extension field (or any plain string field) off
// an operation map. ok is false when the key is absent OR present with a
// non-string value.
func StringExt(op map[string]any, key string) (string, bool) {
	v, ok := op[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// BoolExt reads a boolean extension field off an operation map. ok is false
// when the key is absent OR present with a non-bool value — callers that
// must treat "absent" as a failure (ADR-0005 V3: origin-guard has no
// default) check ok, not just the returned bool.
func BoolExt(op map[string]any, key string) (bool, bool) {
	v, ok := op[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// SchemaByName returns a components.schemas entry by name (nil if absent).
func (s *Spec) SchemaByName(name string) map[string]any {
	schemas, _ := navigateMap(s.raw, "components", "schemas")
	sch, _ := schemas[name].(map[string]any)
	return sch
}

// navigateMap walks nested map[string]any keys, returning (nil, false) as
// soon as any hop is missing or not itself a map.
func navigateMap(root map[string]any, keys ...string) (map[string]any, bool) {
	cur := root
	for _, k := range keys {
		next, ok := cur[k]
		if !ok {
			return nil, false
		}
		m, ok := next.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = m
	}
	return cur, true
}

// resolve follows a single $ref to #/components/schemas/<Name> and/or
// flattens a single-level allOf by merging each element's properties. Both
// are exactly what docs/openapi-*.yaml uses (a $ref-carrying property, or an
// allOf whose sole purpose is to attach a sibling `description` next to a
// $ref — see Journey.detail) — this is not a general JSON Schema resolver.
func (s *Spec) resolve(schema map[string]any) map[string]any {
	if schema == nil {
		return nil
	}
	if ref, ok := schema["$ref"].(string); ok {
		const prefix = "#/components/schemas/"
		if strings.HasPrefix(ref, prefix) {
			return s.resolve(s.SchemaByName(strings.TrimPrefix(ref, prefix)))
		}
		return nil
	}
	if allOf, ok := schema["allOf"].([]any); ok && len(allOf) > 0 {
		merged := map[string]any{}
		for _, el := range allOf {
			elm, ok := el.(map[string]any)
			if !ok {
				continue
			}
			resolved := s.resolve(elm)
			if props, ok := resolved["properties"].(map[string]any); ok {
				for k, v := range props {
					merged[k] = v
				}
			}
		}
		return map[string]any{"properties": merged}
	}
	return schema
}

// PropertyNames returns the resolved schema's declared `properties` key set
// (empty if the schema declares none, e.g. an additionalProperties map or a
// scalar). ADR-0005 V5 compares this — NOT `required` — against a response's
// actual top-level keys, so a generated type may still use a pointer for an
// optional field without failing parity.
func (s *Spec) PropertyNames(schema map[string]any) map[string]bool {
	resolved := s.resolve(schema)
	props, _ := resolved["properties"].(map[string]any)
	out := make(map[string]bool, len(props))
	for k := range props {
		out[k] = true
	}
	return out
}

// PropertySchema returns the resolved schema for a named property (nil if
// the property or the schema itself is absent).
func (s *Spec) PropertySchema(schema map[string]any, key string) map[string]any {
	resolved := s.resolve(schema)
	props, _ := resolved["properties"].(map[string]any)
	prop, _ := props[key].(map[string]any)
	return prop
}

// ItemsSchema returns the resolved `items` schema of an array schema (nil if
// absent).
func (s *Spec) ItemsSchema(schema map[string]any) map[string]any {
	resolved := s.resolve(schema)
	items, _ := resolved["items"].(map[string]any)
	return items
}
