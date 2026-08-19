package apispec

import "sort"

// FieldMismatch is one location where a decoded JSON value's key set
// disagrees with the spec schema's declared `properties` key set
// (ADR-0005 V5).
type FieldMismatch struct {
	// Path is a dotted/bracketed locator, e.g. "detail.hints.opened[0]".
	Path string
	// Extra holds keys present in the actual JSON but not declared by the
	// schema at Path ("implemented but undocumented", V5's mirror of V1).
	Extra []string
	// Missing holds keys the schema declares at Path but absent from the
	// actual JSON ("documented but not implemented").
	Missing []string
}

// CompareResponse recursively compares a decoded JSON value (from
// encoding/json into any — objects as map[string]any, arrays as []any)
// against a spec schema, per ADR-0005 V5's rules:
//
//   - object: the top level, and every NESTED level where the schema itself
//     declares `properties`, must have an EXACT key match (not `required` —
//     required is reserved for "never null", V5's own note).
//   - array: only the FIRST element is checked, against the schema's `items`.
//   - anything else (schema has neither `properties` nor `items` at a given
//     level — e.g. additionalProperties maps, or a scalar) is a leaf: V5
//     does not recurse there and does not check it (see ADR-0005's "見ない
//     もの" list — types and additionalProperties map contents are
//     explicitly out of scope).
//
// A nil actual value (a documented "null when nothing to show" case, e.g.
// Journey.detail with everything solved) produces no mismatch and no
// recursion — there is nothing to compare.
func CompareResponse(s *Spec, schema map[string]any, actual any, path string) []FieldMismatch {
	var out []FieldMismatch
	compareInto(s, schema, actual, path, &out)
	return out
}

func compareInto(s *Spec, schema map[string]any, actual any, path string, out *[]FieldMismatch) {
	if actual == nil {
		return
	}
	resolved := s.resolve(schema)
	switch v := actual.(type) {
	case map[string]any:
		props, hasProps := resolved["properties"].(map[string]any)
		if !hasProps {
			return
		}
		want := make(map[string]bool, len(props))
		for k := range props {
			want[k] = true
		}
		got := make(map[string]bool, len(v))
		for k := range v {
			got[k] = true
		}
		var extra, missing []string
		for k := range got {
			if !want[k] {
				extra = append(extra, k)
			}
		}
		for k := range want {
			if !got[k] {
				missing = append(missing, k)
			}
		}
		if len(extra) > 0 || len(missing) > 0 {
			sort.Strings(extra)
			sort.Strings(missing)
			*out = append(*out, FieldMismatch{Path: path, Extra: extra, Missing: missing})
		}
		for k, propSchemaAny := range props {
			val, present := v[k]
			if !present {
				continue
			}
			propSchema, _ := propSchemaAny.(map[string]any)
			compareInto(s, propSchema, val, path+"."+k, out)
		}
	case []any:
		items, _ := resolved["items"].(map[string]any)
		if items == nil || len(v) == 0 {
			return
		}
		compareInto(s, items, v[0], path+"[0]", out)
	default:
		// scalar leaf — type/value checking is explicitly out of V5's scope.
	}
}
