package specparity

import (
	"fmt"
	"sort"
)

// FieldMismatch is one location where a decoded JSON value disagrees with
// the spec schema at that path (ADR-0005 V5, fail-closed per ADR-0009
// Decision B).
type FieldMismatch struct {
	// Path is a dotted/bracketed locator, e.g. "detail.hints.opened[0]".
	Path string
	// Extra holds keys present in the actual JSON but not declared by the
	// schema at Path ("implemented but undocumented", V5's mirror of V1).
	Extra []string
	// Missing holds keys the schema declares at Path but absent from the
	// actual JSON ("documented but not implemented").
	Missing []string
	// Note holds a human-readable explanation for mismatches that are NOT a
	// simple key-set diff — a schema node declaring neither `properties` nor
	// `oneOf`/`anyOf` while actual is still an object (ADR-0009 Decision
	// B-1), a `oneOf`/`anyOf` node where zero or 2+ branches' `properties`
	// exactly match actual's key set (Decision B-2), or a `$ref` that names a
	// components.schemas entry which does not exist (Decision B-3, "dangling
	// $ref"). Empty for ordinary Extra/Missing key-diff mismatches.
	Note string
}

// CompareResponse recursively compares a decoded JSON value (from
// encoding/json into any — objects as map[string]any, arrays as []any)
// against a spec schema, per ADR-0005 V5's rules as fail-closed by
// ADR-0009 Decision B:
//
//   - object: the top level, and every NESTED level where the schema itself
//     declares `properties` (directly, or via a `oneOf`/`anyOf` branch that
//     matched, see below), must have an EXACT key match (not `required` —
//     required is reserved for "never null", V5's own note).
//   - object with no `properties`: this is a MISMATCH (not a silent leaf)
//     unless the schema declares `additionalProperties` — i.e. it is
//     genuinely a free-form map, ADR-0005's explicitly out-of-scope case
//     (type/value checking, additionalProperties map CONTENTS). A
//     `properties`-less, `additionalProperties`-less object node is either a
//     spec bug (dropped `properties`) or a dangling `$ref` (see B-3) — both
//     are now reported.
//   - object where the schema resolves to `oneOf`/`anyOf`: exactly one
//     branch's `properties` key set must exactly match actual's key set. Zero
//     matches or 2+ matches (overlapping branches — a spec bug) are both a
//     mismatch. Only `$ref`-carrying branches with `properties` are
//     considered candidates — this is not a general JSON Schema resolver,
//     see spec.go's package doc.
//   - `$ref` to a components.schemas name that does not exist: reported as a
//     mismatch ("dangling $ref"), never silently propagated as nil.
//   - array: only the FIRST element is checked, against the schema's `items`.
//   - anything else (schema has neither `properties`/`oneOf`/`anyOf` nor
//     `items` at a given level, and actual is not itself an object — a
//     scalar) is a leaf: V5 does not recurse there and does not check it
//     (see ADR-0005's "見ないもの" list — types and additionalProperties map
//     contents are explicitly out of scope, unchanged by ADR-0009).
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
	resolved, dangling := s.resolveForCompare(schema)
	if dangling != "" {
		*out = append(*out, FieldMismatch{Path: path, Note: dangling})
		return
	}
	switch v := actual.(type) {
	case map[string]any:
		if branches, isVariant := variantBranches(resolved); isVariant {
			compareVariant(s, branches, v, path, out)
			return
		}
		props, hasProps := resolved["properties"].(map[string]any)
		if !hasProps {
			if _, hasAdditional := resolved["additionalProperties"]; hasAdditional {
				// A genuinely free-form map (additionalProperties declared,
				// no fixed `properties`) — ADR-0005's explicit "見ないもの"
				// (additionalProperties map CONTENTS are out of scope).
				// Leaf, no mismatch, by design — not by omission.
				return
			}
			// ADR-0009 Decision B-1: a `properties`-less,
			// `additionalProperties`-less object node while actual is
			// itself an object. This used to be a silent fail-open return
			// (ADR-0005's original gap); now it is a reported mismatch —
			// it is either a spec bug (typo'd/dropped `properties`) or a
			// dangling $ref that resolveForCompare's own check (above)
			// somehow didn't already catch (e.g. a non-$ref, non-allOf,
			// non-oneOf/anyOf schema node that is simply malformed).
			*out = append(*out, FieldMismatch{
				Path: path,
				Note: "schema declares neither properties nor oneOf/anyOf but actual is an object at this path",
			})
			return
		}
		compareObjectProps(s, props, v, path, out)
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

// compareObjectProps is the exact-key-match + per-property recursion shared
// by the plain `properties` case and (once a single oneOf/anyOf branch has
// been selected) compareVariant.
func compareObjectProps(s *Spec, props map[string]any, v map[string]any, path string, out *[]FieldMismatch) {
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
}

// variantBranches returns a resolved schema's `oneOf` or `anyOf` branch list,
// if either is present and non-empty at this level.
func variantBranches(resolved map[string]any) ([]any, bool) {
	if resolved == nil {
		return nil, false
	}
	if b, ok := resolved["oneOf"].([]any); ok && len(b) > 0 {
		return b, true
	}
	if b, ok := resolved["anyOf"].([]any); ok && len(b) > 0 {
		return b, true
	}
	return nil, false
}

// compareVariant is ADR-0009 Decision B-2: resolve each branch (each is
// assumed to be a $ref to a components.schemas object with `properties` —
// docs/openapi-*.yaml's only current oneOf/anyOf usage shape, e.g. `POST
// /falco/events`'s 200 = oneOf[IngestAccepted, IngestIgnored]) and require
// that EXACTLY ONE branch's declared `properties` key set exactly matches
// actual's key set. Zero matches (actual fits no documented branch) and 2+
// matches (branches overlap — a spec bug) are both reported as a mismatch.
// A branch that does not resolve to an object with `properties` (out of this
// narrow resolver's scope) is silently skipped as a candidate, matching
// resolveForCompare/resolve's existing "not a general JSON Schema resolver"
// stance elsewhere in this package.
func compareVariant(s *Spec, branches []any, v map[string]any, path string, out *[]FieldMismatch) {
	got := make(map[string]bool, len(v))
	for k := range v {
		got[k] = true
	}

	var matchedProps []map[string]any
	for _, br := range branches {
		brMap, _ := br.(map[string]any)
		brResolved, dangling := s.resolveForCompare(brMap)
		if dangling != "" {
			*out = append(*out, FieldMismatch{Path: path, Note: dangling})
			return
		}
		props, hasProps := brResolved["properties"].(map[string]any)
		if !hasProps {
			continue
		}
		want := make(map[string]bool, len(props))
		for k := range props {
			want[k] = true
		}
		if setsEqual(want, got) {
			matchedProps = append(matchedProps, props)
		}
	}

	switch len(matchedProps) {
	case 1:
		compareObjectProps(s, matchedProps[0], v, path, out)
	case 0:
		*out = append(*out, FieldMismatch{
			Path: path,
			Note: fmt.Sprintf("no oneOf/anyOf branch's properties exactly match actual's key set %v", sortedKeys(got)),
		})
	default:
		*out = append(*out, FieldMismatch{
			Path: path,
			Note: fmt.Sprintf("%d oneOf/anyOf branches exactly match actual's key set %v (overlapping branch schemas — spec bug)", len(matchedProps), sortedKeys(got)),
		})
	}
}

func setsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
