package specparity

import "sort"

// ResponseObjectOperations is ADR-0009 Decision A's machine enumeration: it
// walks every operation in spec and returns, as a sorted "METHOD /path" set,
// every operation whose 200 or 201 `application/json` response schema
// resolves (via resolveForCompare — the SAME resolution CompareResponse
// itself uses, Decision B) to either
//
//   - an object that declares `properties` (directly, or through a $ref/
//     single-level allOf resolve() already followed), or
//   - an "object-only" `oneOf`/`anyOf`: every branch resolves to an object
//     that itself declares `properties` (docs/openapi-*.yaml's only current
//     oneOf/anyOf usage shape — see compareVariant's doc).
//
// There is deliberately no exclusion list (ADR-0005 Decision 1's discipline,
// reaffirmed by ADR-0009 Decision A point 1): every operation in EVERY
// service spec is walked, including collector/auth-policy's inline (non-$ref)
// object schemas. A dangling $ref, or a schema this package's narrow resolver
// cannot follow (see Spec's doc comment), does not count as a response-object
// operation — CompareResponse would itself report those as failures if a
// caller ever tried to compare against them, which is a DIFFERENT gate
// (V(B)-1/V(B)-3) than this enumeration.
func ResponseObjectOperations(s *Spec) []string {
	var out []string
	for key, op := range s.Operations() {
		if hasResponseObjectSchema(s, op) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// hasResponseObjectSchema reports whether op's 200 or 201 application/json
// schema qualifies per ResponseObjectOperations' doc.
func hasResponseObjectSchema(s *Spec, op map[string]any) bool {
	for _, status := range [...]string{"200", "201"} {
		schema := s.OperationResponseSchema(op, status)
		if schema == nil {
			continue
		}
		if isObjectSchema(s, schema) {
			return true
		}
	}
	return false
}

// isObjectSchema resolves schema exactly as CompareResponse would (Decision
// B's resolveForCompare) and reports whether it is a `properties`-object or
// an object-only oneOf/anyOf. A dangling $ref (resolveForCompare's second
// return value non-empty) is NOT a response-object schema — it can never be
// compared against successfully, so enumerating it here would only produce a
// v5Coverage entry nothing could ever satisfy.
func isObjectSchema(s *Spec, schema map[string]any) bool {
	resolved, dangling := s.resolveForCompare(schema)
	if dangling != "" || resolved == nil {
		return false
	}
	if branches, isVariant := variantBranches(resolved); isVariant {
		for _, br := range branches {
			brMap, ok := br.(map[string]any)
			if !ok {
				return false
			}
			brResolved, dangling := s.resolveForCompare(brMap)
			if dangling != "" {
				return false
			}
			if _, hasProps := brResolved["properties"].(map[string]any); !hasProps {
				return false
			}
		}
		return true
	}
	_, hasProps := resolved["properties"].(map[string]any)
	return hasProps
}

// CoverageDiff is ADR-0009 Verification V(A)-1's bidirectional comparison
// between ResponseObjectOperations()'s machine-derived set and a service's
// hand-maintained `v5Coverage` table (RouteSetDiff's exact shape, applied to
// a different pair of sets — same no-exclusion-list discipline, ADR-0005
// Decision 1). derivedOnly ("documented operation, no V5 coverage" — the
// operation the spec declares a response-object schema for has no entry, or
// a false entry, in the table) and coverageOnly ("stale coverage entry" — the
// table claims coverage for an operation ResponseObjectOperations() no
// longer derives, e.g. after a schema was dropped `properties` or the route
// was removed) are both returned sorted; either being non-empty is a parity
// failure.
func CoverageDiff(derived []string, coverage map[string]bool) (derivedOnly, coverageOnly []string) {
	derivedSet := make(map[string]bool, len(derived))
	for _, k := range derived {
		derivedSet[k] = true
		if !coverage[k] {
			derivedOnly = append(derivedOnly, k)
		}
	}
	for k, covered := range coverage {
		if covered && !derivedSet[k] {
			coverageOnly = append(coverageOnly, k)
		}
	}
	sort.Strings(derivedOnly)
	sort.Strings(coverageOnly)
	return
}
