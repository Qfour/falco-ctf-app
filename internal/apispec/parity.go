package apispec

import (
	"fmt"
	"sort"
	"strings"
)

// RouteSetDiff is ADR-0005 V1: the bidirectional route-set comparison.
// specOnly ("documented but not implemented") and implOnly ("implemented but
// undocumented") are both returned sorted; either being non-empty is a
// parity failure. There is deliberately no allowlist/exclusion parameter —
// ADR-0005 Decision 1 rejects exclusion lists outright (they are how the
// pre-ADR-0005 spec decayed to 50% coverage).
func RouteSetDiff(specOps map[string]map[string]any, routes []Route) (specOnly, implOnly []string) {
	implSet := make(map[string]bool, len(routes))
	for _, rt := range routes {
		implSet[rt.MuxPattern()] = true
	}
	specSet := make(map[string]bool, len(specOps))
	for k := range specOps {
		specSet[k] = true
	}
	for k := range specSet {
		if !implSet[k] {
			specOnly = append(specOnly, k)
		}
	}
	for k := range implSet {
		if !specSet[k] {
			implOnly = append(implOnly, k)
		}
	}
	sort.Strings(specOnly)
	sort.Strings(implOnly)
	return
}

// BoolExtParity checks a single boolean x-ctf-* extension (extKey) between a
// spec's operations and a route table, using tableValue to read the
// corresponding field off each Route (rt.OriginGuarded for
// "x-ctf-origin-guard", rt.CollectorForward for "x-ctf-collector-forward").
//
// missingKey lists spec operations where extKey is ABSENT — ADR-0005 V3's
// core rule: "a missing key is a parity failure, not a default of false"
// (fail-closed; an absent key must never be treated as an implicit false).
// onlyImpl / onlySpec are the two directions of a mismatch once both sides
// declare a value for a matched (same MuxPattern) route: the route says
// true but the spec says false (or the spec says true but the route says
// false).
//
// Matching is keyed on MuxPattern(), so an operation with no corresponding
// route (or a route with no corresponding operation) is silently skipped
// here — that class of drift is RouteSetDiff's job (V1), not this
// function's, to keep each check's failure message about exactly one thing.
func BoolExtParity(specOps map[string]map[string]any, routes []Route, extKey string, tableValue func(Route) bool) (missingKey, onlyImpl, onlySpec []string) {
	routeByPattern := make(map[string]Route, len(routes))
	for _, rt := range routes {
		routeByPattern[rt.MuxPattern()] = rt
	}
	for key, op := range specOps {
		val, ok := op[extKey]
		if !ok {
			missingKey = append(missingKey, key)
			continue
		}
		specVal, isBool := val.(bool)
		if !isBool {
			missingKey = append(missingKey, key+" (non-bool value)")
			continue
		}
		rt, matched := routeByPattern[key]
		if !matched {
			continue // V1's job
		}
		implVal := tableValue(rt)
		switch {
		case implVal && !specVal:
			onlyImpl = append(onlyImpl, key)
		case specVal && !implVal:
			onlySpec = append(onlySpec, key)
		}
	}
	sort.Strings(missingKey)
	sort.Strings(onlyImpl)
	sort.Strings(onlySpec)
	return
}

// CollectorForwardBijection is ADR-0005 V4's core check: a pure spec-to-spec
// comparison (no implementation table needed — the collector spec's
// x-ctf-forward-target field IS the claim being verified) that every
// collector operation with x-ctf-collector-forward: true names, via
// x-ctf-forward-target, a scoreboard operation that is ITSELF
// x-ctf-collector-forward: true, and that every such scoreboard operation is
// named by EXACTLY ONE collector operation. Returns a sorted, human-readable
// problem list (empty = bijection holds).
func CollectorForwardBijection(collectorOps, scoreboardOps map[string]map[string]any) []string {
	var problems []string
	claims := map[string][]string{}
	for opKey, op := range collectorOps {
		fwd, ok := op["x-ctf-collector-forward"].(bool)
		if !ok || !fwd {
			continue
		}
		target, ok := op["x-ctf-forward-target"].(string)
		if !ok || target == "" {
			problems = append(problems, fmt.Sprintf("collector %s: x-ctf-collector-forward=true but missing/empty x-ctf-forward-target", opKey))
			continue
		}
		sbOp, ok := scoreboardOps[target]
		if !ok {
			problems = append(problems, fmt.Sprintf("collector %s: x-ctf-forward-target %q does not exist in the scoreboard spec", opKey, target))
			continue
		}
		if sbFwd, ok := sbOp["x-ctf-collector-forward"].(bool); !ok || !sbFwd {
			problems = append(problems, fmt.Sprintf("collector %s: target %q is not x-ctf-collector-forward=true in the scoreboard spec", opKey, target))
		}
		claims[target] = append(claims[target], opKey)
	}
	for opKey, op := range scoreboardOps {
		fwd, ok := op["x-ctf-collector-forward"].(bool)
		if !ok || !fwd {
			continue
		}
		switch n := len(claims[opKey]); {
		case n == 0:
			problems = append(problems, fmt.Sprintf("scoreboard %s: x-ctf-collector-forward=true but no collector operation names it as x-ctf-forward-target", opKey))
		case n > 1:
			problems = append(problems, fmt.Sprintf("scoreboard %s: named by %d collector operations (want exactly 1): %s", opKey, n, strings.Join(claims[opKey], ", ")))
		}
	}
	sort.Strings(problems)
	return problems
}

// ResetDirtyPattern is the exact MuxPattern of the ADR-0003 A2-2 destructive
// self-scoped reset. It must never be reachable via the collector's
// server-to-server forward (that would make the destructive cross-user
// receipt delete unauthenticated — see api.Handler.Routes' doc on this
// route). ADR-0005 V4 requires a DEDICATED assert for this, not just
// reliance on the general bijection above (a bug in the bijection logic
// itself must not silently let this one specific route through).
const ResetDirtyPattern = "POST /api/users/{user}/challenges/{cid}/reset-dirty"

// ResetDirtySpecViolation reports whether the scoreboard spec's reset-dirty
// operation is (mis)declared x-ctf-collector-forward: true. Returns "" when
// clean (route absent from the spec is not this function's concern — V1
// reports that).
func ResetDirtySpecViolation(scoreboardOps map[string]map[string]any) string {
	op, ok := scoreboardOps[ResetDirtyPattern]
	if !ok {
		return ""
	}
	if fwd, ok := op["x-ctf-collector-forward"].(bool); ok && fwd {
		return ResetDirtyPattern + ": docs/openapi-scoreboard.yaml declares x-ctf-collector-forward: true — forbidden (ADR-0003 A2-2)"
	}
	return ""
}

// ResetDirtyRouteViolation is ResetDirtySpecViolation's implementation-side
// twin: reports whether the ACTUAL scoreboard route table marks
// reset-dirty's Route.CollectorForward true.
func ResetDirtyRouteViolation(routes []Route) string {
	for _, rt := range routes {
		if rt.MuxPattern() == ResetDirtyPattern && rt.CollectorForward {
			return ResetDirtyPattern + ": Route.CollectorForward=true — forbidden (ADR-0003 A2-2)"
		}
	}
	return ""
}
