package specparity

import (
	"fmt"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// RouteLabelViolations is the ROUTE-TABLE property behind the `route` label of a
// request-duration histogram (collector_request_duration_seconds,
// scoreboard_http_request_duration_seconds; app#491): the label is the pattern
// ServeMux.Handler reports, and it must be a closed set, one value per declared
// route. It is defined ONCE here and run on every service's live Routes()
// (TestAPISpec_RouteLabelIsClosed, required in every mux-owning package by
// parity_coverage_test.go), so a service added later is held to it too.
//
// The pattern is request-derived in exactly one case. For a CONNECT request
// net/http does not clean the path, and when no pattern matches it but one would
// match path+"/", it answers with a trailing-slash redirect and reports the
// REQUEST's path as the pattern (e.g. "/a b"): one series per path a caller
// names. That needs a SUBTREE pattern (one ending in "/") that can match CONNECT:
//
//   - a pattern with no method matches every method, CONNECT included: dangerous;
//   - a CONNECT pattern: dangerous;
//   - a pattern with any other method ("GET /") matches only that method (and HEAD
//     for GET), never CONNECT, so no redirect is made for it: allowed. The
//     scoreboard's portal is "GET /" for this reason.
//
// An exact pattern ("GET /healthz") cannot be redirected to, whatever its method.
// A route whose Method is empty is a violation on its own account (the mux
// pattern would be " /x", which is not a method-qualified pattern).
//
// httpx.MethodLabel (the method label) does not trust such a pattern either, but
// the route label would still be unbounded; this property closes that half.
func RouteLabelViolations(routes []apispec.Route) []string {
	var out []string
	for _, rt := range routes {
		if rt.Method == "" {
			out = append(out, fmt.Sprintf("route %q has no method: a pattern with no method matches CONNECT", rt.Pattern))
			continue
		}
		if len(rt.Pattern) > 0 && rt.Pattern[len(rt.Pattern)-1] == '/' && rt.Method == "CONNECT" {
			out = append(out, fmt.Sprintf("%s is a subtree pattern that matches CONNECT: a CONNECT request would make the route label request-derived (one series per path)", rt.MuxPattern()))
		}
	}
	return out
}
