package specparity

import "github.com/Qfour/falco-ctf-app/internal/apispec"

// ClaimedIdentityForwardViolations is the ROUTE-TABLE property behind
// ADR-0034 判定 (c) / app#346 / #376: a route whose authorization is a
// CLAIMED identity (AuthzClaimedIdentity, AuthzInternalClaimedIdentity — the
// identity comes from the path, the body or the event payload and is never
// proven) has to be there for a reason, and the only reasons this codebase
// has are
//
//   - the collector's forward allowlist reaches it (CollectorForward=true:
//     the workspace has no X-Auth-Request-Email to present), or
//   - it is an internal-only endpoint (Audience == AudienceInternal: the
//     falcosidekick webhook POST /falco/events, which no participant path
//     routes to).
//
// Any other claimed-identity route is an unauthenticated write door with no
// legitimate caller — exactly what app#346 deleted from submit-detect. The
// property is derived from the table, not from a route name, so a new route
// is covered the moment it declares the Authz.
//
// checked is how many claimed-identity routes the scan looked at; a caller
// that knows its service has some asserts checked > 0, so a scan that saw no
// route at all cannot pass as "no violations".
func ClaimedIdentityForwardViolations(routes []apispec.Route) (checked int, violations []string) {
	for _, rt := range routes {
		if rt.Authz != apispec.AuthzClaimedIdentity && rt.Authz != apispec.AuthzInternalClaimedIdentity {
			continue
		}
		checked++
		if rt.CollectorForward || rt.Audience == apispec.AudienceInternal {
			continue
		}
		violations = append(violations, rt.MuxPattern()+": Authz="+string(rt.Authz)+
			" with CollectorForward=false and Audience="+string(rt.Audience)+
			" — a claimed identity is accepted for a route nothing legitimate calls without a proven one (app#346)")
	}
	return checked, violations
}
