package specparity

import "github.com/Qfour/falco-ctf-app/internal/apispec"

// ClaimedIdentityForwardViolations is the ROUTE-TABLE property behind
// app#346 / #376. The vocabulary half of that work — an x-ctf-authz word may
// only exist if its constant, a Route and a spec all agree and something uses
// it — is ADR-0034 判定 (c) (a word nothing uses any more is deleted);
// internal/apispec/authz_vocabulary_test.go checks it. This function is the
// other half: the PROPERTY app#346 established. A route whose authorization
// is a CLAIMED identity (the identity comes from the path, the body or the
// event payload and is never proven) has to be there for a reason, and the
// reason depends on which claimed-identity word it declares:
//
//   - AuthzClaimedIdentity (header-bearing requests are still authorised by
//     the header, the header-less ones are claimed) exists for the collector's
//     forwards: the workspace has no X-Auth-Request-Email to present. So it
//     requires CollectorForward=true. Audience does NOT exempt it — a
//     participant-facing or internal route that accepts a claimed identity
//     and that the collector does not forward has no legitimate caller (the
//     app#346 shape: submit-detect after S1), whatever its Audience says.
//   - AuthzInternalClaimedIdentity (no header is ever consulted) is for
//     internal-only endpoints no participant path routes to: the
//     falcosidekick webhook POST /falco/events, and the collector->scoreboard
//     /internal/exfil/{cid} leg. It requires Audience=internal.
//
// Any other claimed-identity route is an unauthenticated write door with no
// legitimate caller. The property is derived from the table, not from a route
// name, so a new route is covered the moment it declares the Authz.
//
// checked is how many claimed-identity routes the scan looked at; a caller
// that knows its service has some asserts checked > 0, so a scan that saw no
// route at all cannot pass as "no violations".
func ClaimedIdentityForwardViolations(routes []apispec.Route) (checked int, violations []string) {
	for _, rt := range routes {
		switch rt.Authz {
		case apispec.AuthzClaimedIdentity:
			checked++
			if !rt.CollectorForward {
				violations = append(violations, rt.MuxPattern()+": Authz="+string(rt.Authz)+
					" with CollectorForward=false (Audience="+string(rt.Audience)+
					") — a claimed identity is accepted for a route the collector does not forward, so nothing legitimate calls it without a proven one (app#346)")
			}
		case apispec.AuthzInternalClaimedIdentity:
			checked++
			if rt.Audience != apispec.AudienceInternal {
				violations = append(violations, rt.MuxPattern()+": Authz="+string(rt.Authz)+
					" with Audience="+string(rt.Audience)+
					" (CollectorForward="+boolStr(rt.CollectorForward)+
					") — internal-claimed-identity is only for Audience=internal endpoints; a forward does not make a participant/operator route internal (app#346)")
			}
		}
	}
	return checked, violations
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
