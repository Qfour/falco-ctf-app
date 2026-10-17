package specparity

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// IdentitySourceViolations is the ROUTE-TABLE property behind
// app#346 / #376 / #393: every route's Authz word is looked up in
// apispec.AuthzIdentitySources (never in a list of word names) and must
// satisfy the rule for its identity source. It was
// ClaimedIdentityForwardViolations until app#413; the property had grown from
// the claimed words to every word, and the old name said only the claimed
// half. The vocabulary half of that work — an x-ctf-authz word may only exist
// if its constant, a Route, a spec and apispec.AuthzIdentitySources all agree
// and something uses it — is ADR-0034 判定 (c);
// internal/apispec/authz_vocabulary_test.go checks it. This function is the
// other half: a route may accept an identity nobody proved only for a
// written-down reason. Per identity source:
//
//   - a word the table does not classify is a violation (fail-closed): it
//     cannot be shown not to accept a claimed identity.
//   - claimed: each claimed word has its own rule, and a claimed word with no
//     rule here is a violation, so a new word with the meaning of
//     claimed-identity cannot slip past under another name.
//     AuthzClaimedIdentity (header-bearing requests are still authorised by
//     the header, the header-less ones are claimed) exists for the
//     collector's forwards: the workspace has no X-Auth-Request-Email to
//     present. So it requires CollectorForward=true. Audience does NOT
//     exempt it — a route that accepts a claimed identity and that the
//     collector does not forward has no legitimate caller (the app#346
//     shape: submit-detect after S1). AuthzInternalClaimedIdentity (no header
//     is ever consulted) is for internal-only endpoints no participant path
//     routes to: the falcosidekick webhook POST /falco/events, and the
//     collector->scoreboard /internal/exfil/{cid} leg. It requires
//     Audience=internal.
//   - none (the access decision, and whose data is used, do not depend on the
//     caller; a display hint from the proven header is allowed, see
//     apispec.IdentityNone): every path parameter is in nonIdentityPathParam.
//     A route that takes an identity from its path reads a claimed identity,
//     whatever it declares, and the set is an allowlist so the identity
//     parameter cannot get past it under another name ({seat} as well as
//     {user}). LIMIT: an identity read from the BODY, the QUERY STRING or a
//     header other than X-Auth-Request-* is not caught here; each service's
//     authz test pins its none routes as a literal set, so such a route is
//     at least a named diff in review.
//   - proven: nothing structural; the behaviour (no identity -> refused) is
//     tested per service from the same table.
//
// The checks run on each service's live Routes(): parity_coverage_test.go
// requires a test named TestAPISpec_IdentitySourceProperty in every
// mux-owning package (that the test calls this function on the live Routes()
// is held by review, not by a check). Together with
// authz_vocabulary_test.go (c) (every constant is in a spec) and V1 / V3b
// (every spec operation is a live route with the same x-ctf-authz), every
// declared word is on some live route this function reads, so the
// per-service wiring alone forces every word to be classified.
//
// checked is how many claimed routes the scan looked at; a caller that knows
// its service has some asserts checked > 0, so a scan that saw no route at
// all cannot pass as "no violations".
func IdentitySourceViolations(routes []apispec.Route) (checked int, violations []string) {
	return identitySourceViolations(routes, apispec.AuthzIdentitySources())
}

// identitySourceViolations is the property against an injected table, so the
// mutation tests can classify words the real vocabulary does not have.
func identitySourceViolations(routes []apispec.Route, sources map[apispec.Authz]apispec.IdentitySource) (checked int, violations []string) {
	for _, rt := range routes {
		head := rt.MuxPattern() + ": Authz=" + string(rt.Authz)
		src, ok := sources[rt.Authz]
		if !ok {
			violations = append(violations, head+" is not classified in apispec.AuthzIdentitySources — an unclassified word cannot be shown not to accept a claimed identity (app#393)")
			continue
		}
		switch src {
		case apispec.IdentityProven:
		case apispec.IdentityNone:
			for _, m := range pathParam.FindAllStringSubmatch(rt.Pattern, -1) {
				if name := strings.TrimSuffix(m[1], "..."); name != "$" && !nonIdentityPathParam(name) {
					violations = append(violations, head+" with path parameter {"+name+"}, which is not a known non-identity parameter — a path parameter can select whose data is used, which is a claimed identity declared as none (app#393)")
				}
			}
		case apispec.IdentityClaimed:
			checked++
			switch rt.Authz {
			case apispec.AuthzClaimedIdentity:
				if !rt.CollectorForward {
					violations = append(violations, head+
						" with CollectorForward=false (Audience="+string(rt.Audience)+
						") — a claimed identity is accepted for a route the collector does not forward, so nothing legitimate calls it without a proven one (app#346)")
				}
			case apispec.AuthzInternalClaimedIdentity:
				if rt.Audience != apispec.AudienceInternal {
					violations = append(violations, head+
						" with Audience="+string(rt.Audience)+
						" (CollectorForward="+strconv.FormatBool(rt.CollectorForward)+
						") — internal-claimed-identity is only for Audience=internal endpoints; a forward does not make a participant/operator route internal (app#346)")
				}
			default:
				violations = append(violations, head+" is classified claimed but has no rule in IdentitySourceViolations — write down its legitimate caller before a route uses it (app#393)")
			}
		default:
			violations = append(violations, head+" has identity source "+strconv.Quote(string(src))+", which is none of proven / claimed / none (app#393)")
		}
	}
	return checked, violations
}

// pathParam matches one http.ServeMux path wildcard: {name}, {name...} or
// the {$} end anchor.
var pathParam = regexp.MustCompile(`\{([^}]*)\}`)

// nonIdentityPathParam reports whether a path parameter name is known never
// to name a caller. It is the one set the none rule reads, and an allowlist
// on purpose: {user}, or the same thing renamed, is not in it. Adding a name
// is a reviewed claim that the parameter never selects whose data is read or
// written.
func nonIdentityPathParam(name string) bool {
	switch name {
	case "asset": // GET /static/{asset}: a content-hashed file name (ADR-0028)
		return true
	}
	return false
}
