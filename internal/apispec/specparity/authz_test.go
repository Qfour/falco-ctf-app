package specparity

import (
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// claimedIdentityBaseline is a clean table covering every legitimate shape:
// a forwarded claimed-identity route, the internal-only webhook, and routes
// whose Authz is not a claimed identity (which the property ignores).
func claimedIdentityBaseline() []apispec.Route {
	return []apispec.Route{
		{Method: "POST", Pattern: "/api/challenges/{cid}/submit", Audience: apispec.AudienceParticipant, Authz: apispec.AuthzClaimedIdentity, CollectorForward: true},
		{Method: "POST", Pattern: "/internal/exfil/{cid}", Audience: apispec.AudienceInternal, Authz: apispec.AuthzInternalClaimedIdentity, CollectorForward: true},
		{Method: "POST", Pattern: "/falco/events", Audience: apispec.AudienceInternal, Authz: apispec.AuthzInternalClaimedIdentity},
		{Method: "POST", Pattern: "/api/challenges/{cid}/submit-detect", Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin},
		{Method: "GET", Pattern: "/healthz", Audience: apispec.AudienceInfra, Authz: apispec.AuthzNone},
	}
}

func TestClaimedIdentityForwardViolations_CleanBaseline(t *testing.T) {
	checked, v := ClaimedIdentityForwardViolations(claimedIdentityBaseline())
	if len(v) != 0 {
		t.Fatalf("clean baseline must have no violations, got %v", v)
	}
	if checked != 3 {
		t.Fatalf("baseline has 3 claimed-identity routes, scan checked %d", checked)
	}
}

// TestClaimedIdentityForwardViolations_Mutations is the V8 proof for the
// property: each mutation of the clean table must turn it red, and name the
// route.
func TestClaimedIdentityForwardViolations_Mutations(t *testing.T) {
	for name, mutate := range map[string]func([]apispec.Route) []apispec.Route{
		"submit loses CollectorForward (participant claimed-identity, nobody forwards it)": func(rs []apispec.Route) []apispec.Route {
			rs[0].CollectorForward = false
			return rs
		},
		"synthetic claimed-identity route with CollectorForward=false (the app#346 shape)": func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "POST", Pattern: "/api/challenges/{cid}/submit-detect", Audience: apispec.AudienceParticipant, Authz: apispec.AuthzClaimedIdentity})
		},
		"admin-audience route declared internal-claimed-identity without a forward": func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "POST", Pattern: "/api/admin/reset", Audience: apispec.AudienceOperator, Authz: apispec.AuthzInternalClaimedIdentity})
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, v := ClaimedIdentityForwardViolations(mutate(claimedIdentityBaseline()))
			if len(v) != 1 {
				t.Fatalf("want exactly 1 violation, got %v", v)
			}
			if !strings.Contains(v[0], "CollectorForward=false") {
				t.Fatalf("violation does not say why: %q", v[0])
			}
		})
	}
	// Not vacuous the other way round: an empty table checks nothing, and says so.
	if checked, v := ClaimedIdentityForwardViolations(nil); checked != 0 || len(v) != 0 {
		t.Fatalf("empty table: checked=%d violations=%v", checked, v)
	}
}
