package specparity

import (
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// claimedIdentityBaseline is a clean table covering every legitimate shape:
// a forwarded claimed-identity route, the internal-only webhook, a proven
// route with {user} in its path, and a none route without one.
func claimedIdentityBaseline() []apispec.Route {
	return []apispec.Route{
		{Method: "POST", Pattern: "/api/challenges/{cid}/submit", Audience: apispec.AudienceParticipant, Authz: apispec.AuthzClaimedIdentity, CollectorForward: true},
		{Method: "POST", Pattern: "/internal/exfil/{cid}", Audience: apispec.AudienceInternal, Authz: apispec.AuthzInternalClaimedIdentity, CollectorForward: true},
		{Method: "POST", Pattern: "/falco/events", Audience: apispec.AudienceInternal, Authz: apispec.AuthzInternalClaimedIdentity},
		{Method: "POST", Pattern: "/api/challenges/{cid}/submit-detect", Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin},
		{Method: "GET", Pattern: "/api/users/{user}/me", Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin},
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
// route and the reason. The two rules are separate (claimed-identity needs a
// forward, internal-claimed-identity needs Audience=internal), so each
// mutation is one that a looser "forward OR internal" rule would let through
// or that the strict rule must still catch.
func TestClaimedIdentityForwardViolations_Mutations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]apispec.Route) []apispec.Route
		want   string
		// table, when set, edits a copy of apispec.AuthzIdentitySources for
		// the shapes the real vocabulary cannot express.
		table func(map[apispec.Authz]apispec.IdentitySource)
	}{
		{"submit loses CollectorForward (participant claimed-identity, nobody forwards it)", func(rs []apispec.Route) []apispec.Route {
			rs[0].CollectorForward = false
			return rs
		}, "Authz=claimed-identity with CollectorForward=false", nil},
		// NOT the historical app#346 code: a synthetic composition that
		// relabels a route as claimed-identity with no forward, which is the
		// shape app#346 removed from submit-detect.
		{"synthetic: submit-detect relabelled claimed-identity, no forward (the shape app#346 removed)", func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "POST", Pattern: "/api/challenges/{cid}/submit-detect", Audience: apispec.AudienceParticipant, Authz: apispec.AuthzClaimedIdentity})
		}, "Authz=claimed-identity with CollectorForward=false", nil},
		// The hole a "forward OR internal" rule leaves: Audience=internal must
		// NOT exempt AuthzClaimedIdentity from needing a forward.
		{"claimed-identity + AudienceInternal + CollectorForward=false (Audience does not exempt claimed-identity)", func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "POST", Pattern: "/internal/other", Audience: apispec.AudienceInternal, Authz: apispec.AuthzClaimedIdentity})
		}, "Authz=claimed-identity with CollectorForward=false", nil},
		{"admin-audience route declared internal-claimed-identity without a forward", func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "POST", Pattern: "/api/admin/reset", Audience: apispec.AudienceOperator, Authz: apispec.AuthzInternalClaimedIdentity})
		}, "Authz=internal-claimed-identity with Audience=operator", nil},
		// A forward does not make a participant route internal.
		{"participant route declared internal-claimed-identity WITH a forward (the forward does not exempt it)", func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "POST", Pattern: "/api/users/{user}/display-name", Audience: apispec.AudienceParticipant, Authz: apispec.AuthzInternalClaimedIdentity, CollectorForward: true})
		}, "Authz=internal-claimed-identity with Audience=participant", nil},
		{"internal-claimed-identity loses its Audience=internal", func(rs []apispec.Route) []apispec.Route {
			rs[2].Audience = apispec.AudienceInfra
			return rs
		}, "Authz=internal-claimed-identity with Audience=infra", nil},
		// app#393: the words are read from the table, so a word under another
		// name is not outside the property but a violation.
		{"a route carries a word the table does not classify (claimed-identity under another name)", func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "POST", Pattern: "/api/challenges/{cid}/submit-v2", Audience: apispec.AudienceParticipant, Authz: apispec.Authz("collector-claimed"), CollectorForward: true})
		}, "Authz=collector-claimed is not classified in apispec.AuthzIdentitySources", nil},
		{"a word classified claimed that has no rule", func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "POST", Pattern: "/api/challenges/{cid}/submit-v2", Audience: apispec.AudienceParticipant, Authz: apispec.Authz("collector-claimed"), CollectorForward: true})
		}, "Authz=collector-claimed is classified claimed but has no rule", func(m map[apispec.Authz]apispec.IdentitySource) {
			m["collector-claimed"] = apispec.IdentityClaimed
		}},
		{"a word classified as a source that is none of the three", func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "GET", Pattern: "/x", Audience: apispec.AudienceInfra, Authz: apispec.Authz("odd")})
		}, `Authz=odd has identity source "maybe"`, func(m map[apispec.Authz]apispec.IdentitySource) {
			m["odd"] = apispec.IdentitySource("maybe")
		}},
		// The #391 hole: a header-less write that reads its identity from the
		// path, declared none instead of claimed-identity.
		{"a none route with {user} in its path (a claimed identity declared as none)", func(rs []apispec.Route) []apispec.Route {
			return append(rs, apispec.Route{Method: "POST", Pattern: "/api/users/{user}/display-name", Audience: apispec.AudienceParticipant, Authz: apispec.AuthzNone})
		}, "Authz=none with {user} in the Pattern", nil},
		{"a none route with a {user...} wildcard", func(rs []apispec.Route) []apispec.Route {
			rs[5].Pattern = "/files/{user...}"
			return rs
		}, "Authz=none with {user} in the Pattern", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := apispec.AuthzIdentitySources()
			if tc.table != nil {
				tc.table(table)
			}
			_, v := claimedIdentityViolations(tc.mutate(claimedIdentityBaseline()), table)
			if len(v) != 1 {
				t.Fatalf("want exactly 1 violation, got %v", v)
			}
			if !strings.Contains(v[0], tc.want) {
				t.Fatalf("violation does not say why (want %q): %q", tc.want, v[0])
			}
		})
	}
	// Not vacuous the other way round: an empty table checks nothing, and says so.
	if checked, v := ClaimedIdentityForwardViolations(nil); checked != 0 || len(v) != 0 {
		t.Fatalf("empty table: checked=%d violations=%v", checked, v)
	}
}
