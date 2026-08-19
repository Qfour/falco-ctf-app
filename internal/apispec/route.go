// Package apispec is the shared plumbing behind ADR-0005 (OpenAPI canon +
// parity gate): each HTTP-mux-owning binary (scoreboard, collector,
// auth-policy) exposes its route set as a declarative table (Route), and
// Register is the ONLY function in this codebase allowed to call
// http.ServeMux.Handle for such a table-driven package.
//
// Why a table instead of parsing the mux or grepping source: http.ServeMux
// cannot enumerate its own registered patterns, and literal-grep extraction
// is ALREADY broken by internal/scoreboard/view/vendorassets.go's
// cybercoreCSSPath, which used to be wired via string concatenation
// (mux.HandleFunc("GET "+cybercoreCSSPath, ...)) — a lexical scan would
// silently drop that route. A Go slice of structs, read back at test time via
// the owning package's exported Routes() method, has no such blind spot: the
// test sees the exact runtime string value, however it was computed.
//
// Route also carries the same audience/authorization/origin-guard/
// collector-forward/rate-limit metadata declared per-operation in
// docs/openapi-*.yaml (the x-ctf-* extensions), so the ADR-0005 parity tests
// can compare a package's ACTUAL registered route set against the spec's
// DECLARED operation set structurally, never by re-parsing source text.
package apispec

import "net/http"

// Audience mirrors docs/openapi-*.yaml's x-ctf-audience enum.
type Audience string

const (
	AudienceParticipant Audience = "participant"
	AudienceOperator    Audience = "operator"
	AudienceInternal    Audience = "internal"
	AudienceInfra       Audience = "infra"
)

// Authz mirrors docs/openapi-*.yaml's x-ctf-authz enum.
type Authz string

const (
	AuthzNone             Authz = "none"
	AuthzAdmin            Authz = "admin"
	AuthzSelfOrAdmin      Authz = "self-or-admin"
	AuthzSelfOrAdminWrite Authz = "self-or-admin-write"
	AuthzClaimedIdentity  Authz = "claimed-identity"
)

// Route is one row of a service's declarative route table — the single
// artifact that BOTH drives http.ServeMux registration (via Register, below)
// AND is what the ADR-0005 parity tests compare against docs/openapi-*.yaml.
// Building the mux from anything other than this slice (e.g. a second,
// "for documentation only" list) would reopen the exact drift ADR-0005
// closes, so there is deliberately no second representation anywhere in this
// codebase — see each owning package's Routes() method.
type Route struct {
	// Method is the HTTP method ("GET", "POST", ...).
	Method string
	// Pattern is the http.ServeMux path pattern, WITHOUT the method prefix
	// (e.g. "/api/users/{user}/journey"). Go 1.22+ mux pattern syntax and
	// this codebase's OpenAPI path templates both use "{name}" for a path
	// parameter, so Pattern compares directly against a spec path key with
	// no translation.
	Pattern string
	// Audience mirrors x-ctf-audience.
	Audience Audience
	// Authz mirrors x-ctf-authz.
	Authz Authz
	// OriginGuarded mirrors x-ctf-origin-guard: whether this route is
	// wrapped by the browser-CSRF origin-guard middleware (ADR-0005
	// Decision 4 — the asymmetry is a security contract, not a default).
	OriginGuarded bool
	// CollectorForward mirrors x-ctf-collector-forward: whether the
	// collector's allowlisted forward can reach this route on a
	// participant's behalf.
	CollectorForward bool
	// RateLimit is a free-text description of the bucket applied (or
	// "none"). Not parity-checked against the spec's prose by ADR-0005 V1-V8
	// (only Origin/CollectorForward parity are); carried for completeness
	// and for any future strengthening (ADR-0005 Signposts).
	RateLimit string
	// Handler is the actual handler Register installs. Left nil in a table
	// built purely for metadata inspection (e.g. a parity test that never
	// calls Register) is fine — Register nil-checks before installing.
	Handler http.Handler
}

// MuxPattern re-joins Method and Pattern into the "METHOD /pattern" string
// http.ServeMux.Handle expects.
func (rt Route) MuxPattern() string { return rt.Method + " " + rt.Pattern }

// Register installs every route in the table onto mux. It is the ONLY call
// site in this codebase allowed to invoke mux.Handle for a table-driven
// package (ADR-0005 V2's blocking design constraint) —
// internal/apispec/staticreg_test.go statically asserts that no owning
// package (internal/scoreboard{,/api,/view,/ingest}, internal/collector,
// internal/authpolicy) calls mux.Handle/mux.HandleFunc directly outside this
// function, so a future route added the old way (bypassing the table) fails
// the build instead of silently becoming a V1 blind spot.
func Register(mux *http.ServeMux, routes []Route) {
	for _, rt := range routes {
		if rt.Handler == nil {
			continue
		}
		mux.Handle(rt.MuxPattern(), rt.Handler)
	}
}
