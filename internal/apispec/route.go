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
//
// This package holds ONLY Route/Register + the stdlib "net/http" import — no
// YAML parsing, no spec comparison logic. That logic (Spec/LoadSpec/
// RouteSetDiff/BoolExtParity/StringExtParity/CompareResponse/...) lives in
// the sibling internal/apispec/specparity package instead, imported ONLY
// from *_test.go files. Before that split, every production binary that
// imports this package for Route/Register alone (cmd/auth-policy,
// cmd/collector) also pulled specparity's "gopkg.in/yaml.v3" dependency into
// its OWN build — Go compiles every non-test .go file in a directory as one
// unit, so a yaml import anywhere in this directory would have widened both
// distroless services' SBOM/CVE surface for zero runtime benefit (5x review,
// BLOCKING 1: `go list -deps ./cmd/auth-policy | grep yaml` was non-empty).
// Keep it this way: if you need YAML/spec-comparison logic, it goes in
// specparity, not here — this package must stay buildable with nothing but
// the stdlib.
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

// Register installs every route in routes that has a non-nil Handler onto
// mux, and returns exactly that installed subset — the routes list a
// top-level Handler.Routes() method should store and hand back, so a parity
// test comparing against docs/openapi-*.yaml sees what the mux ACTUALLY
// serves, never a second, independently-maintained "what we meant to
// install" list.
//
// It is the ONLY call site in this codebase allowed to invoke mux.Handle for
// a table-driven package (ADR-0005 V2's blocking design constraint) —
// internal/apispec/staticreg_test.go statically asserts that no owning
// package (internal/scoreboard{,/api,/view,/ingest}, internal/collector,
// internal/authpolicy) calls mux.Handle/mux.HandleFunc directly outside this
// function, so a future route added the old way (bypassing the table) fails
// the build instead of silently becoming a V1 blind spot.
//
// A nil Handler is silently skipped rather than passed to mux.Handle (which
// would panic on a nil handler) — deliberately, so a table built purely for
// metadata inspection (e.g. a parity test constructing Route values that are
// never run through Register at all) stays legal. This is NOT a silent
// production hole: before this function returned its installed subset, a
// production Route entry with Handler == nil would 404 at the mux while its
// OWN package's Routes() method still listed it — vacuously "documented and
// implemented" to every ADR-0005 V1-V4 check, because those checks read
// Routes() directly rather than what Register actually did (5x review,
// MEDIUM 1: R1 confirmed no ADR-0005 check goes red for `Handler: nil` on a
// real route, only the behavioural handler tests do). Every top-level
// Handler.Routes() method (scoreboard, collector, auth-policy) now returns
// THIS function's return value, stored at construction time — so "the route
// set the parity gate checks" and "the route set the mux actually serves"
// are, structurally, the same slice; a Handler{} literal can no longer drift
// the two apart by leaving Handler nil.
func Register(mux *http.ServeMux, routes []Route) []Route {
	installed := make([]Route, 0, len(routes))
	for _, rt := range routes {
		if rt.Handler == nil {
			continue
		}
		mux.Handle(rt.MuxPattern(), rt.Handler)
		installed = append(installed, rt)
	}
	return installed
}
