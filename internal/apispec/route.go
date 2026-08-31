// Package apispec is the shared plumbing behind ADR-0005 (OpenAPI canon +
// parity gate): each HTTP-mux-owning binary (scoreboard, collector,
// auth-policy) exposes its route set as a declarative table (Route), and
// NewMux is the ONLY function in this codebase allowed to call
// http.ServeMux.Handle for such a table-driven package.
//
// NewMux OWNS mux construction (task #146 — see its own doc for the full
// rationale): it builds a fresh *http.ServeMux internally and returns it,
// rather than taking a caller-supplied mux and mutating it in place the way
// the former Register(mux, routes) did. That old shape let a second call —
// `apispec.Register(h.mux, sneakyRoutes)` pasted right after the real
// `h.routes = apispec.Register(h.mux, declared)` — install a spec-less,
// origin-guard-less route onto the SAME live production mux while every
// ADR-0005 V1-V4 check stayed green, because every check reads
// Handler.Routes() (== h.routes, only the FIRST call's return value); the
// second call's routes were live on the mux but invisible to every parity
// check (this codebase's own register_singlecall_test.go pins that exploit).
// A static assert (TestApispecRegisterSingleCallPerMuxOwningPackage, now
// renamed for NewMux) closed the gap by detection; NewMux closes it
// structurally: since NewMux never accepts an existing mux to add routes to,
// a second call can only ever produce a SECOND, independent *http.ServeMux —
// there is no operation in this package or in net/http that merges two
// ServeMux instances together, and staticreg_test.go already bans any direct
// mux.Handle/HandleFunc call outside this file, so there is no OTHER way to
// graft more routes onto the real production mux after construction either.
// Public Register no longer exists in this package at all — "write a second
// Register call on the same mux" is not merely detected, it does not
// typecheck (the call has no eligible callee to bind to).
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
// This package holds ONLY Route/NewMux + the stdlib "net/http" import — no
// YAML parsing, no spec comparison logic. That logic (Spec/LoadSpec/
// RouteSetDiff/BoolExtParity/StringExtParity/CompareResponse/...) lives in
// the sibling internal/apispec/specparity package instead, imported ONLY
// from *_test.go files. Before that split, every production binary that
// imports this package for Route/NewMux alone (cmd/auth-policy,
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
// artifact that BOTH drives http.ServeMux registration (via NewMux, below)
// AND is what the ADR-0005 parity tests compare against docs/openapi-*.yaml.
// Building the mux from anything other than this slice (e.g. a second,
// "for documentation only" list) would reopen the exact drift ADR-0005
// closes, so there is deliberately no second representation anywhere in this
// codebase — see each owning package's Routes() method.
//
// A field on this struct is a DECLARATION, not a guarantee, unless something
// in make test's suite actually EXERCISES the behaviour it claims — the same
// gap closed twice for OriginGuarded (5x mutation proof) and Authz
// (Requirement 1, final review round: a fake `x-ctf-authz: admin` route whose
// handler never called an authorization gate at all passed every ADR-0005
// V1-V4 check, because StringExtParity only compares the DECLARED string
// against the spec's declared string — neither side ever calls the gate
// function). This table records, per field, whether "declared" and
// "enforced" are the SAME claim in this codebase today, so a future field
// doesn't quietly repeat the pattern with nobody noticing the gap exists:
//
//	field             | enforced by a BEHAVIOURAL test?
//	------------------|----------------------------------------------------
//	Method / Pattern  | yes — IS the http.ServeMux registration itself; a
//	                  | wrong value 404s at the mux, there is no separate
//	                  | "declared vs installed" gap to have.
//	OriginGuarded     | yes — TestOriginGuard_AllProtectedRoutesEnforced
//	                  | (internal/scoreboard/origin_guard_test.go) derives
//	                  | its case table from Routes() and asserts the actual
//	                  | HTTP status a cross-origin request gets, not just
//	                  | that the field's value matches the spec's.
//	Authz             | yes — TestAuthz_AllDeclaredGatesEnforced
//	                  | (internal/scoreboard/authz_test.go) is OriginGuarded's
//	                  | direct counterpart, added specifically because the
//	                  | field existed and was spec-compared for a full
//	                  | review round before anything called the gate.
//	CollectorForward  | partially — StringExtParity/BoolExtParity check the
//	                  | DECLARATION against the spec (bijection across
//	                  | collector+scoreboard specs, V4), and the dedicated
//	                  | ResetDirtyRouteViolation/ResetDirtySpecViolation/
//	                  | ResetDirtyOriginGuardViolation asserts pin the ONE
//	                  | security-critical case by name. There is no generic
//	                  | behavioural test that drives every CollectorForward
//	                  | route through collector.go's actual forward allowlist
//	                  | and checks it lands on exactly the marked routes —
//	                  | internal/collector/apispec_parity_test.go checks the
//	                  | collector's OWN forward table against ITS spec, not
//	                  | against scoreboard's live mux.
//	Audience          | no — declaration only (StringExtParity checks it
//	                  | matches the spec string; nothing in this codebase
//	                  | reads Audience at request time to change behaviour).
//	                  | Documentation value for whoever is reading the spec
//	                  | to know who a route is for.
//	RateLimit         | no (implementation, not declaration) — StringExtParity
//	                  | DOES check this field's exact string against the
//	                  | spec's x-ctf-rate-limit (apispec_parity_test.go's
//	                  | TestAPISpec_V3b_StringExtParity; this field was
//	                  | PREVIOUSLY documented here as unchecked, which was
//	                  | itself wrong — Requirement 6.3, final review round).
//	                  | What is NOT checked is whether the STRING correctly
//	                  | describes the actual ratelimit.Limiter wired into the
//	                  | handler (e.g. "per-IP 1 req/s burst 10" could drift
//	                  | from the real ratelimit.New(...) call and nothing
//	                  | would notice) — a third, so-far-unclosed instance of
//	                  | exactly this struct's "declared vs enforced" gap.
//	                  | Signposted, not fixed, by ADR-0005.
type Route struct {
	// Method is the HTTP method ("GET", "POST", ...).
	Method string
	// Pattern is the http.ServeMux path pattern, WITHOUT the method prefix
	// (e.g. "/api/users/{user}/journey"). Go 1.22+ mux pattern syntax and
	// this codebase's OpenAPI path templates both use "{name}" for a path
	// parameter, so Pattern compares directly against a spec path key with
	// no translation.
	Pattern string
	// Audience mirrors x-ctf-audience. Declaration only — see the table
	// above.
	Audience Audience
	// Authz mirrors x-ctf-authz. Enforced by a behavioural test — see the
	// table above (internal/scoreboard/authz_test.go).
	Authz Authz
	// OriginGuarded mirrors x-ctf-origin-guard: whether this route is
	// wrapped by the browser-CSRF origin-guard middleware (ADR-0005
	// Decision 4 — the asymmetry is a security contract, not a default).
	// Enforced by a behavioural test — see the table above
	// (internal/scoreboard/origin_guard_test.go).
	OriginGuarded bool
	// CollectorForward mirrors x-ctf-collector-forward: whether the
	// collector's allowlisted forward can reach this route on a
	// participant's behalf. Partially enforced — see the table above.
	CollectorForward bool
	// RateLimit is a free-text description of the bucket applied (or
	// "none"). Parity-checked as a STRING against the spec's x-ctf-rate-limit
	// by ADR-0005 V3b (specparity.StringExtParity) — do not describe this
	// field as unchecked; see the table above for the actual, narrower gap
	// (the string vs. the real limiter behind it) that IS still unchecked.
	RateLimit string
	// Handler is the actual handler NewMux installs. Left nil in a table
	// built purely for metadata inspection (e.g. a parity test that never
	// calls NewMux) is fine — NewMux nil-checks before installing.
	Handler http.Handler
}

// MuxPattern re-joins Method and Pattern into the "METHOD /pattern" string
// http.ServeMux.Handle expects.
func (rt Route) MuxPattern() string { return rt.Method + " " + rt.Pattern }

// NewMux builds a brand-new *http.ServeMux, installs every route in routes
// that has a non-nil Handler onto it, and returns BOTH the mux and exactly
// that installed subset — the routes list a top-level Handler.Routes()
// method should store and hand back, so a parity test comparing against
// docs/openapi-*.yaml sees what the mux ACTUALLY serves, never a second,
// independently-maintained "what we meant to install" list.
//
// It is the ONLY call site in this codebase allowed to invoke mux.Handle for
// a table-driven package (ADR-0005 V2's blocking design constraint) —
// internal/apispec/staticreg_test.go statically asserts that no owning
// package (internal/scoreboard{,/api,/view,/ingest}, internal/collector,
// internal/authpolicy) calls mux.Handle/mux.HandleFunc directly outside this
// function, so a future route added the old way (bypassing the table) fails
// the build instead of silently becoming a V1 blind spot.
//
// NewMux deliberately does NOT take a *http.ServeMux parameter (task #146,
// unlike the former Register(mux, routes)): a caller cannot hand it an
// ALREADY-WIRED production mux and ask for more routes to be added later.
// Every call starts a fresh mux, so a second call anywhere in a mux-owning
// package's production code can only ever produce a second, freestanding
// *http.ServeMux that nothing wires to a listener — it cannot silently graft
// extra routes onto the mux already stored in h.mux the way a second
// Register(h.mux, sneakyRoutes) call used to (see the package doc above for
// the exact exploit this closes). This is the structural half of the fix;
// internal/apispec/register_singlecall_test.go's
// TestApispecNewMuxSingleCallPerMuxOwningPackage is the remaining detective
// half, now guarding against wasted/confusing extra calls and against a
// call's return value being silently dropped, rather than against a route
// actually reaching the live mux unnoticed (that class of bug no longer
// typechecks).
//
// A nil Handler is silently skipped rather than passed to mux.Handle (which
// would panic on a nil handler) — deliberately, so a table built purely for
// metadata inspection (e.g. a parity test constructing Route values that are
// never run through NewMux at all) stays legal. This is NOT a silent
// production hole: before this function returned its installed subset, a
// production Route entry with Handler == nil would 404 at the mux while its
// OWN package's Routes() method still listed it — vacuously "documented and
// implemented" to every ADR-0005 V1-V4 check, because those checks read
// Routes() directly rather than what NewMux actually did (5x review,
// MEDIUM 1: R1 confirmed no ADR-0005 check goes red for `Handler: nil` on a
// real route, only the behavioural handler tests do). Every top-level
// Handler.Routes() method (scoreboard, collector, auth-policy) now returns
// THIS function's second return value, stored at construction time — so "the
// route set the parity gate checks" and "the route set the mux actually
// serves" are, structurally, the same slice; a Handler{} literal can no
// longer drift the two apart by leaving Handler nil.
func NewMux(routes []Route) (*http.ServeMux, []Route) {
	mux := http.NewServeMux()
	installed := make([]Route, 0, len(routes))
	for _, rt := range routes {
		if rt.Handler == nil {
			continue
		}
		mux.Handle(rt.MuxPattern(), rt.Handler)
		installed = append(installed, rt)
	}
	return mux, installed
}
