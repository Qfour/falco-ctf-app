// Package ingressparity is the ADR-0021 (Issue #238) counterpart to
// internal/apispec/specparity: it holds the comparison logic behind the new
// Hard Invariant I15 — "the scoreboard's single-origin production ingress
// (charts/scoreboard/templates/ingress-journey.yaml) actually lets every
// AudienceParticipant mux.Route through, and lets NOTHING else through" —
// and nothing a production binary needs.
//
// Why this exists as a package separate from both internal/apispec
// (Route/Register, stdlib-only by contract — see route.go's own package
// doc) and internal/apispec/specparity (OpenAPI-spec comparison, imported
// only from *_test.go files): ADR-0021's Context C1/C2 found a THIRD
// artifact — the ingress allow-list — that neither I14 (ADR-0005, mux vs.
// spec) nor any existing check reads at all. #95 (POST /csp-report) and
// #235 (/vendor/cybercore.min.css, /static/tokens.css — landed in
// PRODUCTION before the fix) are both instances of a route being correctly
// declared in BOTH the mux table and docs/openapi-scoreboard.yaml (I14
// green) while missing from ingress-journey.yaml's allow-list — a
// participant-facing route that 404s at the single-origin ingress even
// though every OTHER layer says it should work.
//
// Like specparity, this package is imported ONLY from *_test.go files
// (internal/scoreboard's ADR-0021 test, plus this package's own
// coverage_test.go) — internal/apispec/dependency_boundary_test.go's
// TestNoProductionBinaryImportsIngressParity statically enforces that no
// cmd/* binary's build ever pulls this package in, mirroring
// TestNoProductionBinaryImportsSpecparity's proof for the same reason
// (route.go's package doc: a yaml.v3 / os/exec dependency belongs nowhere
// near a distroless production binary's SBOM for zero runtime benefit).
//
// D4 (ADR-0021 Decision): extraction (LoadIngressEntries — helm template +
// YAML parse, helm.go) and comparison (covers/CoverageDiff/DeadExact, this
// file) are split at a function boundary specifically so the comparison
// logic's mutation tests (V(I15)-5) can run against synthetic
// ([]apispec.Route, []IngressEntry) input without invoking helm or reading
// any real chart file — only LoadIngressEntries' own non-empty assertion
// (V(I15)-4, this package's caller's responsibility — see helm.go) touches
// the real chart.
package ingressparity

import (
	"sort"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// IngressEntry is one charts/scoreboard/templates/ingress-journey.yaml
// spec.rules[].http.paths[] entry, exactly as `helm template` renders it —
// see LoadIngressEntries. PathType is the raw k8s
// networking.k8s.io/v1 pathType string ("Exact" or "Prefix"); any other
// value is treated as covering nothing (covers' default case) rather than
// causing a parse error, so a future pathType this package doesn't know
// about fails CLOSED (uncovered participant routes go red) rather than
// silently matching everything.
type IngressEntry struct {
	Path     string
	PathType string
}

// normalize strips exactly one trailing "/" from path (ADR-0021 D3,
// security-engineer HIGH fix). k8s's Prefix pathType ignores a trailing "/"
// on the DECLARED path when matching a request path — a declared
// `path: /aaa/bbb/` Prefix entry matches a request for `/aaa/bbb` too, per
// the k8s networking.k8s.io/v1 Ingress docs' own Prefix examples. Only the
// declared side is normalized; there is no "request path" here at all
// (this package compares mux Patterns, which never carry a trailing slash
// convention of their own).
func normalize(path string) string {
	return strings.TrimSuffix(path, "/")
}

// staticPrefix returns the longest literal prefix of an http.ServeMux
// Pattern (e.g. "/api/users/{user}/journey") that every concrete request
// path the pattern can match must start with, and whether the pattern
// carries a path parameter at all. Go 1.22+ mux syntax requires a "{name}"
// segment to occupy an ENTIRE path segment — never a partial segment like
// "/api/users{user}" — so the substring up to and including the "/"
// immediately before the first "{" is always a literal, param-free prefix
// of pattern, AND (review-5x R2-F3, LOW: the earlier version of this
// comment overclaimed "always ends in /" without qualification) that
// prefix ends in "/" for every hasParam==true pattern this codebase's
// route tables actually contain — every one of them starts with a literal
// "/" before any "{", because a bare "{param}" with no leading "/" is not
// a legal http.ServeMux pattern at all (patterns are always rooted paths).
// The only way prefix could fail to end in "/" is i==0 (the FIRST byte of
// pattern is "{" — pattern[:0] is ""), which the mux's own pattern syntax
// makes unreachable in practice; if some future pattern-construction bug
// ever DID produce that, staticPfx == p2 (a Prefix ingress entry, itself
// always normalize()d to end in "/") would just never match "" — the
// route would show up as uncovered (V(I15)-1), not silently pass. When
// pattern has no "{" at all, hasParam is false and prefix equals pattern
// itself; callers must branch on hasParam rather than treating a
// param-free pattern's "prefix" as meaningful on its own (D3: the
// param-free and param-carrying cases compare against ingress paths with
// DIFFERENT rules).
func staticPrefix(pattern string) (prefix string, hasParam bool) {
	if i := strings.IndexByte(pattern, '{'); i >= 0 {
		return pattern[:i], true
	}
	return pattern, false
}

// covers reports whether a single ingress-journey.yaml entry (path,
// pathType) makes an http.ServeMux Pattern reachable through the
// single-origin participant ingress. This is ADR-0021 D3's matching rule —
// the security-engineer-reviewed, k8s-Prefix-trailing-slash-correct
// version (the initial draft under-covered bare exact routes against a
// trailing-slash Prefix entry, which was a false NEGATIVE on the reverse
// audience-mixing check V(I15)-2; see D3's own writeup for the false one
// this replaces).
func covers(pattern, path, pathType string) bool {
	staticPfx, hasParam := staticPrefix(pattern)
	switch pathType {
	case "Exact":
		// An Exact ingress entry proves exactly ONE concrete URL is
		// reachable. A param-carrying Pattern generates a whole FAMILY of
		// concrete paths (one per param value) — an Exact entry matching
		// just one member of that family is not "coverage" of the route (D3:
		// "1 つの param 値だけ通ることをカバーと呼ぶのは過大な主張"). Only a
		// param-free Pattern can be covered by Exact, and then only by
		// LITERAL equality — k8s's Exact pathType does NOT normalize a
		// trailing slash the way Prefix does, so `path` is compared raw,
		// never through normalize().
		return !hasParam && pattern == path
	case "Prefix":
		p2 := normalize(path) + "/"
		if hasParam {
			// staticPfx ends in "/" for every pattern this codebase's route
			// tables produce (see staticPrefix's doc for the exact
			// qualification and the fail-closed fallback if that ever
			// stopped holding), so it is already in the same normalized
			// shape as p2 — compare directly.
			return staticPfx == p2 || strings.HasPrefix(staticPfx, p2)
		}
		// A param-free Pattern may equal the ingress path itself (with its
		// own trailing slash normalized away), or live at a literal
		// sub-path underneath it.
		return pattern == normalize(path) || strings.HasPrefix(pattern, p2)
	default:
		// An unrecognised pathType (not Exact/Prefix — e.g. a future k8s
		// pathType this package hasn't been taught, or a chart typo) covers
		// nothing: fail closed, so a participant route hiding behind it
		// shows up as uncovered rather than silently passing.
		return false
	}
}

// CoverageDiff implements ADR-0021's two blocking Verification items as one
// synthetic-input-testable pure function (D4):
//
//   - V(I15)-1 (forward): every apispec.AudienceParticipant route in routes
//     not covered by ANY entry in paths is reported in uncovered, by its
//     "METHOD /pattern" MuxPattern() string.
//   - V(I15)-2 (reverse, audience mixing): every route of ANY OTHER
//     audience that is reachable through some Prefix entry in paths is
//     reported in foreign, annotated with the entry that exposes it — a
//     future admin/operator route accidentally added under an existing
//     Prefix (e.g. "/api/users/") would show up here even though nobody
//     touched ingress-journey.yaml itself (ADR-0021 D2's asymmetry, the
//     same "both directions have an incident" pattern ADR-0005 Decision 4
//     already established for origin-guard).
//
// Both slices are sorted for stable, diffable fail messages; both are nil
// (not just empty) when there is nothing to report, so callers can use
// len(...) == 0 as the pass condition without an extra nil check.
func CoverageDiff(routes []apispec.Route, paths []IngressEntry) (uncovered, foreign []string) {
	for _, rt := range routes {
		if rt.Audience != apispec.AudienceParticipant {
			continue
		}
		covered := false
		for _, e := range paths {
			if covers(rt.Pattern, e.Path, e.PathType) {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, rt.MuxPattern())
		}
	}
	for _, e := range paths {
		if e.PathType != "Prefix" {
			// Exact entries expose exactly the one literal path they name —
			// V(I15)-2 only worries about Prefix entries, which can expose
			// routes nobody enumerated by name (D2).
			continue
		}
		for _, rt := range routes {
			if rt.Audience == apispec.AudienceParticipant {
				continue
			}
			if covers(rt.Pattern, e.Path, e.PathType) {
				foreign = append(foreign, rt.MuxPattern()+" (audience="+string(rt.Audience)+", via ingress Prefix "+e.Path+")")
			}
		}
	}
	sort.Strings(uncovered)
	sort.Strings(foreign)
	return uncovered, foreign
}

// DeadExact implements ADR-0021 V(I15)-3 (advisory, non-blocking): each
// Exact entry in paths whose literal path has no LITERALLY matching mux
// Route at all (any audience) — a rename/removal that left the ingress
// allow-list entry behind. This is hygiene/drift, not a security defect
// (D2's "Reverse — Exact エントリの死んだ登録" is explicitly advisory, not
// blocking, to avoid landing-order flakiness between the PR that
// renames/removes a mux route and the PR that updates the ingress chart).
// Returned sorted.
func DeadExact(routes []apispec.Route, paths []IngressEntry) []string {
	var dead []string
	for _, e := range paths {
		if e.PathType != "Exact" {
			continue
		}
		found := false
		for _, rt := range routes {
			if rt.Pattern == e.Path {
				found = true
				break
			}
		}
		if !found {
			dead = append(dead, e.Path)
		}
	}
	sort.Strings(dead)
	return dead
}
