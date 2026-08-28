package view

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/http"
)

// cybercoreCSS is the vendored, pinned cybercore-css minified stylesheet
// (P23-6 — see vendor/cybercore/PROVENANCE.md for the exact npm version /
// upstream commit / shasum this was fetched from, and the MIT LICENSE copied
// alongside it). It is embedded into the scoreboard binary and served
// same-origin at GET /vendor/cybercore.min.css — never loaded from a CDN —
// so the portal's browser-side CSS fetch never leaves the deploy's own
// origin (P12: egress-zero for this asset; see PROVENANCE.md's "External
// references inside the file" audit for why the one http://www.w3.org/2000/svg
// string inside it is a namespace identifier in a data: URI, not a network
// fetch).
//
//go:embed vendor/cybercore/cybercore.min.css
var cybercoreCSS []byte

// cybercoreCSSPath is the same-origin path templates/portal.html's <link>
// tag points at. Kept as a named constant (rather than duplicating the
// literal string in both the Go handler and the HTML template) so a future
// rename touches one place; view.go's Register wires it to serveCybercoreCSS.
const cybercoreCSSPath = "/vendor/cybercore.min.css"

// cybercoreCSSETag is computed once at init from the embedded bytes so a
// re-deploy of the SAME pinned version (I4/I5: image tag = git SHA, so this
// only ever changes when the binary itself changes) yields a stable,
// content-addressed ETag rather than a per-process-start value — a
// conditional GET (If-None-Match) after a pod restart with unchanged content
// still gets a cheap 304. sha256.Sum256 (not sha256.New().Sum(data), which
// would append data onto an EMPTY hash's already-finalized digest rather
// than hashing it) is the correct one-shot hash-of-bytes call here.
var cybercoreCSSSum = sha256.Sum256(cybercoreCSS)
var cybercoreCSSETag = `"` + hex.EncodeToString(cybercoreCSSSum[:8]) + `"`

// serveCybercoreCSS serves the vendored stylesheet with a long-lived,
// immutable Cache-Control: this file only ever changes when the scoreboard
// image itself is rebuilt (I4/I5 — image tag is the git SHA), so there is no
// scenario where the SAME image serves different bytes at this path later.
// A browser that already cached it for a prior deploy of a DIFFERENT image
// tag/SHA will simply re-fetch (new deploy = new pod = fresh cache lookup
// keyed by the deploy's own asset URL versioning is out of scope here; this
// is a same-origin, single-file, no-query-string asset, matching the other
// embedded HTML pages' lack of cache headers today — the only reason this
// one gets explicit headers at all is its size (~76KB) makes repeated
// fetches on every /portal load worth avoiding).
func serveCybercoreCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("ETag", cybercoreCSSETag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == cybercoreCSSETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(cybercoreCSS)))
	_, _ = w.Write(cybercoreCSS)
}

// tokensCSS is the design-token single source (app#116 — see
// static/tokens.css's own doc for the full "why" of this file). Same
// embed-and-serve pattern as cybercoreCSS above: baked into the binary at
// build time, no filesystem access at runtime.
//
//go:embed static/tokens.css
var tokensCSS []byte

// tokensCSSPath is the same-origin path templates/index.html and
// templates/portal.html's <link> tags point at. See cybercoreCSSPath's doc
// above for why this is a named constant rather than a duplicated literal.
const tokensCSSPath = "/static/tokens.css"

// tokensCSSETag mirrors cybercoreCSSETag's rationale exactly: a stable,
// content-addressed ETag from the embedded bytes so a re-deploy of the SAME
// pinned version (I4/I5) still gets a cheap 304 on a conditional GET.
var tokensCSSSum = sha256.Sum256(tokensCSS)
var tokensCSSETag = `"` + hex.EncodeToString(tokensCSSSum[:8]) + `"`

// serveTokensCSS mirrors serveCybercoreCSS exactly — see that function's
// doc. tokens.css is far smaller than cybercore.min.css, but the same
// same-origin/immutable/ETag treatment costs nothing extra and keeps both
// vendored-asset handlers symmetric.
func serveTokensCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("ETag", tokensCSSETag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == tokensCSSETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tokensCSS)))
	_, _ = w.Write(tokensCSS)
}
