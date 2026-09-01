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

// --- Google Fonts self-host (app#96 / P12 follow-up) ---
//
// Replaces templates/portal.html's and templates/index.html's former
// `<link href="https://fonts.googleapis.com/css2?...">` (a pre-existing,
// P23-6-predating external CDN load) with the exact same 10 family+weight
// combinations, vendored and served same-origin — same go:embed
// self-host/never-a-CDN pattern as cybercoreCSS above. See
// vendor/fonts/PROVENANCE.md for the fetch URL, per-file sha256, subset
// scope (latin-only — see that doc for why), and the SIL OFL license text
// each family ships under (3 separate LICENSE-<family>.txt files, since
// each family has its own copyright holder).
//
// embeddedAsset factors out the identical embed/ETag/immutable-cache/304
// logic serveCybercoreCSS and serveTokensCSS above hand-write individually
// (they predate this helper and are left as-is — a working, tested code
// path is not worth touching just to de-duplicate two call sites); every
// NEW vendored asset below goes through this instead of repeating that
// logic a sixth time.
type embeddedAsset struct {
	data        []byte
	contentType string
	etag        string
}

// newEmbeddedAsset computes the same 8-byte-prefix sha256 ETag scheme
// cybercoreCSSETag/tokensCSSETag use, once, at package init (data is a
// go:embed'd byte slice — see each call site below).
func newEmbeddedAsset(data []byte, contentType string) embeddedAsset {
	sum := sha256.Sum256(data)
	return embeddedAsset{
		data:        data,
		contentType: contentType,
		etag:        `"` + hex.EncodeToString(sum[:8]) + `"`,
	}
}

// serve mirrors serveCybercoreCSS/serveTokensCSS's Content-Type/Cache-
// Control/ETag/conditional-GET behavior exactly.
func (a embeddedAsset) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("ETag", a.etag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == a.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(a.data)))
	_, _ = w.Write(a.data)
}

// vendorFontsCSSPath is the same-origin path templates/portal.html's and
// templates/index.html's <link> tags point at (replacing the former
// Google Fonts css2 URL — same rationale as cybercoreCSSPath's doc above).
const vendorFontsCSSPath = "/vendor/fonts.css"

//go:embed vendor/fonts/fonts.css
var vendorFontsCSSBytes []byte

var vendorFontsCSS = newEmbeddedAsset(vendorFontsCSSBytes, "text/css; charset=utf-8")

func serveVendorFontsCSS(w http.ResponseWriter, r *http.Request) { vendorFontsCSS.serve(w, r) }

// The 5 vendored woff2 files fonts.css's @font-face src: url(...) rules
// reference (PROVENANCE.md's pin table has the exact upstream URL + sha256
// for each). Content-Type "font/woff2" is the IANA-registered MIME type for
// this format (RFC 8081).
const (
	fontChakraPetch500Path = "/vendor/fonts/chakrapetch-500.woff2"
	fontChakraPetch600Path = "/vendor/fonts/chakrapetch-600.woff2"
	fontChakraPetch700Path = "/vendor/fonts/chakrapetch-700.woff2"
	fontInterPath          = "/vendor/fonts/inter-var.woff2"
	fontJetBrainsMonoPath  = "/vendor/fonts/jetbrainsmono-var.woff2"
	woff2ContentType       = "font/woff2"
)

//go:embed vendor/fonts/chakrapetch-500.woff2
var fontChakraPetch500Bytes []byte

//go:embed vendor/fonts/chakrapetch-600.woff2
var fontChakraPetch600Bytes []byte

//go:embed vendor/fonts/chakrapetch-700.woff2
var fontChakraPetch700Bytes []byte

//go:embed vendor/fonts/inter-var.woff2
var fontInterBytes []byte

//go:embed vendor/fonts/jetbrainsmono-var.woff2
var fontJetBrainsMonoBytes []byte

var (
	fontChakraPetch500 = newEmbeddedAsset(fontChakraPetch500Bytes, woff2ContentType)
	fontChakraPetch600 = newEmbeddedAsset(fontChakraPetch600Bytes, woff2ContentType)
	fontChakraPetch700 = newEmbeddedAsset(fontChakraPetch700Bytes, woff2ContentType)
	fontInter          = newEmbeddedAsset(fontInterBytes, woff2ContentType)
	fontJetBrainsMono  = newEmbeddedAsset(fontJetBrainsMonoBytes, woff2ContentType)
)

func serveFontChakraPetch500(w http.ResponseWriter, r *http.Request) { fontChakraPetch500.serve(w, r) }
func serveFontChakraPetch600(w http.ResponseWriter, r *http.Request) { fontChakraPetch600.serve(w, r) }
func serveFontChakraPetch700(w http.ResponseWriter, r *http.Request) { fontChakraPetch700.serve(w, r) }
func serveFontInter(w http.ResponseWriter, r *http.Request)          { fontInter.serve(w, r) }
func serveFontJetBrainsMono(w http.ResponseWriter, r *http.Request)  { fontJetBrainsMono.serve(w, r) }
