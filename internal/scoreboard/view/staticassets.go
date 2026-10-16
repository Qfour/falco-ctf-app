package view

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/avatar"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
)

// First-party static assets (ADR-0028, P28-0c, app#277).
//
// ONE route — GET /static/{asset} — serves every embedded asset under a
// content-hash name `<stem>.<hash><ext>` (tokens.1a2b3c4d5e6f7a8b.css). The
// hash is taken over the bytes AFTER references to other assets are resolved
// (D2), so a changed font changes fonts.css's name too. Because the URL is
// decided by the content, the response can be `immutable` for a year (D3): a
// browser holding a stale copy is holding a stale URL that no HTML references
// any more, never a stale copy of the current URL (the app#277 failure mode).
//
// What the registry is NOT: it never serves an embed.FS or an
// http.FileServer. Only names built into the registry at start-up answer;
// LICENSE / PROVENANCE.md next to the vendored files, un-hashed names and
// anything else are 404 (D2).
//
// D5 — what may live here: public, display-only assets that are identical for
// every viewer. Enforced mechanically, not by prose: buildAssetRegistry
// rejects every extension but .css, .woff2 and .svg (so a script can never be
// registered while CSP carries script-src 'self'), and the set of logical
// names is pinned by TestStaticAssets_RegistryPin — changing that pin needs a
// security-engineer review.
//
// ADR-0034 D9 is a LIMITED supersede of that D5 extension set: .svg is added,
// and only under the avatars/ directory (one logical-name prefix, see
// staticAssetDirs), because a participant's picture is one of 8 glyphs drawn
// for this repo. An SVG is a document, not an image format: it can carry
// script, a foreignObject, an external reference. So an .svg is never served
// as-is: buildAssetRegistry parses it and checks every (namespace, element)
// and (namespace, attribute) against an allow-list (svgsanitize.go), and a
// name outside the list is a START-UP error, not a runtime strip. The response
// also carries a CSP of its own (staticSVGCSP), so a script that somehow got in
// still cannot run when the URL is opened directly.
const (
	// staticRoutePattern is the single mux/spec pattern for static assets.
	staticRoutePattern = "/static/{asset}"
	// staticURLPrefix is what every served URL starts with.
	staticURLPrefix = "/static/"

	// staticImmutableCache is the Cache-Control of a content-hash name.
	staticImmutableCache = "public, max-age=31536000, immutable"
)

// assetHashLen is the number of hex characters of the sha256 kept in a
// served name (64 bits — a collision needs a deliberate attack on a repo
// whose contents are public and reviewed, not an accident).
const assetHashLen = 16

// assetRefRe matches a reference to another registered asset inside a CSS
// source: `url(asset:<logical name>)`. It is resolved to the target's served
// URL before the CSS is hashed. A CSS source never spells a literal
// /static/... or /vendor/... path.
var assetRefRe = regexp.MustCompile(`url\(asset:([^)]*)\)`)

// cssCommentRe matches a CSS comment (non-greedy, across lines). The
// "unresolved asset: reference" check below ignores comments, because a
// vendored stylesheet may legitimately DESCRIBE the asset: form in prose
// (fonts.css does).
var cssCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)

// assetNameRe is the shape of one path segment of a logical name: lower-case
// and an extension that is one of staticAssetTypes.
var assetNameRe = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

// staticAssetTypes is the allow-list of extensions and their Content-Type
// (D5). `.js` is deliberately absent: see the const block's doc.
var staticAssetTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".woff2": "font/woff2", // RFC 8081
	".svg":   "image/svg+xml",
}

// staticAssetDirs lists the only directory prefixes a logical name may have,
// and the one extension allowed inside each. A logical name is otherwise a
// single segment. The SERVED name is still one segment (ADR-0028 D1: the route
// has no sub-directories): "avatars/falcon.svg" is served as
// "avatars-falcon.<hash>.svg". Every extension that needs a sanitizer
// (staticSanitizedExts) is allowed ONLY inside a directory listed here, so a
// top-level .svg is an error.
var staticAssetDirs = map[string]string{
	"avatars": ".svg", // ADR-0034 D9
}

// staticSanitizedExts are the extensions whose bytes are parsed and checked
// before they are registered.
var staticSanitizedExts = map[string]func(name string, data []byte) error{
	".svg": sanitizeSVG,
}

const (
	// staticSVGCSP is ADR-0034 D9 (b): on a directly opened .svg URL no script
	// runs, nothing is fetched, and the document is in a unique origin.
	staticSVGCSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
)

// assetSource is one input to the registry. Sources are processed in order;
// a CSS source may only reference sources listed BEFORE it.
type assetSource struct {
	name string // logical name, e.g. "tokens.css"
	data []byte
}

type staticAsset struct {
	name        string // logical name
	servedName  string // <stem>.<hash><ext>
	body        []byte
	contentType string
	etag        string
	csp         string // Content-Security-Policy of the response; "" = none
}

// assetRegistry maps logical names to their served form and back.
type assetRegistry struct {
	byName   map[string]*staticAsset
	byServed map[string]*staticAsset
}

// buildAssetRegistry resolves references and hashes every source. Any
// problem (bad name, disallowed extension, duplicate, unresolved reference)
// is an error: a registry that is wrong must not start.
func buildAssetRegistry(sources []assetSource) (*assetRegistry, error) {
	reg := &assetRegistry{
		byName:   make(map[string]*staticAsset, len(sources)),
		byServed: make(map[string]*staticAsset, len(sources)),
	}
	for _, src := range sources {
		ext := path.Ext(src.name)
		ctype, ok := staticAssetTypes[ext]
		if !ok {
			return nil, fmt.Errorf("static asset %q: extension %q is not allowed (D5: only .css, .woff2 and, under avatars/, .svg)", src.name, ext)
		}
		stem, err := logicalStem(src.name, ext)
		if err != nil {
			return nil, err
		}
		if _, dup := reg.byName[src.name]; dup {
			return nil, fmt.Errorf("static asset %q registered twice", src.name)
		}
		if len(src.data) == 0 {
			return nil, fmt.Errorf("static asset %q is empty", src.name)
		}
		var csp string
		if check, sanitized := staticSanitizedExts[ext]; sanitized {
			if err := check(src.name, src.data); err != nil {
				return nil, err
			}
			csp = staticSVGCSP
		}
		body := src.data
		if ext == ".css" {
			var rerr error
			body = assetRefRe.ReplaceAllFunc(src.data, func(m []byte) []byte {
				target := assetRefRe.FindSubmatch(m)[1]
				dep, found := reg.byName[string(target)]
				if !found {
					rerr = fmt.Errorf("static asset %q references %q, which is not registered before it", src.name, target)
					return m
				}
				return []byte("url(" + staticURLPrefix + dep.servedName + ")")
			})
			if rerr != nil {
				return nil, rerr
			}
			// assetRefRe only understands the exact form url(asset:NAME). A
			// reference written any other way (url("asset:NAME"), url( asset:NAME ),
			// a src: that is not inside url()) would survive resolution and be
			// served as a dead link, with no start-up error. Anything that still
			// says asset: outside a comment is such a reference.
			if bytes.Contains(cssCommentRe.ReplaceAll(body, nil), []byte("asset:")) {
				return nil, fmt.Errorf("static asset %q: an \"asset:\" reference is left unresolved after resolution (write it exactly as url(asset:<name>): no quotes, no spaces)", src.name)
			}
		}
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])[:assetHashLen]
		a := &staticAsset{
			name:        src.name,
			servedName:  stem + "." + hash + ext,
			body:        body,
			contentType: ctype,
			etag:        `"` + hash + `"`,
			csp:         csp,
		}
		reg.byName[a.name] = a
		reg.byServed[a.servedName] = a
	}
	if len(reg.byName) == 0 {
		return nil, fmt.Errorf("static asset registry is empty")
	}
	return reg, nil
}

// logicalStem validates a logical name's shape and returns the stem of its
// served name (the name without the extension, any directory joined with '-').
// A name is one segment, or "<dir>/<segment>" for a dir in staticAssetDirs
// whose required extension matches. An .svg outside such a directory is
// refused for that reason, not for its shape.
func logicalStem(name, ext string) (string, error) {
	dir, file, inDir := strings.Cut(name, "/")
	if !inDir {
		file, dir = name, ""
	}
	if dir != "" {
		want, known := staticAssetDirs[dir]
		if !known || want != ext {
			return "", fmt.Errorf("static asset %q: not a single lower-case path segment (only the directories in staticAssetDirs, each with its one extension, are allowed)", name)
		}
	} else if _, sanitized := staticSanitizedExts[ext]; sanitized {
		return "", fmt.Errorf("static asset %q: %s is allowed only inside a directory of staticAssetDirs (ADR-0034 D9)", name, ext)
	}
	if !assetNameRe.MatchString(file) {
		return "", fmt.Errorf("static asset %q: not a single lower-case path segment", name)
	}
	stem := strings.TrimSuffix(file, ext)
	if dir != "" {
		stem = dir + "-" + stem
	}
	return stem, nil
}

// URL returns the served URL for a logical name. It is what templates call
// ({{.Assets.URL "tokens.css"}}). An unknown name — or a nil registry — is an
// ERROR, so a typo fails the render loudly instead of emitting a dead link.
func (g *assetRegistry) URL(name string) (string, error) {
	if g == nil {
		return "", fmt.Errorf("static asset %q requested but no registry is attached", name)
	}
	a, ok := g.byName[name]
	if !ok {
		return "", fmt.Errorf("static asset %q is not registered", name)
	}
	return staticURLPrefix + a.servedName, nil
}

// handler is GET /static/{asset}: a registered served name answers 200/304;
// anything else is 404 + no-store + {"error": ...}. no-store on the 404
// matters: served names are computable from the public repo, so a probe
// before a deploy must not leave a 404 in a shared cache (D3).
func (g *assetRegistry) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := g.byServed[r.PathValue("asset")]
		if !ok {
			w.Header().Set("Cache-Control", "no-store")
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		h := w.Header()
		h.Set("Content-Type", a.contentType)
		h.Set("Cache-Control", staticImmutableCache)
		h.Set("ETag", a.etag)
		h.Set("X-Content-Type-Options", "nosniff")
		if a.csp != "" {
			h.Set("Content-Security-Policy", a.csp)
		}
		if match := r.Header.Get("If-None-Match"); match != "" && match == a.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		h.Set("Content-Length", strconv.Itoa(len(a.body)))
		_, _ = w.Write(a.body)
	})
}

// --- embedded inputs (D5: view/static and view/vendor only) ---------------

//go:embed static/tokens.css
var tokensCSSBytes []byte

//go:embed vendor/cybercore/cybercore.min.css
var cybercoreCSSBytes []byte

//go:embed vendor/fonts/fonts.css
var fontsCSSBytes []byte

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

// avatarFS holds the avatar glyphs (ADR-0034 D9). Only *.svg is embedded, so
// avatars/PROVENANCE.md next to them is not part of any registry input.
//
//go:embed static/avatars/*.svg
var avatarFS embed.FS

// avatarAssetGlyphs is the glyph set whose files are registered, in the
// registry's order. It is derived from avatar.GlyphNames(), the one table that
// validates ids (ADR-0034 D9, <glyph>-<color>), so the asset side cannot keep
// a second list. TestAvatarAssets_CoverGlyphsAndColors pins it against the
// design contract (8 glyphs, one file each, nothing else in the directory) and
// TestAvatarAssets_MatchAvatarTable against the table.
var avatarAssetGlyphs = avatar.GlyphNames()

// avatarAssetSources reads one source per glyph; a missing file is a build
// bug, so it panics at start-up like the rest of the registry.
func avatarAssetSources() []assetSource {
	out := make([]assetSource, 0, len(avatarAssetGlyphs))
	for _, g := range avatarAssetGlyphs {
		b, err := avatarFS.ReadFile("static/avatars/" + g + ".svg")
		if err != nil {
			panic("view: avatar asset " + g + ": " + err.Error())
		}
		out = append(out, assetSource{"avatars/" + g + ".svg", b})
	}
	return out
}

// embeddedAssetSources lists every first-party asset. woff2 files come first
// because fonts.css references them. This list IS the registry's logical-name
// set; TestStaticAssets_RegistryPin pins it.
func embeddedAssetSources() []assetSource {
	srcs := []assetSource{
		{"chakrapetch-500.woff2", fontChakraPetch500Bytes},
		{"chakrapetch-600.woff2", fontChakraPetch600Bytes},
		{"chakrapetch-700.woff2", fontChakraPetch700Bytes},
		{"inter-var.woff2", fontInterBytes},
		{"jetbrainsmono-var.woff2", fontJetBrainsMonoBytes},
		{"fonts.css", fontsCSSBytes},
		{"cybercore.min.css", cybercoreCSSBytes},
		{"tokens.css", tokensCSSBytes},
	}
	return append(srcs, avatarAssetSources()...)
}

// avatarURLs returns the served URL of every avatar glyph, keyed by glyph id.
// The portal's JavaScript cannot call {{.Assets.URL}}, so a template that
// needs the URLs serializes this map (the names are content hashes and change
// with the bytes).
func (g *assetRegistry) avatarURLs() (map[string]string, error) {
	out := make(map[string]string, len(avatarAssetGlyphs))
	for _, glyph := range avatarAssetGlyphs {
		u, err := g.URL("avatars/" + glyph + ".svg")
		if err != nil {
			return nil, err
		}
		out[glyph] = u
	}
	return out, nil
}

// staticAssets is the process-wide registry, built once at init from the
// embedded bytes. A build failure panics at start-up (same stance as
// template.Must): serving with a wrong registry is worse than not starting.
var staticAssets = func() *assetRegistry {
	reg, err := buildAssetRegistry(embeddedAssetSources())
	if err != nil {
		panic("view: static asset registry: " + err.Error())
	}
	return reg
}()
