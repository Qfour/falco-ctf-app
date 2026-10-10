package view

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

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
// rejects every extension but .css and .woff2 (so a script can never be
// registered while CSP carries script-src 'self'), and the set of logical
// names is pinned by TestStaticAssets_RegistryPin — changing that pin needs a
// security-engineer review.
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

// assetNameRe is the shape of a logical name: one path segment, lower-case,
// and an extension that is one of staticAssetTypes.
var assetNameRe = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

// staticAssetTypes is the allow-list of extensions and their Content-Type
// (D5). `.js` is deliberately absent: see the const block's doc.
var staticAssetTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".woff2": "font/woff2", // RFC 8081
}

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
			return nil, fmt.Errorf("static asset %q: extension %q is not allowed (D5: only .css and .woff2)", src.name, ext)
		}
		if !assetNameRe.MatchString(src.name) {
			return nil, fmt.Errorf("static asset %q: not a single lower-case path segment", src.name)
		}
		if _, dup := reg.byName[src.name]; dup {
			return nil, fmt.Errorf("static asset %q registered twice", src.name)
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
		}
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])[:assetHashLen]
		a := &staticAsset{
			name:        src.name,
			servedName:  strings.TrimSuffix(src.name, ext) + "." + hash + ext,
			body:        body,
			contentType: ctype,
			etag:        `"` + hash + `"`,
		}
		reg.byName[a.name] = a
		reg.byServed[a.servedName] = a
	}
	if len(reg.byName) == 0 {
		return nil, fmt.Errorf("static asset registry is empty")
	}
	return reg, nil
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

// embeddedAssetSources lists every first-party asset. woff2 files come first
// because fonts.css references them. This list IS the registry's logical-name
// set; TestStaticAssets_RegistryPin pins it.
func embeddedAssetSources() []assetSource {
	return []assetSource{
		{"chakrapetch-500.woff2", fontChakraPetch500Bytes},
		{"chakrapetch-600.woff2", fontChakraPetch600Bytes},
		{"chakrapetch-700.woff2", fontChakraPetch700Bytes},
		{"inter-var.woff2", fontInterBytes},
		{"jetbrainsmono-var.woff2", fontJetBrainsMonoBytes},
		{"fonts.css", fontsCSSBytes},
		{"cybercore.min.css", cybercoreCSSBytes},
		{"tokens.css", tokensCSSBytes},
	}
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
