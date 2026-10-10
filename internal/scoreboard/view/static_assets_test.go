package view

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

// ADR-0028 Verification V1-V6 for the static-asset registry. The route-set
// half of V1 (one route, spec parity) lives in the scoreboard package's
// apispec_parity_test.go; the I15 half (V5) lives in
// ingress_journey_parity_test.go.

// staticTestMux wires the real view routes (admin allowed, participant
// "user1") into a fresh mux, the way scoreboard.NewHandler does.
func staticTestMux(t *testing.T) http.Handler {
	t.Helper()
	h := New(func(*http.Request) bool { return true }, func(*http.Request) string { return "user1" }, "", slog.New(slog.DiscardHandler))
	mux, _ := apispec.NewMux(h.Routes())
	return mux
}

func doGET(mux http.Handler, target string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// wantLogicalNames is the registry pin (ADR-0028 D5). Adding, renaming or
// removing an asset changes this list, and a PR that changes it needs
// security-engineer review (the registry is what 'script-src self' and the
// public cache trust). Extensions are pinned separately below.
var wantLogicalNames = []string{
	"chakrapetch-500.woff2",
	"chakrapetch-600.woff2",
	"chakrapetch-700.woff2",
	"cybercore.min.css",
	"fonts.css",
	"inter-var.woff2",
	"jetbrainsmono-var.woff2",
	"tokens.css",
}

// TestStaticAssets_RegistryPin is V6's pin: the logical-name set and the
// extension set are fixed, and every served name has the <stem>.<hash><ext>
// shape.
func TestStaticAssets_RegistryPin(t *testing.T) {
	var got []string
	for name := range staticAssets.byName {
		got = append(got, name)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, wantLogicalNames) {
		t.Fatalf("static asset registry names changed (D5 pin — needs security-engineer review):\n got  %v\n want %v", got, wantLogicalNames)
	}

	gotExts := map[string]bool{}
	for ext := range staticAssetTypes {
		gotExts[ext] = true
	}
	if !reflect.DeepEqual(gotExts, map[string]bool{".css": true, ".woff2": true}) {
		t.Fatalf("allowed static asset extensions = %v, want exactly .css and .woff2 (D5: no .js while CSP carries script-src 'self')", gotExts)
	}

	servedRe := regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*\.[0-9a-f]{16}\.(css|woff2)$`)
	for name, a := range staticAssets.byName {
		if !servedRe.MatchString(a.servedName) {
			t.Errorf("%s: served name %q does not match <stem>.<16 hex>.<ext>", name, a.servedName)
		}
		if staticAssets.byServed[a.servedName] != a {
			t.Errorf("%s: byServed does not map %q back to the asset", name, a.servedName)
		}
	}
	if len(staticAssets.byServed) != len(staticAssets.byName) {
		t.Errorf("byServed has %d entries, byName %d", len(staticAssets.byServed), len(staticAssets.byName))
	}
}

// TestBuildAssetRegistry_Rejects is V6's deliberate-violation half: a .js, a
// nested or upper-case name, a duplicate, a forward/unknown reference and an
// empty registry all fail the build (so they fail process start-up).
func TestBuildAssetRegistry_Rejects(t *testing.T) {
	css := []byte("a{}")
	cases := []struct {
		name string
		in   []assetSource
	}{
		{"a script cannot be registered (D5)", []assetSource{{"app.js", []byte("alert(1)")}}},
		{"an extension outside the allow-list", []assetSource{{"LICENSE", []byte("x")}, {"readme.md", []byte("x")}}},
		{"a subdirectory in the name", []assetSource{{"fonts/a.woff2", []byte("x")}}},
		{"an upper-case name", []assetSource{{"Tokens.css", css}}},
		{"a duplicate name", []assetSource{{"a.css", css}, {"a.css", css}}},
		{"a reference to an unregistered asset", []assetSource{{"a.css", []byte("x{src:url(asset:missing.woff2)}")}}},
		{"a reference to an asset listed AFTER it", []assetSource{{"a.css", []byte("x{src:url(asset:b.woff2)}")}, {"b.woff2", []byte("w")}}},
		{"an empty registry", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reg, err := buildAssetRegistry(tc.in); err == nil {
				t.Fatalf("buildAssetRegistry accepted %q, want an error (got %d assets)", tc.name, len(reg.byName))
			}
		})
	}
}

// TestStaticAssets_HashProperties is V3: one changed byte changes the asset's
// served name, and the name of every CSS that references it; an unrelated
// asset keeps its name.
func TestStaticAssets_HashProperties(t *testing.T) {
	build := func(font string) *assetRegistry {
		t.Helper()
		reg, err := buildAssetRegistry([]assetSource{
			{"f.woff2", []byte(font)},
			{"fonts.css", []byte("@font-face{src:url(asset:f.woff2)}")},
			{"tokens.css", []byte(":root{--a:1}")},
		})
		if err != nil {
			t.Fatal(err)
		}
		return reg
	}
	a, b := build("font-bytes-1"), build("font-bytes-2")
	if a.byName["f.woff2"].servedName == b.byName["f.woff2"].servedName {
		t.Error("changing the font's bytes did not change its served name")
	}
	if a.byName["fonts.css"].servedName == b.byName["fonts.css"].servedName {
		t.Error("changing the font did not change fonts.css's served name — the CSS references the font, its name must follow (D2)")
	}
	if a.byName["tokens.css"].servedName != b.byName["tokens.css"].servedName {
		t.Error("an unrelated asset's served name changed")
	}
	if want := "url(/static/" + a.byName["f.woff2"].servedName + ")"; !bytes.Contains(a.byName["fonts.css"].body, []byte(want)) {
		t.Errorf("fonts.css body does not contain the resolved reference %q: %s", want, a.byName["fonts.css"].body)
	}
	if bytes.Contains(a.byName["fonts.css"].body, []byte("asset:")) {
		t.Error("fonts.css still carries an unresolved asset: placeholder")
	}
}

// TestStaticAssets_ServeAndCacheHeaders is V4's positive half: every
// registered served name answers 200 with the immutable header, an ETag and
// the right Content-Type; a matching If-None-Match gets an empty 304.
func TestStaticAssets_ServeAndCacheHeaders(t *testing.T) {
	mux := staticTestMux(t)
	for name, a := range staticAssets.byName {
		url := "/static/" + a.servedName
		w := doGET(mux, url, nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s: GET %s = %d, want 200 (body %q)", name, url, w.Code, w.Body.String())
			continue
		}
		if got := w.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("%s: Cache-Control = %q", name, got)
		}
		wantCT := staticAssetTypes[a.name[strings.LastIndex(a.name, "."):]]
		if got := w.Header().Get("Content-Type"); got != wantCT {
			t.Errorf("%s: Content-Type = %q, want %q", name, got, wantCT)
		}
		etag := w.Header().Get("ETag")
		if etag == "" {
			t.Errorf("%s: no ETag", name)
		}
		if !bytes.Equal(w.Body.Bytes(), a.body) {
			t.Errorf("%s: served %d bytes, want the registry's %d", name, w.Body.Len(), len(a.body))
		}

		w2 := doGET(mux, url, map[string]string{"If-None-Match": etag})
		if w2.Code != http.StatusNotModified || w2.Body.Len() != 0 {
			t.Errorf("%s: conditional GET = %d with %d body bytes, want an empty 304", name, w2.Code, w2.Body.Len())
		}
		if w2.Header().Get("ETag") != etag || w2.Header().Get("Cache-Control") == "" {
			t.Errorf("%s: the 304 must repeat ETag and Cache-Control, got %v", name, w2.Header())
		}
	}
}

// TestStaticAssets_NotFoundIsNoStoreJSON is V4's negative half: names the
// registry did not produce are 404 + no-store + {"error": ...} — the
// un-hashed names, files that are merely embedded, a wrong hash, and the
// shapes that could fall through to the catch-all GET / (two segments,
// percent-encoded dot-dot). None may return the admin HTML.
func TestStaticAssets_NotFoundIsNoStoreJSON(t *testing.T) {
	mux := staticTestMux(t)
	tokens := staticAssets.byName["tokens.css"].servedName
	for _, path := range []string{
		"/static/tokens.css",                  // un-hashed
		"/static/cybercore.min.css",           // un-hashed
		"/static/does-not-exist",              // unknown
		"/static/LICENSE",                     // embedded next to the assets, not registered
		"/static/PROVENANCE.md",               // same
		"/static/tokens.0000000000000000.css", // right stem, wrong hash
		"/static/" + tokens + ".map",          // right name, extra suffix
		"/vendor/cybercore.min.css",           // the removed old route (D1: no alias)
		"/vendor/fonts.css",
	} {
		w := doGET(mux, path, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (body %q)", path, w.Code, w.Body.String())
			continue
		}
		if strings.HasPrefix(path, "/static/") {
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("GET %s: Cache-Control = %q on the 404, want no-store", path, got)
			}
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] == nil {
				t.Errorf("GET %s: 404 body is not {\"error\": ...}: %q (%v)", path, w.Body.String(), err)
			}
		}
	}

	// The route-shape probes only need: 404 and not the dashboard HTML.
	for _, path := range []string{"/static/a/b", "/static/" + tokens + "/x", "/static/..%2Fx", "/static/%2e%2e", "/static/%2e%2e%2f", "/static/", "/static"} {
		w := doGET(mux, path, nil)
		if w.Code == http.StatusOK || strings.Contains(strings.ToLower(w.Body.String()), "<html") {
			t.Errorf("GET %s = %d with body %q — must not serve a page or an asset", path, w.Code, w.Body.String())
		}
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, w.Code)
		}
	}
}

// TestHTMLShells_AreNoStore is D3: both shells (and the 403 of GET /) carry
// no-store — they embed a per-response nonce and, for /portal, the viewer's
// own identifier.
func TestHTMLShells_AreNoStore(t *testing.T) {
	mux := staticTestMux(t)
	for _, path := range []string{"/", "/portal"} {
		w := doGET(mux, path, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, w.Code)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s: Cache-Control = %q, want no-store", path, got)
		}
	}
	h := New(func(*http.Request) bool { return false }, nil, "", slog.New(slog.DiscardHandler))
	w := httptest.NewRecorder()
	h.index(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusForbidden || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("GET / as non-admin = %d, Cache-Control %q; want 403 + no-store", w.Code, w.Header().Get("Cache-Control"))
	}
}

var (
	// htmlRefRe: <link rel="stylesheet" href=...> and <script src=...>.
	linkHrefRe  = regexp.MustCompile(`(?i)<link\b[^>]*\brel="stylesheet"[^>]*\bhref="([^"]*)"`)
	scriptSrcRe = regexp.MustCompile(`(?i)<script\b[^>]*\bsrc="([^"]*)"`)
	cssURLRe    = regexp.MustCompile(`url\(([^)]*)\)`)
)

// sameOriginRefs returns the HTML refs V2 covers: stylesheet hrefs and
// script srcs that are same-origin paths (start with one "/").
func sameOriginRefs(body string) []string {
	var out []string
	for _, re := range []*regexp.Regexp{linkHrefRe, scriptSrcRe} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if strings.HasPrefix(m[1], "/") && !strings.HasPrefix(m[1], "//") {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// checkAssetRefs is V2: every same-origin reference in a rendered document —
// and, transitively, every same-origin url() in the CSS it loads — answers
// 200 through the mux, is a /static/ hash name, and no external url() leaks
// in. It returns what it found (so a caller can assert non-emptiness) and
// the problems.
func checkAssetRefs(mux http.Handler, doc string) (found int, problems []string) {
	seen := map[string]bool{}
	var visit func(from, ref string)
	visit = func(from, ref string) {
		if seen[ref] {
			return
		}
		seen[ref] = true
		found++
		if strings.HasPrefix(ref, "/vendor/") {
			problems = append(problems, from+" references the removed "+ref)
		}
		if !strings.HasPrefix(ref, staticURLPrefix) {
			problems = append(problems, from+" references "+ref+", outside /static/")
		}
		w := doGET(mux, ref, nil)
		if w.Code != http.StatusOK {
			problems = append(problems, from+" references "+ref+" which answers "+http.StatusText(w.Code))
			return
		}
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
			return
		}
		css := w.Body.String()
		if strings.Contains(css, "@import") {
			problems = append(problems, ref+" contains @import (a second fetch the audit does not cover)")
		}
		for _, m := range cssURLRe.FindAllStringSubmatch(css, -1) {
			target := strings.Trim(strings.TrimSpace(m[1]), `"'`)
			switch {
			case strings.HasPrefix(target, "data:"), strings.HasPrefix(target, "#"):
			case strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//"):
				visit(ref, target)
			default:
				problems = append(problems, ref+" has a url() target outside the same origin: "+target)
			}
		}
	}
	for _, ref := range sameOriginRefs(doc) {
		visit("document", ref)
	}
	return found, problems
}

// TestRenderedDocuments_AssetReferencesResolve is V2 against the real
// GET / and GET /portal output.
func TestRenderedDocuments_AssetReferencesResolve(t *testing.T) {
	mux := staticTestMux(t)
	// want = minimum number of distinct refs: / links fonts.css + tokens.css
	// (+ 5 woff2 via fonts.css); /portal adds cybercore.min.css.
	for _, tc := range []struct {
		path string
		want int
	}{{"/", 7}, {"/portal", 8}} {
		w := doGET(mux, tc.path, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", tc.path, w.Code)
		}
		found, problems := checkAssetRefs(mux, w.Body.String())
		if found < tc.want {
			t.Errorf("GET %s: resolved %d distinct same-origin refs, want >= %d — the extraction is checking nothing", tc.path, found, tc.want)
		}
		for _, p := range problems {
			t.Errorf("GET %s: %s", tc.path, p)
		}
	}
}

// TestCheckAssetRefs_MutationsGoRed is V6's permanent deliberate violations:
// each way the references can break turns checkAssetRefs (or the render) red.
func TestCheckAssetRefs_MutationsGoRed(t *testing.T) {
	mux := staticTestMux(t)
	doc := doGET(mux, "/portal", nil).Body.String()
	tokensURL := "/static/" + staticAssets.byName["tokens.css"].servedName
	if !strings.Contains(doc, tokensURL) {
		t.Fatalf("rendered /portal does not link %s", tokensURL)
	}

	t.Run("a literal un-hashed /static/tokens.css in a template", func(t *testing.T) {
		_, problems := checkAssetRefs(mux, strings.Replace(doc, tokensURL, "/static/tokens.css", 1))
		if len(problems) == 0 {
			t.Fatal("a literal /static/tokens.css link passed V2")
		}
	})
	t.Run("a literal /vendor/ path", func(t *testing.T) {
		_, problems := checkAssetRefs(mux, strings.Replace(doc, tokensURL, "/vendor/cybercore.min.css", 1))
		if len(problems) == 0 {
			t.Fatal("a /vendor/ link passed V2")
		}
	})
	t.Run("a script that is not served", func(t *testing.T) {
		_, problems := checkAssetRefs(mux, doc+`<script src="/static/app.0000000000000000.js"></script>`)
		if len(problems) == 0 {
			t.Fatal("an unserved <script src> passed V2")
		}
	})
	t.Run("an external stylesheet is not silently counted as covered", func(t *testing.T) {
		// Absolute URLs are out of V2's scope by definition; the CSP
		// (style-src 'self') is what blocks them. Prove the extractor
		// ignores them rather than mis-reporting them as same-origin.
		if refs := sameOriginRefs(`<link rel="stylesheet" href="https://example.invalid/x.css">`); len(refs) != 0 {
			t.Fatalf("extracted %v from an absolute URL", refs)
		}
	})
	t.Run("a registry missing tokens.css fails the render", func(t *testing.T) {
		var srcs []assetSource
		for _, s := range embeddedAssetSources() {
			if s.name != "tokens.css" {
				srcs = append(srcs, s)
			}
		}
		reg, err := buildAssetRegistry(srcs)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := portalTmpl.Execute(&buf, portalData{Nonce: "n", Assets: reg}); err == nil {
			t.Fatal("portal rendered although tokens.css is not in the registry")
		}
		if err := indexTmpl.Execute(&buf, indexData{Nonce: "n", Assets: reg}); err == nil {
			t.Fatal("index rendered although tokens.css is not in the registry")
		}
	})
	t.Run("a nil registry fails the render", func(t *testing.T) {
		var buf bytes.Buffer
		if err := portalTmpl.Execute(&buf, portalData{Nonce: "n"}); err == nil {
			t.Fatal("portal rendered with no registry attached")
		}
	})
}
