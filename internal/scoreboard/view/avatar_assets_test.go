package view

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ADR-0034 D9 + V6: the avatar glyphs, their SVG sanitizer, the response
// headers of a .svg, and the six background colors in tokens.css.

// The VP-fixed design contract (ADR-0034 D9): id = <glyph>-<color>, 8 x 6 = 48
// combinations (40 seats + 8 reserved). The profile code owns the Go table
// that validates an id; these lists are the ASSET side and are pinned here.
var (
	wantAvatarGlyphs = []string{"falcon", "shield", "key", "terminal", "radar", "lock", "bug", "flame"}
	wantAvatarColors = []string{"cyan", "magenta", "amber", "lime", "violet", "slate"}
)

// okSVG is a minimal glyph that passes the sanitizer; the reject cases below
// each add exactly one defect to it.
const okSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#fff"><path d="M2 2h20v20H2z"/></svg>`

func avatarSVGSource(body string) []assetSource {
	return []assetSource{{"avatars/x.svg", []byte(body)}}
}

// TestSanitizeSVG_Rejects is V6: one defect per case, each refused for ITS
// reason (wantErr is a fragment naming the element or attribute). The cases
// include names the allow-list never heard of (<animate>, <set>, <use>): a
// deny-list implementation would pass those and this test would go red.
func TestSanitizeSVG_Rejects(t *testing.T) {
	const p = `<path d="M2 2h20v20H2z"/>`
	wrap := func(inner string) string {
		return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#fff">` + inner + `</svg>`
	}
	cases := []struct{ name, svg, wantErr string }{
		{"script element", wrap(`<script>alert(1)</script>`), `element {http://www.w3.org/2000/svg}script is not allowed`},
		{"XHTML-namespace script", wrap(`<script xmlns="http://www.w3.org/1999/xhtml">alert(1)</script>`), `element {http://www.w3.org/1999/xhtml}script is not allowed`},
		{"a second namespace declared with a prefix", `<svg xmlns="http://www.w3.org/2000/svg" xmlns:h="http://www.w3.org/1999/xhtml" viewBox="0 0 24 24"><h:script>alert(1)</h:script></svg>`, `attribute {xmlns}h on <svg> is not allowed`},
		{"a prefixed XHTML script (the prefix declared on the element)", wrap(`<h:script xmlns:h="http://www.w3.org/1999/xhtml">alert(1)</h:script>`), `element {http://www.w3.org/1999/xhtml}script is not allowed`},
		{"foreignObject", wrap(`<foreignObject><div xmlns="http://www.w3.org/1999/xhtml"/></foreignObject>`), `element {http://www.w3.org/2000/svg}foreignObject is not allowed`},
		{"animate (not in the list, so a deny-list would pass it)", wrap(`<path d="M0 0"><animate attributeName="d" to="M1 1"/></path>`), `element {http://www.w3.org/2000/svg}animate is not allowed`},
		{"set", wrap(`<path d="M0 0"><set attributeName="fill" to="#000"/></path>`), `element {http://www.w3.org/2000/svg}set is not allowed`},
		{"use with an internal reference", wrap(`<use href="#a"/>`), `element {http://www.w3.org/2000/svg}use is not allowed`},
		{"style element", wrap(`<style>path{fill:url(http://evil.example/x)}</style>`), `element {http://www.w3.org/2000/svg}style is not allowed`},
		{"image element", wrap(`<image href="http://evil.example/x.png"/>`), `element {http://www.w3.org/2000/svg}image is not allowed`},
		{"onload on the root", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" onload="alert(1)"></svg>`, `attribute onload on <svg> is not allowed`},
		{"onclick on a path", wrap(`<path d="M0 0" onclick="alert(1)"/>`), `attribute onclick on <path> is not allowed`},
		{"external xlink:href", `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 24 24"><path xlink:href="http://evil.example/x" d="M0 0"/></svg>`, `attribute {xmlns}xlink on <svg> is not allowed`},
		{"xlink:href with the prefix undeclared", wrap(`<path xlink:href="http://evil.example/x" d="M0 0"/>`), `attribute {xlink}href on <path> is not allowed`},
		{"plain href to an internal id", wrap(`<path href="#a" d="M0 0"/>`), `attribute href on <path> is not allowed`},
		{"xml:base", wrap(`<path xml:base="http://evil.example/" d="M0 0"/>`), `attribute {http://www.w3.org/XML/1998/namespace}base on <path> is not allowed`},
		{"style attribute with a url", wrap(`<path d="M0 0" style="fill:url(http://evil.example/x)"/>`), `attribute style on <path> is not allowed`},
		{"fill that is a url() to another origin", wrap(`<path d="M0 0" fill="url(http://evil.example/x)"/>`), `attribute fill on <path> has a value outside its allowed form`},
		{"fill that is url(#id), a reference", wrap(`<path d="M0 0" fill="url(#g)"/>`), `attribute fill on <path> has a value outside its allowed form`},
		{"path data carrying a url", wrap(`<path d="M0 0 url(http://evil.example/)"/>`), `attribute d on <path> has a value outside its allowed form`},
		{"a viewBox other than the fixed one", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 9999 9999"><path d="M0 0"/></svg>`, `attribute viewBox on <svg> has a value outside its allowed form`},
		{"an xmlns that is not SVG", `<svg xmlns="http://www.w3.org/1999/xhtml" viewBox="0 0 24 24"></svg>`, `root element is {http://www.w3.org/1999/xhtml}svg`},
		{"a root that is not svg", `<g xmlns="http://www.w3.org/2000/svg"/>`, `root element is {http://www.w3.org/2000/svg}g`},
		{"two root elements", okSVG + okSVG, `more than one root element`},
		{"xml-stylesheet processing instruction", `<?xml-stylesheet href="http://evil.example/x.css" type="text/css"?>` + okSVG, `processing instruction <?xml-stylesheet`},
		{"the XML declaration", `<?xml version="1.0"?>` + okSVG, `processing instruction <?xml `},
		{"DOCTYPE", `<!DOCTYPE svg>` + okSVG, `a <!...> declaration is not allowed`},
		{"ENTITY (external)", `<!DOCTYPE svg [<!ENTITY x SYSTEM "http://evil.example/x">]>` + okSVG, `a <!...> declaration is not allowed`},
		{"an undefined entity reference", wrap(`<path d="M0 0" fill="&xxe;"/>`), `not well-formed XML`},
		{"a comment", wrap(`<!-- hi -->` + p), `a comment is not allowed`},
		{"text content", wrap(`hello` + p), `text content is not allowed`},
		{"CDATA text", wrap(`<![CDATA[x]]>` + p), `text content is not allowed`},
		{"trailing text after the root", okSVG + `x`, `text content is not allowed`},
		{"not XML", `<svg`, `not well-formed XML`},
		{"empty of elements", ` `, `no root element`},
		{"too large", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="` + strings.Repeat("M0 0 ", 1000) + `"/></svg>`, `more than the 4096 a glyph may take`},
		{"too many elements", wrap(strings.Repeat(p, maxSVGElements)), `more than 32 elements`},
	}
	if len(cases) < 10 {
		t.Fatalf("only %d fixtures; V6 wants a spread of 10 or more", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildAssetRegistry(avatarSVGSource(tc.svg))
			if err == nil {
				t.Fatalf("buildAssetRegistry accepted %q, want a start-up error", tc.name)
			}
			if !strings.Contains(err.Error(), `static asset "avatars/x.svg": svg: `) {
				t.Fatalf("error does not name the asset and the sanitizer: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("refused for a different reason:\n got  %v\n want it to contain %q", err, tc.wantErr)
			}
		})
	}

	// The control: the reject cases are okSVG plus one defect, so okSVG itself
	// must pass, or every case above would be rejected for the wrong reason.
	t.Run("the base glyph the cases are built from passes", func(t *testing.T) {
		if _, err := buildAssetRegistry(avatarSVGSource(okSVG)); err != nil {
			t.Fatalf("okSVG rejected: %v", err)
		}
	})
}

// TestSanitizeSVG_DuplicateAttribute: a repeated attribute is refused (the
// decoder lets it through; browsers disagree on which one wins).
func TestSanitizeSVG_DuplicateAttribute(t *testing.T) {
	err := sanitizeSVG("avatars/x.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0" d="M1 1"/></svg>`))
	if err == nil || !strings.Contains(err.Error(), "attribute d on <path> is repeated") {
		t.Fatalf("a repeated attribute: got %v, want it refused as repeated", err)
	}
}

// TestAvatarAssets_AllEightPassTheSanitizer is V6's positive half: the files
// that ship go through the real registry, and each is a small glyph.
func TestAvatarAssets_AllEightPassTheSanitizer(t *testing.T) {
	for _, g := range wantAvatarGlyphs {
		b, err := avatarFS.ReadFile("static/avatars/" + g + ".svg")
		if err != nil {
			t.Fatalf("%s: %v", g, err)
		}
		if err := sanitizeSVG("avatars/"+g+".svg", b); err != nil {
			t.Errorf("%s: %v", g, err)
		}
		if len(b) > 3*1024 {
			t.Errorf("%s: %d bytes, want <= 3 KB (a glyph is a few paths)", g, len(b))
		}
		if a, ok := staticAssets.byName["avatars/"+g+".svg"]; !ok {
			t.Errorf("%s: not in the registry", g)
		} else if a.csp != staticSVGCSP || a.contentType != "image/svg+xml" {
			t.Errorf("%s: csp %q contentType %q", g, a.csp, a.contentType)
		}
	}
}

// TestStaticAssets_SVGResponseHeaders is V6's header pin (ADR-0034 D9 (b)): a
// .svg answers image/svg+xml with nosniff and the sandboxing CSP, so opening
// the URL directly runs nothing; and only the .svg carries that CSP.
func TestStaticAssets_SVGResponseHeaders(t *testing.T) {
	mux := staticTestMux(t)
	var svgs int
	for name, a := range staticAssets.byName {
		w := doGET(mux, "/static/"+a.servedName, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", name, w.Code)
		}
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.HasSuffix(name, ".svg") {
			if csp != "" {
				t.Errorf("%s: carries a Content-Security-Policy %q; only the .svg responses do", name, csp)
			}
			continue
		}
		svgs++
		if got := w.Header().Get("Content-Type"); got != "image/svg+xml" {
			t.Errorf("%s: Content-Type = %q, want image/svg+xml", name, got)
		}
		if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", name, got)
		}
		if csp != "default-src 'none'; style-src 'unsafe-inline'; sandbox" {
			t.Errorf("%s: Content-Security-Policy = %q", name, csp)
		}
		// the 304 repeats it (a cache revalidation must not drop the CSP)
		w2 := doGET(mux, "/static/"+a.servedName, map[string]string{"If-None-Match": w.Header().Get("ETag")})
		if w2.Code != http.StatusNotModified || w2.Header().Get("Content-Security-Policy") != csp {
			t.Errorf("%s: 304 = %d, CSP %q", name, w2.Code, w2.Header().Get("Content-Security-Policy"))
		}
	}
	if svgs != len(wantAvatarGlyphs) {
		t.Errorf("%d .svg assets served, want %d", svgs, len(wantAvatarGlyphs))
	}
}

// TestAvatarAssets_CoverGlyphsAndColors is V6's coverage in both directions:
// every glyph has an SVG and nothing else is in the directory; every color has
// a tokens.css variable and tokens.css has no other --avatar- variable; every
// color has its CSS class in the rendered portal.
func TestAvatarAssets_CoverGlyphsAndColors(t *testing.T) {
	if got := append([]string(nil), avatarAssetGlyphs...); !equalAsSets(got, wantAvatarGlyphs) {
		t.Fatalf("avatarAssetGlyphs = %v, want %v", got, wantAvatarGlyphs)
	}

	entries, err := os.ReadDir("static/avatars")
	if err != nil {
		t.Fatal(err)
	}
	var files, want []string
	for _, e := range entries {
		files = append(files, e.Name())
	}
	want = []string{"PROVENANCE.md"} // the ledger; not embedded (avatarFS takes *.svg only)
	for _, g := range wantAvatarGlyphs {
		want = append(want, g+".svg")
	}
	if !equalAsSets(files, want) {
		t.Errorf("static/avatars holds %v, want exactly %v (a file with no glyph, or a glyph with no file)", files, want)
	}

	vars := avatarTokenValues(t)
	var gotColors []string
	for c := range vars {
		gotColors = append(gotColors, c)
	}
	if !equalAsSets(gotColors, wantAvatarColors) {
		t.Errorf("tokens.css --avatar-<color> = %v, want %v", gotColors, wantAvatarColors)
	}

	css := doGET(staticTestMux(t), "/portal", nil).Body.String()
	for _, c := range wantAvatarColors {
		rule := regexp.MustCompile(`\.avatar-` + c + `\s*\{\s*background-color:\s*var\(--avatar-` + c + `\);`)
		if !rule.MatchString(css) {
			t.Errorf("rendered /portal has no .avatar-%s rule bound to --avatar-%s", c, c)
		}
	}
}

func equalAsSets(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, ",") == strings.Join(b, ",")
}

var (
	avatarVarRe = regexp.MustCompile(`(?m)^\s*--avatar-([a-z]+):\s*([^;]+);`)
	cssVarDefRe = regexp.MustCompile(`(?m)^\s*(--[a-z0-9-]+):\s*(#[0-9A-Fa-f]{6})\s*;`)
)

// avatarTokenValues returns color name -> "#RRGGBB" for every --avatar-<color>
// in tokens.css, following one var(--other) alias (cyan and violet reuse
// palette steps that tokens.css defines as literals).
func avatarTokenValues(t *testing.T) map[string]string {
	t.Helper()
	src := string(tokensCSSBytes)
	literal := map[string]string{}
	for _, m := range cssVarDefRe.FindAllStringSubmatch(src, -1) {
		literal[m[1]] = strings.ToUpper(m[2])
	}
	out := map[string]string{}
	for _, m := range avatarVarRe.FindAllStringSubmatch(src, -1) {
		v := strings.TrimSpace(m[2])
		if alias := regexp.MustCompile(`^var\((--[a-z0-9-]+)\)$`).FindStringSubmatch(v); alias != nil {
			v = literal[alias[1]]
		} else {
			v = strings.ToUpper(v)
		}
		if !regexp.MustCompile(`^#[0-9A-F]{6}$`).MatchString(v) {
			t.Fatalf("--avatar-%s = %q does not resolve to a #RRGGBB literal", m[1], m[2])
		}
		out[m[1]] = v
	}
	return out
}

func srgbLinear(c float64) float64 {
	c /= 255
	if c <= 0.04045 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

func hexRGB(t *testing.T, h string) [3]float64 {
	t.Helper()
	var out [3]float64
	for i := range out {
		v, err := strconv.ParseUint(h[1+2*i:3+2*i], 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = float64(v)
	}
	return out
}

func avatarRelLuminance(rgb [3]float64) float64 {
	return 0.2126*srgbLinear(rgb[0]) + 0.7152*srgbLinear(rgb[1]) + 0.0722*srgbLinear(rgb[2])
}

// TestAvatarColors_WhiteContrast pins ADR-0034 D9's design rule: the white
// glyph reads on every color, >= 3:1 (WCAG 1.4.11 non-text contrast). The
// values are computed from tokens.css itself, so a lighter edit goes red here.
func TestAvatarColors_WhiteContrast(t *testing.T) {
	white := avatarRelLuminance([3]float64{255, 255, 255})
	for color, hex := range avatarTokenValues(t) {
		l := avatarRelLuminance(hexRGB(t, hex))
		ratio := (white + 0.05) / (l + 0.05)
		if ratio < 3.0 {
			t.Errorf("--avatar-%s %s: contrast with a white glyph %.2f:1, want >= 3:1", color, hex, ratio)
		}
		t.Logf("--avatar-%s %s  white-glyph contrast %.2f:1", color, hex, ratio)
	}
}

func labOf(t *testing.T, hex string) [3]float64 {
	rgb := hexRGB(t, hex)
	r, g, b := srgbLinear(rgb[0]), srgbLinear(rgb[1]), srgbLinear(rgb[2])
	x := (0.4124*r + 0.3576*g + 0.1805*b) / 0.9505
	y := 0.2126*r + 0.7152*g + 0.0722*b
	z := (0.0193*r + 0.1192*g + 0.9505*b) / 1.089
	f := func(v float64) float64 {
		if v > 0.008856 {
			return math.Cbrt(v)
		}
		return 7.787*v + 16.0/116
	}
	return [3]float64{116*f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))}
}

// TestAvatarColors_Distinguishable guards the Result screen (40 seats at
// once): no two of the six colors are close (CIE76 delta-E >= 20; the nearest
// pair today, cyan and slate, is about 24).
func TestAvatarColors_Distinguishable(t *testing.T) {
	vals := avatarTokenValues(t)
	var names []string
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			a, b := labOf(t, vals[names[i]]), labOf(t, vals[names[j]])
			d := math.Sqrt(math.Pow(a[0]-b[0], 2) + math.Pow(a[1]-b[1], 2) + math.Pow(a[2]-b[2], 2))
			if d < 20 {
				t.Errorf("--avatar-%s and --avatar-%s are %.1f apart (CIE76), want >= 20", names[i], names[j], d)
			}
		}
	}
}

// TestAvatarURLs: the map a template serializes for the portal's JavaScript
// has one served URL per glyph, in the /static/ hash-name shape, and each URL
// answers 200 as an SVG.
func TestAvatarURLs(t *testing.T) {
	urls, err := staticAssets.avatarURLs()
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != len(wantAvatarGlyphs) {
		t.Fatalf("%d urls, want %d", len(urls), len(wantAvatarGlyphs))
	}
	mux := staticTestMux(t)
	for _, g := range wantAvatarGlyphs {
		u := urls[g]
		if !regexp.MustCompile(fmt.Sprintf(`^/static/avatars-%s\.[0-9a-f]{16}\.svg$`, g)).MatchString(u) {
			t.Errorf("%s: url %q", g, u)
		}
		if w := doGET(mux, u, nil); w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/svg+xml" {
			t.Errorf("%s: GET %s = %d %q", g, u, w.Code, w.Header().Get("Content-Type"))
		}
	}
	if _, err := (*assetRegistry)(nil).avatarURLs(); err == nil {
		t.Error("a nil registry produced urls")
	}
}
