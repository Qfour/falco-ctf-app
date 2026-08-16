package view

import (
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// TestNewNonce_UniquePerCall proves newNonce does not return a fixed or
// predictable value — a nonce an attacker could guess ahead of time would
// defeat the entire point of nonce-restricting script-src (see csp.go's
// portalCSP doc).
func TestNewNonce_UniquePerCall(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		n, err := newNonce()
		if err != nil {
			t.Fatalf("newNonce: %v", err)
		}
		if n == "" {
			t.Fatal("newNonce returned empty string")
		}
		if seen[n] {
			t.Fatalf("newNonce produced a duplicate value across 100 calls: %q", n)
		}
		seen[n] = true
	}
}

// TestNewNonce_Base64Encoded proves the nonce is valid standard base64 (what
// portalCSP embeds into 'nonce-<value>' and what the HTML nonce="" attribute
// carries) — a nonce containing characters that could break out of either
// context (quotes, semicolons) would be a bug in the encoding choice, not
// just a cosmetic issue.
func TestNewNonce_Base64Encoded(t *testing.T) {
	n, err := newNonce()
	if err != nil {
		t.Fatalf("newNonce: %v", err)
	}
	b64 := regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	if !b64.MatchString(n) {
		t.Fatalf("newNonce value is not standard base64: %q", n)
	}
	// 16 bytes -> 24 base64 chars (with padding).
	if len(n) != 24 {
		t.Fatalf("newNonce length = %d, want 24 (base64 of 16 bytes): %q", len(n), n)
	}
}

// TestPortalCSP_ContainsExpectedDirectives pins the exact directive set the
// P23-6 design settled on (see csp.go's portalCSP doc for the per-directive
// rationale): script-src is nonce-restricted WITHOUT 'unsafe-inline',
// style-src deliberately DOES carry 'unsafe-inline' (documented tradeoff —
// see portalCSP's doc for why), and the Google Fonts origins this page's
// pre-existing <link> tags depend on are present so CSP does not regress
// font loading.
func TestPortalCSP_ContainsExpectedDirectives(t *testing.T) {
	nonce := "abc123=="
	csp := portalCSP(nonce)

	mustContain := []string{
		"default-src 'self'",
		"script-src 'self' 'nonce-abc123=='",
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
		"font-src 'self' https://fonts.gstatic.com",
		"img-src 'self' data:",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	}
	for _, want := range mustContain {
		if !strings.Contains(csp, want) {
			t.Errorf("portalCSP missing directive %q; got: %s", want, csp)
		}
	}

	// script-src must NOT carry 'unsafe-inline' — that is the entire point
	// of nonce-restricting it (see portalCSP's doc: a nonce-source alongside
	// 'unsafe-inline' would have browsers ignore 'unsafe-inline' per spec
	// anyway, but this asserts it is not even present in the string, so a
	// future edit that carelessly appends it is caught here rather than
	// relying on spec behaviour silently saving us).
	scriptSrcRe := regexp.MustCompile(`script-src [^;]*`)
	scriptSrc := scriptSrcRe.FindString(csp)
	if strings.Contains(scriptSrc, "unsafe-inline") {
		t.Errorf("script-src must not contain 'unsafe-inline' (defeats the nonce restriction): %q", scriptSrc)
	}

	// frame-ancestors must be absent — that directive belongs to
	// internal/ttydproxy (P23-3), a different response entirely (see
	// portalCSP's doc for why conflating the two would be wrong).
	if strings.Contains(csp, "frame-ancestors") {
		t.Errorf("portal CSP must not set frame-ancestors (owned by ttydproxy, not the portal response): %s", csp)
	}
}

// TestPortalCSP_NonceIsPerInvocation proves two calls with different nonce
// inputs produce different header values embedding EXACTLY that nonce (not
// a stale/cached one) — a regression here (e.g. a package-level cached CSP
// string) would silently make every response share one nonce, defeating the
// per-response guarantee writeSecurityHeaders/newNonce rely on.
func TestPortalCSP_NonceIsPerInvocation(t *testing.T) {
	a := portalCSP("nonceA")
	b := portalCSP("nonceB")
	if !strings.Contains(a, "'nonce-nonceA'") {
		t.Errorf("expected nonceA embedded in %q", a)
	}
	if !strings.Contains(b, "'nonce-nonceB'") {
		t.Errorf("expected nonceB embedded in %q", b)
	}
	if strings.Contains(a, "nonceB") || strings.Contains(b, "nonceA") {
		t.Errorf("nonce values leaked across independent portalCSP calls: a=%q b=%q", a, b)
	}
}

// TestWriteSecurityHeaders_SetsHeadersAndReturnsMatchingNonce proves the
// helper renderPortal calls (1) sets a Content-Security-Policy header whose
// nonce-source matches EXACTLY the string it returns (which the caller must
// thread into the template's {{.Nonce}} for every <script nonce="...">), and
// (2) sets the auxiliary hardening headers.
func TestWriteSecurityHeaders_SetsHeadersAndReturnsMatchingNonce(t *testing.T) {
	w := httptest.NewRecorder()
	nonce, err := writeSecurityHeaders(w)
	if err != nil {
		t.Fatalf("writeSecurityHeaders: %v", err)
	}
	if nonce == "" {
		t.Fatal("writeSecurityHeaders returned empty nonce")
	}

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header not set")
	}
	if !strings.Contains(csp, "'nonce-"+nonce+"'") {
		t.Errorf("CSP header does not embed the returned nonce %q: %s", nonce, csp)
	}

	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := w.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q, want strict-origin-when-cross-origin", got)
	}
}

// TestWriteSecurityHeaders_DistinctNoncePerCall proves consecutive calls
// (modelling consecutive GET /portal requests) never reuse a nonce — this is
// the end-to-end version of TestNewNonce_UniquePerCall, exercised through
// the exact function renderPortal calls per-request.
func TestWriteSecurityHeaders_DistinctNoncePerCall(t *testing.T) {
	n1, err := writeSecurityHeaders(httptest.NewRecorder())
	if err != nil {
		t.Fatalf("writeSecurityHeaders (1st): %v", err)
	}
	n2, err := writeSecurityHeaders(httptest.NewRecorder())
	if err != nil {
		t.Fatalf("writeSecurityHeaders (2nd): %v", err)
	}
	if n1 == n2 {
		t.Fatalf("two independent writeSecurityHeaders calls returned the SAME nonce %q", n1)
	}
}

// TestRenderPortal_CSPHeaderAndNonceInBody is the end-to-end proof (through
// the real GET /portal render path) that: (1) the response carries a CSP
// header restricting script-src to 'self' + a nonce, (2) that EXACT nonce
// appears in the HTML body as every <script nonce="..."> attribute's value
// (so a browser executing the page would find them all authorized), and (3)
// two independent renders of the SAME request never reuse a nonce.
func TestRenderPortal_CSPHeaderAndNonceInBody(t *testing.T) {
	render := func() (string, string) {
		r := httptest.NewRequest("GET", "/portal", nil)
		w := httptest.NewRecorder()
		if err := renderPortal(w, r, nil, nil, ""); err != nil {
			t.Fatalf("renderPortal: %v", err)
		}
		return w.Header().Get("Content-Security-Policy"), w.Body.String()
	}

	csp1, body1 := render()
	if csp1 == "" {
		t.Fatal("expected Content-Security-Policy header on GET /portal response")
	}
	nonceRe := regexp.MustCompile(`'nonce-([^']+)'`)
	m := nonceRe.FindStringSubmatch(csp1)
	if m == nil {
		t.Fatalf("could not find nonce-source in CSP header: %s", csp1)
	}
	nonce1 := m[1]

	scriptNonceRe := regexp.MustCompile(`<script nonce="([^"]*)"`)
	matches := scriptNonceRe.FindAllStringSubmatch(body1, -1)
	if len(matches) == 0 {
		t.Fatal("expected at least one <script nonce=\"...\"> tag in the portal HTML")
	}
	for _, sm := range matches {
		// html/template HTML-escapes attribute values (e.g. "+" -> "&#43;")
		// for browser-safety — that escaping is correct and expected, and a
		// browser's HTML parser decodes it back to the literal nonce before
		// comparing against the CSP header, so the test must do the same
		// (html.UnescapeString) rather than compare the raw escaped source
		// against the raw (unescaped) header value.
		got := html.UnescapeString(sm[1])
		if got != nonce1 {
			t.Errorf("script tag nonce %q (escaped source %q) does not match CSP header nonce %q", got, sm[1], nonce1)
		}
	}

	// Every <script> tag in the page must carry the nonce attribute — a tag
	// without it would be silently blocked by the CSP (fail-closed for
	// functionality, but also a signal that a future <script> was added
	// without wiring the nonce; assert the count matches the template's
	// known tag count so a regression here is caught explicitly rather than
	// discovered as "some tab doesn't work" during manual QA).
	allScriptTagsRe := regexp.MustCompile(`<script\b`)
	allTags := allScriptTagsRe.FindAllString(body1, -1)
	if len(allTags) != len(matches) {
		t.Errorf("found %d <script> tags total but only %d carry nonce=\"...\" — every inline script must be nonced under this CSP", len(allTags), len(matches))
	}

	csp2, _ := render()
	m2 := nonceRe.FindStringSubmatch(csp2)
	if m2 == nil {
		t.Fatalf("could not find nonce-source in second CSP header: %s", csp2)
	}
	if m2[1] == nonce1 {
		t.Fatalf("two independent GET /portal renders reused the same nonce %q", nonce1)
	}
}

// TestServeCybercoreCSS_ContentTypeAndNoExternalRefs proves GET
// /vendor/cybercore.min.css (P23-6) serves the vendored stylesheet
// same-origin with the correct Content-Type, and that the served bytes
// contain no external network reference — a regression here (e.g. a bump to
// a cybercore version that adds a Google Fonts @import) would silently
// reopen the egress-zero property vendorassets.go's doc / PROVENANCE.md
// documents today. This is a lightweight runtime echo of the offline audit
// already recorded in vendor/cybercore/PROVENANCE.md; it does not replace
// that audit's obligation to re-check on every version bump.
func TestServeCybercoreCSS_ContentTypeAndNoExternalRefs(t *testing.T) {
	r := httptest.NewRequest("GET", cybercoreCSSPath, nil)
	w := httptest.NewRecorder()
	serveCybercoreCSS(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/css") {
		t.Errorf("Content-Type = %q, want text/css prefix", ct)
	}
	body := w.Body.String()
	if body == "" {
		t.Fatal("served cybercore.min.css body is empty")
	}

	// No @import (would trigger a second, possibly cross-origin, fetch).
	if strings.Contains(body, "@import") {
		t.Error("vendored cybercore.min.css must not contain @import")
	}
	// Every url(...) must be a data: URI (icons/noise filters are inlined
	// SVG) — never an http(s) fetch. The one non-data string this file is
	// known to contain is the XML namespace "http://www.w3.org/2000/svg"
	// INSIDE a data: URI, which is not itself a url(...) target — this loop
	// specifically inspects url(...) targets, not arbitrary substrings.
	urlRe := regexp.MustCompile(`url\(([^)]*)\)`)
	for _, m := range urlRe.FindAllStringSubmatch(body, -1) {
		target := strings.Trim(m[1], `"'`)
		if !strings.HasPrefix(target, "data:") {
			t.Errorf("found a non-data: url() target in vendored cybercore.min.css: %q", target)
		}
	}
}

// TestServeCybercoreCSS_ConditionalGET proves the ETag-based 304 fast path
// works: a request carrying the SAME ETag the first response advertised
// gets 304 Not Modified with no body, matching the Cache-Control this
// handler sets (see vendorassets.go's doc for why this asset — unlike every
// other embedded HTML page — gets explicit caching headers).
func TestServeCybercoreCSS_ConditionalGET(t *testing.T) {
	w1 := httptest.NewRecorder()
	serveCybercoreCSS(w1, httptest.NewRequest("GET", cybercoreCSSPath, nil))
	etag := w1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected an ETag header on the first response")
	}

	r2 := httptest.NewRequest("GET", cybercoreCSSPath, nil)
	r2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	serveCybercoreCSS(w2, r2)
	if w2.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304 for a matching If-None-Match", w2.Code)
	}
	if w2.Body.Len() != 0 {
		t.Errorf("304 response must have an empty body, got %d bytes", w2.Body.Len())
	}
}
