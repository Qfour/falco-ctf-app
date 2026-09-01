package view

import (
	"html"
	"log/slog"
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
// see portalCSP's doc for why). style-src/font-src carry NO external origin
// (app#96, P12 follow-up: the Google Fonts stylesheet + font files this page
// used to load cross-origin are now vendored same-origin under
// /vendor/fonts.css and /vendor/fonts/*.woff2 — 'self' alone covers them).
// Exercised with an EMPTY ttydSuffix (the local/most-deploys case, see
// PORTAL_TTYD_SUFFIX's doc) — TestPortalCSP_FrameSrc below covers the
// non-empty-suffix case R5 added.
func TestPortalCSP_ContainsExpectedDirectives(t *testing.T) {
	nonce := "abc123=="
	csp := portalCSP(nonce, "")

	mustContain := []string{
		"default-src 'self'",
		"script-src 'self' 'nonce-abc123=='",
		"style-src 'self' 'unsafe-inline'",
		"font-src 'self'",
		"img-src 'self' data:",
		"frame-src 'none'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"report-uri /csp-report",
		"report-to csp-endpoint",
	}
	for _, want := range mustContain {
		if !strings.Contains(csp, want) {
			t.Errorf("portalCSP missing directive %q; got: %s", want, csp)
		}
	}

	// app#96 (P12 follow-up / egress-zero): neither fonts.googleapis.com nor
	// fonts.gstatic.com may appear anywhere in the CSP any more — asserted
	// as an explicit ABSENCE (not just "mustContain the new shorter
	// directive strings" above) so a future edit that re-adds either origin
	// (e.g. reverting to a CDN) is caught here even if it appended the
	// origin to some OTHER directive this test doesn't already pin.
	for _, forbidden := range []string{"fonts.googleapis.com", "fonts.gstatic.com"} {
		if strings.Contains(csp, forbidden) {
			t.Errorf("portalCSP must not reference external font CDN origin %q (app#96: self-hosted): %s", forbidden, csp)
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

// TestPortalCSP_FrameSrc is the R5 (2026-08-16 /review-5x) regression test:
// it proves (1) an EMPTY ttydSuffix yields "frame-src 'none'" (fail-closed —
// no legitimate iframe exists when the Terminal pane has nothing to point
// at, see ttydURLFor), and (2) a CONFIGURED ttydSuffix yields a frame-src
// that actually allows the Terminal pane's cross-origin iframe origin
// (`https://<user>.<ttydSuffix>` — a wildcard subdomain of ttydSuffix, since
// CSP cannot template in the per-request username). The initial P23-6 cut
// had no frame-src at all, which fell back to default-src 'self' and would
// have CSP-blocked the Terminal tab on every real deploy that sets
// PORTAL_TTYD_SUFFIX; this test pins the fix so it cannot silently regress.
func TestPortalCSP_FrameSrc(t *testing.T) {
	cases := []struct {
		name       string
		ttydSuffix string
		want       string
		wantNone   bool
	}{
		{name: "empty suffix (local / most deploys today) fails closed", ttydSuffix: "", wantNone: true},
		{name: "configured suffix allows the ttyd wildcard origin", ttydSuffix: "ctf-event.dev", want: "frame-src https://*.ctf-event.dev"},
		{name: "colima nip.io-style suffix", ttydSuffix: "10.0.0.5.nip.io", want: "frame-src https://*.10.0.0.5.nip.io"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			csp := portalCSP("nonceX", tc.ttydSuffix)
			if tc.wantNone {
				if !strings.Contains(csp, "frame-src 'none'") {
					t.Errorf("expected frame-src 'none' for empty ttydSuffix; got: %s", csp)
				}
				return
			}
			if !strings.Contains(csp, tc.want) {
				t.Errorf("expected %q in CSP for ttydSuffix=%q; got: %s", tc.want, tc.ttydSuffix, csp)
			}
			// The wildcard must cover ANY participant's own subdomain, not
			// just a specific username — CSP has no per-viewer templating,
			// and per-user isolation is enforced elsewhere (auth-policy's
			// /check, I8), not by this directive. Assert the wildcard form
			// specifically (not e.g. a single hardcoded hostname).
			if !strings.Contains(csp, "https://*."+tc.ttydSuffix) {
				t.Errorf("expected a wildcard subdomain allowance for ttydSuffix=%q; got: %s", tc.ttydSuffix, csp)
			}
		})
	}
}

// TestPortalCSP_NonceIsPerInvocation proves two calls with different nonce
// inputs produce different header values embedding EXACTLY that nonce (not
// a stale/cached one) — a regression here (e.g. a package-level cached CSP
// string) would silently make every response share one nonce, defeating the
// per-response guarantee writeSecurityHeaders/newNonce rely on.
func TestPortalCSP_NonceIsPerInvocation(t *testing.T) {
	a := portalCSP("nonceA", "")
	b := portalCSP("nonceB", "")
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
	nonce, err := writeSecurityHeaders(w, "")
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

// TestWriteSecurityHeaders_ReportingEndpointsMatchesCSPReportTo proves the
// Reporting-Endpoints header (Issue #95) declares the SAME group name
// ("csp-endpoint") the CSP header's "report-to" directive names, and that
// the URL it advertises is cspReportPath — the exact path POST /csp-report
// registers under (view.go's Routes()). A mismatch here would make
// report-to violations vanish silently in a compliant browser (it would
// look for a group name the header never defined, or POST to a path
// nothing serves) with no error visible anywhere in this codebase.
func TestWriteSecurityHeaders_ReportingEndpointsMatchesCSPReportTo(t *testing.T) {
	w := httptest.NewRecorder()
	if _, err := writeSecurityHeaders(w, ""); err != nil {
		t.Fatalf("writeSecurityHeaders: %v", err)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "report-to csp-endpoint") {
		t.Fatalf("CSP header does not name the csp-endpoint report-to group: %s", csp)
	}
	re := w.Header().Get("Reporting-Endpoints")
	want := `csp-endpoint="` + cspReportPath + `"`
	if re != want {
		t.Errorf("Reporting-Endpoints = %q, want %q", re, want)
	}
}

// TestWriteSecurityHeaders_ThreadsTtydSuffixIntoFrameSrc is the
// writeSecurityHeaders-level companion to TestPortalCSP_FrameSrc: proves the
// suffix argument actually reaches the emitted header (not silently dropped
// somewhere between renderPortal and portalCSP).
func TestWriteSecurityHeaders_ThreadsTtydSuffixIntoFrameSrc(t *testing.T) {
	w := httptest.NewRecorder()
	if _, err := writeSecurityHeaders(w, "ctf-event.dev"); err != nil {
		t.Fatalf("writeSecurityHeaders: %v", err)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src https://*.ctf-event.dev") {
		t.Errorf("expected frame-src to allow the ttyd wildcard origin; got: %s", csp)
	}
}

// TestWriteSecurityHeaders_RejectsControlCharInSuffix proves a malformed
// PORTAL_TTYD_SUFFIX (containing CR/LF, which could otherwise attempt a
// header-injection-shaped value) is rejected outright rather than silently
// producing whatever net/http's header writer would do with it — mirrors
// internal/ttydproxy.validateFrameAncestors's same fail-closed posture for
// the analogous operator-supplied CSP value there.
func TestWriteSecurityHeaders_RejectsControlCharInSuffix(t *testing.T) {
	_, err := writeSecurityHeaders(httptest.NewRecorder(), "ctf-event.dev\r\nX-Injected: 1")
	if err == nil {
		t.Fatal("expected an error for a ttydSuffix containing CR/LF, got nil")
	}
}

// TestWriteSecurityHeaders_DistinctNoncePerCall proves consecutive calls
// (modelling consecutive GET /portal requests) never reuse a nonce — this is
// the end-to-end version of TestNewNonce_UniquePerCall, exercised through
// the exact function renderPortal calls per-request.
func TestWriteSecurityHeaders_DistinctNoncePerCall(t *testing.T) {
	n1, err := writeSecurityHeaders(httptest.NewRecorder(), "")
	if err != nil {
		t.Fatalf("writeSecurityHeaders (1st): %v", err)
	}
	n2, err := writeSecurityHeaders(httptest.NewRecorder(), "")
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

// TestRenderPortal_TtydIframeAllowedByCSP is the R5 (2026-08-16 /review-5x)
// end-to-end regression test: with a REAL PORTAL_TTYD_SUFFIX configured
// (the case the initial P23-6 cut's colima smoke test never exercised,
// since local envs default this to "" — see cmd/scoreboard/main.go's
// PORTAL_TTYD_SUFFIX doc), the response's CSP frame-src must actually cover
// the origin the Terminal pane's OWN rendered iframe src uses. Without this
// test, a future edit could re-break frame-src while every OTHER test still
// passes (they all default ttydSuffix to ""), exactly how the original gap
// slipped through.
func TestRenderPortal_TtydIframeAllowedByCSP(t *testing.T) {
	r := httptest.NewRequest("GET", "/portal", nil)
	w := httptest.NewRecorder()
	deriveUser := func(*http.Request) string { return "user1" }
	const suffix = "ctf-event.dev"
	if err := renderPortal(w, r, nil, deriveUser, suffix); err != nil {
		t.Fatalf("renderPortal: %v", err)
	}

	csp := w.Header().Get("Content-Security-Policy")
	frameSrcRe := regexp.MustCompile(`frame-src ([^;]*)`)
	m := frameSrcRe.FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("no frame-src directive in CSP: %s", csp)
	}
	frameSrcValue := m[1]

	// The exact iframe src this same response embeds (ttydURLFor's output —
	// see portalData.TtydURLJSON) must be a URL whose origin the CSP
	// frame-src actually allows. Extract it from the body the same way a
	// browser's own script would read window.__PORTAL_TTYD_URL__.
	body := w.Body.String()
	ttydURLRe := regexp.MustCompile(`window\.__PORTAL_TTYD_URL__ = "([^"]*)"`)
	um := ttydURLRe.FindStringSubmatch(body)
	if um == nil {
		t.Fatalf("could not find window.__PORTAL_TTYD_URL__ in body")
	}
	wantOrigin := "https://user1." + suffix
	if um[1] != wantOrigin {
		t.Fatalf("embedded ttyd URL = %q, want %q", um[1], wantOrigin)
	}

	if frameSrcValue == "'none'" {
		t.Fatalf("frame-src is 'none' even though a real ttyd iframe URL (%q) was embedded — the Terminal tab would be CSP-blocked", wantOrigin)
	}
	if !strings.Contains(frameSrcValue, "https://*."+suffix) {
		t.Errorf("frame-src %q does not allow the embedded iframe's origin %q", frameSrcValue, wantOrigin)
	}
}

// TestIndexHandler_CSPHeaderAndNonceInBody is Issue #114's core regression
// test: GET / (the admin dashboard — the single highest-privilege page in
// this service) used to write templates/index.html verbatim via w.Write
// with NO Content-Security-Policy header at all and NO nonce on its inline
// <script> (line ~284) — writeSecurityHeaders was wired into GET /portal
// only (portal.go's renderPortal), never into Handler.index. This mirrors
// TestRenderPortal_CSPHeaderAndNonceInBody above almost line for line, but
// drives it through Handler.index (the actual production handler) since
// index has no bare renderIndex-style function to call directly the way
// renderPortal is for /portal.
func TestIndexHandler_CSPHeaderAndNonceInBody(t *testing.T) {
	render := func() (int, string, string) {
		h := New(nil, nil, "", slog.New(slog.DiscardHandler))
		r := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		h.index(w, r)
		return w.Code, w.Header().Get("Content-Security-Policy"), w.Body.String()
	}

	code1, csp1, body1 := render()
	if code1 != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", code1, http.StatusOK)
	}
	if csp1 == "" {
		t.Fatal("expected Content-Security-Policy header on GET / response")
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
		t.Fatal("expected at least one <script nonce=\"...\"> tag in the index HTML")
	}
	for _, sm := range matches {
		// html/template HTML-escapes attribute values for browser-safety;
		// decode before comparing against the raw (unescaped) header value,
		// same as TestRenderPortal_CSPHeaderAndNonceInBody does for /portal.
		got := html.UnescapeString(sm[1])
		if got != nonce1 {
			t.Errorf("script tag nonce %q (escaped source %q) does not match CSP header nonce %q", got, sm[1], nonce1)
		}
	}

	// Every <script> tag in the page must carry the nonce attribute — see
	// TestRenderPortal_CSPHeaderAndNonceInBody's identical assertion for why
	// this is checked by count rather than trusting the loop above alone.
	allScriptTagsRe := regexp.MustCompile(`<script\b`)
	allTags := allScriptTagsRe.FindAllString(body1, -1)
	if len(allTags) != len(matches) {
		t.Errorf("found %d <script> tags total but only %d carry nonce=\"...\" — every inline script must be nonced under this CSP", len(allTags), len(matches))
	}

	_, csp2, _ := render()
	m2 := nonceRe.FindStringSubmatch(csp2)
	if m2 == nil {
		t.Fatalf("could not find nonce-source in second CSP header: %s", csp2)
	}
	if m2[1] == nonce1 {
		t.Fatalf("two independent GET / renders reused the same nonce %q", nonce1)
	}
}

// TestIndexHandler_FrameSrcIsAlwaysNone proves GET /'s CSP hardcodes an
// empty ttydSuffix into portalCSP (frame-src 'none') REGARDLESS of what
// PORTAL_TTYD_SUFFIX the Handler was constructed with — unlike /portal, the
// admin dashboard embeds no ttyd iframe (see view.go's Handler.index doc),
// so there is nothing legitimate for frame-src to allow. If a future edit
// accidentally threaded h.ttydSuffix into the index handler's
// writeSecurityHeaders call the way portal() does, this page would gain an
// iframe-embedding allowance it has no use for and never had — this test
// pins the deliberately narrower behavior.
func TestIndexHandler_FrameSrcIsAlwaysNone(t *testing.T) {
	h := New(nil, nil, "ctf-event.dev", slog.New(slog.DiscardHandler))
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.index(w, r)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src 'none'") {
		t.Fatalf("GET / CSP = %q, want frame-src 'none' even though the Handler has a non-empty ttydSuffix", csp)
	}
}

// TestIndexHandler_ForbiddenResponseStillCarriesCSP proves the admin-gate
// 403 branch (Handler.index, when isAdmin(r) is false) still gets the CSP
// header — writeSecurityHeaders now runs before the isAdmin check, so a
// non-admin's 403 page is exactly as hardened as the 200 page. This guards
// against a future refactor that moves the isAdmin check back above
// writeSecurityHeaders (which would silently leave the 403 body
// header-less again — a small page, but no reason for it to regress).
func TestIndexHandler_ForbiddenResponseStillCarriesCSP(t *testing.T) {
	h := New(func(*http.Request) bool { return false }, nil, "", slog.New(slog.DiscardHandler))
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.index(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if csp := w.Header().Get("Content-Security-Policy"); csp == "" {
		t.Fatal("expected Content-Security-Policy header on GET / 403 response too")
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

// TestServeTokensCSS_ContentTypeAndBody mirrors
// TestServeCybercoreCSS_ContentTypeAndNoExternalRefs above, for the
// design-token single source (app#116) — see static/tokens.css's own doc
// for the full "why".
func TestServeTokensCSS_ContentTypeAndBody(t *testing.T) {
	r := httptest.NewRequest("GET", tokensCSSPath, nil)
	w := httptest.NewRecorder()
	serveTokensCSS(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/css") {
		t.Errorf("Content-Type = %q, want text/css prefix", ct)
	}
	body := w.Body.String()
	if body == "" {
		t.Fatal("served tokens.css body is empty")
	}
	if !strings.Contains(body, ":root") {
		t.Error("tokens.css must define a :root block")
	}
}

// TestServeTokensCSS_ConditionalGET mirrors
// TestServeCybercoreCSS_ConditionalGET above — see that test's doc.
func TestServeTokensCSS_ConditionalGET(t *testing.T) {
	w1 := httptest.NewRecorder()
	serveTokensCSS(w1, httptest.NewRequest("GET", tokensCSSPath, nil))
	etag := w1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected an ETag header on the first response")
	}

	r2 := httptest.NewRequest("GET", tokensCSSPath, nil)
	r2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	serveTokensCSS(w2, r2)
	if w2.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304 for a matching If-None-Match", w2.Code)
	}
	if w2.Body.Len() != 0 {
		t.Errorf("304 response must have an empty body, got %d bytes", w2.Body.Len())
	}
}

// stripCommentsForHexScan mirrors scripts/check-template-hex.py's
// strip_comments() exactly (same three passes, same "blank non-newline
// characters so line numbers stay meaningful" trick) — see that script's
// module doc for the full "why": a naive 3-or-6-digit hex regex over the
// RAW template source would false-positive on this file's own
// `app#125`/`Issue #167`-style GitHub issue-number comments (3-digit,
// decimal digits are valid hex digits too), which a pure prefix allowlist
// can't reliably cover (references appear in varied prose: "before #167).",
// "for #124's persistent", not just after a fixed "app#"/"Issue #" prefix).
// Blanking HTML `<!-- -->` and JS/CSS `//`/`/* */` comment bodies before
// matching closes that hole structurally instead.
func stripCommentsForHexScan(src string) string {
	blank := func(s string) string {
		b := []byte(s)
		for i, c := range b {
			if c != '\n' {
				b[i] = ' '
			}
		}
		return string(b)
	}
	htmlComment := regexp.MustCompile(`(?s)<!--.*?-->`)
	blockComment := regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment := regexp.MustCompile(`//[^\n]*`)
	src = htmlComment.ReplaceAllStringFunc(src, blank)
	src = blockComment.ReplaceAllStringFunc(src, blank)
	src = lineComment.ReplaceAllStringFunc(src, blank)
	return src
}

// TestTemplates_NoRawHexColorLiterals is a Go-level echo of
// scripts/check-template-hex.py (app#116, 3-digit extension: review-5x
// follow-up) — see that script's doc for the full rationale. Kept here too
// (not just in the Python script) so `go test` alone — without running the
// script separately — catches a future PR that reintroduces a hand-typed
// hex literal (6-digit #RRGGBB OR 3-digit #RGB shorthand) into either
// template instead of adding a token to static/tokens.css and referencing
// it via var(...).
func TestTemplates_NoRawHexColorLiterals(t *testing.T) {
	// Exactly 3 or 6 hex digits with a trailing word boundary — see
	// check-template-hex.py's HEX_RE doc for why \b at the end (not the
	// start) is what stops a longer hex-like run from partial-matching.
	hexRe := regexp.MustCompile(`#(?:[0-9a-fA-F]{3}){1,2}\b`)
	for _, src := range []struct {
		name string
		body string
	}{
		{"templates/index.html", indexHTML},
		{"templates/portal.html", portalHTMLSrc},
	} {
		scannable := stripCommentsForHexScan(src.body)
		if m := hexRe.FindAllString(scannable, -1); len(m) > 0 {
			t.Errorf("%s contains raw hex color literal(s) %v (outside comments) — reference a token in static/tokens.css via var(...) instead (app#116)", src.name, m)
		}
		if !strings.Contains(src.body, tokensCSSPath) {
			t.Errorf("%s does not link %s — it must consume design tokens via <link> (app#116)", src.name, tokensCSSPath)
		}
	}
}

// TestStripCommentsForHexScan_LeavesRealHexAlone proves the comment
// stripper doesn't accidentally blank real (non-comment) content — a
// stripper with an overly greedy regex could hide a genuine violation from
// TestTemplates_NoRawHexColorLiterals above, silently defeating the gate.
func TestStripCommentsForHexScan_LeavesRealHexAlone(t *testing.T) {
	src := "<style>.x { color: #abc; /* app#125 */ background: #EAF7FA; }</style>\n<!-- app#116 -->\n// Issue #167: prose\nfoo();\n"
	got := stripCommentsForHexScan(src)
	if !strings.Contains(got, "#abc") {
		t.Errorf("real hex #abc was blanked by comment-stripping (too aggressive): %q", got)
	}
	if !strings.Contains(got, "#EAF7FA") {
		t.Errorf("real hex #EAF7FA was blanked by comment-stripping (too aggressive): %q", got)
	}
	if strings.Contains(got, "125") || strings.Contains(got, "116") || strings.Contains(got, "167") {
		t.Errorf("issue-number comment text survived stripping (should be blanked): %q", got)
	}
}
