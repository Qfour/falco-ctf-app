package view

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"unicode"
)

// newNonce returns a fresh, per-request base64-encoded 128-bit random value
// suitable for a CSP nonce-source (script-src 'nonce-<value>'). 16 bytes of
// crypto/rand is the same size Content-Security-Policy Level 3 examples use
// and is far beyond brute-forceable within a single page load, so a fresh
// value per response is enough to make a nonce useless to anyone who cannot
// already read the response body (an attacker who CAN read the response
// already has the injected content itself, at which point the nonce buys
// nothing extra — the security property nonces provide is "an attacker who
// can only INJECT markup, e.g. via a stored XSS payload, cannot also predict
// the nonce", which holds as long as each response gets its own value).
func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// portalCSP builds the Content-Security-Policy header value for GET
// /portal. nonce must be a freshly generated newNonce() value for this exact
// response (never reused across requests/responses) and must be the SAME
// value stamped onto every inline <script> tag portal.html emits via
// {{.Nonce}}. ttydSuffix is the SAME PORTAL_TTYD_SUFFIX deploy-time value
// renderPortal already threads into ttydURLFor for the Terminal pane's
// iframe src (see portal.go) — it drives frame-src below (fixup R5,
// 2026-08-16 /review-5x: the initial P23-6 cut omitted frame-src, which
// left it falling back to default-src 'self' and CSP-blocking the
// Terminal pane's cross-origin `https://<user>.<ttydSuffix>` iframe on
// every real deploy that sets PORTAL_TTYD_SUFFIX — local/colima's smoke
// test did not catch this because that env defaults to "" there, which
// degrades to no-iframe-at-all rather than exercising the blocked path).
//
// Directive-by-directive rationale (P23-6 design decision, security-lead
// reviewed via /review-5x):
//
//   - script-src 'self' 'nonce-<nonce>': strict-by-default. Only same-origin
//     external scripts (none exist today) or an inline <script> carrying the
//     exact per-response nonce may execute. This is the high-value half of
//     the policy: it makes a reflected/stored HTML-injection bug unable to
//     execute attacker JS, because the attacker cannot know the nonce ahead
//     of time (see newNonce's doc) and 'unsafe-inline' is deliberately NOT
//     also listed (a nonce-source present alongside 'unsafe-inline' would
//     make browsers ignore 'unsafe-inline' per the CSP spec anyway, but we
//     don't rely on that — it's simply absent).
//   - style-src 'self' 'unsafe-inline' https://fonts.googleapis.com:
//     DELIBERATELY NOT nonce-restricted, unlike script-src. portal.html uses
//     ~34 static inline style="..." attributes plus another ~20 CLIENT-SIDE
//     JS-GENERATED style="..." attributes (template literals computing
//     e.g. `style="width:${pct}%"` for progress bars / score bars / table
//     column widths — see templates/portal.html's render() functions for
//     the journey/me/scoreboard panes). A CSP nonce can be stamped onto a
//     <style> ELEMENT or a <link>, but the spec has no mechanism to
//     nonce-authorize an inline style ATTRIBUTE — style-src's nonce-source
//     only covers <style> tags, not style="" attributes on arbitrary
//     elements (this is a real CSP Level 3 limitation, not an
//     implementation gap here). Refactoring every dynamic inline style
//     (particularly the ones computed from live poll data: percentages,
//     hex colors already driven by CSS variables) into toggled utility
//     classes would be a substantial, high-risk rewrite of the client-side
//     rendering logic across 3 panes for a control whose payoff is low:
//     style injection cannot execute script on its own (no history of CSS
//     used to exfiltrate credentials or run code in modern browsers absent
//     an additional bug), and every value that flows into these
//     style="width:${pct}%" expressions is either a server-computed number
//     (score/progress percentages, gated the same as the rest of the API)
//     or passed through esc()/numeric coercion before use — there is no
//     known injection path INTO these attributes from an untrusted
//     request today. Given that, 'unsafe-inline' on style-src is the
//     pragmatic tradeoff: it keeps the existing rendering code unchanged
//     (no scope creep beyond P23-6's stated cybercore + CSP task) while
//     script-src — the directive that actually stops code execution —
//     stays strict. https://fonts.googleapis.com is additionally allowed
//     because portal.html's <link href="https://fonts.googleapis.com/css2?...">
//     (pre-existing, unrelated to this task) fetches a stylesheet from
//     that origin; leaving it off would break the page's fonts.
//   - font-src 'self' https://fonts.gstatic.com: the Google Fonts
//     stylesheet above in turn references font files hosted on
//     fonts.gstatic.com — 'self' alone would 404 in-browser for all
//     @font-face src loads and silently fall back to system fonts.
//   - img-src 'self' data:: the vendored cybercore.min.css's icon/noise
//     glyphs are inline `url("data:image/svg+xml,...")` (see
//     vendor/cybercore/PROVENANCE.md's external-reference audit) — no
//     other image source is used anywhere in the portal.
//   - object-src 'none': no <object>/<embed>/<applet> anywhere in this
//     page; disabling them outright removes a legacy plugin-based XSS
//     vector for free.
//   - base-uri 'self': prevents an injected <base> tag from rewriting
//     every relative URL on the page (script src, fetch(), form action) to
//     an attacker-controlled origin — cheap, no legitimate use of <base>
//     exists here.
//   - frame-src (R5 fixup): the DIRECTIVE THIS PAGE NEEDS for its OWN
//     <iframe>, as opposed to frame-ancestors below (who may frame US) —
//     the two are opposite directions and easy to conflate. The Terminal
//     pane embeds `<iframe src="https://<derived-username>.<ttydSuffix>">`
//     (see portal.go's ttydURLFor / templates/portal.html), a CROSS-ORIGIN
//     subdomain of the SAME ttydSuffix wired in at deploy time. Without an
//     explicit frame-src, CSP falls back to default-src 'self', which
//     blocks that cross-origin iframe outright — every real deploy that
//     sets PORTAL_TTYD_SUFFIX would 100% CSP-block the Terminal tab. When
//     ttydSuffix is non-empty, this allows `https://*.<ttydSuffix>` — the
//     wildcard covers every participant's own subdomain (not just the
//     current caller's), which is intentionally broader than "this one
//     user's host" because CSP has no per-request/per-viewer templating
//     mechanism and per-user isolation is NOT this directive's job anyway:
//     the iframe SRC itself is always server-generated from the caller's
//     OWN derived identity (never client-supplied — see ttydURLFor's
//     security doc), and even a manually-edited src pointed at a
//     DIFFERENT user's subdomain still independently 403s at
//     auth-policy's per-host `/check` (I8) — CSP frame-src here is only
//     ever a "may this ORIGIN be framed at all by this page" allowlist,
//     not an authorization boundary (matches TtydURLJSON's own doc: "this
//     field only ever narrows a caller to their OWN workspace"). When
//     ttydSuffix is empty (local/most non-P19 deploys today — see
//     cmd/scoreboard/main.go's PORTAL_TTYD_SUFFIX doc), ttydURLFor already
//     yields "" and the Terminal pane renders its fail-safe placeholder
//     instead of an iframe, so frame-src 'none' costs nothing (there is no
//     legitimate frame to allow) and is fail-closed if a future bug ever
//     tried to frame something anyway.
//   - frame-ancestors is DELIBERATELY OMITTED here — that directive is
//     owned by internal/ttydproxy (P23-3), one layer down (protecting the
//     ttyd iframe target FROM being framed), not by the page that DOES the
//     framing. Setting frame-ancestors on the portal's own response would
//     control who may frame the PORTAL, an orthogonal concern P23-6 was
//     not asked to change and that has no operator-supplied value wired in
//     yet (see cmd/scoreboard/main.go — no PORTAL_FRAME_ANCESTORS-equivalent
//     env exists). Do not conflate the two: ttyd-proxy's CSP protects ttyd
//     from being framed by anything other than the portal; this CSP
//     protects the portal's OWN script/style/resource loading.
//   - report-uri + report-to (Issue #95 / P23-6 follow-up — observability,
//     not enforcement; adding these cannot make the policy MORE permissive,
//     only makes an existing violation visible): P12's egress-zero posture
//     rules out an external report collector, so both directives point at
//     a same-origin sink this binary now serves itself
//     (cspReportPath/cspReport, csp_report.go) rather than a third-party
//     endpoint. Both are wired, deliberately, because current browser
//     support is split and neither alone covers everyone: report-uri is
//     formally deprecated but still the ONLY mechanism Safari implements
//     for CSP reporting and is universally understood by every browser
//     that has ever shipped CSP reporting; report-to (routed via the
//     Reporting-Endpoints header below, see writeSecurityHeaders) is the
//     current/future mechanism and the ONLY one of the two Chrome's own
//     docs describe as being actively maintained, but Firefox has never
//     wired report-to INTO CSP violation reporting specifically (it
//     supports the Reporting API for some other report types) — a
//     Firefox/Safari-heavy participant population would go dark under
//     report-to alone. SIGNPOST (re-visit trigger, R4 /review-5x): if
//     Firefox ever DOES wire report-to into CSP violation reporting, that
//     removes the reason report-uri is still carried here — reconsider
//     dropping the legacy report-uri directive (and legacyCSPReport's
//     application/csp-report decode path in csp_report.go) at that point,
//     rather than carrying both indefinitely once a single mechanism
//     covers every browser this project cares about. A browser that
//     understands report-to uses it and
//     ignores report-uri for the SAME violation (no double-reporting in
//     practice); a browser that only understands report-uri still gets a
//     report. Both directives name the same cspReportPath, and
//     internal/scoreboard/view/csp_report.go's handler accepts EITHER wire
//     format the two mechanisms produce (application/csp-report vs.
//     application/reports+json) at that one route.
func portalCSP(nonce, ttydSuffix string) string {
	frameSrc := "frame-src 'none'"
	if ttydSuffix != "" {
		frameSrc = "frame-src https://*." + ttydSuffix
	}
	return "default-src 'self'; " +
		"script-src 'self' 'nonce-" + nonce + "'; " +
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
		"font-src 'self' https://fonts.gstatic.com; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		frameSrc + "; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"report-uri " + cspReportPath + "; " +
		"report-to csp-endpoint"
}

// validateTtydSuffix rejects a PORTAL_TTYD_SUFFIX value containing CR, LF,
// or any other control character before it is concatenated into the CSP
// header (mirrors internal/ttydproxy.validateFrameAncestors's rationale:
// this is an operator-supplied deploy-time value, not participant input,
// but it still ends up directly inside an HTTP header value, so a
// misconfiguration must fail loudly at first-use rather than silently
// producing a malformed header net/http would otherwise just refuse to
// write). Called from writeSecurityHeaders on every request rather than
// once at startup because view.Handler has no explicit "boot" hook to wire
// a one-time check into today — the cost of re-checking a short, static
// string per-request is negligible.
func validateTtydSuffix(v string) error {
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("csp: PORTAL_TTYD_SUFFIX contains a control character (%q); refusing to render", v)
		}
	}
	return nil
}

// writeSecurityHeaders stamps the CSP (built from a freshly generated nonce
// and the deploy-time ttydSuffix — see portalCSP's frame-src doc for why
// the Terminal pane's cross-origin iframe needs this) plus a couple of
// standard, low-risk hardening headers onto w, and returns the nonce so the
// caller can pass it into the template ({{.Nonce}}) for the SAME response.
// Must be called before any write to w (headers cannot follow a
// WriteHeader/Write). ttydSuffix is the SAME PORTAL_TTYD_SUFFIX value
// renderPortal already has in hand for ttydURLFor — pass it straight
// through rather than re-deriving anything.
func writeSecurityHeaders(w http.ResponseWriter, ttydSuffix string) (string, error) {
	if err := validateTtydSuffix(ttydSuffix); err != nil {
		return "", err
	}
	nonce, err := newNonce()
	if err != nil {
		return "", fmt.Errorf("csp: generate nonce: %w", err)
	}
	w.Header().Set("Content-Security-Policy", portalCSP(nonce, ttydSuffix))
	// Reporting-Endpoints (Issue #95) declares the "csp-endpoint" group
	// portalCSP's "report-to csp-endpoint" directive names, pointing it at
	// this SAME response's own origin + cspReportPath — a relative URL is
	// valid here per the Reporting spec (resolved against the response
	// URL), so this never needs to know its own scheme/host. See
	// portalCSP's doc for why both this header and the older report-uri
	// directive are wired simultaneously.
	w.Header().Set("Reporting-Endpoints", `csp-endpoint="`+cspReportPath+`"`)
	// X-Content-Type-Options: nosniff — stops a browser from MIME-sniffing a
	// response into an executable context (e.g. treating a JSON error body
	// returned with the wrong Content-Type as HTML/script). Cheap,
	// universally safe, no known legitimate reliance on sniffing here.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Referrer-Policy: strict-origin-when-cross-origin — do not leak the full
	// portal path (which may embed nothing sensitive today, but could in a
	// future edit) to a cross-origin resource (e.g. the Google Fonts
	// stylesheet request above); same-origin requests still get the full
	// referrer.
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	return nonce, nil
}
