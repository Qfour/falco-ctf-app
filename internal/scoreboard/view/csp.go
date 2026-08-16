package view

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
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
// {{.Nonce}}.
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
func portalCSP(nonce string) string {
	return "default-src 'self'; " +
		"script-src 'self' 'nonce-" + nonce + "'; " +
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
		"font-src 'self' https://fonts.gstatic.com; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'"
}

// writeSecurityHeaders stamps the CSP (built from a freshly generated nonce)
// plus a couple of standard, low-risk hardening headers onto w, and returns
// the nonce so the caller can pass it into the template ({{.Nonce}}) for the
// SAME response. Must be called before any write to w (headers cannot follow
// a WriteHeader/Write).
func writeSecurityHeaders(w http.ResponseWriter) (string, error) {
	nonce, err := newNonce()
	if err != nil {
		return "", fmt.Errorf("csp: generate nonce: %w", err)
	}
	w.Header().Set("Content-Security-Policy", portalCSP(nonce))
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
