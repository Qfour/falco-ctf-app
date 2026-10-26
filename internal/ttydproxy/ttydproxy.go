// Package ttydproxy is a tiny reverse proxy that sits in front of ttyd inside
// the same workspace Pod (P23-3, security mitigation ② for the P23 unified
// portal). ttyd is started with --writable (an interactive, arbitrary-command
// shell), so if the portal (P23-4) embeds it in a cross-origin <iframe>, a
// malicious page could iframe the same ttyd URL and trick the participant
// into clicking/typing into a frame they believe is something else
// (clickjacking → attacker-directed shell commands). The mitigation is to
// have ttyd's HTTP responses carry a Content-Security-Policy: frame-ancestors
// directive naming only the portal origin, so browsers refuse to render the
// frame anywhere else.
//
// Why a proxy instead of an ingress annotation/snippet: adding response
// headers via ingress-nginx `configuration-snippet` is blocked by the
// platform's Key Guard tripwire (arbitrary snippet injection is treated as a
// privileged escape hatch and is not something this project accepts without
// CEO sign-off). Doing it at the app layer, in a small Go binary this repo
// already owns, keeps the header-injection point auditable and testable.
//
// Why Go's net/http/httputil.ReverseProxy rather than nginx: ReverseProxy
// already tunnels WebSocket Upgrade requests transparently (Go 1.12+), so
// ttyd's terminal keeps working (the one thing this package adds to an Upgrade
// is the Origin check below), while giving this
// package full control over response headers in plain Go (testable with
// httptest, no separate nginx config to keep in sync with the Dockerfile).
//
// # Header semantics (frame-ancestors vs X-Frame-Options)
//
// Content-Security-Policy: frame-ancestors is the modern, authoritative
// clickjacking control and is the ONLY one of the two that can express
// "allow framing from this one additional origin" — it accepts a list of
// sources. X-Frame-Options (XFO) cannot express that: XFO's only values are
// DENY, SAMEORIGIN, and the obsolete/unsupported-by-modern-browsers
// ALLOW-FROM. There is no way to spell "allow this specific cross-origin
// portal" in XFO. FRAME_ANCESTORS is wired to the real portal origin (the
// platform's deploy-event-workspaces.sh passes it to deploy-user.sh), so
// emitting XFO: SAMEORIGIN or DENY alongside the CSP would be actively wrong
// — browsers that honour XFO (some still do, as a legacy fallback) would
// block the very portal embedding this proxy exists to allow, breaking the
// feature it protects. So this proxy's policy is:
//
//   - frame-ancestors == "'none'" (the fail-safe default, and the value of a
//     deployment that has not wired the portal origin): also emit
//     X-Frame-Options: DENY. Both headers agree ("nobody may frame this"),
//     so there is no legacy-browser gap and no conflict.
//   - frame-ancestors names a real origin (the portal's, P23-4): emit CSP only. XFO is omitted entirely rather than set to SAMEORIGIN/
//     DENY, because either value would contradict the CSP for the one
//     legitimate embedder and there is no XFO spelling that doesn't.
//
// # Fail-safe default
//
// FRAME_ANCESTORS defaults to "'none'" (nobody may frame ttyd at all) —
// mirrors the ALLOWED_ORIGINS fail-closed pattern in
// internal/scoreboard/originguard. A deployment that does not set it keeps the
// restrictive default (direct navigation to the ttyd URL is a top-level load,
// which frame-ancestors does not affect). It is set via
// `deploy-user.sh --frame-ancestors` (ctf-user is not a platform helmfile
// release); the platform's deploy-event-workspaces.sh passes the real portal
// origin through to that same flag, and its grammar is ADR-0044 (below).
//
// # WebSocket Upgrade Origin (ADR-0048)
//
// An Upgrade request is served only when its Origin is exactly "https://" + the
// request's Host (the seat's own origin; the ttyd page inside the portal's iframe
// opens its socket from there). Anything else is 403, and a missing Origin is not
// an exemption: fail-closed. Other requests are untouched. The check sits here,
// next to the CSP, because this proxy is the one consumer in front of ttyd.
// Detail and the Host assumption: docs/adr/0048-*.md; platform#297.
package ttydproxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/dnsname"
)

// noneAncestors is the fail-safe default: no origin (including same-origin)
// may frame the proxied ttyd response.
const noneAncestors = "'none'"

// FrameAncestorsPattern is the ONE definition of the FRAME_ANCESTORS grammar
// (ADR-0044 D2, app#520): exactly one source, either the quoted lower-case keyword
// 'none' or `https://` and one host. The host is dnsname.Body (ADR-0047), the RFC 1123
// grammar of deploy-user.sh's --app-host, so the two are the same set by construction.
// Out: 'self', `*` and `*.`, a scheme alone (`https:`), `http://`, a port, a path, a
// trailing `/`, a query, userinfo, an upper-case letter, more than one source (a space,
// `,` or `;`), any other keyword, nonce or hash, and a bare `none` (a host named none,
// a misconfiguration that reads as safe). The whole value is at most
// FrameAncestorsMaxLen characters; a regex cannot count the whole, so New checks the
// length after the pattern.
//
// charts/ctf-user/deploy-user.sh holds this text as FRAME_ANCESTORS_PATTERN and
// internal/ttydproxy/testdata/frame-ancestors-cases.tsv as its `# pattern: ` header;
// frame_ancestors_grammar_test.go holds the three equal and runs every row. The host
// part has no copy here: internal/dnsname holds it, and dnsname_test.go holds
// deploy-user.sh's DNS_SUFFIX_PATTERN equal to it.
const FrameAncestorsPattern = "^('none'|https://" + dnsname.Body + ")$"

// FrameAncestorsMaxLen is `https://` (8) and the 253 characters of a whole RFC 1123 name.
const FrameAncestorsMaxLen = len("https://") + dnsname.MaxLen

var frameAncestorsRE = regexp.MustCompile(FrameAncestorsPattern)

// Handler reverse-proxies to a local ttyd instance and stamps every response
// with a Content-Security-Policy: frame-ancestors directive (see package
// doc for the exact semantics and the X-Frame-Options interplay).
type Handler struct {
	proxy          *httputil.ReverseProxy
	frameAncestors string
	logger         *slog.Logger
}

// New builds a Handler forwarding to upstream (e.g. http://127.0.0.1:7681,
// the localhost-bound ttyd in the same Pod). frameAncestors is the raw
// CSP source-list value to place after "frame-ancestors " (e.g. "'none'" or
// "https://ctf-event.example.com"); an empty string is normalised to the
// fail-safe "'none'" default rather than emitting an empty/absent directive.
//
// frameAncestors is operator-supplied (env var, ultimately a chart value)
// rather than participant-controlled, but it still ends up concatenated
// directly into an HTTP response header value (and is a CSP source list, so a
// `*` or a second origin widens who may frame a root shell). New therefore
// rejects anything outside FrameAncestorsPattern (ADR-0044 D4) — fail-closed on
// a malformed operator input rather than attempting to sanitise it. This is the
// last check point: it also closes the paths that do not go through
// deploy-user.sh (a values file, a direct helm run). The grammar is the ONLY
// thing that stops a value with a line break: net/http's header writer does not
// refuse CR/LF, it replaces each with a space, so "https://a.example\nhttps://b.example"
// would be sent as two sources, a widened policy rather than an error. Every bad
// value is an explicit startup error instead.
func New(upstream string, frameAncestors string, logger *slog.Logger) (*Handler, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	if frameAncestors == "" {
		frameAncestors = noneAncestors
	}
	if err := validateFrameAncestors(frameAncestors); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	h := &Handler{frameAncestors: frameAncestors, logger: logger}
	h.proxy = httputil.NewSingleHostReverseProxy(u)

	// ModifyResponse runs after the upstream (ttyd) response is received but
	// before it is written to the client — the right place to stamp headers
	// regardless of ttyd's own response (HTML doc, WS upgrade response,
	// static asset, etc). ReverseProxy calls this on every response,
	// including the 101 Switching Protocols for the WebSocket upgrade; CSP
	// on a 101 is harmless (browsers don't apply frame-ancestors to it) and
	// keeping the logic unconditional avoids special-casing status codes.
	h.proxy.ModifyResponse = func(resp *http.Response) error {
		h.stampFrameHeaders(resp.Header)
		return nil
	}

	// Fail closed on upstream errors: a dial failure to ttyd must not leak a
	// Go default 502 body/address to the participant's browser.
	h.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		h.logger.Error("ttyd upstream unreachable", "path", strconv.Quote(r.URL.Path), "err", err)
		h.stampFrameHeaders(w.Header())
		w.WriteHeader(http.StatusBadGateway)
	}

	return h, nil
}

// stampFrameHeaders is the one place the framing headers are written, for a proxied
// response, the 502 and the 403 alike. See package doc "Header semantics": XFO cannot
// express "allow this one cross-origin portal", so it is only added when it agrees
// with a fully-restrictive CSP (nobody may frame this response).
func (h *Handler) stampFrameHeaders(hd http.Header) {
	hd.Set("Content-Security-Policy", "frame-ancestors "+h.frameAncestors)
	if h.frameAncestors == noneAncestors {
		hd.Set("X-Frame-Options", "DENY")
	} else {
		hd.Del("X-Frame-Options")
	}
}

// ServeHTTP forwards every request to ttyd. httputil.ReverseProxy tunnels
// WebSocket Upgrade requests transparently; this method only refuses the ones
// whose Origin is not the seat's own (ADR-0048, fail-closed) before they get there.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isUpgrade(r) && !originIsSeat(r) {
		h.rejectUpgrade(w, r)
		return
	}
	h.proxy.ServeHTTP(w, r)
}

// isUpgrade reports whether httputil.ReverseProxy would tunnel r as a protocol
// upgrade: a `Connection` token "upgrade" (any case, in any of the header lines or in
// a comma list) and a non-empty `Upgrade`. It is deliberately not limited to the
// value "websocket": the proxy tunnels any upgrade type, so a narrower test would
// leave a variant that the proxy still tunnels (ADR-0048 D3).
func isUpgrade(r *http.Request) bool {
	if !headerHasToken(r.Header.Values("Connection"), "upgrade") {
		return false
	}
	for _, v := range r.Header.Values("Upgrade") {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func headerHasToken(values []string, token string) bool {
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// originIsSeat is the whole acceptance set (ADR-0048 D2): exactly one Origin header
// whose value is byte-for-byte "https://" + r.Host. No normalisation (case, default
// port, trailing dot, a path), so no value is accepted that the browser would not
// itself have written. An empty Host never matches (it would equal a bare "https://").
func originIsSeat(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	return r.Host != "" && len(origins) == 1 && origins[0] == "https://"+r.Host
}

// rejectUpgrade answers 403 and logs without the raw Origin (it is a request-supplied
// string): only whether it was present, its length, and a scheme if it has the plain
// lower-case form. The path is %q-escaped, so a control or bidi character in it
// cannot reach a log raw.
func (h *Handler) rejectUpgrade(w http.ResponseWriter, r *http.Request) {
	origins := r.Header.Values("Origin")
	h.logger.Warn("ttyd websocket upgrade rejected: origin is not the seat's own (ADR-0048)",
		"path", strconv.Quote(r.URL.Path), "origin_headers", len(origins), "origin_len", totalLen(origins), "origin_scheme", schemeOf(origins))
	h.stampFrameHeaders(w.Header())
	w.WriteHeader(http.StatusForbidden)
}

func totalLen(vs []string) int {
	n := 0
	for _, v := range vs {
		n += len(v)
	}
	return n
}

// schemeOf returns "http" or "https" when the single Origin starts with that scheme and
// "://", else "other" (or "none" when absent). Nothing else of the value is returned.
func schemeOf(origins []string) string {
	if len(origins) == 0 {
		return "none"
	}
	if len(origins) == 1 {
		for _, s := range []string{"https", "http"} {
			if strings.HasPrefix(origins[0], s+"://") {
				return s
			}
		}
	}
	return "other"
}

// validateFrameAncestors rejects a value outside FrameAncestorsPattern or longer
// than FrameAncestorsMaxLen. The value is %q-escaped in the error, so a control or
// bidi character in it cannot reach a log raw.
func validateFrameAncestors(v string) error {
	if len(v) > FrameAncestorsMaxLen || !frameAncestorsRE.MatchString(v) {
		return fmt.Errorf("ttydproxy: FRAME_ANCESTORS %q is not 'none' or one https://<host> origin (ADR-0044, at most %d characters); refusing to start", v, FrameAncestorsMaxLen)
	}
	return nil
}
