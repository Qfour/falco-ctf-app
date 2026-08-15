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
// ttyd's terminal keeps working with zero special-casing, while giving this
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
// portal" in XFO. Once P23-4 wires FRAME_ANCESTORS to the real portal origin,
// emitting XFO: SAMEORIGIN or DENY alongside the CSP would be actively wrong
// — browsers that honour XFO (some still do, as a legacy fallback) would
// block the very portal embedding this proxy exists to allow, breaking the
// feature it protects. So this proxy's policy is:
//
//   - frame-ancestors == "'none'" (the fail-safe default, and today's
//     reality since nothing embeds ttyd yet): also emit
//     X-Frame-Options: DENY. Both headers agree ("nobody may frame this"),
//     so there is no legacy-browser gap and no conflict.
//   - frame-ancestors names a real origin (P23-4, once the portal exists):
//     emit CSP only. XFO is omitted entirely rather than set to SAMEORIGIN/
//     DENY, because either value would contradict the CSP for the one
//     legitimate embedder and there is no XFO spelling that doesn't.
//
// # Fail-safe default
//
// FRAME_ANCESTORS defaults to "'none'" (nobody may frame ttyd at all) —
// mirrors the ALLOWED_ORIGINS fail-closed pattern in
// internal/scoreboard/originguard. Before the portal exists, nothing embeds
// ttyd in an iframe, so a restrictive default changes no legitimate
// behaviour (direct navigation to the ttyd URL is a top-level load, which
// frame-ancestors does not affect). Set today via
// `deploy-user.sh --frame-ancestors` (ctf-user is not a platform helmfile
// release); once P23-4 lands, the platform's deploy-event-workspaces.sh is
// expected to pass the real portal origin through to that same flag.
package ttydproxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"unicode"
)

// noneAncestors is the fail-safe default: no origin (including same-origin)
// may frame the proxied ttyd response.
const noneAncestors = "'none'"

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
// directly into an HTTP response header value, so New rejects it outright if
// it contains CR, LF, or any other control character (validateFrameAncestors)
// — fail-closed on a malformed operator input rather than attempting to
// sanitise it. net/http's header writer already refuses to write a header
// value containing CR/LF (it would otherwise enable response-splitting), so
// this check does not change what ever reaches the wire; it turns a
// same-class mistake into an explicit startup error instead of a silent
// per-request net/http failure discovered only once traffic arrives.
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
		resp.Header.Set("Content-Security-Policy", "frame-ancestors "+h.frameAncestors)
		// See package doc "Header semantics": XFO cannot express "allow this
		// one cross-origin portal", so it is only safe to add when it agrees
		// with a fully-restrictive CSP (nobody may frame this response).
		if h.frameAncestors == noneAncestors {
			resp.Header.Set("X-Frame-Options", "DENY")
		} else {
			resp.Header.Del("X-Frame-Options")
		}
		return nil
	}

	// Fail closed on upstream errors: a dial failure to ttyd must not leak a
	// Go default 502 body/address to the participant's browser.
	h.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		h.logger.Error("ttyd upstream unreachable", "path", r.URL.Path, "err", err)
		w.Header().Set("Content-Security-Policy", "frame-ancestors "+h.frameAncestors)
		w.WriteHeader(http.StatusBadGateway)
	}

	return h, nil
}

// ServeHTTP forwards every request to ttyd, including WebSocket Upgrade
// requests used by the terminal session — httputil.ReverseProxy tunnels
// Upgrade transparently, so no special handling is needed here.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.proxy.ServeHTTP(w, r)
}

// validateFrameAncestors rejects a CSP frame-ancestors value containing CR,
// LF, or any other Unicode control character. It is deliberately strict
// (reject-on-any-control-char rather than trying to enumerate "safe"
// control characters) because the only legitimate values are ASCII source
// expressions (`'none'`, `'self'`, `https://host[:port]`) — none of which
// ever need a control character, so any that appear indicate a
// misconfiguration (or a copy-paste/env-injection accident) rather than a
// legitimate value New should try to accommodate.
func validateFrameAncestors(v string) error {
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("ttydproxy: FRAME_ANCESTORS contains a control character (%q); refusing to start", v)
		}
	}
	return nil
}
