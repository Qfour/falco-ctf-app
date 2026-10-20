// Package httpx provides shared HTTP helpers for scoreboard sub-handlers.
//
// The collector imports this package too (WriteJSON, PeerHost, MethodLabel), so
// it uses the standard library only: the collector is a distroless image whose
// SBOM carries only what runs, and collector/Dockerfile COPYs this directory by
// name. A third-party import here would change that image
// (internal/apispec's TestCollectorThirdPartyImportsArePinned is the tripwire).
package httpx

import (
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"strings"
)

// PeerHost is the request's peer address without the port (r.RemoteAddr is
// "host:port"); a RemoteAddr that has no host:port shape is returned as it is. The
// scoreboard's closed-attribute observation lines (identityobs, the flag-shape
// refusal) log this one form, so a log reader can join them on remote_addr.
func PeerHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// WriteJSON sets Content-Type and encodes body as JSON.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// HasProxyIdentityHeader reports whether the request carries ANY
// X-Auth-Request-* header (present, even with an empty value; matched
// case-insensitively on the key, including a non-canonical map key). The
// ingress (oauth2-proxy / auth-response-headers) stamps these on every
// browser-path request; the cluster-internal callers (collector,
// falcosidekick) never set them. Routes that are internal-only use this to
// refuse the browser path before evaluating anything else.
func HasProxyIdentityHeader(r *http.Request) bool {
	for k := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Auth-Request-") {
			return true
		}
	}
	return false
}

// IsJSONContentType reports whether the Content-Type media type is exactly
// application/json (parameters such as charset are allowed). A cross-site
// no-cors POST can only send text/plain, form-urlencoded or multipart, so
// requiring this closes that vector independently of any header check.
func IsJSONContentType(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}
