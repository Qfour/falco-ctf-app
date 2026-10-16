// Package httpx provides shared HTTP helpers for scoreboard sub-handlers.
package httpx

import (
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

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
