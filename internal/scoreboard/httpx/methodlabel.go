package httpx

import "strings"

// OtherMethod is the one method label value of every request that did not match
// a declared route with a method the route allows.
const OtherMethod = "other"

// MethodLabel is the closed set of a metric's `method` label: the method the
// matched route declares ("POST /api/..." -> "POST"), the method of a HEAD that
// net/http serves from a GET pattern, or OtherMethod. It is the ONE definition
// the collector and the scoreboard share (app#491; a copy in each binary is the
// drift TestMethodLabelHasOneDefinition forbids): a caller picks the method of
// its request freely, and a label built from it is one series per distinct
// value on any surface the request reaches before a route answers it (404 /
// 405 from outside the cluster).
//
// route is the pattern ServeMux.Handler reports, "" when nothing matched. The
// declared method comes from the pattern, not from the request: a request can
// carry any method and still be answered by net/http's redirect for a path it
// cleans (301 for GET / HEAD, 307 for any other method), so the request's own
// value proves nothing. HEAD on a GET route keeps its own value.
//
// A pattern that does not start with a method token is not trusted. For a
// CONNECT request net/http reports the (request-derived) path as the pattern
// when it redirects to a trailing slash, and a path can hold a space
// ("/a b/"); the declared part must therefore be upper-case letters only, which
// no path ("/..." ) is.
//
// The package is standard library only: the collector (a distroless image)
// imports it, and its Dockerfile COPYs this directory by name.
func MethodLabel(route, method string) string {
	declared, _, ok := strings.Cut(route, " ")
	if !ok || !isMethodToken(declared) {
		return OtherMethod
	}
	if method == declared || (declared == "GET" && method == "HEAD") {
		return method
	}
	return OtherMethod
}

// isMethodToken reports whether s is non-empty and made of A-Z only (GET, POST,
// ... as a ServeMux pattern spells them).
func isMethodToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}
