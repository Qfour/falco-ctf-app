package collector

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// forwardDuration observes collector request latency by route/method/status.
// Route label uses the matched ServeMux pattern (bounded cardinality), never
// the raw path — so a flood of distinct paths can't explode the series. The
// method label is just as bounded (methodLabel): the declared method of the
// matched route, or "other", never the raw r.Method, which a workspace chooses
// freely and which the default-deny 404/405 surface would otherwise turn into
// one series per distinct value (app#485).
var forwardDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "collector_request_duration_seconds",
	Help:    "Collector request duration by route, method, and status.",
	Buckets: prometheus.DefBuckets,
}, []string{"route", "method", "status"})

// otherMethod is the one method label value of every request that did not
// match a declared route with a method the route allows.
const otherMethod = "other"

// methodLabel is the closed set of the method label: the method the matched
// route declares ("POST /api/..." -> "POST"), or otherMethod. route is the
// pattern ServeMux.Handler reports, "" when nothing matched (404 and 405). The
// declared method comes from the pattern, not from the request: a request can
// carry any method and still be answered by net/http's redirect for a path it
// cleans (301 for GET / HEAD, 307 for any other method), so the request's own
// value proves nothing. HEAD on a GET route keeps its own value
// (net/http serves it from the GET pattern), as before this fold.
func methodLabel(route, method string) string {
	declared, _, ok := strings.Cut(route, " ")
	if !ok || declared == "" {
		return otherMethod
	}
	if method == declared || (declared == "GET" && method == "HEAD") {
		return method
	}
	return otherMethod
}
