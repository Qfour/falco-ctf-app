package collector

import (
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// validCID matches a challenge id slug (e.g. "10-final-exfil"). Guards the
// value reflected into the upstream /internal/exfil/{cid} path.
var validCID = regexp.MustCompile(`^[0-9]{2}-[a-z0-9-]{1,60}$`)

// forwardDuration observes collector request latency by route/method/status.
// Route label uses the matched ServeMux pattern (bounded cardinality), never
// the raw path — so a flood of distinct paths can't explode the series.
var forwardDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "collector_request_duration_seconds",
	Help:    "Collector request duration by route, method, and status.",
	Buckets: prometheus.DefBuckets,
}, []string{"route", "method", "status"})
