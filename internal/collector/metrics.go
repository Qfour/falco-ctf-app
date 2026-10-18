package collector

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// forwardDuration observes collector request latency by route/method/status.
// Route label uses the matched ServeMux pattern (bounded cardinality), never
// the raw path — so a flood of distinct paths can't explode the series.
var forwardDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "collector_request_duration_seconds",
	Help:    "Collector request duration by route, method, and status.",
	Buckets: prometheus.DefBuckets,
}, []string{"route", "method", "status"})
