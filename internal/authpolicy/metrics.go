package authpolicy

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// checksTotal counts /check decisions by outcome. Cardinality is bounded
// (~5 enum values), no per-user labels.
//
//	result: "ok" | "unauthenticated" | "forbidden" | "bad_request" | "upstream_error"
var checksTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "auth_policy",
		Name:      "checks_total",
		Help:      "auth-policy /check decisions, labelled by outcome.",
	},
	[]string{"result"},
)

// adminChecksTotal mirrors checksTotal for /check-admin so operators can
// alert on admin-gate failures separately from the per-user gate.
var adminChecksTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "auth_policy",
		Name:      "admin_checks_total",
		Help:      "auth-policy /check-admin decisions, labelled by outcome.",
	},
	[]string{"result"},
)

// upstreamDuration tracks how long the oauth2-proxy subrequest takes.
// Used to spot regressions in the auth hot path.
var upstreamDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Namespace: "auth_policy",
		Name:      "upstream_duration_seconds",
		Help:      "Latency of the oauth2-proxy /oauth2/auth subrequest.",
		Buckets:   prometheus.DefBuckets,
	},
)
