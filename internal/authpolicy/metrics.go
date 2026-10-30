package authpolicy

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// checksTotal counts /check-workspace and /check-participant decisions by
// endpoint and outcome. Cardinality is bounded (2 x ~6 enum values), no
// per-user labels. Alerts that sum over it without `by (endpoint)` keep working.
//
//	endpoint: "workspace" | "participant"
//	result:   "ok" | "ok_admin" | "admin_refused" | "unauthenticated" | "forbidden" | "bad_request" | "upstream_error"
//
// "ok_admin" is /check-participant only; "admin_refused" is /check-workspace
// only (ADR-0050: an ADMIN_EMAILS identity on a seat's host is refused).
var checksTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "auth_policy",
		Name:      "checks_total",
		Help:      "auth-policy /check-workspace and /check-participant decisions, labelled by endpoint and outcome.",
	},
	[]string{"endpoint", "result"},
)

// adminChecksTotal mirrors checksTotal for /check-admin so operators can
// alert on admin-gate failures separately from the roster gates.
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
