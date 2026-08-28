// Package metrics defines the Prometheus metrics exposed by scoreboard.
//
// Cardinality discipline:
//   - No per-user labels (CTFs grow, user labels are unbounded).
//   - challenge_id is bounded by `challenges/` directory contents.
//   - result/outcome labels are small enumerated sets.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// FalcoEventsReceived counts /falco/events POST receipts.
//
//	outcome: "accepted" | "ignored" | "decode_error" | "store_error" |
//	         "taint_error"
//
// taint_error (ADR-0003 A5) is distinct from store_error: it fires when the
// event was otherwise accepted but the persistent evade-dirty taint write
// (scoring.Grader.OnRuleFire's TaintErr) failed. The in-memory taint is still
// set (store.MarkDirty is fail-closed), but this metric being non-zero during
// an event means the on-disk record may be missing — see the ingest handler
// and scoring package doc for the residual risk if the pod restarts before a
// later successful write.
var FalcoEventsReceived = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "scoreboard",
		Subsystem: "ingest",
		Name:      "falco_events_received_total",
		Help:      "Falco webhook events received, labelled by ingest outcome.",
	},
	[]string{"outcome"},
)

// SolvesTotal counts solves recorded (trigger or evade path).
//
//	challenge_id: catalog id
//	kind:         "trigger" | "evade"
var SolvesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "scoreboard",
		Name:      "solves_total",
		Help:      "Solves recorded since process start.",
	},
	[]string{"challenge_id", "kind"},
)

// SubmissionsTotal counts evade-challenge flag submissions.
//
//	outcome: "solved" | "wrong_flag" | "not_evaded" | "unknown_challenge" |
//	         "not_evade" | "bad_request"
var SubmissionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "scoreboard",
		Subsystem: "api",
		Name:      "submissions_total",
		Help:      "Flag submission attempts on evade challenges.",
	},
	[]string{"challenge_id", "outcome"},
)

// CSPViolationReports counts POST /csp-report intake (Issue #95 / P23-6
// follow-up), labelled by outcome. Reports are UNAUTHENTICATED and their
// content is attacker-forgeable (any client can POST here, not just a real
// browser reacting to a real CSP violation) — this counter and the
// accompanying log line (internal/scoreboard/view/csp_report.go) are the
// full extent of what this endpoint does with a report: it is never
// persisted to the store, so a flood of forged reports cannot touch
// scoring-integrity tables.
//
//	outcome: "accepted" | "bad_content_type" | "too_large" | "decode_error"
var CSPViolationReports = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "scoreboard",
		Subsystem: "csp",
		Name:      "violation_reports_total",
		Help:      "CSP violation reports received via POST /csp-report, labelled by outcome.",
	},
	[]string{"outcome"},
)

// HTTPRequestDuration measures handler latency per route.
//
//	route:  Go 1.22 ServeMux pattern (e.g. "POST /falco/events")
//	method: HTTP method
//	status: response status code as string
var HTTPRequestDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: "scoreboard",
		Name:      "http_request_duration_seconds",
		Help:      "HTTP request latency by route, method, and status.",
		Buckets:   prometheus.DefBuckets,
	},
	[]string{"route", "method", "status"},
)
