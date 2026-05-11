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
//	outcome: "accepted" | "ignored" | "decode_error" | "store_error"
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
