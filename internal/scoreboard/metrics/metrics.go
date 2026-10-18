// Package metrics defines the Prometheus metrics exposed by scoreboard.
//
// Cardinality discipline:
//   - No per-user labels (CTFs grow, user labels are unbounded).
//   - challenge_id is bounded by `challenges/` directory contents plus the single
//     value "_unknown": an id that is not a catalog key (or is outside the {cid}
//     grammar) is folded into it by the API handlers before it is used as a label.
//   - result/outcome labels are small enumerated sets.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// FalcoEventsReceived counts /falco/events POST receipts.
//
//	outcome: "accepted" | "ignored" | "decode_error" | "store_error" |
//	         "taint_error" | "forbidden" | "unsupported_media_type" |
//	         "rate_limited" | "overflow_tainted" | "overflow_skipped"
//
// forbidden / unsupported_media_type are requests refused before any decode:
// the browser path (an X-Auth-Request-* header) and a non-JSON Content-Type.
//
// rate_limited / overflow_tainted (app#359) are the two per-participant
// rate-limit outcomes: an observation-only event answered 429, and a
// scoring-relevant event that exceeded its participant's bucket and was
// converted into a fail-closed taint (overflow_tainted) or, when the normal
// taint predicate did not apply (current mission is not an evade mission
// forbidding that rule), skipped without a taint (overflow_skipped).
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

// FalcoEventsRateLimited counts POST /falco/events requests answered 429
// because the participant's (ns's) OBSERVATION bucket was empty (app#359).
// Only events that never affect scoring (their rule is in no challenge's
// forbidden/expected rules) are ever dropped; a non-zero value means only that
// presentational feed entries were lost. A preflight/verify that wants "the
// ingest path lost nothing that matters" should require
// FalcoEventsScoringOverflow == 0, not this.
//
//	ns: the participant's namespace (bounded: see ingest.nsLabel; "_other"
//	    past the cap so a forged ns cannot grow the series set)
var FalcoEventsRateLimited = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "scoreboard",
		Subsystem: "ingest",
		Name:      "falco_events_rate_limited_total",
		Help:      "POST /falco/events requests answered 429 (observation-only rule over its per-participant bucket), by participant namespace.",
	},
	[]string{"ns"},
)

// FalcoEventsScoringOverflow counts scoring-relevant events (their rule is in
// some challenge's forbidden or expected rules) that exceeded the
// participant's scoring bucket (app#359). They are never silently dropped: the
// normal taint predicate is applied (current evade mission forbids the rule ->
// taint, fail-closed — "not seen" must not read as "clean", ADR-0003); other
// scoring rules are skipped (overflow_skipped). Non-zero means a participant
// fired scoring rules faster than a human plausibly does; an event-day verify
// should require 0.
//
//	ns: as FalcoEventsRateLimited
var FalcoEventsScoringOverflow = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "scoreboard",
		Subsystem: "ingest",
		Name:      "falco_events_scoring_overflow_total",
		Help:      "Scoring-relevant /falco/events over the per-participant bucket: tainted if the current evade mission forbids the rule (fail-closed), else skipped; never answered 429. By participant namespace.",
	},
	[]string{"ns"},
)

// FalcoEventsSecretMismatch counts POST /falco/events requests whose
// X-Falco-Shared-Secret header failed the ADR-WS-0006 Layer 2 constant-time
// comparison against FALCO_WEBHOOK_SHARED_SECRET. Kept as a SEPARATE metric
// from FalcoEventsReceived rather than a new outcome label on it, to
// preserve that metric's "one outcome label per request" exclusivity
// discipline (see its own doc): an enforce-mode mismatch returns 401 before
// any FalcoEventsReceived outcome branch runs, while a warn-mode mismatch
// continues on to bump one of those branches too — the two metrics are not
// meant to sum to the same total.
//
//	mode: "warn" | "enforce" (only ever incremented in these two modes; off
//	      mode skips the check entirely — see internal/scoreboard/ingest)
var FalcoEventsSecretMismatch = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "scoreboard",
		Subsystem: "ingest",
		Name:      "falco_events_secret_mismatch_total",
		Help:      "POST /falco/events requests with a missing/incorrect X-Falco-Shared-Secret header, labelled by WEBHOOK_SECRET_MODE.",
	},
	[]string{"mode"},
)

// SolvesTotal counts solves recorded (trigger or evade path).
//
//	challenge_id: catalog id, or "_unknown" (never an id that is not a catalog key)
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
//	challenge_id: catalog id, or "_unknown" (never an id that is not a catalog key)
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
