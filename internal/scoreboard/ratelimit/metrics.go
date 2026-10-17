package ratelimit

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ClientIPSourceTotal counts which header a rate-limit Middleware's ClientIPKeyed
// keyFn used to key a request (ADR-0023 V5), labelled by:
//
//	caller: which route family called ClientIPKeyed — e.g. "submit" |
//	        "display_name" | "questions" | "csp_report"
//	        (see each ClientIPKeyed call site for the exact names in use).
//	        "falco_events" is no longer emitted: POST /falco/events is keyed by
//	        participant, not client IP (app#359), so it has no IP source.
//	source: "cf_connecting_ip" | "x_forwarded_for" | "remote_addr"
//
// Only "cf_connecting_ip" is the trusted, Cloudflare-set value ADR-0023
// prioritizes; the other two source labels mean ClientIPKeyed fell back for
// that request. The caller label distinguishes route families; before
// app#359 "falco_events" (never Cloudflare-routed, ADR-0023 D5, always falling
// back) had to be excluded from the drift query. It is gone, so now ANY
// sustained non-cf_connecting_ip rate on a Cloudflare-fronted caller is the
// ADR-0023 Signpost 2 signal. Plain ClientIP() (no Middleware wiring, e.g. a log line computing
// the same value a Middleware already recorded for this request) does NOT
// touch this counter — see its doc.
//
// This is intentionally package-scoped (not gated to the scoreboard binary)
// since ClientIPKeyed itself is package-scoped — it is safe to import from
// any binary that links this package; it simply stays at zero if that
// binary never calls ClientIPKeyed (e.g. collector, which deliberately keys
// its own limiter on RemoteAddr — see collector.go's remoteIP doc).
var ClientIPSourceTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "ratelimit",
		Name:      "client_ip_source_total",
		Help:      "Header a rate-limit Middleware used to key a request, labelled by caller and source. A sustained non-cf_connecting_ip rate on a Cloudflare-fronted caller signals the ADR-0023 CF-Connecting-IP contract has drifted (POST /falco/events no longer emits this series: it is keyed by participant, app#359).",
	},
	[]string{"caller", "source"},
)

// IdentityRequestsTotal counts requests that went through an identity-keyed
// bucket (Limiter.MiddlewareStrict, app#315), labelled by:
//
//	bucket:  which bucket — a fixed set of constants at the call sites
//	         (e.g. "participant_action" for steps/check + hints + reset-dirty,
//	         "detect" for submit-detect).
//	         Distinguishes these from the IP-keyed submit bucket, whose own
//	         counter is ClientIPSourceTotal{caller="submit"}.
//	outcome: "allowed" | "limited" (429) | "no_identity" (403, no token consumed)
//
// A sustained "no_identity" rate means something reaches an authenticated
// route without the ingress-injected header (a header-less caller that got
// past the origin guard, or an ingress change dropping the header).
var IdentityRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "ratelimit",
		Name:      "identity_requests_total",
		Help:      "Requests through an identity-keyed rate-limit bucket, by bucket and outcome (allowed|limited|no_identity). no_identity requests are denied 403 without consuming a token.",
	},
	[]string{"bucket", "outcome"},
)
