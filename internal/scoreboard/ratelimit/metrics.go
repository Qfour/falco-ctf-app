package ratelimit

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ClientIPSourceTotal counts which header a rate-limit Middleware's ClientIPKeyed
// keyFn used to key a request (ADR-0023 V5), labelled by:
//
//	caller: which route family called ClientIPKeyed. The set of values is not a
//	        contract (each call site names its own; ClientIPKeyed creates that
//	        caller's three source series at 0 when it is assembled, ADR-0040).
//	        POST /falco/events is not a caller: it is keyed by participant, not
//	        client IP (app#359), so it has no IP source.
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
// any binary that links this package. The family has NO series until a binary
// calls ClientIPKeyed (which creates the caller's three source series at 0 when it
// is assembled, ADR-0040 D2); the collector, which deliberately keys its own limiter
// on RemoteAddr (see collector.go's remoteIP doc), never does, so it does not
// expose this family at all.
var ClientIPSourceTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "ratelimit",
		Name:      "client_ip_source_total",
		Help:      "Header a rate-limit Middleware used to key a request, labelled by caller and source. A sustained non-cf_connecting_ip rate on a Cloudflare-fronted caller signals the ADR-0023 CF-Connecting-IP contract has drifted (POST /falco/events no longer emits this series: it is keyed by participant, app#359).",
	},
	[]string{"caller", "source"},
)

// IdentityRequestsTotal counts requests that reached an identity-keyed bucket
// and were let through or limited (Limiter.MiddlewareStrict, app#315), labelled
// by:
//
//	bucket:  which bucket — a fixed set of constants at the call sites
//	         (e.g. "participant_action" for steps/check + hints + reset-dirty,
//	         "detect" for submit-detect).
//	         Distinguishes these from the IP-keyed submit bucket, whose own
//	         counter is ClientIPSourceTotal{caller="submit"}.
//	outcome: "allowed" | "limited" (429)
//
// A request with no usable identity never reaches the bucket: MiddlewareStrict
// answers it 403 without consuming a token, and that refusal is counted in
// scoreboard_identity_denials_total{gate="strict",reason="no_identity"}
// (internal/scoreboard/identityobs), not here (app#404, ADR-0038 D1): one
// refusal, one metric, and "requests that reached the bucket" stays exact.
var IdentityRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "ratelimit",
		Name:      "identity_requests_total",
		Help:      "Requests through an identity-keyed rate-limit bucket, by bucket and outcome (allowed|limited). Requests with no usable identity are refused before the bucket and counted in scoreboard_identity_denials_total{gate=\"strict\"}.",
	},
	[]string{"bucket", "outcome"},
)
