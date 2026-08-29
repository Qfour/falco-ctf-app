package ratelimit

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ClientIPSourceTotal counts which header a rate-limit Middleware's ClientIPKeyed
// keyFn used to key a request (ADR-0023 V5), labelled by:
//
//	caller: which route family called ClientIPKeyed — e.g. "submit" |
//	        "display_name" | "questions" | "falco_events" | "csp_report"
//	        (see each ClientIPKeyed call site for the exact names in use).
//	source: "cf_connecting_ip" | "x_forwarded_for" | "remote_addr"
//
// Only "cf_connecting_ip" is the trusted, Cloudflare-set value ADR-0023
// prioritizes; the other two source labels mean ClientIPKeyed fell back for
// that request. The caller label exists specifically so "falco_events" (the
// one caller ADR-0023 D5 documents as NEVER going through Cloudflare, hence
// always falling back) can be excluded from the query that watches for
// contract drift — a sustained non-cf_connecting_ip rate on any OTHER,
// Cloudflare-fronted caller is the ADR-0023 Signpost 2 signal; the same rate
// on falco_events is expected baseline noise, not a signal (ADR-0023 review
// R5-F1). Plain ClientIP() (no Middleware wiring, e.g. a log line computing
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
		Help:      "Header a rate-limit Middleware used to key a request, labelled by caller and source. Filter out caller=\"falco_events\" (never Cloudflare-routed, ADR-0023 D5) before watching for a sustained non-cf_connecting_ip rate — that combination on any other, Cloudflare-fronted caller signals the ADR-0023 CF-Connecting-IP contract has drifted.",
	},
	[]string{"caller", "source"},
)
