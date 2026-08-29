package ratelimit

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// clientIPSource counts which header ClientIP used to key a request
// (ADR-0023 V5), labelled by source:
//
//	source: "cf_connecting_ip" | "x_forwarded_for" | "remote_addr"
//
// Only "cf_connecting_ip" is the trusted, Cloudflare-set value ADR-0023
// prioritizes; the other two labels mean ClientIP fell back for that
// request. This is intentionally package-scoped (not gated to the
// scoreboard binary) since ClientIP itself is package-scoped — it is safe
// to import from any binary that links this package; it simply stays at
// zero if that binary never calls ClientIP (e.g. collector, which
// deliberately keys its own limiter on RemoteAddr — see collector.go's
// remoteIP doc).
var clientIPSource = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "ratelimit",
		Name:      "client_ip_source_total",
		Help:      "Header ratelimit.ClientIP used to key a request, labelled by source. A sustained non-cf_connecting_ip rate on a Cloudflare-fronted environment signals the ADR-0023 CF-Connecting-IP contract has drifted.",
	},
	[]string{"source"},
)
