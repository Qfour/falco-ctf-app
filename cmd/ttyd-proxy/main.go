// Command ttyd-proxy is a tiny reverse proxy that sits in front of ttyd
// inside the same workspace Pod (P23-3). It listens on the port the Ingress
// reaches (default 7681, matching today's ttyd port so the ctf-user chart's
// Service/Ingress wiring needs no change beyond retargeting ttyd itself to a
// localhost-only port), forwards everything to ttyd on UPSTREAM_ADDR, and
// stamps every response with Content-Security-Policy: frame-ancestors so a
// malicious page cannot iframe ttyd's writable shell (clickjacking). See
// internal/ttydproxy for the header semantics and WebSocket-tunnelling
// details.
package main

import (
	"log/slog"
	"os"

	"github.com/Qfour/falco-ctf-app/internal/serverutil"
	"github.com/Qfour/falco-ctf-app/internal/ttydproxy"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// UPSTREAM_ADDR is ttyd's localhost address in the same Pod. Default
	// matches the ctf-user chart moving ttyd off the Ingress-reachable port
	// (7681) onto a proxy-only loopback port (7682) — see the chart-side
	// wiring contract in .claude/rules/falco-ctf-app-conventions.md.
	upstream := serverutil.Env("UPSTREAM_ADDR", "http://127.0.0.1:7682")
	// LISTEN_ADDR is the port the Ingress/Service reaches. Defaults to
	// ttyd's historical port (7681) so the chart's existing
	// Service.targetPort / containerPort wiring keeps working unchanged.
	addr := serverutil.Env("LISTEN_ADDR", ":7681")
	// FRAME_ANCESTORS is the raw CSP frame-ancestors source list (e.g.
	// "https://ctf-event.example.com"). Fail-safe default "'none'" — see
	// ttydproxy package doc. The platform chart injects the real portal
	// origin once P23-4 (portal iframe embedding) lands.
	frameAncestors := serverutil.Env("FRAME_ANCESTORS", "'none'")

	handler, err := ttydproxy.New(upstream, frameAncestors, logger)
	if err != nil {
		logger.Error("ttyd-proxy init failed", "upstream", upstream, "err", err)
		os.Exit(1)
	}

	err = serverutil.Serve(addr, handler, logger, func() {
		logger.Info("listening", "addr", addr, "upstream", upstream, "frame_ancestors", frameAncestors)
	})
	if err != nil {
		logger.Error("listen failed", "err", err)
		os.Exit(1)
	}
}
