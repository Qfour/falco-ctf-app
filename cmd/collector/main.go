// Command collector is the participant-facing front for CTF workspaces
// (P11.5 full one-pipe). Once ctf-user egress lockdown is on, a workspace can
// reach only the collector — it forwards submit / me / display-name verbatim to
// the scoreboard and rewrites the boss exfil drop to the scoreboard's
// internal-only sink. It holds no CTF state (no catalog, flags, or DB).
// See internal/collector for the HTTP surface.
package main

import (
	"log/slog"
	"os"

	"github.com/Qfour/falco-ctf-app/internal/collector"
	"github.com/Qfour/falco-ctf-app/internal/serverutil"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// SCOREBOARD_URL is the in-cluster base URL of the scoreboard Service.
	// Default matches the ctf-user chart's FALCO_CTF_SCOREBOARD default so
	// local dev works without extra wiring.
	upstream := serverutil.Env("SCOREBOARD_URL", "http://scoreboard.scoreboard.svc:80")
	addr := serverutil.Env("LISTEN_ADDR", ":8000")

	handler, err := collector.New(upstream, logger)
	if err != nil {
		logger.Error("collector init failed", "upstream", upstream, "err", err)
		os.Exit(1)
	}

	err = serverutil.Serve(addr, handler, logger, func() {
		logger.Info("listening", "addr", addr, "upstream", upstream)
	})
	if err != nil {
		logger.Error("listen failed", "err", err)
		os.Exit(1)
	}
}
