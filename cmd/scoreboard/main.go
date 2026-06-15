// Command scoreboard ingests falcosidekick webhooks, attributes events to
// CTF users via the `ctf-<username>` namespace convention, and serves a
// live dashboard. See internal/scoreboard for the HTTP surface and
// internal/store for persistence guarantees.
package main

import (
	"log/slog"
	"os"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/serverutil"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	challengesDir := serverutil.Env("CHALLENGES_DIR", "/app/challenges")
	dbPath := serverutil.Env("SCOREBOARD_DB", "/var/lib/scoreboard/scoreboard.db")
	addr := serverutil.Env("LISTEN_ADDR", ":8000")
	// FLAGS_FILE injects real per-event flags over the FALCO{dev-...}
	// placeholders baked into the public image. Empty = use placeholders.
	flagsFile := serverutil.Env("FLAGS_FILE", "")
	// SCENARIO_FILE restricts scoring + /api/state to one event composition
	// (e.g. the 2-hour killchain subset). Empty = all challenges.
	scenarioFile := serverutil.Env("SCENARIO_FILE", "")
	// ADMIN_EMAILS gates POST /api/admin/reset (verified against the
	// auth-policy-propagated X-Auth-Request-Email). Empty = nobody.
	adminEmails := serverutil.SplitCSV(serverutil.Env("ADMIN_EMAILS", ""))

	cat, err := catalog.Load(challengesDir)
	if err != nil {
		logger.Error("catalog load failed", "dir", challengesDir, "err", err)
		os.Exit(1)
	}
	if err := cat.ApplyFlagOverrides(flagsFile); err != nil {
		logger.Error("flag overrides failed", "file", flagsFile, "err", err)
		os.Exit(1)
	}
	scenarioID := ""
	if scenarioFile != "" {
		sc, err := catalog.LoadScenario(scenarioFile)
		if err != nil {
			logger.Error("scenario load failed", "file", scenarioFile, "err", err)
			os.Exit(1)
		}
		if cat, err = cat.Restrict(sc.Challenges); err != nil {
			logger.Error("scenario restrict failed", "scenario", sc.ID, "err", err)
			os.Exit(1)
		}
		scenarioID = sc.ID
	}
	logger.Info("catalog loaded", "dir", challengesDir, "challenges", cat.IDs(), "flag_overrides", flagsFile != "", "scenario", scenarioID)

	st, err := store.Open(dbPath)
	if err != nil {
		logger.Error("store open failed", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()
	logger.Info("store opened", "path", dbPath, "solved_loaded", st.SolvedCount())

	handler := scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithDBPath(dbPath),
		scoreboard.WithAdminEmails(adminEmails),
	)

	err = serverutil.Serve(addr, handler, logger, func() {
		logger.Info("listening", "addr", addr)
	})
	if err != nil {
		logger.Error("listen failed", "err", err)
		os.Exit(1)
	}
}
