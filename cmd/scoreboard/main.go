// Command scoreboard ingests falcosidekick webhooks, attributes events to
// CTF users via the `ctf-<username>` namespace convention, and serves a
// live dashboard. See internal/scoreboard for the HTTP surface and
// internal/store for persistence guarantees.
package main

import (
	"context"
	"log/slog"
	"os"
	"sync"

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
	// ADMIN_EMAILS is the operator allowlist verified against the
	// auth-policy-propagated X-Auth-Request-Email. It gates the admin writes
	// (POST /api/admin/*), the full-event views (GET /api/state and the operator
	// index GET /), and is the self-or-admin exception on the participant
	// self-scope read gate (P18: GET /api/users/{user}/{me,journey} — an admin
	// may read any user, a participant only their own). Empty = nobody
	// (fail-closed everywhere).
	adminEmails := serverutil.SplitCSV(serverutil.Env("ADMIN_EMAILS", ""))
	// DOCS_BASE_URL is the origin of the participant docs site (a separate host,
	// e.g. https://docs.<suffix>). When set, the /journey API rewrites each
	// mission's relative docsUrl (/missions/<NN>-<slug>/) into an absolute URL so
	// the link resolves off-origin. Empty = keep the relative path (local dev,
	// where docs are served under the same host or not at all).
	docsBaseURL := serverutil.Env("DOCS_BASE_URL", "")

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
	// order is the mission sequence the Journey UI walks. When a scenario is
	// pinned we honour its explicit challenge order (Restrict returns a map,
	// which loses ordering); otherwise fall back to the catalog's sorted ids
	// (NN- prefixes sort into 01..10 sequence).
	var order []string
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
		order = sc.Challenges
	} else {
		order = cat.IDs()
	}
	// Journey UI content (title/tagline/briefing/steps/hints/docsUrl). Optional
	// per challenge; a missing journey.yaml just yields no briefing for that
	// mission and the UI degrades gracefully ("ブリーフィング準備中").
	journeys, err := catalog.LoadJourneys(challengesDir, cat)
	if err != nil {
		logger.Error("journey load failed", "dir", challengesDir, "err", err)
		os.Exit(1)
	}
	logger.Info("catalog loaded", "dir", challengesDir, "challenges", cat.IDs(), "journeys", len(journeys), "docs_base_url", docsBaseURL, "flag_overrides", flagsFile != "", "scenario", scenarioID)

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
		scoreboard.WithJourneys(journeys),
		scoreboard.WithOrder(order),
		scoreboard.WithDocsBaseURL(docsBaseURL),
	)

	// Auto-solve sweeper (P16): re-derives exfil-delivered-but-unsolved evade
	// pairs from the store every tick and auto-solves any whose clean window is
	// met, so participants need not manually submit. Runs in its own goroutine
	// bound to sweepCtx; cancelled after Serve returns (SIGINT/SIGTERM) so the
	// ticker stops and the goroutine exits before we close the store.
	sweepCtx, cancelSweep := context.WithCancel(context.Background())
	var sweepWG sync.WaitGroup
	sweepWG.Add(1)
	go func() {
		defer sweepWG.Done()
		handler.Sweeper().Run(sweepCtx)
	}()

	err = serverutil.Serve(addr, handler, logger, func() {
		logger.Info("listening", "addr", addr)
	})
	// Serve has returned (shutdown or listen error): stop the sweeper and wait
	// for its goroutine before the deferred st.Close() runs, so no sweep is
	// mid-MarkSolved against a closing DB.
	cancelSweep()
	sweepWG.Wait()
	if err != nil {
		logger.Error("listen failed", "err", err)
		os.Exit(1)
	}
}
