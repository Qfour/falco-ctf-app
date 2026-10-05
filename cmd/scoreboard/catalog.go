package main

import "github.com/Qfour/falco-ctf-app/internal/catalog"

// catalogEnv is the catalog-related configuration read from the environment.
type catalogEnv struct {
	// challengesDir is CHALLENGES_DIR.
	challengesDir string
	// scenarioFile is SCENARIO_FILE: restricts scoring + /api/state to one
	// event composition (e.g. the 2-hour killchain subset). Empty = all
	// challenges.
	scenarioFile string
	// flagsFile is FLAGS_FILE: real per-event flags over the FALCO{dev-...}
	// placeholders baked into the public image. Empty = use placeholders.
	flagsFile string
}

// scoredFromEnv reads the catalog configuration through getenv (key,
// fallback — serverutil.Env in production) and returns the catalog this
// instance scores. It is the single place the scoreboard's catalog is
// built: main() calls it once and uses the result as-is, so the scenario
// restriction and the FLAGS_FILE override cannot be dropped or applied to a
// different catalog value by the wiring in main().
//
// The returned catalogEnv is valid even when err is non-nil (for logging).
func scoredFromEnv(getenv func(key, fallback string) string) (catalogEnv, catalog.Scored, error) {
	cfg := catalogEnv{
		challengesDir: getenv("CHALLENGES_DIR", "/app/challenges"),
		scenarioFile:  getenv("SCENARIO_FILE", ""),
		flagsFile:     getenv("FLAGS_FILE", ""),
	}
	scored, err := catalog.LoadScored(cfg.challengesDir, cfg.scenarioFile, cfg.flagsFile)
	return cfg, scored, err
}
