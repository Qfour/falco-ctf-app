package main

import (
	"log/slog"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// startEdition is the start-up step of ADR-0056 (D8, D9, D16, D19 A2b): it calls
// edition.Load, the one door to the answers table, with the catalog this instance
// scores, ANSWERS_FILE, and the event mode ("FLAGS_FILE is not empty", the same
// signal that makes the flags mandatory, ADR-0033 D9 (a)).
//
// It writes the two records the platform's scripts/verify.sh reads (contract-table
// row "scoreboard の起動ログ", items (4) and (5); bootlog_contract_test.go pins the
// text):
//   - a refusal: `msg="edition check failed"`, level ERROR, once, with the error.
//     The error names a rule, a line and a seat / cid / qid, never a table value
//     (edition.Load's doc). The caller exits right after it (main: os.Exit(1)).
//   - a table that was accepted: `msg="edition loaded"`, level INFO, once per
//     start, with the run id only (D9: the platform will compare it with the run id
//     of the digests it paid out with; that is P1b, not implemented yet).
//
// Nothing is logged when there is no table and none is needed (no investigate
// challenge in scope, no ANSWERS_FILE): that is every environment that exists
// before an investigate challenge does, and its boot log is unchanged.
//
// The returned Judge is nil when there is no table. It is held by the handler
// (scoreboard.WithEditionJudge), which passes it to the Grader (A3a); the answer
// route (A3b-1) is the one caller of the Grader's SubmitAnswer. With no table (the
// practice mode, until A4a-2 makes its Judge) the Grader has no Judge and
// SubmitAnswer answers ErrAnswersUnavailable (a 500, nothing spent).
//
// cfg.challengesDir is CHALLENGES_DIR, the directory the catalog was read from:
// edition.Load reads the practice answers of every challenge under it for T6
// (ADR-0056 A4a-1), so an event table that repeats a published practice answer is
// refused here, at start-up.
func startEdition(logger *slog.Logger, cfg catalogEnv, cat catalog.Catalog) (*edition.Judge, error) {
	judge, runID, err := edition.Load(cat, cfg.challengesDir, cfg.answersFile, cfg.flagsFile != "")
	if err != nil {
		logger.Error("edition check failed", "err", err)
		return nil, err
	}
	if judge != nil {
		logger.Info("edition loaded", "run_id", runID)
	}
	return judge, nil
}
