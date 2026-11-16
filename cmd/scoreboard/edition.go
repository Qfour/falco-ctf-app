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
//     start, with the run id only (D9: the platform compares it with the run id of
//     the digests it paid out with).
//
// Nothing is logged when there is no table and none is needed (no investigate
// challenge in scope, no ANSWERS_FILE): that is every environment that exists
// before an investigate challenge does, and its boot log is unchanged.
//
// The returned Judge is nil when there is no table. It is held by the handler
// (scoreboard.WithEditionJudge) and is not used yet: the Grader takes it in A3a.
func startEdition(logger *slog.Logger, cfg catalogEnv, cat catalog.Catalog) (*edition.Judge, error) {
	judge, runID, err := edition.Load(cat, cfg.answersFile, cfg.flagsFile != "")
	if err != nil {
		logger.Error("edition check failed", "err", err)
		return nil, err
	}
	if judge != nil {
		logger.Info("edition loaded", "run_id", runID)
	}
	return judge, nil
}
