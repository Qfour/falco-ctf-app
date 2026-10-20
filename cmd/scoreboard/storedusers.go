package main

import (
	"log/slog"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// storedUserCheckMsg is the message of BOTH the Info (clean) and the Warn
// (violations) record, so a reader greps one string and reads the
// `solved_violations` / `exfil_violations` attributes; the operator's next step
// is the separate `remedy` attribute. The platform runbook (platform#257) and
// ADR-0039 Signpost 3 read this msg and those two attribute names: change any of
// them only together with the readers. The contract-table row "scoreboard の起動ログ"
// in .claude/rules/falco-ctf-app-conventions.md lists them all; the literal golden is
// bootlog_contract_test.go.
const storedUserCheckMsg = "stored user slug check"

// storedUserRemedy says what each kind of stored row means and what an operator
// can do, before and after the event opens.
const storedUserRemedy = "an exfil receipt under such a user is not turned into a solve (the sweeper skips it); " +
	"a solved row under such a user is already a solve and stays on the leaderboard and in State " +
	"(score, rank, first_solver, recent_solves) until a reset. Before the event: start from a new PVC, or " +
	"POST /api/admin/reset (admin session, allowed Origin) to clear solves and receipts. After the event " +
	"opened: do not reset (it removes every participant's solves); review the scoring by hand."

// warnStoredUsers reports, once at boot, how many stored solves and exfil
// receipts are keyed by a user that is not a username slug (app#439). The slug
// is checked on write only (app#433), so a row saved before that check keeps its
// key. Grader.Sweep skips such a receipt, so it can never become a solve.
//
// It logs COUNTS only: the user value is caller-chosen text, not a seat, so
// neither the value nor a list of them is written to the log.
func warnStoredUsers(logger *slog.Logger, st *store.Store) {
	solved, exfil := scoring.CountNonSlugStoredUsers(st)
	if solved == 0 && exfil == 0 {
		logger.Info(storedUserCheckMsg, "solved_violations", 0, "exfil_violations", 0)
		return
	}
	logger.Warn(storedUserCheckMsg,
		"solved_violations", solved, "exfil_violations", exfil, "remedy", storedUserRemedy)
}
