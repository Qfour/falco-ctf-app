package main

import (
	"log/slog"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// storedUserCheckMsg is the message of BOTH the Info (clean) and the Warn
// (violations) record, as for the stored display name check; a reader greps one
// string and reads the `solved_violations` / `exfil_violations` attributes.
const storedUserCheckMsg = "stored user slug check"

// storedUserRemedy is what an operator can run before the event.
const storedUserRemedy = "these rows are never scored (the sweeper skips a receipt whose user is not a " +
	"username slug); before the event start from a new PVC, or POST /api/admin/reset (admin session, " +
	"allowed Origin) to clear solves and receipts."

// warnStoredUsers reports, once at boot, how many stored solves and exfil
// receipts are keyed by a user that is not a username slug (app#439). The slug
// is checked on write only (app#433), so a row saved before that check keeps its
// key. Grader.Sweep skips such a receipt, so it can never become a solve.
//
// It logs COUNTS only: the user value is caller-chosen text, not a seat, so
// neither the value nor a list of them is written to the log.
func warnStoredUsers(logger *slog.Logger, st *store.Store) {
	var solved, exfil int
	for k := range st.Snapshot().Solved {
		if !scoring.ValidUser(k.User) {
			solved++
		}
	}
	for _, u := range st.ExfilUsers() {
		if !scoring.ValidUser(u) {
			exfil++
		}
	}
	if solved == 0 && exfil == 0 {
		logger.Info(storedUserCheckMsg, "solved_violations", 0, "exfil_violations", 0)
		return
	}
	logger.Warn(storedUserCheckMsg,
		"solved_violations", solved, "exfil_violations", exfil, "remedy", storedUserRemedy)
}
