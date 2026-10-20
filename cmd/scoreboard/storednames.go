package main

import (
	"log/slog"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// maxLoggedSeats bounds the seat list in the boot warning so one corrupt table
// cannot produce an unbounded log line; the count is always the full count.
const maxLoggedSeats = 50

// storedNameCheckMsg is the message of BOTH the Info (clean) and the Warn
// (violations) record, so a reader greps one string and reads the `violations`
// attribute; the operator's next step is the separate `remedy` attribute. The
// platform runbook (platform issue #248) reads this msg and `violations`: change
// either only together with it (contract-table row "scoreboard の起動ログ" in
// .claude/rules/falco-ctf-app-conventions.md; literal golden: bootlog_contract_test.go).
const storedNameCheckMsg = "stored display name check"

// storedNameRemedy is what an operator can actually run for a listed seat.
const storedNameRemedy = "fix the name alone from the operator dashboard (admin display-name, the same validator), " +
	"or POST /api/admin/users/{user}/profile-reset (resets display name AND avatar to the seat default; " +
	"needs an admin session and an allowed Origin). `seats` is capped at 50: after fixing those, restart " +
	"the scoreboard to list the rest."

// warnStoredDisplayNames reports, once at boot, how many stored display names
// are no longer what the CURRENT write path would store, and for which seats
// (app#403). The rule is checked on write only, so a name saved before the rule
// tightened (app#331 / #381: Unicode Cf, C1 controls) keeps showing on the public
// board.
//
// It never rewrites a name (the operator decides) and never logs a name's value:
// the value is by definition one the rule refuses, so it can carry bidi or
// zero-width characters that would corrupt the log line or reach a viewer.
//
// Where this sits: a display name is protected in three layers, the write-time
// rule (validDisplayName), the render layer's bidi isolation (nameHTML,
// portal_bidi_test) and this boot-time Warn. Unlike an avatar (avatar.Resolve
// falls back on every read), a name has NO read-time fallback, by choice
// (ADR-0034 residual (4): the operator resets it, so the display never differs
// from the stored value). Turning to a fallback would first need the five
// displayOf closures in internal/scoreboard/api/api.go collapsed into one
// resolver (workspace REFACTORING.md).
func warnStoredDisplayNames(logger *slog.Logger, st *store.Store) {
	seats := api.StoredDisplayNameViolations(st.Snapshot().DisplayNames)
	if len(seats) == 0 {
		logger.Info(storedNameCheckMsg, "violations", 0)
		return
	}
	shown := seats
	if len(shown) > maxLoggedSeats {
		shown = shown[:maxLoggedSeats]
	}
	logger.Warn(storedNameCheckMsg,
		"violations", len(seats), "seats", shown, "seats_truncated", len(seats) > len(shown),
		"remedy", storedNameRemedy)
}
