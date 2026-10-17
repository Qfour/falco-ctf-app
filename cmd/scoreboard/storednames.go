package main

import (
	"log/slog"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// maxLoggedSeats bounds the seat list in the boot warning so one corrupt table
// cannot produce an unbounded log line; the count is always the full count.
const maxLoggedSeats = 50

// warnStoredDisplayNames reports, once at boot, how many stored display names
// no longer pass the CURRENT display-name rule, and for which seats (app#403).
// The rule is checked on write only, so a name saved before the rule tightened
// (app#331 / #381: Unicode Cf, C1 controls) keeps showing on the public board.
//
// It never rewrites a name (the operator decides) and never logs a name's value:
// the value is by definition one the rule refuses, so it can carry bidi or
// zero-width characters that would corrupt the log line or reach a viewer.
// The fix is the existing admin route POST /api/admin/users/{user}/profile-reset.
func warnStoredDisplayNames(logger *slog.Logger, st *store.Store) {
	seats := api.StoredDisplayNameViolations(st.Snapshot().DisplayNames)
	if len(seats) == 0 {
		logger.Info("stored display names checked against the current rule", "violations", 0)
		return
	}
	shown := seats
	if len(shown) > maxLoggedSeats {
		shown = shown[:maxLoggedSeats]
	}
	logger.Warn("stored display names no longer pass the current rule; they are still shown on the board. "+
		"Reset each seat with POST /api/admin/users/{user}/profile-reset (resets display name and avatar to the seat default)",
		"violations", len(seats), "seats", shown, "seats_truncated", len(seats) > len(shown))
}
