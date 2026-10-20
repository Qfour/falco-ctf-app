package identityobs

import (
	"log/slog"
	"net/http"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
)

// The Grader's second seat gate is an observation of the same kind as the
// identity gates above: a request the adapter should have refused earlier reached
// a deeper check. It lives here, with the other observation lines, and not in
// httpx (transport helpers the collector links too).

// LogGraderRefused records ONE Warn line when a scoring.Grader entry refused a
// user that is not a seat slug (scoring.ErrInvalidUser, app#479). It is the
// Grader's SECOND gate: the adapter's own seat check runs first and answers the
// request, so reaching this means the adapter lost that check, a defect an
// operator should see (the first gate's refusal is only a typo, and stays an
// Info audit).
//
// It takes NO user: the refused value is not a seat, and a value that failed
// its grammar is not logged (app#459, app#422). The attributes are a closed set:
//
//	entry        one of scoring.Entry*, the Grader method that refused
//	route        r.Pattern, the registered route (not the URL)
//	remote_addr  the peer host without the port (PeerHost)
//
// The caller rate-limits it where the route is not already behind a limiter.
func LogGraderRefused(l *slog.Logger, r *http.Request, entry string) {
	l.Warn("grader refused a non-seat user",
		"entry", entry,
		"route", r.Pattern,
		"remote_addr", httpx.PeerHost(r),
	)
}
