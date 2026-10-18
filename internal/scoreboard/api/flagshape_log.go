package api

import "net/http"

// The text fields a flag-shaped value can be refused in (app#456). A closed set of
// fixed words: the only "what was refused" a log line carries.
const (
	flagFieldDisplayName = "display_name"
	flagFieldSubject     = "subject"
	flagFieldBody        = "body"
)

// logFlagShapeRefused records ONE Warn line when flagShapePattern refused a
// participant-written text (a board subject / body, a display name), so an operator
// can see afterwards that someone tried to share a flag-shaped value (app#456).
//
// It takes NO text: the signature cannot carry the refused value or any part of it,
// because a real flag must never be copied into the log infrastructure (app#422,
// policy (a): a log field is either a fixed word or a value that already passed a
// closed grammar). The four attributes are:
//
//	seat         a seat slug (validUser) or the fixed staff author, never an email
//	field        one of the flagField* words above
//	route        r.Pattern, the registered route (not the URL, which may hold an id)
//	remote_addr  the peer address, as the neighbouring Warn lines log it
//
// No sampling: every route that reaches it is behind the identity rate limit
// (profile and board writes) or is operator-only (admin rename, admin reply), so a
// seat cannot make this line faster than that limit, and a refusal is rare.
func (h *Handler) logFlagShapeRefused(r *http.Request, seat, field string) {
	h.logger.Warn("flag shape refused",
		"seat", seat,
		"field", field,
		"route", r.Pattern,
		"remote_addr", r.RemoteAddr,
	)
}
