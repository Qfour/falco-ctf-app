package api

import (
	"net/http"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
)

// The text fields a flag-shaped value can be refused in (app#456). A closed set of
// fixed words: the only "what was refused" a log line carries.
const (
	flagFieldDisplayName = "display_name"
	flagFieldSubject     = "subject"
	flagFieldBody        = "body"
)

// The writer of a refused text, a closed pair of words. "admin" is a request whose
// identity header is in ADMIN_EMAILS; the address itself is never logged.
const (
	flagActorSelf  = "self"
	flagActorAdmin = "admin"
)

// refuseFlagShape is the one place a board text meets flagShapePattern: if text has
// the shape of a flag it logs the refusal (logFlagShapeRefused), answers 400 with the
// fixed sentence (never the input) and reports true, and the caller returns. Gate and
// log are one call, so a gate site cannot be added without its log line.
func (h *Handler) refuseFlagShape(w http.ResponseWriter, r *http.Request, seat, field, text string) bool {
	if !flagShapePattern.MatchString(text) {
		return false
	}
	h.logFlagShapeRefused(r, seat, field)
	httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgFlagShapeRejected})
	return true
}

// logFlagShapeRefused records ONE Warn line when flagShapePattern refused a
// participant-written text (a board subject / body, a display name), so an operator
// can see afterwards that someone tried to share a flag-shaped value (app#456).
//
// It takes NO text: the signature cannot carry the refused value or any part of it,
// because a real flag must never be copied into the log infrastructure. This is this
// line's design (a log attribute here is a fixed word or a value that already passed
// a closed grammar); the rule for every log line is decided in app#422, not here. The
// five attributes are:
//
//	seat         where the refused text WOULD HAVE BEEN STORED: a seat slug
//	             (identity.ValidSeat) or, for an admin board reply, the fixed author "staff";
//	             never an email. Same direction as ADR-0039 D1's storage target.
//	actor        who wrote it: "self" or "admin" (flagActor*). An operator who renames
//	             a seat, or sets a seat's profile, has seat = that seat and actor = admin.
//	field        one of the flagField* words above
//	route        r.Pattern, the registered route (not the URL, which may hold an id)
//	remote_addr  the peer host without the port (httpx.PeerHost, as identityobs logs it)
//
// What is recorded: a refusal in which the flag-shape check was the DECIDING one. A
// text that an earlier check refused first (too long, a forbidden character, an empty
// body) is a 400 for that reason and writes no line, so the absence of a line is not
// evidence that nobody tried. The order of the checks is not changed for this.
//
// No sampling: every route that reaches it is behind the identity rate limit
// (profile and board writes) or is operator-only (admin rename, admin reply), so a
// seat cannot make this line faster than that limit, and a refusal is rare.
func (h *Handler) logFlagShapeRefused(r *http.Request, seat, field string) {
	h.logger.Warn("flag shape refused",
		"seat", seat,
		"actor", h.flagActor(r),
		"field", field,
		"route", r.Pattern,
		"remote_addr", httpx.PeerHost(r),
	)
}

// flagActor is flagActorAdmin when the request's identity header is an operator's.
func (h *Handler) flagActor(r *http.Request) string {
	if _, ok := h.isAdmin(r); ok {
		return flagActorAdmin
	}
	return flagActorSelf
}
