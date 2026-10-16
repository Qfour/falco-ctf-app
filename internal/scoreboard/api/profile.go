package api

// ADR-0034 D8: the participant profile. Two routes, both browser-only:
//
//	POST /api/users/{user}/profile                  (self-or-admin, header REQUIRED)
//	POST /api/admin/users/{user}/profile-reset      (admin)
//
// A profile is a display name plus one avatar id from internal/scoreboard/avatar.
// Nothing else is ever stored or returned here: no email, no real name, no
// image (ADR-0034 conditions 8 and 9; the store's column set is pinned by a
// test). The collector does NOT forward either route.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/avatar"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
)

const (
	errMsgSetProfileFailed   = "could not set profile"
	errMsgResetProfileFailed = "could not reset profile"
	errMsgProfileNoField     = "profile needs display_name and/or avatar"
	errMsgUnknownAvatar      = "unknown avatar"
	errMsgProfileFieldType   = "display_name and avatar must be strings"
)

// errProfileFieldType marks a present key whose value is not a JSON string; the
// handler maps it to its own fixed message (a different 400 text than "the body
// is malformed"). Every other parse failure is just errMsgInvalidBody.
var errProfileFieldType = errors.New("profile field is not a string")

// profileBodyMax bounds the request. A valid body is a ~32-rune name and a
// ~20-byte id inside a two-key object; a name of 32 four-byte runes JSON-escaped
// is still well under this.
const profileBodyMax = 1 << 10

// avatarFor is the avatar id every response carries for `user`: the stored id
// when it is still in the table, else the seat's default (ADR-0034 D9). It
// never returns "" and never an id outside the table.
func (h *Handler) avatarFor(user string) string {
	return avatar.Resolve(h.store.Avatar(user), user)
}

// parseProfileBody reads the strict {display_name?, avatar?} object. It is
// stricter than the other handlers on purpose, because this is the one route
// where a "silently ignored" field would look like a saved setting:
//
//   - exactly one JSON object, nothing after it;
//   - only the two known keys (an unknown key is an error, not ignored);
//   - each present key must be a JSON string (null / number / bool is an error,
//     so `{"avatar": null}` can never mean "clear");
//   - at least one key.
//
// Every returned error is mapped to a fixed message by the caller; the decoder's
// own text never reaches the response (Issue #113).
func parseProfileBody(body io.Reader) (displayName, avatarID *string, err error) {
	dec := json.NewDecoder(body)
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, nil, errors.New("not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("trailing data after the JSON object")
	}
	if raw == nil { // body was the JSON literal null
		return nil, nil, errors.New("not a JSON object")
	}
	for k := range raw {
		if k != "display_name" && k != "avatar" {
			return nil, nil, errors.New("unknown field")
		}
	}
	str := func(key string) (*string, error) {
		rm, ok := raw[key]
		if !ok {
			return nil, nil
		}
		var s string
		if err := json.Unmarshal(rm, &s); err != nil {
			return nil, errProfileFieldType
		}
		return &s, nil
	}
	if displayName, err = str("display_name"); err != nil {
		return nil, nil, err
	}
	if avatarID, err = str("avatar"); err != nil {
		return nil, nil, err
	}
	return displayName, avatarID, nil
}

// setProfile is POST /api/users/{user}/profile.
//
// Authorization is selfOrAdmin (the identity header is REQUIRED; a header-less
// caller is 403; there is no claimed-identity fallback). The route is origin-guarded and rate-limited on the identity bucket
// (actionMW) in Routes(); both run before this handler.
//
// Order is: validate EVERYTHING, then write once. A good display_name next to a
// bad avatar is a 400 and the name is not changed (ADR-0034 V2); the two tables
// are written by one Store.SetProfile transaction so a store failure cannot
// leave only one of them updated either.
func (h *Handler) setProfile(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdmin(w, r, user) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, profileBodyMax)
	rawName, rawAvatar, err := parseProfileBody(r.Body)
	if err != nil {
		h.logger.Warn("set profile: invalid body", "err", err, "user", user, "remote_addr", r.RemoteAddr)
		msg := errMsgInvalidBody
		if errors.Is(err, errProfileFieldType) {
			msg = errMsgProfileFieldType
		}
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}
	if rawName == nil && rawAvatar == nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgProfileNoField})
		return
	}

	var name *string
	if rawName != nil {
		n, err := validDisplayName(*rawName)
		if err != nil {
			// Self-crafted validation message (validDisplayName), not an
			// internal/store error — safe to return verbatim.
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		name = &n
	}
	// Selectable, not Valid: the operator's fixed StaffID is a table id but a
	// participant may not hold it (ADR-0034 D8).
	if rawAvatar != nil && !avatar.Selectable(*rawAvatar) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgUnknownAvatar})
		return
	}

	at := h.now().UTC().Format(time.RFC3339Nano)
	if err := h.store.SetProfile(user, name, rawAvatar, at); err != nil {
		h.logger.Error("set profile", "err", err, "user", user)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgSetProfileFailed})
		return
	}
	h.logger.Info("profile",
		"user", user,
		"display_name_set", name != nil,
		"avatar_set", rawAvatar != nil,
		"remote_addr", r.RemoteAddr,
	)
	httpx.WriteJSON(w, http.StatusOK, h.profileResult(user))
}

// adminResetProfile is POST /api/admin/users/{user}/profile-reset: the display
// name and avatar go back to the seat and the seat's derived avatar, in one
// transaction. Admin-only (isAdmin), origin-guarded in Routes().
func (h *Handler) adminResetProfile(w http.ResponseWriter, r *http.Request) {
	email, ok := h.isAdmin(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if err := h.store.ResetProfile(user); err != nil {
		h.logger.Error("reset profile", "err", err, "user", user)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgResetProfileFailed})
		return
	}
	// "by" is logged (as the other admin audit lines do for reset) but is never
	// part of any response.
	h.logger.Info("admin profile_reset", "user", user, "by", email, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, h.profileResult(user))
}

// profileResult is the post-write value both routes answer with, built through
// the generated oapi.ProfileResult so a spec rename fails to compile here.
func (h *Handler) profileResult(user string) oapi.ProfileResult {
	return oapi.ProfileResult{
		Ok:          true,
		User:        user,
		DisplayName: h.store.DisplayName(user),
		Avatar:      oapi.AvatarId(h.avatarFor(user)),
	}
}
