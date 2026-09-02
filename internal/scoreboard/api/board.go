// QA Board HTTP handlers (app#292 Phase 2 — the destination-model,
// public-or-private thread board that replaces P25's per-user QA ticket
// chat wholesale). Route declarations + gate/rate-limit/origin-guard wiring
// live in api.go's Routes() table alongside every other route; this file
// holds only the handler bodies, following the same "one Routes() table per
// package, handler bodies split across files" pattern api.go itself already
// uses (see stepCheck / openHint / etc., and P25's own qa.go before it).
//
// Issue #194 / #113's discipline (same as P25's qa.go before it): the
// json.NewDecoder(r.Body).Decode(&req) calls below must never put a raw
// decode err.Error() into the response body — reuse api.go's
// errMsgInvalidBody constant and log the real err via h.logger next to the
// WriteJSON call. The validBoardSubject/validBoardBody validation errors are
// the SAME exception api.go's validDisplayName is: self-crafted messages
// that name no internal struct field, driver, or schema, so they are
// returned verbatim on purpose.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
)

// boardStaffAuthor is the FIXED author value every operator reply writes
// (internal/board.Store.AppendAdminReply's adminAuthor parameter) —
// deliberately NOT the caller's raw X-Auth-Request-Email, unlike P25's
// adminReply before it. app#292's design does not put a real operator email
// on a wire a participant reads back; the real identity is still logged
// server-side (h.logger.Info("board_admin_reply", "by", email, ...)) for
// traceability, just never serialized into the response body.
const boardStaffAuthor = "staff"

// maxBoardSubjectRunes / maxBoardBodyBytes mirror P25's ADR-0006 Decision
// 1 caps exactly (unchanged by app#292 — no reason to relitigate input
// sizing alongside a visibility-model change).
const (
	maxBoardSubjectRunes = 120
	maxBoardBodyBytes    = 4096
)

// maxBoardRequestBytes bounds the raw HTTP body MaxBytesReader accepts
// before decode — comfortably above maxBoardBodyBytes plus JSON framing and
// a subject, mirroring submitDetect's "cap + slack" convention.
const maxBoardRequestBytes = maxBoardBodyBytes + 1<<10

// validBoardSubject trims and bound-checks a thread subject (<=120 runes
// after trimming, matching validDisplayName's rune-counting convention —
// subject is display text).
func validBoardSubject(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("subject required")
	}
	if utf8.RuneCountInString(s) > maxBoardSubjectRunes {
		return "", fmt.Errorf("subject too long (max %d runes)", maxBoardSubjectRunes)
	}
	return s, nil
}

// validBoardBody trims and bound-checks a thread/message/reply body (<=4096
// BYTES after trimming — a byte cap, not a rune cap, matching P25's
// validQuestionBody).
func validBoardBody(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("body required")
	}
	if len(s) > maxBoardBodyBytes {
		return "", fmt.Errorf("body too long (max %d bytes)", maxBoardBodyBytes)
	}
	return s, nil
}

// --- participant: list / create ---------------------------------------------

// boardListThreads serves GET /api/board/threads: every audience='all'
// thread PLUS the caller's own audience='admin' threads.
func (h *Handler) boardListThreads(w http.ResponseWriter, r *http.Request) {
	viewer, ok := h.boardIdentity(w, r)
	if !ok {
		return
	}
	summaries, err := h.board.ListThreads(viewer, false)
	if err != nil {
		h.logger.Error("board list", "err", err, "viewer", viewer)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardListFailed})
		return
	}
	resp, err := toOapiBoardList(summaries)
	if err != nil {
		h.logger.Error("board list convert", "err", err, "viewer", viewer)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardListFailed})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// boardCreateThread serves POST /api/board/threads: opens a new thread.
// author/author_role are ALWAYS hardcoded to the caller's own derived
// username / RoleParticipant server-side via board.Store.CreateThread's
// fixed parameters — never read from the request body (same discipline P25's
// createQuestion enforced, security-engineer finding 1).
func (h *Handler) boardCreateThread(w http.ResponseWriter, r *http.Request) {
	author, ok := h.boardIdentity(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBoardRequestBytes)
	var req oapi.BoardCreateThreadJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("board create: invalid body", "err", err, "author", author, "remote_addr", r.RemoteAddr)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}

	// Fail-closed audience coercion (spec's CreateThreadRequest.Audience
	// doc): anything other than the LITERAL string "all" becomes "admin" —
	// a malformed, absent, or unexpected value never accidentally becomes
	// public. This coercion happens BEFORE board.Store.CreateThread is ever
	// called, so that method's own ErrInvalidAudience guard (which rejects
	// anything outside {admin,all}) can never actually fire from this route.
	audience := board.AudienceAdmin
	if strings.TrimSpace(req.Audience) == string(board.AudienceAll) {
		audience = board.AudienceAll
	}

	subject, err := validBoardSubject(req.Subject)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	body, err := validBoardBody(req.Body)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if flagShapePattern.MatchString(body) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgFlagShapeRejected})
		return
	}

	at := h.now().UTC().Format(time.RFC3339Nano)
	tid, err := h.board.CreateThread(author, audience, subject, body, at)
	if err != nil {
		h.logger.Error("board create", "err", err, "author", author)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardCreateFailed})
		return
	}
	// author is always entitled to read their own brand-new thread
	// regardless of audience (visibleToParticipant: audience=all is public,
	// audience=admin+author==viewer is the private-own case) — isAdmin=false
	// here is a real, non-bypassing read, not a shortcut.
	th, err := h.board.GetThread(author, false, tid)
	if err != nil {
		h.logger.Error("board create reload", "err", err, "author", author, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardCreateFailed})
		return
	}
	resp, err := toOapiBoardThread(th)
	if err != nil {
		h.logger.Error("board create convert", "err", err, "author", author, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardCreateFailed})
		return
	}
	h.logger.Info("board_thread_created", "author", author, "tid", tid, "audience", string(audience), "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// --- participant: thread / follow-up ----------------------------------------

// boardGetThread serves GET /api/board/threads/{tid}. The
// audience/ownership/moderation-state entitlement check happens inside
// board.Store.GetThread (isAdmin=false); an unknown id, a wrong-audience
// id, and a moderated-away id all produce the SAME 404 (no existence
// oracle).
func (h *Handler) boardGetThread(w http.ResponseWriter, r *http.Request) {
	viewer, ok := h.boardIdentity(w, r)
	if !ok {
		return
	}
	tid := r.PathValue("tid")
	th, err := h.board.GetThread(viewer, false, tid)
	if err != nil {
		if errors.Is(err, board.ErrNotFound) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgBoardThreadNotFound})
			return
		}
		h.logger.Error("board get", "err", err, "viewer", viewer, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardGetFailed})
		return
	}
	resp, err := toOapiBoardThread(th)
	if err != nil {
		h.logger.Error("board get convert", "err", err, "viewer", viewer, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardGetFailed})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// boardAppendMessage serves POST /api/board/threads/{tid}/messages: a
// participant follow-up on their OWN thread. board.Store.AppendOwnMessage
// performs the ownership check and the insert inside ONE call, under one
// lock hold (never a separate check-then-write pair) — another
// participant's {tid} 404s exactly like an unknown one. author/author_role
// are ALWAYS the caller's own derived username / RoleParticipant, never read
// from the request body.
func (h *Handler) boardAppendMessage(w http.ResponseWriter, r *http.Request) {
	author, ok := h.boardIdentity(w, r)
	if !ok {
		return
	}
	tid := r.PathValue("tid")
	r.Body = http.MaxBytesReader(w, r.Body, maxBoardRequestBytes)
	var req oapi.BoardAppendMessageJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("board append: invalid body", "err", err, "author", author, "tid", tid, "remote_addr", r.RemoteAddr)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}
	body, err := validBoardBody(req.Body)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if flagShapePattern.MatchString(body) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgFlagShapeRejected})
		return
	}
	at := h.now().UTC().Format(time.RFC3339Nano)
	th, err := h.board.AppendOwnMessage(author, tid, body, at)
	if err != nil {
		if errors.Is(err, board.ErrNotFound) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgBoardThreadNotFound})
			return
		}
		h.logger.Error("board append", "err", err, "author", author, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardAppendFailed})
		return
	}
	resp, err := toOapiBoardThread(th)
	if err != nil {
		h.logger.Error("board append convert", "err", err, "author", author, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardAppendFailed})
		return
	}
	h.logger.Info("board_message", "author", author, "tid", tid, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// --- participant: like / unlike ---------------------------------------------

// boardLike serves POST /api/board/threads/{tid}/like. board.Store.Like
// enforces audience=all + state=visible fail-closed (ErrNotFound — no
// existence/audience oracle) and rejects a self-like (ErrSelfLike, 409 —
// distinct from 404 because a self-like thread IS one the caller can see,
// it is just a disallowed action on it) before the insert.
func (h *Handler) boardLike(w http.ResponseWriter, r *http.Request) {
	user, ok := h.boardIdentity(w, r)
	if !ok {
		return
	}
	tid := r.PathValue("tid")
	at := h.now().UTC().Format(time.RFC3339Nano)
	if err := h.board.Like(user, tid, at); err != nil {
		switch {
		case errors.Is(err, board.ErrNotFound):
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgBoardThreadNotFound})
		case errors.Is(err, board.ErrSelfLike):
			httpx.WriteJSON(w, http.StatusConflict, map[string]any{"error": errMsgBoardSelfLike})
		default:
			h.logger.Error("board like", "err", err, "user", user, "tid", tid)
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardLikeFailed})
		}
		return
	}
	count, liked, _ := h.boardLikeStatus(tid, user)
	h.logger.Info("board_like", "user", user, "tid", tid, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, toOapiLikeResult(tid, count, liked))
}

// boardUnlike serves POST /api/board/threads/{tid}/unlike.
// board.Store.Unlike is an unconditional, idempotent delete — a no-op for a
// thread the caller never liked, or one that was never likeable at all
// (there is nothing to leak by allowing it unconditionally, unlike Like's
// insert path — see that method's own doc).
func (h *Handler) boardUnlike(w http.ResponseWriter, r *http.Request) {
	user, ok := h.boardIdentity(w, r)
	if !ok {
		return
	}
	tid := r.PathValue("tid")
	if err := h.board.Unlike(user, tid); err != nil {
		h.logger.Error("board unlike", "err", err, "user", user, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardUnlikeFailed})
		return
	}
	count, liked, _ := h.boardLikeStatus(tid, user)
	h.logger.Info("board_unlike", "user", user, "tid", tid, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, toOapiLikeResult(tid, count, liked))
}

// boardLikeStatus fetches tid's current like count and whether user has
// liked it, for the like/unlike routes' own response. This is NOT a new
// visibility grant: it is only ever called immediately after user's OWN
// Like/Unlike call on tid — a thread the caller either just successfully
// liked (guaranteeing it exists and is audience=all) or attempted to unlike
// (defined to succeed even for an unknown or never-likeable tid).
// isAdmin=true bypasses GetThread's entitlement check so an Unlike on a
// genuinely unknown tid still gets a clean liked=false/like_count=0
// response instead of erroring — board threads are never hard-deleted (only
// soft-moderated), so this can only ever miss for a tid that never existed.
func (h *Handler) boardLikeStatus(tid, user string) (count int, liked bool, ok bool) {
	th, err := h.board.GetThread(user, true, tid)
	if err != nil {
		return 0, false, false
	}
	return th.LikeCount, th.Liked, true
}

// --- operator ----------------------------------------------------------------

// boardAdminListThreads serves GET /api/admin/board/threads: every thread,
// every audience, every moderation state (isAdmin=true) — the operator
// moderation queue. Admin-only (isAdmin); no {user} in this route.
func (h *Handler) boardAdminListThreads(w http.ResponseWriter, r *http.Request) {
	adminEmail, ok := h.isAdmin(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	summaries, err := h.board.ListThreads(adminEmail, true)
	if err != nil {
		h.logger.Error("board admin list", "err", err)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardListFailed})
		return
	}
	sortBoardSummaries(summaries, r.URL.Query().Get("sort"))
	resp, err := toOapiBoardList(summaries)
	if err != nil {
		h.logger.Error("board admin list convert", "err", err)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardListFailed})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// sortBoardSummaries applies the operator moderation UI's optional
// `?sort=likes|recent` display hint. board.Store.ListThreads already
// returns pinned-first then most-recently-active order (the "recent" case,
// and the default for any unrecognised value — fail-soft, never an error
// for a bad query param on a display-only sort hint); "likes" re-sorts by
// LikeCount descending, most-liked first, stably (ties keep the store's own
// pinned/recency order).
func sortBoardSummaries(list []board.ThreadSummary, sortParam string) {
	if sortParam != "likes" {
		return
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].LikeCount > list[j].LikeCount })
}

// boardAdminGetThread serves GET /api/admin/board/threads/{tid}: the
// operator's single-thread FULL-TEXT read — the admin counterpart to
// boardGetThread. isAdmin=true bypasses board.Store.GetThread's audience/
// ownership entitlement check entirely, so hidden AND deleted threads are
// both visible here (same posture as boardAdminListThreads' moderation
// queue). A deleted MESSAGE's body is still scrubbed to "" by the Store
// itself regardless of viewer (board.go's own doc: deleting is a content
// removal, not a from-participants-only hide) — admin sees that the
// message existed and was deleted, never its content. Returns the SAME
// BoardThread shape boardGetThread does (toOapiBoardThread reused
// verbatim, #164 discipline).
//
// Deliberately does NOT exist under /api/board/ — see api.go's Routes()
// comment on this entry and boardGetThread's own doc: the participant
// route carries no isAdmin bypass by design, so this is the ONLY route
// through which an admin can read one thread's full messages directly
// (as opposed to via a side effect of boardAdminReply/
// boardAdminSetThreadState).
func (h *Handler) boardAdminGetThread(w http.ResponseWriter, r *http.Request) {
	adminEmail, ok := h.isAdmin(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	tid := r.PathValue("tid")
	th, err := h.board.GetThread(adminEmail, true, tid)
	if err != nil {
		if errors.Is(err, board.ErrNotFound) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgBoardThreadNotFound})
			return
		}
		h.logger.Error("board admin get", "err", err, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardGetFailed})
		return
	}
	resp, err := toOapiBoardThread(th)
	if err != nil {
		h.logger.Error("board admin get convert", "err", err, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardGetFailed})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// boardAdminReply serves POST /api/admin/board/threads/{tid}/reply — THE
// only legitimate operator reply path (mirrors P25's adminReply /
// ADR-0006 Decision 1 / security-engineer finding 5 reasoning exactly: an
// admin identity technically CAN reach boardAppendMessage too since that
// route's authz=authenticated has no admin-exclusion, but that route
// hardcodes author_role=participant unconditionally, so a reply posted
// through it would never contribute to `answered` — self-detecting, same as
// before). author is ALWAYS the fixed boardStaffAuthor constant (never the
// caller's raw email — see that constant's own doc for why), author_role is
// ALWAYS admin.
func (h *Handler) boardAdminReply(w http.ResponseWriter, r *http.Request) {
	email, ok := h.isAdmin(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	tid := r.PathValue("tid")
	r.Body = http.MaxBytesReader(w, r.Body, maxBoardRequestBytes)
	var req oapi.BoardAdminReplyJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("board admin reply: invalid body", "err", err, "tid", tid, "remote_addr", r.RemoteAddr)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}
	body, err := validBoardBody(req.Body)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if flagShapePattern.MatchString(body) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgFlagShapeRejected})
		return
	}
	at := h.now().UTC().Format(time.RFC3339Nano)
	th, err := h.board.AppendAdminReply(boardStaffAuthor, tid, body, at)
	if err != nil {
		if errors.Is(err, board.ErrNotFound) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgBoardThreadNotFound})
			return
		}
		h.logger.Error("board admin reply", "err", err, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardReplyFailed})
		return
	}
	resp, err := toOapiBoardThread(th)
	if err != nil {
		h.logger.Error("board admin reply convert", "err", err, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardReplyFailed})
		return
	}
	// The REAL operator identity is logged here, server-side only — it is
	// never serialized into the response body (boardStaffAuthor is the only
	// value that ever reaches the wire as `author`).
	h.logger.Info("board_admin_reply", "by", email, "tid", tid, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// boardAdminSetThreadState serves POST
// /api/admin/board/threads/{tid}/state: any combination of
// pinned/answered/state, applied in one board.Store.SetThreadState call.
func (h *Handler) boardAdminSetThreadState(w http.ResponseWriter, r *http.Request) {
	adminEmail, ok := h.isAdmin(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	tid := r.PathValue("tid")
	r.Body = http.MaxBytesReader(w, r.Body, maxBoardRequestBytes)
	var req oapi.BoardAdminSetThreadStateJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("board admin thread-state: invalid body", "err", err, "tid", tid, "remote_addr", r.RemoteAddr)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}
	upd := board.ThreadStateUpdate{Pinned: req.Pinned, Answered: req.Answered}
	if req.State != nil {
		st := board.State(*req.State)
		upd.State = &st
	}
	if err := h.board.SetThreadState(tid, upd); err != nil {
		switch {
		case errors.Is(err, board.ErrInvalidState):
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgBoardInvalidState})
		case errors.Is(err, board.ErrNotFound):
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgBoardThreadNotFound})
		default:
			h.logger.Error("board admin thread-state", "err", err, "tid", tid)
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardStateFailed})
		}
		return
	}
	th, err := h.board.GetThread(adminEmail, true, tid)
	if err != nil {
		h.logger.Error("board admin thread-state reload", "err", err, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardStateFailed})
		return
	}
	resp, err := toOapiBoardThread(th)
	if err != nil {
		h.logger.Error("board admin thread-state convert", "err", err, "tid", tid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardStateFailed})
		return
	}
	h.logger.Info("board_admin_thread_state", "by", adminEmail, "tid", tid, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// boardAdminSetMessageState serves POST
// /api/admin/board/messages/{mid}/state: moderates ONE message by id
// without touching the rest of its thread.
func (h *Handler) boardAdminSetMessageState(w http.ResponseWriter, r *http.Request) {
	adminEmail, ok := h.isAdmin(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	mid := r.PathValue("mid")
	r.Body = http.MaxBytesReader(w, r.Body, maxBoardRequestBytes)
	var req oapi.BoardAdminSetMessageStateJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("board admin message-state: invalid body", "err", err, "mid", mid, "remote_addr", r.RemoteAddr)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}
	state := board.State(req.State)
	if err := h.board.SetMessageState(mid, state); err != nil {
		switch {
		case errors.Is(err, board.ErrInvalidState):
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgBoardInvalidState})
		case errors.Is(err, board.ErrNotFound):
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgBoardMsgNotFound})
		default:
			h.logger.Error("board admin message-state", "err", err, "mid", mid)
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgBoardStateFailed})
		}
		return
	}
	h.logger.Info("board_admin_message_state", "by", adminEmail, "mid", mid, "state", string(state), "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, toOapiMessageStateResult(mid, state))
}
