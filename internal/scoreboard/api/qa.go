// P25 QA ticket-chat handlers (ADR-0006). Route declarations + gate/rate-
// limit/origin-guard wiring live in api.go's Routes() table alongside every
// other route; this file holds only the handler bodies, following the same
// "one Routes() table per package, handler bodies split across files"
// pattern api.go itself already uses (see stepCheck / openHint / etc.).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/qa"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
)

// maxQuestionSubjectRunes / maxQuestionBodyBytes are ADR-0006 Decision 1's
// input caps.
const (
	maxQuestionSubjectRunes = 120
	maxQuestionBodyBytes    = 4096
)

// maxQuestionRequestBytes bounds the raw HTTP body MaxBytesReader accepts
// before decode — comfortably above maxQuestionBodyBytes plus JSON framing
// and a subject, mirroring submitDetect's "cap + slack" convention
// (detect.MaxConditionBytes+1<<10).
const maxQuestionRequestBytes = maxQuestionBodyBytes + 1<<10

// validQuestionSubject trims and bound-checks a ticket subject (ADR-0006
// Decision 1: <=120 runes after trimming, matching validDisplayName's
// rune-counting convention rather than byte length — subject is
// display text).
func validQuestionSubject(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("subject required")
	}
	if utf8.RuneCountInString(s) > maxQuestionSubjectRunes {
		return "", fmt.Errorf("subject too long (max %d runes)", maxQuestionSubjectRunes)
	}
	return s, nil
}

// validQuestionBody trims and bound-checks a ticket/message body (ADR-0006
// Decision 1: <=4096 BYTES after trimming — unlike subject, the ADR text
// specifies a byte cap here, not a rune cap).
func validQuestionBody(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("body required")
	}
	if len(s) > maxQuestionBodyBytes {
		return "", fmt.Errorf("body too long (max %d bytes)", maxQuestionBodyBytes)
	}
	return s, nil
}

// --- participant: list / create -------------------------------------------

// listQuestions serves GET /api/users/{user}/questions: the caller's own
// ticket summaries, most-recently-active first.
func (h *Handler) listQuestions(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdmin(w, r, user) {
		return
	}
	summaries, err := h.qa.ListForUser(user)
	if err != nil {
		h.logger.Error("qa list", "err", err, "user", user)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list questions"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"questions": summaries})
}

// createQuestion serves POST /api/users/{user}/questions: opens a new P25
// QA ticket. author_role/author are ALWAYS hardcoded to "participant"/user
// server-side via qa.Store.CreateQuestion's fixed parameters — never read
// from the request body (ADR-0006 Decision 1 / security-engineer finding
// 1).
func (h *Handler) createQuestion(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdminWrite(w, r, user) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxQuestionRequestBytes)
	var req oapi.CreateQuestionJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	subject, err := validQuestionSubject(req.Subject)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	body, err := validQuestionBody(req.Body)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	at := h.now().UTC().Format(time.RFC3339Nano)
	th, err := h.qa.CreateQuestion(user, subject, body, at)
	if err != nil {
		h.logger.Error("qa create", "err", err, "user", user)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not create question"})
		return
	}
	h.logger.Info("qa_created", "user", user, "qid", th.ID, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, th)
}

// --- participant: thread / follow-up ---------------------------------------

// getQuestion serves GET /api/users/{user}/questions/{qid}. The composite
// (id,user) ownership check happens inside qa.Store.GetThreadForUser
// (ADR-0006 Decision 2); an unknown id and a cross-user id both produce the
// SAME 404 (no existence oracle for another participant's ticket).
func (h *Handler) getQuestion(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdmin(w, r, user) {
		return
	}
	qid := r.PathValue("qid")
	th, err := h.qa.GetThreadForUser(qid, user)
	if err != nil {
		if errors.Is(err, qa.ErrNotFound) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "question not found"})
			return
		}
		h.logger.Error("qa get", "err", err, "user", user, "qid", qid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not load question"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, th)
}

// postMessage serves POST /api/users/{user}/questions/{qid}/messages: a
// participant follow-up on their OWN thread. The ownership check and the
// insert happen inside ONE qa.Store call (AppendMessageForUser), never a
// separate check-then-write pair (ADR-0006 Decision 2 / security-engineer
// finding 4 — see that method's own doc). author_role/author are ALWAYS
// "participant"/user, never read from the request body.
func (h *Handler) postMessage(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdminWrite(w, r, user) {
		return
	}
	qid := r.PathValue("qid")
	r.Body = http.MaxBytesReader(w, r.Body, maxQuestionRequestBytes)
	var req oapi.PostQuestionMessageJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	body, err := validQuestionBody(req.Body)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	at := h.now().UTC().Format(time.RFC3339Nano)
	th, err := h.qa.AppendMessageForUser(qid, user, body, at)
	if err != nil {
		if errors.Is(err, qa.ErrNotFound) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "question not found"})
			return
		}
		h.logger.Error("qa append", "err", err, "user", user, "qid", qid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not append message"})
		return
	}
	h.logger.Info("qa_message", "user", user, "qid", qid, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, th)
}

// --- operator ---------------------------------------------------------------

// adminListQuestions serves GET /api/admin/questions: every ticket, every
// participant. Admin-only (isAdmin); no {user} in this route.
func (h *Handler) adminListQuestions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.isAdmin(r); !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	summaries, err := h.qa.ListAll()
	if err != nil {
		h.logger.Error("qa admin list", "err", err)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list questions"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"questions": summaries})
}

// adminGetQuestion serves GET /api/admin/questions/{qid}: any ticket, by id
// alone. Admin-only; no {user} path segment and so no composite-key check
// (ADR-0006 Decision 2 — isAdmin alone is the intended gate for this
// route).
func (h *Handler) adminGetQuestion(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.isAdmin(r); !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	qid := r.PathValue("qid")
	th, err := h.qa.GetThread(qid)
	if err != nil {
		if errors.Is(err, qa.ErrNotFound) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "question not found"})
			return
		}
		h.logger.Error("qa admin get", "err", err, "qid", qid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not load question"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, th)
}

// adminReply serves POST /api/admin/questions/{qid}/reply — THE only
// legitimate operator reply path (ADR-0006 Decision 1, security-engineer
// finding 5, LOW). selfOrAdminWrite's admin branch would technically also
// let an admin identity through POST .../questions/{qid}/messages (the
// PARTICIPANT follow-up route above), since that gate is "self OR admin" —
// this codebase does not add a technical block against that misuse (no new
// gate primitive), because doing so is self-detecting anyway: postMessage
// hardcodes author_role="participant" unconditionally, so an admin who
// mistakenly used that route would have their reply recorded as a
// participant message, which never flips a ticket's derived `answered` to
// true. This route is what actually sets author_role="admin" (from THIS
// caller's OWN proven identity, X-Auth-Request-Email — never request-body
// input), which is what "answered" derives from.
func (h *Handler) adminReply(w http.ResponseWriter, r *http.Request) {
	email, ok := h.isAdmin(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	qid := r.PathValue("qid")
	r.Body = http.MaxBytesReader(w, r.Body, maxQuestionRequestBytes)
	var req oapi.AdminReplyQuestionJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	body, err := validQuestionBody(req.Body)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	at := h.now().UTC().Format(time.RFC3339Nano)
	th, err := h.qa.AppendAdminReply(qid, email, body, at)
	if err != nil {
		if errors.Is(err, qa.ErrNotFound) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "question not found"})
			return
		}
		h.logger.Error("qa admin reply", "err", err, "qid", qid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not reply"})
		return
	}
	h.logger.Info("qa_admin_reply", "by", email, "qid", qid, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, th)
}
