package api

// ADR-0056 D4 / D5 / D6 / D13: the participant's answer to one question of an
// investigate challenge.
//
//	POST /api/users/{user}/challenges/{cid}/questions/{qid}/answer
//
// This file is an adapter. The comparison, the attempt budget and the solve are the
// Grader's (scoring.Grader.SubmitAnswer, the one door; internal/edition's Judge is
// reached from nowhere else). The adapter checks who is asking (Authz: self), reads
// a strictly shaped body, hands the text to the Grader once, and turns its typed
// error into a status. It never reads, compares, stores or logs the answer text,
// and no response or log line carries the input, a length, an expected value, or
// anything the Grader returned beyond the four fields of AnswerResult (D6, D13).

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
)

const (
	// answerMaxRunes is AnswerRequest.answer's maxLength. A JSON Schema maxLength
	// counts characters, so the check counts runes.
	answerMaxRunes = 256
	// answerBodyMax bounds the bytes read: 256 characters, every one a JSON \u
	// escape pair (12 bytes) is 3 KiB, plus the object. A larger body is a
	// malformed request, not something to parse.
	answerBodyMax = 4 << 10

	// Fixed 4xx / 5xx texts. None of them is built from the request, so no answer,
	// qid or cid is echoed (D13); a 404 for a cid or qid that is unknown, or outside
	// its grammar, is one body.
	errMsgNotInvestigate  = "not an investigate challenge"
	errMsgUnknownQuestion = "unknown question"
	errMsgAnswerFormat    = "answer does not fit the question's format"
	errMsgAnswerFailed    = "could not grade the answer"
)

// selfOnly is the gate of Authz: self (ADR-0056 D4, the word of ADR-0050): the
// proven X-Auth-Request-Email must be exactly {user}'s canonical identity,
// `<user>@<EXPECTED_EMAIL_DOMAIN>` (I8). Unlike selfOrAdmin there is NO ADMIN_EMAILS
// override: an operator who answers in a participant's name would spend that
// participant's attempts and could solve the challenge for them, so an admin
// identity is a 403 here whoever {user} is. A missing or blank header, an empty
// EXPECTED_EMAIL_DOMAIN, and any other identity are 403 as well (fail-closed).
//
// The refusals are counted at the same observation point as selfOrAdmin's
// (scoreboard_identity_denials_total{gate="self_or_admin"}): that metric's series
// set is a cross-repo contract (platform's alert reads it), so the self gate does
// not add a gate label value of its own. The reason is judged here, the observer
// only records it, and neither the caller's email nor {user} is logged.
func (h *Handler) selfOnly(w http.ResponseWriter, r *http.Request, user string) bool {
	email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")))
	if email == "" {
		h.denials.Record(r, identityobs.GateSelfOrAdmin, identityobs.ReasonNoIdentity)
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return false
	}
	if emailMatchesUser(email, user, h.emailDomain) {
		return true
	}
	reason := identityobs.ReasonMismatch
	if UsernameFromEmail(email, h.emailDomain) == "" {
		reason = identityobs.ReasonNonCanonical
	}
	h.denials.Record(r, identityobs.GateSelfOrAdmin, reason)
	httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
	return false
}

// selfFront runs selfOnly BEFORE the rate limiter, so a wrong identity is a 403
// that spends no token (D4: the identity gate comes before the bucket, as
// selfOrAdmin's header check does through MiddlewareStrict; here the equality
// check is early too, so a participant cannot drain another seat's bucket by
// naming it in the path with their own identity: the bucket is keyed by the
// caller's identity, and that identity has to be {user}'s first).
//
// A request with NO identity header is passed on on purpose: the strict limiter
// behind it refuses it (403, no token, counted at gate=strict like every other
// identity-keyed route), and submitAnswer runs selfOnly in full again, so the
// route never answers a header-less request with anything but 403 even if the
// limiter were removed from the wiring.
func (h *Handler) selfFront(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")) != "" && !h.selfOnly(w, r, r.PathValue("user")) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// decodeAnswerBody reads the strict AnswerRequest: exactly one JSON object, only
// the key `answer`, nothing after it. The decoder's own error text (it can name
// struct fields) is never used: every failure is the one invalid-body answer.
func decodeAnswerBody(body io.Reader) (oapi.AnswerRequest, bool) {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	var req oapi.AnswerRequest
	if err := dec.Decode(&req); err != nil {
		return oapi.AnswerRequest{}, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return oapi.AnswerRequest{}, false
	}
	return req, true
}

// isJSONRequest reports whether the request says it is application/json (a
// parameter such as charset is fine). The route is JSON only.
func isJSONRequest(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// submitAnswer is POST /api/users/{user}/challenges/{cid}/questions/{qid}/answer.
//
// Before this handler runs, Routes() has applied selfFront, the origin guard and
// the identity-keyed answer bucket. Here: selfOnly again in full, then the seat,
// cid and qid, then the body, then ONE call to the Grader, which counts the
// attempt, compares, and solves (D5). The answers an adapter must not get wrong:
//
//   - a form-invalid answer costs nothing (the Grader normalises before it counts);
//   - an answer to a question that is already correct is not refused here: the
//     Grader answers already-correct, and, when the challenge is not yet solved
//     because the write that followed the correct answer failed, completes it (D5's
//     self-repair needs the route to accept that re-submission);
//   - the response is the four fields of D6 and nothing else, built from the
//     generated oapi.AnswerResult. scoring.AnswerResult.Newly is Go-only.
func (h *Handler) submitAnswer(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if !h.selfOnly(w, r, user) {
		return
	}
	if !identity.ValidSeat(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	cid := r.PathValue("cid")
	ch, label, ok := h.challenge(cid)
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownChallenge})
		return
	}
	if ch.Type != catalog.TypeInvestigate {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgNotInvestigate})
		return
	}
	// The qid is held to its grammar here, so what the logs below carry is a short
	// [a-z0-9-] token whether or not it names a question.
	qid := r.PathValue("qid")
	if !answerformat.ValidID(qid) {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownQuestion})
		return
	}

	if !isJSONRequest(r) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, answerBodyMax)
	req, ok := decodeAnswerBody(r.Body)
	if !ok || utf8.RuneCountInString(req.Answer) > answerMaxRunes {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}

	res, err := h.gradeAnswer(r.Context(), user, cid, qid, req.Answer)
	if err != nil {
		h.answerRefused(w, r, label, qid, err)
		return
	}
	// res.Newly (this call recorded the solve) is deliberately NOT in the response.
	// It is kept in the operator log line below, and A3b-2 counts
	// scoreboard_solves_total{kind="investigate"} here, on res.Newly, so a solve is
	// counted once however many answers follow it.
	h.logger.Info("answer", "user", user, "cid", label, "qid", qid,
		"status", string(res.Status), "newly", res.Newly, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, oapi.AnswerResult{
		Status:    oapi.AnswerResultStatus(res.Status),
		Correct:   res.Correct,
		Solved:    res.Solved,
		Remaining: res.Remaining,
	})
}

// answerRefused turns the Grader's error into the route's one error shape,
// {"error": <fixed text>}. The mapping is the ADR-0056 D4 list:
//
//	ErrUnknownChallenge, ErrUnknownQuestion      404, fixed body
//	ErrNotInvestigate, ErrAnswerFormat           400, fixed body (no attempt was spent)
//	ErrInvalidUser                               400 invalid user + the one fixed-field Warn
//	ErrAnswerCellMissing                         500 (the Grader logged it: ids only; not again)
//	ErrAnswersUnavailable and anything else      500, one Error line with the operator's err
//
// The 500 body never carries the error. err can name a store, a table, a file;
// the Grader's errors carry no input, no expected value and no length (D13), so
// logging err for the operator is safe, and the answer text is never in scope here.
func (h *Handler) answerRefused(w http.ResponseWriter, r *http.Request, label, qid string, err error) {
	switch {
	case errors.Is(err, scoring.ErrInvalidUser):
		h.refuseGraderUser(w, r, scoring.EntrySubmitAnswer, func() {})
	case errors.Is(err, scoring.ErrUnknownChallenge):
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownChallenge})
	case errors.Is(err, scoring.ErrUnknownQuestion):
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownQuestion})
	case errors.Is(err, scoring.ErrNotInvestigate):
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgNotInvestigate})
	case errors.Is(err, scoring.ErrAnswerFormat):
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgAnswerFormat})
	case errors.Is(err, scoring.ErrAnswerCellMissing):
		// The Grader logged this once, with ids only; a second line is noise.
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgAnswerFailed})
	default:
		h.logger.Error("answer: could not grade", "err", err, "cid", label, "qid", qid, "remote_addr", r.RemoteAddr)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgAnswerFailed})
	}
}
