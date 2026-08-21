// Issue #164 (ADR-0006 Decision 5's software-engineer discretion, review-5x
// R4 finding on PR #162): QA responses were being written straight from the
// hand-written internal/qa.Thread/Summary structs (json struct tags happened
// to line up with docs/openapi-scoreboard.yaml's QuestionThread/
// QuestionSummary schemas, but nothing enforced that at compile time — a
// future spec field rename would silently stop matching the wire body with
// zero build failure, exactly the response-side gap falco-api's skill index
// and Issue #115 already call out as a broader pattern).
//
// The fix here is a conversion at the HTTP boundary, NOT changing
// internal/qa's own types: qa.Thread/Summary keep their existing shape
// (string timestamps, qa's own AuthorRole type) because internal/qa is
// deliberately isolated from service-specific concerns (package doc:
// physically separate from internal/store/internal/scoreboard/scoring, and
// more generally not a package that should need to know what
// internal/scoreboard/oapi — the SCOREBOARD BINARY's own generated
// contract — looks like). Instead, this file's toOapi* functions build the
// generated oapi.QuestionThread/QuestionList values the handlers actually
// write, so if a future `make gen` changes QuestionThread's field set, this
// file fails to COMPILE (a required field disappearing, a type changing)
// rather than the response silently drifting from the spec at runtime —
// the same "compile-time bound to the schema" property the request-body
// side (oapi.CreateQuestionJSONRequestBody etc.) already had.
package api

import (
	"fmt"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/qa"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
)

// parseQATimestamp parses a qa package timestamp string (always written as
// time.Now().UTC().Format(time.RFC3339Nano) by this handler package — see
// qa.go's Open doc) into the time.Time oapi's generated `format: date-time`
// fields require. A parse failure here means the QA SQLite file holds a
// value this binary never wrote (corruption, or a manual edit) — a real
// but very unlikely failure mode, propagated as an error rather than
// silently substituting the zero time.Time (which would render as
// "0001-01-01T00:00:00Z" and look like a valid, very wrong, answer).
func parseQATimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse QA timestamp %q: %w", s, err)
	}
	return t, nil
}

// toOapiMessage converts one qa.Message into its oapi.QuestionMessage wire
// shape. qa.AuthorRole and oapi.QuestionMessageAuthorRole are both plain
// string-based types over the same two values ("participant"/"admin"), so
// the conversion is a direct cast — qa.go's own CHECK constraint on the
// author_role column is what actually keeps that domain closed.
func toOapiMessage(m qa.Message) (oapi.QuestionMessage, error) {
	createdAt, err := parseQATimestamp(m.CreatedAt)
	if err != nil {
		return oapi.QuestionMessage{}, err
	}
	return oapi.QuestionMessage{
		Author:     m.Author,
		AuthorRole: oapi.QuestionMessageAuthorRole(m.AuthorRole),
		Body:       m.Body,
		CreatedAt:  createdAt,
	}, nil
}

// toOapiThread converts a qa.Thread into the oapi.QuestionThread every QA
// thread-returning handler (createQuestion, getQuestion, postMessage,
// adminGetQuestion, adminReply) now writes.
func toOapiThread(th qa.Thread) (oapi.QuestionThread, error) {
	createdAt, err := parseQATimestamp(th.CreatedAt)
	if err != nil {
		return oapi.QuestionThread{}, err
	}
	msgs := make([]oapi.QuestionMessage, 0, len(th.Messages))
	for _, m := range th.Messages {
		om, err := toOapiMessage(m)
		if err != nil {
			return oapi.QuestionThread{}, err
		}
		msgs = append(msgs, om)
	}
	return oapi.QuestionThread{
		Id:        th.ID,
		User:      th.User,
		Subject:   th.Subject,
		CreatedAt: createdAt,
		Messages:  msgs,
		Answered:  th.Answered,
	}, nil
}

// toOapiSummary converts one qa.Summary into oapi.QuestionSummary.
// Summary.User is already "" for the participant's own listing (qa.go's
// listLocked only populates it for ListAll) — carried through as a nil
// *string in that case via oapi's own `omitempty`-shaped pointer field, so
// the participant listing's wire body keeps omitting "user" exactly as it
// did before this conversion existed.
func toOapiSummary(sm qa.Summary) (oapi.QuestionSummary, error) {
	createdAt, err := parseQATimestamp(sm.CreatedAt)
	if err != nil {
		return oapi.QuestionSummary{}, err
	}
	updatedAt, err := parseQATimestamp(sm.UpdatedAt)
	if err != nil {
		return oapi.QuestionSummary{}, err
	}
	out := oapi.QuestionSummary{
		Id:           sm.ID,
		Subject:      sm.Subject,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
		Answered:     sm.Answered,
		MessageCount: sm.MessageCount,
	}
	if sm.User != "" {
		user := sm.User
		out.User = &user
	}
	return out, nil
}

// toOapiList converts a []qa.Summary listing into oapi.QuestionList — the
// listQuestions/adminListQuestions response shape.
func toOapiList(summaries []qa.Summary) (oapi.QuestionList, error) {
	out := make([]oapi.QuestionSummary, 0, len(summaries))
	for _, sm := range summaries {
		os, err := toOapiSummary(sm)
		if err != nil {
			return oapi.QuestionList{}, err
		}
		out = append(out, os)
	}
	return oapi.QuestionList{Questions: out}, nil
}
