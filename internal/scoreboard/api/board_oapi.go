// Issue #164 (applied to app#292 Phase 2 the same way qa_oapi.go applied it
// to P25): board responses are built through generated oapi.Board* types,
// NOT written straight from internal/board's own Thread/ThreadSummary/
// Message structs — even though those structs' json tags happen to already
// line up with docs/openapi-scoreboard.yaml's BoardThread/BoardSummary/
// BoardMessage schemas today, nothing would enforce that at compile time.
// The conversion at this HTTP boundary means a future `make gen` field
// rename fails to COMPILE here rather than silently drifting the wire body
// away from the spec at runtime.
//
// internal/board's own types are NOT changed to match oapi's shape —
// mirrors qa_oapi.go's reasoning: internal/board is deliberately isolated
// from service-specific concerns (its package doc: physically separate from
// internal/store/internal/scoreboard/scoring, and not a package that should
// need to know what the SCOREBOARD BINARY's generated contract looks like).
package api

import (
	"fmt"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
)

// parseBoardTimestamp parses a board package timestamp string (always
// written as time.Now().UTC().Format(time.RFC3339Nano) by this handler
// package — see board.go's create/append/reply handlers) into the
// time.Time oapi's generated `format: date-time` fields require. Mirrors
// P25's qa_oapi.go parseQATimestamp exactly (same reasoning, same shape) —
// this is that helper's replacement, not a new design.
func parseBoardTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse board timestamp %q: %w", s, err)
	}
	return t, nil
}

// toOapiBoardMessage converts one board.Message into its oapi.BoardMessage
// wire shape. board.Message.CreatedAt is always written as
// h.now().UTC().Format(time.RFC3339Nano) by this handler package (see
// board.go's create/append/reply handlers) — a parse failure here means the
// board SQLite file holds a value this binary never wrote (corruption, or a
// manual edit), so it is propagated as an error rather than silently
// substituting the zero time.Time (qa_oapi.go's parseBoardTimestamp used the
// exact same reasoning for the P25 predecessor this file replaces).
func toOapiBoardMessage(m board.Message) (oapi.BoardMessage, error) {
	createdAt, err := parseBoardTimestamp(m.CreatedAt)
	if err != nil {
		return oapi.BoardMessage{}, err
	}
	return oapi.BoardMessage{
		Id:         m.ID,
		AuthorRole: oapi.BoardMessageAuthorRole(m.AuthorRole),
		Author:     m.Author,
		Body:       m.Body,
		CreatedAt:  createdAt,
		State:      oapi.BoardMessageState(m.State),
	}, nil
}

// toOapiBoardThread converts a board.Thread into the oapi.BoardThread every
// thread-returning board handler writes.
func toOapiBoardThread(th board.Thread) (oapi.BoardThread, error) {
	createdAt, err := parseBoardTimestamp(th.CreatedAt)
	if err != nil {
		return oapi.BoardThread{}, err
	}
	msgs := make([]oapi.BoardMessage, 0, len(th.Messages))
	for _, m := range th.Messages {
		om, err := toOapiBoardMessage(m)
		if err != nil {
			return oapi.BoardThread{}, err
		}
		msgs = append(msgs, om)
	}
	return oapi.BoardThread{
		Id:        th.ID,
		Author:    th.Author,
		Audience:  oapi.BoardThreadAudience(th.Audience),
		Subject:   th.Subject,
		CreatedAt: createdAt,
		Pinned:    th.Pinned,
		Answered:  th.Answered,
		State:     oapi.BoardThreadState(th.State),
		Messages:  msgs,
		LikeCount: th.LikeCount,
		Liked:     th.Liked,
	}, nil
}

// toOapiBoardSummary converts one board.ThreadSummary into oapi.BoardSummary.
func toOapiBoardSummary(sm board.ThreadSummary) (oapi.BoardSummary, error) {
	createdAt, err := parseBoardTimestamp(sm.CreatedAt)
	if err != nil {
		return oapi.BoardSummary{}, err
	}
	updatedAt, err := parseBoardTimestamp(sm.UpdatedAt)
	if err != nil {
		return oapi.BoardSummary{}, err
	}
	return oapi.BoardSummary{
		Id:           sm.ID,
		Author:       sm.Author,
		Audience:     oapi.BoardSummaryAudience(sm.Audience),
		Subject:      sm.Subject,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
		Pinned:       sm.Pinned,
		Answered:     sm.Answered,
		State:        oapi.BoardSummaryState(sm.State),
		MessageCount: sm.MessageCount,
		LikeCount:    sm.LikeCount,
		Liked:        sm.Liked,
	}, nil
}

// toOapiBoardList converts a []board.ThreadSummary listing into
// oapi.BoardList — the boardListThreads/boardAdminListThreads response
// shape.
func toOapiBoardList(summaries []board.ThreadSummary) (oapi.BoardList, error) {
	out := make([]oapi.BoardSummary, 0, len(summaries))
	for _, sm := range summaries {
		os, err := toOapiBoardSummary(sm)
		if err != nil {
			return oapi.BoardList{}, err
		}
		out = append(out, os)
	}
	return oapi.BoardList{Threads: out}, nil
}

// toOapiLikeResult builds the boardLike/boardUnlike routes' small result
// shape — a full thread refetch is unnecessary for a toggle (see api.go's
// boardLikeStatus, which supplies count/liked).
func toOapiLikeResult(tid string, count int, liked bool) oapi.LikeResult {
	return oapi.LikeResult{Ok: true, Tid: tid, Liked: liked, LikeCount: count}
}

// toOapiMessageStateResult builds the boardAdminSetMessageState route's
// result shape.
func toOapiMessageStateResult(mid string, state board.State) oapi.MessageStateResult {
	return oapi.MessageStateResult{Ok: true, Mid: mid, State: oapi.MessageStateResultState(state)}
}
