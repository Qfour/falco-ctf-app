package api

// Issue #164: unit tests for the qa.Thread/Summary -> oapi.QuestionThread/
// QuestionList boundary conversion (qa_oapi.go). The HTTP-level round trip
// through these functions is already exercised end-to-end by
// internal/scoreboard/qa_api_test.go (via httptest against the real
// handlers); these are the narrower, package-internal cases that file
// cannot reach directly — a malformed stored timestamp, and the exact
// User-pointer shape toOapiSummary produces for the participant vs. admin
// listing.

import (
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/qa"
)

func TestToOapiMessage_ConvertsAuthorRoleAndTimestamp(t *testing.T) {
	m := qa.Message{
		AuthorRole: qa.RoleAdmin,
		Author:     "admin@ctf.local",
		Body:       "hello",
		CreatedAt:  "2026-01-01T00:00:00.5Z",
	}
	got, err := toOapiMessage(m)
	if err != nil {
		t.Fatalf("toOapiMessage: %v", err)
	}
	if string(got.AuthorRole) != "admin" || got.Author != "admin@ctf.local" || got.Body != "hello" {
		t.Fatalf("unexpected conversion: %+v", got)
	}
	want := time.Date(2026, 1, 1, 0, 0, 0, 500_000_000, time.UTC)
	if !got.CreatedAt.Equal(want) {
		t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt, want)
	}
}

func TestToOapiMessage_MalformedTimestampErrors(t *testing.T) {
	m := qa.Message{AuthorRole: qa.RoleParticipant, Author: "alice", Body: "b", CreatedAt: "not-a-timestamp"}
	if _, err := toOapiMessage(m); err == nil {
		t.Fatal("expected an error for a malformed stored timestamp, got nil — a corrupt QA row must not silently render as the zero time")
	}
}

func TestToOapiThread_PropagatesAnsweredAndMessages(t *testing.T) {
	th := qa.Thread{
		ID:        "abc123",
		User:      "alice",
		Subject:   "help",
		CreatedAt: "2026-01-01T00:00:00Z",
		Answered:  true,
		Messages: []qa.Message{
			{AuthorRole: qa.RoleParticipant, Author: "alice", Body: "hi", CreatedAt: "2026-01-01T00:00:00Z"},
			{AuthorRole: qa.RoleAdmin, Author: "admin@ctf.local", Body: "hi back", CreatedAt: "2026-01-01T00:01:00Z"},
		},
	}
	got, err := toOapiThread(th)
	if err != nil {
		t.Fatalf("toOapiThread: %v", err)
	}
	if got.Id != "abc123" || got.User != "alice" || got.Subject != "help" {
		t.Fatalf("unexpected top-level fields: %+v", got)
	}
	if !got.Answered {
		t.Fatalf("expected Answered=true to propagate through, got %+v", got)
	}
	if len(got.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %+v", got.Messages)
	}
}

func TestToOapiThread_MalformedThreadTimestampErrors(t *testing.T) {
	th := qa.Thread{ID: "x", User: "alice", Subject: "s", CreatedAt: "garbage"}
	if _, err := toOapiThread(th); err == nil {
		t.Fatal("expected an error for a malformed thread-level CreatedAt, got nil")
	}
}

func TestToOapiSummary_UserPointerOmittedWhenEmpty(t *testing.T) {
	// Participant's own listing: qa.go's listLocked leaves Summary.User ""
	// (the caller already knows it's their own ticket).
	sm := qa.Summary{
		ID: "id1", Subject: "s", CreatedAt: "2026-01-01T00:00:00Z",
		UpdatedAt: "2026-01-01T00:00:00Z", MessageCount: 1,
	}
	got, err := toOapiSummary(sm)
	if err != nil {
		t.Fatalf("toOapiSummary: %v", err)
	}
	if got.User != nil {
		t.Fatalf("expected a nil User pointer for the participant listing shape, got %v", *got.User)
	}
}

func TestToOapiSummary_UserPointerPopulatedForAdminListing(t *testing.T) {
	sm := qa.Summary{
		ID: "id1", Subject: "s", CreatedAt: "2026-01-01T00:00:00Z",
		UpdatedAt: "2026-01-01T00:00:00Z", MessageCount: 1, User: "alice",
	}
	got, err := toOapiSummary(sm)
	if err != nil {
		t.Fatalf("toOapiSummary: %v", err)
	}
	if got.User == nil || *got.User != "alice" {
		t.Fatalf("expected User=alice for the admin listing shape, got %v", got.User)
	}
}

func TestToOapiList_EmptyInputProducesEmptySliceNotNil(t *testing.T) {
	got, err := toOapiList(nil)
	if err != nil {
		t.Fatalf("toOapiList: %v", err)
	}
	if got.Questions == nil {
		t.Fatal("expected an empty (non-nil) Questions slice for a zero-ticket listing, matching qa.go's own listLocked convention (make([]Summary, 0, ...)) — a nil slice marshals to `null`, an empty one to `[]`")
	}
	if len(got.Questions) != 0 {
		t.Fatalf("expected zero questions, got %+v", got.Questions)
	}
}
