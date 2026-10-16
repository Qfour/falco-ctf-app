package api

// Issue #164 (applied to app#292 Phase 2, same shape P25's
// qa_oapi_test.go used before it): unit tests for the board.Thread/
// ThreadSummary/Message -> oapi.Board* boundary conversion (board_oapi.go).
// The HTTP-level round trip through these functions is already exercised
// end-to-end by internal/scoreboard/board_api_test.go (via httptest against
// the real handlers); these are the narrower, package-internal cases that
// file cannot reach directly — a malformed stored timestamp, and the exact
// shape each conversion produces.

import (
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/avatar"
)

// identityDisplayName is a trivial boardDisplayNameFunc stub for tests that
// don't care about display-name resolution itself — it echoes the slug
// back unchanged, same as a real Store.DisplayName lookup would for a user
// who never set one.
func identityDisplayName(user string) string { return user }

// defaultAvatar is a boardAvatarFunc stub for a seat that never chose: the
// derived default, exactly what Handler.avatarFor returns with an empty store.
func defaultAvatar(user string) string { return avatar.Default(user) }

// spyAvatar must never be reached for an admin-authored message.
func spyAvatar(user string) string { return "SHOULD NOT BE CALLED: " + user }

func TestToOapiBoardMessage_ConvertsAuthorRoleStateAndTimestamp(t *testing.T) {
	m := board.Message{
		ID:         "m1",
		AuthorRole: board.RoleAdmin,
		Author:     "staff",
		Body:       "hello",
		CreatedAt:  "2026-01-01T00:00:00.5Z",
		State:      board.StateVisible,
	}
	got, err := toOapiBoardMessage(m, identityDisplayName, defaultAvatar)
	if err != nil {
		t.Fatalf("toOapiBoardMessage: %v", err)
	}
	if got.Id != "m1" || string(got.AuthorRole) != "admin" || got.Author != "staff" || got.Body != "hello" || string(got.State) != "visible" {
		t.Fatalf("unexpected conversion: %+v", got)
	}
	want := time.Date(2026, 1, 1, 0, 0, 0, 500_000_000, time.UTC)
	if !got.CreatedAt.Equal(want) {
		t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt, want)
	}
}

func TestToOapiBoardMessage_MalformedTimestampErrors(t *testing.T) {
	m := board.Message{AuthorRole: board.RoleParticipant, Author: "alice", Body: "b", CreatedAt: "not-a-timestamp", State: board.StateVisible}
	if _, err := toOapiBoardMessage(m, identityDisplayName, defaultAvatar); err == nil {
		t.Fatal("expected an error for a malformed stored timestamp, got nil — a corrupt board row must not silently render as the zero time")
	}
}

// TestToOapiBoardMessage_AdminAuthorGetsFixedStaffLabel proves an
// admin-authored message NEVER calls displayName at all — it must always
// render the fixed boardStaffDisplay label, regardless of what the resolver
// would have returned for the literal "staff" slug.
func TestToOapiBoardMessage_AdminAuthorGetsFixedStaffLabel(t *testing.T) {
	spy := func(user string) string { return "SHOULD NOT BE CALLED: " + user }
	m := board.Message{ID: "m1", AuthorRole: board.RoleAdmin, Author: "staff", Body: "hi", CreatedAt: "2026-01-01T00:00:00Z", State: board.StateVisible}
	got, err := toOapiBoardMessage(m, spy, spyAvatar)
	if err != nil {
		t.Fatalf("toOapiBoardMessage: %v", err)
	}
	if got.AuthorDisplay != "運営" {
		t.Fatalf("AuthorDisplay = %q, want the fixed staff label", got.AuthorDisplay)
	}
}

// TestToOapiBoardMessage_ParticipantAuthorResolvesThroughDisplayName proves
// a participant-authored message's AuthorDisplay is whatever displayName
// resolves the slug to (the api-layer boundary that actually plugs in
// h.store.DisplayName at the real call sites) — this unit test only proves
// the plumbing, not Store.DisplayName's own fallback (that lives in
// internal/store's own test suite).
func TestToOapiBoardMessage_ParticipantAuthorResolvesThroughDisplayName(t *testing.T) {
	resolve := func(user string) string {
		if user == "alice" {
			return "Alice A."
		}
		return user
	}
	m := board.Message{ID: "m1", AuthorRole: board.RoleParticipant, Author: "alice", Body: "hi", CreatedAt: "2026-01-01T00:00:00Z", State: board.StateVisible}
	got, err := toOapiBoardMessage(m, resolve, defaultAvatar)
	if err != nil {
		t.Fatalf("toOapiBoardMessage: %v", err)
	}
	if got.AuthorDisplay != "Alice A." {
		t.Fatalf("AuthorDisplay = %q, want the resolved display name", got.AuthorDisplay)
	}
}

// TestToOapiBoardMessage_AvatarComesFromTheAuthorRole is ADR-0034 D8 for
// BoardMessage.authorAvatar: an admin-authored message carries the ONE fixed
// staff id and never consults the resolver; a participant-authored one
// carries whatever the resolver returns for the slug (the plumbing only —
// Resolve's fallback is the avatar package's own test).
func TestToOapiBoardMessage_AvatarComesFromTheAuthorRole(t *testing.T) {
	adminMsg := board.Message{ID: "m1", AuthorRole: board.RoleAdmin, Author: "staff", Body: "hi", CreatedAt: "2026-01-01T00:00:00Z", State: board.StateVisible}
	got, err := toOapiBoardMessage(adminMsg, identityDisplayName, spyAvatar)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.AuthorAvatar) != avatar.StaffID {
		t.Fatalf("admin message AuthorAvatar = %q, want the fixed %q", got.AuthorAvatar, avatar.StaffID)
	}

	pick := func(user string) string {
		if user == "alice" {
			return "bug-lime"
		}
		return avatar.Default(user)
	}
	partMsg := board.Message{ID: "m2", AuthorRole: board.RoleParticipant, Author: "alice", Body: "hi", CreatedAt: "2026-01-01T00:00:00Z", State: board.StateVisible}
	got, err = toOapiBoardMessage(partMsg, identityDisplayName, pick)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthorAvatar != "bug-lime" {
		t.Fatalf("participant message AuthorAvatar = %q, want the resolved bug-lime", got.AuthorAvatar)
	}
	if !avatar.Valid(string(got.AuthorAvatar)) {
		t.Fatalf("AuthorAvatar %q is not a table id", got.AuthorAvatar)
	}
}

func TestToOapiBoardThread_PropagatesFieldsAndMessages(t *testing.T) {
	th := board.Thread{
		ID:        "abc123",
		Author:    "alice",
		Audience:  board.AudienceAll,
		Subject:   "help",
		CreatedAt: "2026-01-01T00:00:00Z",
		Pinned:    true,
		Answered:  true,
		State:     board.StateVisible,
		Messages: []board.Message{
			{ID: "m1", AuthorRole: board.RoleParticipant, Author: "alice", Body: "hi", CreatedAt: "2026-01-01T00:00:00Z", State: board.StateVisible},
			{ID: "m2", AuthorRole: board.RoleAdmin, Author: "staff", Body: "hi back", CreatedAt: "2026-01-01T00:01:00Z", State: board.StateVisible},
		},
		LikeCount: 3,
		Liked:     true,
	}
	got, err := toOapiBoardThread(th, identityDisplayName, defaultAvatar)
	if err != nil {
		t.Fatalf("toOapiBoardThread: %v", err)
	}
	if got.Id != "abc123" || got.Author != "alice" || string(got.Audience) != "all" || got.Subject != "help" {
		t.Fatalf("unexpected top-level fields: %+v", got)
	}
	if got.AuthorDisplay != "alice" {
		t.Fatalf("AuthorDisplay = %q, want the (identity-resolved) author slug", got.AuthorDisplay)
	}
	if !got.Pinned || !got.Answered {
		t.Fatalf("expected Pinned/Answered=true to propagate through, got %+v", got)
	}
	if got.LikeCount != 3 || !got.Liked {
		t.Fatalf("expected LikeCount=3/Liked=true to propagate through, got %+v", got)
	}
	if len(got.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %+v", got.Messages)
	}
}

func TestToOapiBoardThread_MalformedThreadTimestampErrors(t *testing.T) {
	th := board.Thread{ID: "x", Author: "alice", Audience: board.AudienceAll, Subject: "s", CreatedAt: "garbage", State: board.StateVisible}
	if _, err := toOapiBoardThread(th, identityDisplayName, defaultAvatar); err == nil {
		t.Fatal("expected an error for a malformed thread-level CreatedAt, got nil")
	}
}

func TestToOapiBoardSummary_PropagatesAllFields(t *testing.T) {
	sm := board.ThreadSummary{
		ID: "id1", Author: "alice", Audience: board.AudienceAdmin, Subject: "s",
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:05:00Z",
		Pinned: true, Answered: false, State: board.StateVisible,
		MessageCount: 2, LikeCount: 0, Liked: false,
	}
	got, err := toOapiBoardSummary(sm, identityDisplayName)
	if err != nil {
		t.Fatalf("toOapiBoardSummary: %v", err)
	}
	if got.Id != "id1" || got.Author != "alice" || string(got.Audience) != "admin" || got.MessageCount != 2 {
		t.Fatalf("unexpected conversion: %+v", got)
	}
	if got.AuthorDisplay != "alice" {
		t.Fatalf("AuthorDisplay = %q, want the (identity-resolved) author slug", got.AuthorDisplay)
	}
}

func TestToOapiBoardList_EmptyInputProducesEmptySliceNotNil(t *testing.T) {
	got, err := toOapiBoardList(nil, identityDisplayName)
	if err != nil {
		t.Fatalf("toOapiBoardList: %v", err)
	}
	if got.Threads == nil {
		t.Fatal("expected an empty (non-nil) Threads slice for a zero-thread listing — a nil slice marshals to `null`, an empty one to `[]`")
	}
	if len(got.Threads) != 0 {
		t.Fatalf("expected zero threads, got %+v", got.Threads)
	}
}

func TestToOapiLikeResult_BuildsExpectedShape(t *testing.T) {
	got := toOapiLikeResult("tid1", 5, true)
	if !got.Ok || got.Tid != "tid1" || got.LikeCount != 5 || !got.Liked {
		t.Fatalf("unexpected LikeResult: %+v", got)
	}
}

func TestToOapiMessageStateResult_BuildsExpectedShape(t *testing.T) {
	got := toOapiMessageStateResult("mid1", board.StateHidden)
	if !got.Ok || got.Mid != "mid1" || string(got.State) != "hidden" {
		t.Fatalf("unexpected MessageStateResult: %+v", got)
	}
}
