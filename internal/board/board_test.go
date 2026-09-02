package board_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/board"
)

func openStore(t *testing.T) *board.Store {
	t.Helper()
	st, err := board.Open(filepath.Join(t.TempDir(), "board.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mustCreate(t *testing.T, st *board.Store, author string, audience board.Audience, subject, body, at string) string {
	t.Helper()
	tid, err := st.CreateThread(author, audience, subject, body, at)
	if err != nil {
		t.Fatalf("CreateThread(%q, %q): %v", author, audience, err)
	}
	return tid
}

// --- CreateThread -----------------------------------------------------

func TestCreateThread_RejectsInvalidAudience(t *testing.T) {
	st := openStore(t)
	if _, err := st.CreateThread("alice", board.Audience("public"), "s", "b", "2026-01-01T00:00:00Z"); !errors.Is(err, board.ErrInvalidAudience) {
		t.Fatalf("got err=%v, want ErrInvalidAudience", err)
	}
	if _, err := st.CreateThread("alice", board.Audience(""), "s", "b", "2026-01-01T00:00:00Z"); !errors.Is(err, board.ErrInvalidAudience) {
		t.Fatalf("empty audience: got err=%v, want ErrInvalidAudience (no fail-open coercion to the schema default)", err)
	}
}

func TestCreateThread_FirstMessageIsParticipantAuthoredByCaller(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAdmin, "help", "how do I do X?", "2026-01-01T00:00:00Z")

	th, err := st.GetThread("alice", false, tid)
	if err != nil {
		t.Fatalf("GetThread: %v", err)
	}
	if th.Author != "alice" || th.Subject != "help" || th.Audience != board.AudienceAdmin {
		t.Fatalf("thread mismatch: %+v", th)
	}
	if len(th.Messages) != 1 {
		t.Fatalf("want exactly one message, got %d", len(th.Messages))
	}
	m := th.Messages[0]
	if m.AuthorRole != board.RoleParticipant || m.Author != "alice" || m.Body != "how do I do X?" {
		t.Fatalf("first message wrong: %+v", m)
	}
}

func TestCreateThread_IDsAreUnique(t *testing.T) {
	st := openStore(t)
	a := mustCreate(t, st, "alice", board.AudienceAll, "s1", "b1", "2026-01-01T00:00:00Z")
	b := mustCreate(t, st, "alice", board.AudienceAll, "s2", "b2", "2026-01-01T00:00:01Z")
	if a == b {
		t.Fatalf("expected distinct ids, got %q twice", a)
	}
}

// --- Visibility: admin-audience threads (cross-user 404) --------------

func TestGetThread_AdminAudience_CrossUserIsNotFound(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAdmin, "s", "b", "2026-01-01T00:00:00Z")

	if _, err := st.GetThread("bob", false, tid); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("bob reading alice's admin-audience thread: got err=%v, want ErrNotFound", err)
	}
	if _, err := st.GetThread("alice", false, tid); err != nil {
		t.Fatalf("alice reading her own admin-audience thread: %v", err)
	}
	// Admin bypasses the ownership gate entirely.
	if _, err := st.GetThread("admin@ctf.local", true, tid); err != nil {
		t.Fatalf("admin reading alice's admin-audience thread: %v", err)
	}
}

func TestListThreads_Participant_AdminAudience_OnlyOwnThreadsIncluded(t *testing.T) {
	st := openStore(t)
	mustCreate(t, st, "alice", board.AudienceAdmin, "a1", "b", "2026-01-01T00:00:00Z")
	mustCreate(t, st, "bob", board.AudienceAdmin, "b1", "b", "2026-01-01T00:00:00Z")

	got, err := st.ListThreads("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Subject != "a1" {
		t.Fatalf("expected only alice's admin-audience thread, got %+v", got)
	}
}

// --- Visibility: all-audience threads (cross-user 200) -----------------

func TestGetThread_AllAudience_CrossUserSucceeds(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAll, "s", "b", "2026-01-01T00:00:00Z")

	th, err := st.GetThread("bob", false, tid)
	if err != nil {
		t.Fatalf("bob reading alice's public thread: got err=%v, want success", err)
	}
	if th.Author != "alice" {
		t.Fatalf("expected alice's thread, got %+v", th)
	}
}

func TestListThreads_Participant_AllAudience_VisibleToEveryone(t *testing.T) {
	st := openStore(t)
	mustCreate(t, st, "alice", board.AudienceAll, "public-thread", "b", "2026-01-01T00:00:00Z")

	got, err := st.ListThreads("bob", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Subject != "public-thread" {
		t.Fatalf("expected alice's public thread visible to bob, got %+v", got)
	}
}

func TestListThreads_Admin_SeesEveryAudienceAndOwner(t *testing.T) {
	st := openStore(t)
	mustCreate(t, st, "alice", board.AudienceAdmin, "a-private", "b", "2026-01-01T00:00:00Z")
	mustCreate(t, st, "bob", board.AudienceAll, "b-public", "b", "2026-01-01T00:00:00Z")

	got, err := st.ListThreads("admin@ctf.local", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 threads across both users, got %d", len(got))
	}
	seen := map[string]bool{}
	for _, s := range got {
		seen[s.Author] = true
	}
	if !seen["alice"] || !seen["bob"] {
		t.Fatalf("expected both alice and bob, got %+v", got)
	}
}

func TestGetThread_UnknownID(t *testing.T) {
	st := openStore(t)
	if _, err := st.GetThread("alice", false, "nope"); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("got err=%v, want ErrNotFound", err)
	}
	if _, err := st.GetThread("admin@ctf.local", true, "nope"); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("admin unknown id: got err=%v, want ErrNotFound", err)
	}
}

// --- Replies are admin-only ---------------------------------------------

func TestAppendOwnMessage_CrossUserIsNotFound(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAll, "s", "b", "2026-01-01T00:00:00Z")

	if _, err := st.AppendOwnMessage("bob", tid, "sneaky", "2026-01-01T00:01:00Z"); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("bob posting to alice's thread: got err=%v, want ErrNotFound (no participant->participant write path)", err)
	}
	// Confirm the rejected write left no trace.
	th, err := st.GetThread("alice", false, tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(th.Messages) != 1 {
		t.Fatalf("expected the rejected cross-user post to leave the thread untouched, got %d messages", len(th.Messages))
	}
}

func TestAppendOwnMessage_SelfSucceeds(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAdmin, "s", "first", "2026-01-01T00:00:00Z")

	updated, err := st.AppendOwnMessage("alice", tid, "follow-up", "2026-01-01T00:01:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(updated.Messages))
	}
	last := updated.Messages[1]
	if last.AuthorRole != board.RoleParticipant || last.Author != "alice" || last.Body != "follow-up" {
		t.Fatalf("follow-up message wrong: %+v", last)
	}
}

func TestAppendAdminReply_AnyThreadRegardlessOfOwner_SetsAnswered(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAdmin, "s", "b", "2026-01-01T00:00:00Z")

	before, err := st.GetThread("alice", false, tid)
	if err != nil {
		t.Fatal(err)
	}
	if before.Answered {
		t.Fatal("must not be answered before any admin reply")
	}

	updated, err := st.AppendAdminReply("admin@ctf.local", tid, "we're looking into it", "2026-01-01T00:05:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(updated.Messages))
	}
	reply := updated.Messages[1]
	if reply.AuthorRole != board.RoleAdmin || reply.Author != "admin@ctf.local" {
		t.Fatalf("admin reply message wrong: %+v", reply)
	}
	if !updated.Answered {
		t.Fatal("AppendAdminReply must set Answered=true")
	}

	reloaded, err := st.GetThread("alice", false, tid)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Answered {
		t.Fatal("Answered must persist across a fresh GetThread, not just the mutation's own return value")
	}
}

func TestAppendAdminReply_UnknownID(t *testing.T) {
	st := openStore(t)
	if _, err := st.AppendAdminReply("admin@ctf.local", "nope", "hi", "2026-01-01T00:00:00Z"); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("got err=%v, want ErrNotFound", err)
	}
}

// There is no method on Store that lets a participant post into another
// participant's thread as anything other than a like — this is a
// structural assertion by omission: AppendOwnMessage's cross-user test
// above and the fact that AppendAdminReply requires an authorRole caller
// context (a future HTTP-layer concern, not enforceable at the Store level
// beyond "the parameter is literally named adminAuthor") are the two halves
// of that guarantee this package can enforce today.

// --- Like: 1 user 1 like, toggle, self-like, admin-audience rejection --

func TestLike_TogglesIdempotently(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAll, "s", "b", "2026-01-01T00:00:00Z")

	if err := st.Like("bob", tid, "2026-01-01T00:01:00Z"); err != nil {
		t.Fatalf("first like: %v", err)
	}
	// Second Like call from the same user must be a no-op, not an error and
	// not a second row (PRIMARY KEY (thread_id, user) is the one
	// enforcement point — INSERT OR IGNORE must actually be hit).
	if err := st.Like("bob", tid, "2026-01-01T00:02:00Z"); err != nil {
		t.Fatalf("second like (idempotent): %v", err)
	}
	th, err := st.GetThread("bob", false, tid)
	if err != nil {
		t.Fatal(err)
	}
	if th.LikeCount != 1 {
		t.Fatalf("LikeCount = %d, want 1 (double-like must not double-count)", th.LikeCount)
	}
	if !th.Liked {
		t.Fatal("Liked must be true for bob after liking")
	}

	if err := st.Unlike("bob", tid); err != nil {
		t.Fatalf("unlike: %v", err)
	}
	th, err = st.GetThread("bob", false, tid)
	if err != nil {
		t.Fatal(err)
	}
	if th.LikeCount != 0 {
		t.Fatalf("LikeCount after unlike = %d, want 0", th.LikeCount)
	}
	if th.Liked {
		t.Fatal("Liked must be false for bob after unliking")
	}

	// Unlike on an already-unliked thread is idempotent, not an error.
	if err := st.Unlike("bob", tid); err != nil {
		t.Fatalf("second unlike (idempotent): %v", err)
	}
}

func TestLike_SelfLikeRejected(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAll, "s", "b", "2026-01-01T00:00:00Z")

	if err := st.Like("alice", tid, "2026-01-01T00:01:00Z"); !errors.Is(err, board.ErrSelfLike) {
		t.Fatalf("alice liking her own thread: got err=%v, want ErrSelfLike", err)
	}
	th, err := st.GetThread("alice", false, tid)
	if err != nil {
		t.Fatal(err)
	}
	if th.LikeCount != 0 {
		t.Fatalf("self-like must not be recorded, got LikeCount=%d", th.LikeCount)
	}
}

func TestLike_AdminAudienceThreadRejected(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAdmin, "s", "b", "2026-01-01T00:00:00Z")

	if err := st.Like("bob", tid, "2026-01-01T00:01:00Z"); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("liking an admin-audience thread: got err=%v, want ErrNotFound (no oracle for its audience)", err)
	}
}

func TestLike_UnknownThreadRejected(t *testing.T) {
	st := openStore(t)
	if err := st.Like("bob", "nope", "2026-01-01T00:01:00Z"); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("got err=%v, want ErrNotFound", err)
	}
}

// --- Moderation ---------------------------------------------------------

func TestSetThreadState_Hidden_ExcludedFromParticipantListingAndGet(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAll, "s", "b", "2026-01-01T00:00:00Z")

	hidden := board.StateHidden
	if err := st.SetThreadState(tid, board.ThreadStateUpdate{State: &hidden}); err != nil {
		t.Fatalf("SetThreadState hidden: %v", err)
	}

	// Excluded from a non-admin listing entirely.
	got, err := st.ListThreads("bob", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if s.ID == tid {
			t.Fatalf("hidden thread must not appear in a non-admin listing, got %+v", got)
		}
	}

	// Excluded from non-admin GetThread too (same ErrNotFound, no oracle).
	if _, err := st.GetThread("bob", false, tid); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("non-admin GetThread on hidden thread: got err=%v, want ErrNotFound", err)
	}
	// Even the thread's own author loses non-admin visibility once hidden.
	if _, err := st.GetThread("alice", false, tid); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("author's own non-admin GetThread on hidden thread: got err=%v, want ErrNotFound", err)
	}

	// Still fully visible to admin, in both listing and get.
	adminList, err := st.ListThreads("admin@ctf.local", true)
	if err != nil {
		t.Fatal(err)
	}
	foundInAdmin := false
	for _, s := range adminList {
		if s.ID == tid {
			foundInAdmin = true
			if s.State != board.StateHidden {
				t.Fatalf("admin listing State = %q, want hidden", s.State)
			}
		}
	}
	if !foundInAdmin {
		t.Fatal("hidden thread must still appear in the admin listing")
	}
	if _, err := st.GetThread("admin@ctf.local", true, tid); err != nil {
		t.Fatalf("admin GetThread on hidden thread: %v", err)
	}
}

func TestSetMessageState_Deleted_BodyScrubbedFromEveryReturnValue(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAdmin, "s", "opening body", "2026-01-01T00:00:00Z")
	updated, err := st.AppendAdminReply("admin@ctf.local", tid, "sensitive reply body", "2026-01-01T00:01:00Z")
	if err != nil {
		t.Fatal(err)
	}
	replyID := updated.Messages[1].ID

	if err := st.SetMessageState(replyID, board.StateDeleted); err != nil {
		t.Fatalf("SetMessageState deleted: %v", err)
	}

	// Admin view: the message still appears (state='deleted' rows are not
	// filtered out for admin), but its Body must be scrubbed.
	adminThread, err := st.GetThread("admin@ctf.local", true, tid)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range adminThread.Messages {
		if m.ID == replyID {
			found = true
			if m.State != board.StateDeleted {
				t.Fatalf("message State = %q, want deleted", m.State)
			}
			if m.Body != "" {
				t.Fatalf("deleted message Body must be scrubbed even for admin, got %q", m.Body)
			}
		}
	}
	if !found {
		t.Fatal("deleted message must still appear in the admin's message list (tombstone, not removal)")
	}

	// Participant view: the deleted message is omitted from the slice
	// entirely (not merely body-scrubbed — non-admins never see
	// hidden/deleted messages at all).
	participantThread, err := st.GetThread("alice", false, tid)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range participantThread.Messages {
		if m.ID == replyID {
			t.Fatalf("deleted message must be entirely absent from a non-admin's message list, found %+v", m)
		}
	}
}

func TestSetThreadState_InvalidStateRejected(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAll, "s", "b", "2026-01-01T00:00:00Z")

	bogus := board.State("archived")
	if err := st.SetThreadState(tid, board.ThreadStateUpdate{State: &bogus}); !errors.Is(err, board.ErrInvalidState) {
		t.Fatalf("got err=%v, want ErrInvalidState", err)
	}
}

func TestSetThreadState_UnknownIDRejected(t *testing.T) {
	st := openStore(t)
	pinned := true
	if err := st.SetThreadState("nope", board.ThreadStateUpdate{Pinned: &pinned}); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("got err=%v, want ErrNotFound", err)
	}
}

func TestSetThreadState_Pinned(t *testing.T) {
	st := openStore(t)
	tid := mustCreate(t, st, "alice", board.AudienceAll, "s", "b", "2026-01-01T00:00:00Z")

	pinned := true
	if err := st.SetThreadState(tid, board.ThreadStateUpdate{Pinned: &pinned}); err != nil {
		t.Fatal(err)
	}
	th, err := st.GetThread("alice", false, tid)
	if err != nil {
		t.Fatal(err)
	}
	if !th.Pinned {
		t.Fatal("expected Pinned=true after SetThreadState")
	}
}

func TestSetMessageState_UnknownIDRejected(t *testing.T) {
	st := openStore(t)
	if err := st.SetMessageState("nope", board.StateHidden); !errors.Is(err, board.ErrNotFound) {
		t.Fatalf("got err=%v, want ErrNotFound", err)
	}
}

// --- Persistence ---------------------------------------------------------

// TestPersistsAcrossReopen proves this is real SQLite persistence, mirroring
// internal/qa's identically-named test.
func TestPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "board.db")

	st1, err := board.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	tid := mustCreate(t, st1, "alice", board.AudienceAll, "s", "b", "2026-01-01T00:00:00Z")
	if err := st1.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := board.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	got, err := st2.GetThread("admin@ctf.local", true, tid)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got.Subject != "s" {
		t.Fatalf("expected persisted subject, got %+v", got)
	}
}
