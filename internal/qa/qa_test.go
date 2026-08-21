package qa_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/qa"
)

func openStore(t *testing.T) *qa.Store {
	t.Helper()
	st, err := qa.Open(filepath.Join(t.TempDir(), "qa.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestCreateQuestion_FirstMessageIsParticipantAuthoredByCaller(t *testing.T) {
	st := openStore(t)
	th, err := st.CreateQuestion("alice", "help", "how do I do X?", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if th.User != "alice" || th.Subject != "help" {
		t.Fatalf("thread mismatch: %+v", th)
	}
	if len(th.Messages) != 1 {
		t.Fatalf("want exactly one message, got %d", len(th.Messages))
	}
	m := th.Messages[0]
	if m.AuthorRole != qa.RoleParticipant || m.Author != "alice" || m.Body != "how do I do X?" {
		t.Fatalf("first message wrong: %+v", m)
	}
	if th.ID == "" {
		t.Fatal("expected a non-empty generated id")
	}
}

func TestCreateQuestion_IDsAreUnique(t *testing.T) {
	st := openStore(t)
	a, err := st.CreateQuestion("alice", "s1", "b1", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.CreateQuestion("alice", "s2", "b2", "2026-01-01T00:00:01Z")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatalf("expected distinct ids, got %q twice", a.ID)
	}
}

func TestListForUser_OnlyOwnTickets(t *testing.T) {
	st := openStore(t)
	if _, err := st.CreateQuestion("alice", "a1", "body", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateQuestion("bob", "b1", "body", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	got, err := st.ListForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Subject != "a1" {
		t.Fatalf("expected only alice's ticket, got %+v", got)
	}
	// Participant listing never sets User (the caller already knows).
	if got[0].User != "" {
		t.Fatalf("expected empty User on self-listing, got %q", got[0].User)
	}
}

func TestListAll_SetsUserAndSpansEveryone(t *testing.T) {
	st := openStore(t)
	if _, err := st.CreateQuestion("alice", "a1", "body", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateQuestion("bob", "b1", "body", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	got, err := st.ListAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 tickets across both users, got %d", len(got))
	}
	seen := map[string]bool{}
	for _, s := range got {
		if s.User == "" {
			t.Fatalf("admin listing must set User, got %+v", s)
		}
		seen[s.User] = true
	}
	if !seen["alice"] || !seen["bob"] {
		t.Fatalf("expected both alice and bob, got %+v", got)
	}
}

func TestAnswered_DerivedFromAdminMessagePresence(t *testing.T) {
	st := openStore(t)
	th, err := st.CreateQuestion("alice", "s", "b", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	before, err := st.ListForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if before[0].Answered {
		t.Fatal("must not be answered before any admin reply")
	}
	if before[0].MessageCount != 1 {
		t.Fatalf("expected message_count=1, got %d", before[0].MessageCount)
	}

	if _, err := st.AppendAdminReply(th.ID, "admin@ctf.local", "reply", "2026-01-01T00:01:00Z"); err != nil {
		t.Fatal(err)
	}
	after, err := st.ListForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if !after[0].Answered {
		t.Fatal("must be answered after an admin reply")
	}
	if after[0].MessageCount != 2 {
		t.Fatalf("expected message_count=2, got %d", after[0].MessageCount)
	}
}

func TestGetThreadForUser_IDOR_CrossUserIsNotFound(t *testing.T) {
	st := openStore(t)
	th, err := st.CreateQuestion("alice", "s", "b", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetThreadForUser(th.ID, "bob"); !errors.Is(err, qa.ErrNotFound) {
		t.Fatalf("bob reading alice's qid: got err=%v, want ErrNotFound", err)
	}
	// self succeeds
	if _, err := st.GetThreadForUser(th.ID, "alice"); err != nil {
		t.Fatalf("alice reading her own qid: %v", err)
	}
}

func TestGetThreadForUser_UnknownID(t *testing.T) {
	st := openStore(t)
	if _, err := st.GetThreadForUser("nope", "alice"); !errors.Is(err, qa.ErrNotFound) {
		t.Fatalf("got err=%v, want ErrNotFound", err)
	}
}

// TestAppendMessageForUser_IDOR_CrossUserIsNotFound is the WRITE-path
// counterpart to TestGetThreadForUser_IDOR_CrossUserIsNotFound — ADR-0006
// Verification 3 explicitly calls out that the read-only case alone would
// leave the write path's composite-key check unexercised.
func TestAppendMessageForUser_IDOR_CrossUserIsNotFound(t *testing.T) {
	st := openStore(t)
	th, err := st.CreateQuestion("alice", "s", "b", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppendMessageForUser(th.ID, "bob", "sneaky", "2026-01-01T00:01:00Z"); !errors.Is(err, qa.ErrNotFound) {
		t.Fatalf("bob posting to alice's qid: got err=%v, want ErrNotFound", err)
	}
	// Confirm the cross-user attempt left no trace (no message inserted).
	got, err := st.GetThreadForUser(th.ID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("expected the rejected cross-user post to leave the thread untouched, got %d messages", len(got.Messages))
	}
}

func TestAppendMessageForUser_SelfSucceedsAndPersists(t *testing.T) {
	st := openStore(t)
	th, err := st.CreateQuestion("alice", "s", "first", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := st.AppendMessageForUser(th.ID, "alice", "follow-up", "2026-01-01T00:01:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(updated.Messages))
	}
	last := updated.Messages[1]
	if last.AuthorRole != qa.RoleParticipant || last.Author != "alice" || last.Body != "follow-up" {
		t.Fatalf("follow-up message wrong: %+v", last)
	}
}

func TestGetThread_AdminNoOwnershipCheck(t *testing.T) {
	st := openStore(t)
	th, err := st.CreateQuestion("alice", "s", "b", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetThread(th.ID)
	if err != nil {
		t.Fatalf("admin get: %v", err)
	}
	if got.User != "alice" {
		t.Fatalf("expected alice's thread, got %+v", got)
	}
}

func TestGetThread_UnknownID(t *testing.T) {
	st := openStore(t)
	if _, err := st.GetThread("nope"); !errors.Is(err, qa.ErrNotFound) {
		t.Fatalf("got err=%v, want ErrNotFound", err)
	}
}

func TestAppendAdminReply_UnknownID(t *testing.T) {
	st := openStore(t)
	if _, err := st.AppendAdminReply("nope", "admin@ctf.local", "hi", "2026-01-01T00:00:00Z"); !errors.Is(err, qa.ErrNotFound) {
		t.Fatalf("got err=%v, want ErrNotFound", err)
	}
}

func TestAppendAdminReply_AnyTicketRegardlessOfOwner(t *testing.T) {
	st := openStore(t)
	th, err := st.CreateQuestion("alice", "s", "b", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := st.AppendAdminReply(th.ID, "admin@ctf.local", "we're looking into it", "2026-01-01T00:05:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(updated.Messages))
	}
	reply := updated.Messages[1]
	if reply.AuthorRole != qa.RoleAdmin || reply.Author != "admin@ctf.local" {
		t.Fatalf("admin reply message wrong: %+v", reply)
	}
}

// TestPersistsAcrossReopen proves this is real SQLite persistence (not an
// in-memory-only store that happens to pass in-process tests) — the same
// discipline internal/store's tests apply to its own Open/Close.
func TestPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "qa.db")

	st1, err := qa.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	th, err := st1.CreateQuestion("alice", "s", "b", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if err := st1.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := qa.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	got, err := st2.GetThread(th.ID)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got.Subject != "s" {
		t.Fatalf("expected persisted subject, got %+v", got)
	}
}
