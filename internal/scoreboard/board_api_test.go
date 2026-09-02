package scoreboard_test

// app#292 Phase 2 QA Board handler tests — the board-specific behavioural
// assertions that TestAuthz_AllDeclaredGatesEnforced/
// TestAuthz_AuthenticatedGate_MissingHeaderDenied (authz_test.go) and
// TestOriginGuard_AllProtectedRoutesEnforced (origin_guard_test.go) cannot
// reach generically: audience-scoped visibility (public vs. private,
// cross-user), the own-thread-only write boundary, admin-only reply, the
// like/unlike toggle (including self-like rejection), moderation state, the
// fail-closed audience default, and the flag-shape rejection gate. Mirrors
// P25's qa_api_test.go's structure exactly (qaFixture -> boardFixture).

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

const (
	boardFixtureOrigin = "https://scoreboard.ctf.local"
	boardFixtureAdmin  = "admin@ctf.local"
)

type boardFixture struct {
	t   *testing.T
	srv *scoreboard.Handler
	// board is the board SQLite handle wired into srv via
	// scoreboard.WithBoard. Exposed so a future fault-injection test
	// (mirroring qa_errorleak_test.go's technique) can close it mid-test.
	board *board.Store
}

func newBoardFixture(t *testing.T, extra ...scoreboard.Option) *boardFixture {
	t.Helper()
	cat := catalog.Catalog{
		"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "boardapi.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	boardSt, err := board.Open(filepath.Join(t.TempDir(), "boardapi-board.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { boardSt.Close() }) //nolint:errcheck // double-close after a test's own fault-injection Close is fine, error discarded either way
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	opts := append([]scoreboard.Option{
		scoreboard.WithAdminEmails([]string{boardFixtureAdmin}),
		scoreboard.WithAllowedOrigins([]string{boardFixtureOrigin}),
		scoreboard.WithBoard(boardSt),
	}, extra...)
	srv := scoreboard.NewHandler(cat, st, logger, opts...)
	return &boardFixture{t: t, srv: srv, board: boardSt}
}

// do issues a request carrying Origin (so origin-guarded write routes are
// never collaterally denied — this file exercises board-specific behaviour,
// not the origin guard, which has its own dedicated coverage) and, when
// email is non-empty, X-Auth-Request-Email.
func (f *boardFixture) do(method, target, email string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			f.t.Fatalf("marshal body: %v", err)
		}
		r = httptest.NewRequest(method, target, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	r.Header.Set("Origin", boardFixtureOrigin)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

// doRaw sends a literal, possibly-malformed body (bypassing json.Marshal),
// mirroring qa_api_test.go's doRaw.
func (f *boardFixture) doRaw(method, target, email, rawBody string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(rawBody))
	r.Header.Set("Content-Type", "application/json")
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	r.Header.Set("Origin", boardFixtureOrigin)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func (f *boardFixture) decode(w *httptest.ResponseRecorder) map[string]any {
	f.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		f.t.Fatalf("decode JSON: %v (body=%s)", err, w.Body)
	}
	return m
}

// createAs opens a thread as {email} (its derived username is {email}'s
// local part), asserting 200, and returns the decoded BoardThread.
func (f *boardFixture) createAs(email, audience, subject, body string) map[string]any {
	f.t.Helper()
	w := f.do("POST", "/api/board/threads", email, map[string]any{"audience": audience, "subject": subject, "body": body})
	if w.Code != http.StatusOK {
		f.t.Fatalf("create as %s: status=%d body=%s", email, w.Code, w.Body)
	}
	return f.decode(w)
}

// --- create / list / audience default ---------------------------------------

func TestBoard_CreateAndListRoundTrip(t *testing.T) {
	f := newBoardFixture(t)
	th := f.createAs("alice@ctf.local", "all", "help me", "how do I do X?")
	if th["author"] != "alice" || th["subject"] != "help me" || th["audience"] != "all" {
		t.Fatalf("thread wrong: %+v", th)
	}
	msgs, _ := th["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %+v", th)
	}
	m0 := msgs[0].(map[string]any)
	if m0["author_role"] != "participant" || m0["author"] != "alice" || m0["body"] != "how do I do X?" {
		t.Fatalf("first message wrong: %+v", m0)
	}

	w := f.do("GET", "/api/board/threads", "alice@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: status=%d body=%s", w.Code, w.Body)
	}
	list := f.decode(w)
	ts, _ := list["threads"].([]any)
	if len(ts) != 1 {
		t.Fatalf("expected 1 thread in the list, got %+v", list)
	}
	summary := ts[0].(map[string]any)
	if summary["answered"] != false {
		t.Fatalf("must not be answered yet: %+v", summary)
	}
	if summary["message_count"].(float64) != 1 {
		t.Fatalf("expected message_count=1, got %+v", summary)
	}
}

// TestBoard_AudienceDefaultsToAdminFailClosed proves the fail-closed
// coercion: any audience value OTHER than the literal "all" (including
// absent, empty, or garbage) becomes "admin" (private) — never silently
// public.
func TestBoard_AudienceDefaultsToAdminFailClosed(t *testing.T) {
	cases := []struct {
		name     string
		audience any
	}{
		{"absent", nil},
		{"empty", ""},
		{"garbage", "PUBLIC"},
		{"wrong_case", "ALL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newBoardFixture(t)
			body := map[string]any{"subject": "s", "body": "b"}
			if c.audience != nil {
				body["audience"] = c.audience
			}
			w := f.do("POST", "/api/board/threads", "alice@ctf.local", body)
			if w.Code != http.StatusOK {
				t.Fatalf("create: status=%d body=%s", w.Code, w.Body)
			}
			th := f.decode(w)
			if th["audience"] != "admin" {
				t.Fatalf("expected fail-closed audience=admin for %v, got %+v", c.audience, th)
			}
		})
	}
}

// --- author/author_role hardcoding ------------------------------------------

func TestBoard_AuthorFieldsAreServerHardcoded_Create(t *testing.T) {
	f := newBoardFixture(t)
	w := f.do("POST", "/api/board/threads", "alice@ctf.local", map[string]any{
		"audience": "all", "subject": "s", "body": "b",
		"author": "mallory", "author_role": "admin",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("create: status=%d body=%s", w.Code, w.Body)
	}
	th := f.decode(w)
	if th["author"] != "alice" {
		t.Fatalf("expected thread author to be server-hardcoded (alice), got %+v", th)
	}
	msgs, _ := th["messages"].([]any)
	m0 := msgs[0].(map[string]any)
	if m0["author_role"] != "participant" || m0["author"] != "alice" {
		t.Fatalf("expected author_role/author to be server-hardcoded (participant/alice), got %+v", m0)
	}
}

func TestBoard_AuthorFieldsAreServerHardcoded_Message(t *testing.T) {
	f := newBoardFixture(t)
	th := f.createAs("alice@ctf.local", "all", "s", "b")
	tid := th["id"].(string)

	w := f.do("POST", "/api/board/threads/"+tid+"/messages", "alice@ctf.local", map[string]any{
		"body": "follow-up", "author": "mallory", "author_role": "admin",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("post message: status=%d body=%s", w.Code, w.Body)
	}
	updated := f.decode(w)
	msgs, _ := updated["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %+v", updated)
	}
	last := msgs[1].(map[string]any)
	if last["author_role"] != "participant" || last["author"] != "alice" {
		t.Fatalf("expected server-hardcoded participant/alice, got %+v", last)
	}
}

// TestBoard_AdminReplyAuthorIsFixedStaffConstant is app#292's departure from
// P25's adminReply (which used the caller's own raw email as `author`):
// this route's `author` is ALWAYS the fixed constant "staff", never the
// operator's real email, even though the request carries no author field to
// smuggle at all.
func TestBoard_AdminReplyAuthorIsFixedStaffConstant(t *testing.T) {
	f := newBoardFixture(t)
	th := f.createAs("alice@ctf.local", "admin", "help", "b")
	tid := th["id"].(string)

	w := f.do("POST", "/api/admin/board/threads/"+tid+"/reply", boardFixtureAdmin, map[string]any{"body": "we're looking into it"})
	if w.Code != http.StatusOK {
		t.Fatalf("admin reply: status=%d body=%s", w.Code, w.Body)
	}
	replied := f.decode(w)
	msgs, _ := replied["messages"].([]any)
	reply := msgs[len(msgs)-1].(map[string]any)
	if reply["author_role"] != "admin" || reply["author"] != "staff" {
		t.Fatalf("expected server-hardcoded admin/staff (never the raw operator email), got %+v", reply)
	}
}

// --- visibility: audience + cross-user (ADR the board package doc calls
// "no existence oracle") ------------------------------------------------------

// TestBoard_Visibility_AdminAudience_CrossUser404 proves the PRIVATE case:
// a different participant reading another's audience=admin thread by id
// gets 404, indistinguishable from an unknown id.
func TestBoard_Visibility_AdminAudience_CrossUser404(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "admin", "private help", "b")
	tid := alice["id"].(string)

	w := f.do("GET", "/api/board/threads/"+tid, "bob@ctf.local", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("bob reading alice's admin-audience thread: status=%d body=%s, want 404", w.Code, w.Body)
	}
	// Self access still works.
	w = f.do("GET", "/api/board/threads/"+tid, "alice@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("alice reading her own thread: status=%d body=%s, want 200", w.Code, w.Body)
	}
	// GET /api/board/threads/{tid} carries NO {user} path segment and no
	// isAdmin bypass — it is a pure participant-scoped route (authz=
	// authenticated, viewer=caller's own derived identity). An admin email
	// gets 404 here too, exactly like any other non-owner: app#292's design
	// gives admins their OWN dedicated single-thread GET
	// (GET /api/admin/board/threads/{tid}, boardAdminGetThread), not a
	// bypass baked into the participant route — proven below and in
	// TestBoard_AdminGetThread_SeesFullTextIncludingHiddenAndDeleted.
	w = f.do("GET", "/api/board/threads/"+tid, boardFixtureAdmin, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("admin via the PARTICIPANT get-thread route (no isAdmin bypass by design): status=%d body=%s, want 404", w.Code, w.Body)
	}
	// The real admin visibility path: the dedicated admin GET route.
	w = f.do("GET", "/api/admin/board/threads/"+tid, boardFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin reading alice's thread via boardAdminGetThread: status=%d body=%s, want 200", w.Code, w.Body)
	}
}

// TestBoard_AdminGetThread_SeesFullTextIncludingHiddenAndDeleted proves the
// gap-close: GET /api/admin/board/threads/{tid} bypasses the audience/
// ownership/moderation-state entitlement check entirely (isAdmin=true) — a
// PRIVATE thread, a HIDDEN thread, and a thread with a DELETED message are
// all fully readable here, with the deleted message's body still scrubbed
// to "" (a moderation content-removal, not a from-participants-only hide —
// it applies to every viewer, admin included).
func TestBoard_AdminGetThread_SeesFullTextIncludingHiddenAndDeleted(t *testing.T) {
	f := newBoardFixture(t)

	// Private (audience=admin) thread, never hidden/deleted.
	alice := f.createAs("alice@ctf.local", "admin", "private help", "secret body")
	tid := alice["id"].(string)
	w := f.do("GET", "/api/admin/board/threads/"+tid, boardFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin get private thread: status=%d body=%s, want 200", w.Code, w.Body)
	}
	got := f.decode(w)
	msgs, _ := got["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["body"] != "secret body" {
		t.Fatalf("expected the opening message's real body to round-trip for admin, got %+v", got)
	}

	// Hidden thread.
	bob := f.createAs("bob@ctf.local", "all", "public help", "b")
	tid2 := bob["id"].(string)
	if w := f.do("POST", "/api/admin/board/threads/"+tid2+"/state", boardFixtureAdmin, map[string]any{"state": "hidden"}); w.Code != http.StatusOK {
		t.Fatalf("hide: status=%d body=%s", w.Code, w.Body)
	}
	w = f.do("GET", "/api/admin/board/threads/"+tid2, boardFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin get hidden thread: status=%d body=%s, want 200", w.Code, w.Body)
	}
	if f.decode(w)["state"] != "hidden" {
		t.Fatalf("expected state=hidden to round-trip, got %+v", f.decode(w))
	}

	// Deleted message: visible to admin with state=deleted, body scrubbed.
	carol := f.createAs("carol@ctf.local", "all", "s", "message to delete")
	tid3 := carol["id"].(string)
	cmsgs, _ := carol["messages"].([]any)
	mid := cmsgs[0].(map[string]any)["id"].(string)
	if w := f.do("POST", "/api/admin/board/messages/"+mid+"/state", boardFixtureAdmin, map[string]any{"state": "deleted"}); w.Code != http.StatusOK {
		t.Fatalf("delete message: status=%d body=%s", w.Code, w.Body)
	}
	w = f.do("GET", "/api/admin/board/threads/"+tid3, boardFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin get thread with a deleted message: status=%d body=%s, want 200", w.Code, w.Body)
	}
	got = f.decode(w)
	dmsgs, _ := got["messages"].([]any)
	if len(dmsgs) != 1 {
		t.Fatalf("expected the deleted message to remain LISTED for admin (not omitted), got %+v", got)
	}
	dm := dmsgs[0].(map[string]any)
	if dm["state"] != "deleted" || dm["body"] != "" {
		t.Fatalf("expected state=deleted and body=\"\" (scrubbed, even for admin), got %+v", dm)
	}
}

// TestBoard_AdminGetThread_NonAdminForbidden proves the admin gate itself:
// a non-admin identity gets 403, never reaching the entitlement bypass at
// all (regardless of whether they own the thread).
func TestBoard_AdminGetThread_NonAdminForbidden(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "all", "s", "b")
	tid := alice["id"].(string)

	w := f.do("GET", "/api/admin/board/threads/"+tid, "alice@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin (even the thread's own author) on the admin GET route: status=%d body=%s, want 403", w.Code, w.Body)
	}
	w = f.do("GET", "/api/admin/board/threads/"+tid, "mallory@ctf.local", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unrelated non-admin identity on the admin GET route: status=%d body=%s, want 403", w.Code, w.Body)
	}
}

// TestBoard_AdminGetThread_UnknownTid404 proves the unknown-id case on the
// new route specifically (TestBoard_UnknownTid404 above predates this
// route's existence).
func TestBoard_AdminGetThread_UnknownTid404(t *testing.T) {
	f := newBoardFixture(t)
	w := f.do("GET", "/api/admin/board/threads/does-not-exist", boardFixtureAdmin, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", w.Code, w.Body)
	}
}

// TestBoard_Visibility_AllAudience_CrossUser200 proves the PUBLIC case: any
// other authenticated participant CAN read an audience=all thread.
func TestBoard_Visibility_AllAudience_CrossUser200(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "all", "public help", "b")
	tid := alice["id"].(string)

	w := f.do("GET", "/api/board/threads/"+tid, "bob@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("bob reading alice's all-audience thread: status=%d body=%s, want 200", w.Code, w.Body)
	}
}

// TestBoard_OwnThreadOnly_CrossUserMessage404 is the WRITE-path IDOR case
// (mirrors P25's TestQA_IDOR_CrossUserPostMessage404): bob posting a
// follow-up to alice's thread — even her PUBLIC one — must 404, because
// boardAppendMessage is own-thread-only regardless of audience (liking is
// the only cross-user write an all-audience thread permits).
func TestBoard_OwnThreadOnly_CrossUserMessage404(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "all", "s", "b")
	tid := alice["id"].(string)

	w := f.do("POST", "/api/board/threads/"+tid+"/messages", "bob@ctf.local", map[string]any{"body": "sneaky"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("bob posting to alice's thread: status=%d body=%s, want 404", w.Code, w.Body)
	}

	got := f.decode(f.do("GET", "/api/board/threads/"+tid, "alice@ctf.local", nil))
	msgs, _ := got["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("expected the rejected cross-user post to leave the thread untouched, got %d messages: %+v", len(msgs), got)
	}
}

// TestBoard_UnknownTid404 proves an unknown id behaves identically across
// every id-addressed route.
func TestBoard_UnknownTid404(t *testing.T) {
	f := newBoardFixture(t)
	cases := []struct {
		method, target, email string
		body                  any
	}{
		{"GET", "/api/board/threads/does-not-exist", "alice@ctf.local", nil},
		{"POST", "/api/board/threads/does-not-exist/messages", "alice@ctf.local", map[string]any{"body": "x"}},
		{"POST", "/api/admin/board/threads/does-not-exist/reply", boardFixtureAdmin, map[string]any{"body": "x"}},
		{"POST", "/api/admin/board/threads/does-not-exist/state", boardFixtureAdmin, map[string]any{"pinned": true}},
		{"POST", "/api/admin/board/messages/does-not-exist/state", boardFixtureAdmin, map[string]any{"state": "hidden"}},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.target, func(t *testing.T) {
			w := f.do(c.method, c.target, c.email, c.body)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s, want 404", w.Code, w.Body)
			}
		})
	}
}

// --- reply admin-only ---------------------------------------------------------

// TestBoard_ParticipantCannotUseAdminReplyRoute proves the admin reply
// route itself is admin-gated (authz=admin) — a participant cannot reach
// it at all, unlike P25 where a technically-reachable-but-self-detecting
// misuse path existed on the PARTICIPANT route. This is the inverse check:
// TestBoard_ParticipantMessageRouteNeverSetsAdminRole below covers the
// self-detecting half.
func TestBoard_ParticipantCannotUseAdminReplyRoute(t *testing.T) {
	f := newBoardFixture(t)
	th := f.createAs("alice@ctf.local", "admin", "help", "b")
	tid := th["id"].(string)

	w := f.do("POST", "/api/admin/board/threads/"+tid+"/reply", "alice@ctf.local", map[string]any{"body": "trying to reply as myself"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("participant using admin reply route: status=%d body=%s, want 403", w.Code, w.Body)
	}
}

// TestBoard_ParticipantMessageRouteNeverSetsAdminRole is the self-detecting
// half (mirrors P25's TestQA_ParticipantPathAdminMisuseNeverFlipsAnswered):
// even though authz=authenticated grants ANY proven identity — including an
// admin's — access to boardAppendMessage, that route hardcodes
// author_role="participant" unconditionally, so an admin identity posting
// through it (to their OWN thread — cross-user is still 404, see above)
// never contributes an "admin" message.
func TestBoard_ParticipantMessageRouteNeverSetsAdminRole(t *testing.T) {
	f := newBoardFixture(t)
	th := f.createAs(boardFixtureAdmin, "all", "help", "b")
	tid := th["id"].(string)

	w := f.do("POST", "/api/board/threads/"+tid+"/messages", boardFixtureAdmin, map[string]any{"body": "misused path"})
	if w.Code != http.StatusOK {
		t.Fatalf("admin via participant message route: status=%d body=%s, want 200", w.Code, w.Body)
	}
	updated := f.decode(w)
	msgs, _ := updated["messages"].([]any)
	last := msgs[len(msgs)-1].(map[string]any)
	if last["author_role"] != "participant" {
		t.Fatalf("expected author_role=participant even for an admin identity on this route, got %+v", last)
	}
	if updated["answered"] != false {
		t.Fatalf("thread must still be unanswered — only boardAdminReply/boardAdminSetThreadState may flip it, got %+v", updated)
	}
}

// --- like / unlike -----------------------------------------------------------

func TestBoard_LikeToggle(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "all", "s", "b")
	tid := alice["id"].(string)

	w := f.do("POST", "/api/board/threads/"+tid+"/like", "bob@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("like: status=%d body=%s", w.Code, w.Body)
	}
	got := f.decode(w)
	if got["liked"] != true || got["like_count"].(float64) != 1 {
		t.Fatalf("expected liked=true, like_count=1, got %+v", got)
	}

	// Idempotent: liking again is a harmless no-op, still liked=true count=1.
	w = f.do("POST", "/api/board/threads/"+tid+"/like", "bob@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("second like: status=%d body=%s", w.Code, w.Body)
	}
	got = f.decode(w)
	if got["like_count"].(float64) != 1 {
		t.Fatalf("expected a second like to be a no-op (count still 1), got %+v", got)
	}

	w = f.do("POST", "/api/board/threads/"+tid+"/unlike", "bob@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("unlike: status=%d body=%s", w.Code, w.Body)
	}
	got = f.decode(w)
	if got["liked"] != false || got["like_count"].(float64) != 0 {
		t.Fatalf("expected liked=false, like_count=0 after unlike, got %+v", got)
	}
}

// TestBoard_SelfLikeRejected proves board.ErrSelfLike surfaces as 409.
func TestBoard_SelfLikeRejected(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "all", "s", "b")
	tid := alice["id"].(string)

	w := f.do("POST", "/api/board/threads/"+tid+"/like", "alice@ctf.local", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("self-like: status=%d body=%s, want 409", w.Code, w.Body)
	}
}

// TestBoard_LikeRejectsAdminAudienceThread proves board.Store.Like's
// audience=all-only guard surfaces as the SAME 404 an unknown tid would (no
// existence/audience oracle).
func TestBoard_LikeRejectsAdminAudienceThread(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "admin", "s", "b")
	tid := alice["id"].(string)

	w := f.do("POST", "/api/board/threads/"+tid+"/like", boardFixtureAdmin, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("liking an admin-audience thread: status=%d body=%s, want 404", w.Code, w.Body)
	}
}

// TestBoard_Unlike_HiddenThreadDoesNotLeakCount proves boardUnlike's
// response never leaks a hidden thread's real like_count (security+qa
// review, app#292 Phase 3 — boardLikeStatus previously called GetThread
// with isAdmin=true, bypassing the participant entitlement check entirely).
// bob genuinely likes the thread while it is still visible (so a real
// board_likes row exists and the count really is 1), an admin then hides
// the thread, and bob's Unlike call — which Store.Unlike always succeeds at
// unconditionally, hidden or not — must report the fail-closed zero value,
// not the real underlying count.
func TestBoard_Unlike_HiddenThreadDoesNotLeakCount(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "all", "s", "b")
	tid := alice["id"].(string)

	w := f.do("POST", "/api/board/threads/"+tid+"/like", "bob@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("like: status=%d body=%s", w.Code, w.Body)
	}
	got := f.decode(w)
	if got["like_count"].(float64) != 1 {
		t.Fatalf("expected like_count=1 before hiding, got %+v", got)
	}

	w = f.do("POST", "/api/admin/board/threads/"+tid+"/state", boardFixtureAdmin, map[string]any{"state": "hidden"})
	if w.Code != http.StatusOK {
		t.Fatalf("hide: status=%d body=%s", w.Code, w.Body)
	}

	w = f.do("POST", "/api/board/threads/"+tid+"/unlike", "bob@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("unlike on a hidden thread: status=%d body=%s, want 200 (Unlike is unconditional)", w.Code, w.Body)
	}
	got = f.decode(w)
	if got["liked"] != false || got["like_count"].(float64) != 0 {
		t.Fatalf("expected liked=false, like_count=0 for a hidden thread (no count leak), got %+v", got)
	}
}

// --- moderation ----------------------------------------------------------------

// TestBoard_ModerationHiddenThread_NotVisibleToNonAdmin proves state=hidden
// removes a thread from a non-admin's list AND get, while the admin still
// sees it.
func TestBoard_ModerationHiddenThread_NotVisibleToNonAdmin(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "all", "s", "b")
	tid := alice["id"].(string)

	w := f.do("POST", "/api/admin/board/threads/"+tid+"/state", boardFixtureAdmin, map[string]any{"state": "hidden"})
	if w.Code != http.StatusOK {
		t.Fatalf("hide: status=%d body=%s", w.Code, w.Body)
	}

	w = f.do("GET", "/api/board/threads/"+tid, "bob@ctf.local", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("bob reading a hidden thread: status=%d body=%s, want 404", w.Code, w.Body)
	}
	w = f.do("GET", "/api/board/threads/"+tid, "alice@ctf.local", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("even the author reading their own hidden thread: status=%d body=%s, want 404", w.Code, w.Body)
	}

	list := f.decode(f.do("GET", "/api/board/threads", "bob@ctf.local", nil))
	ts, _ := list["threads"].([]any)
	if len(ts) != 0 {
		t.Fatalf("hidden thread must not appear in a non-admin listing, got %+v", list)
	}

	// GET /api/board/threads/{tid} is a pure participant route with no
	// isAdmin bypass (see TestBoard_Visibility_AdminAudience_CrossUser404's
	// doc) — even the admin gets 404 through it. Admin still sees the
	// thread through its OWN surfaces: the moderation queue listing, and
	// the dedicated GET /api/admin/board/threads/{tid}.
	w = f.do("GET", "/api/board/threads/"+tid, boardFixtureAdmin, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("admin via the PARTICIPANT get-thread route: status=%d body=%s, want 404 (no isAdmin bypass by design)", w.Code, w.Body)
	}
	adminList := f.decode(f.do("GET", "/api/admin/board/threads", boardFixtureAdmin, nil))
	adminTs, _ := adminList["threads"].([]any)
	if len(adminTs) != 1 {
		t.Fatalf("admin listing must still include the hidden thread, got %+v", adminList)
	}
	w = f.do("GET", "/api/admin/board/threads/"+tid, boardFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin reading the hidden thread via boardAdminGetThread: status=%d body=%s, want 200", w.Code, w.Body)
	}

	// Same non-admin exclusion for state=deleted (qa review coverage,
	// app#292 Phase 3 — the hidden case above was already covered; deleted
	// shares visibleToParticipant's same `t.state = 'visible'` guard so it
	// must behave identically for a fresh thread).
	deletedTid := f.createAs("alice@ctf.local", "all", "s2", "b2")["id"].(string)
	w = f.do("POST", "/api/admin/board/threads/"+deletedTid+"/state", boardFixtureAdmin, map[string]any{"state": "deleted"})
	if w.Code != http.StatusOK {
		t.Fatalf("delete: status=%d body=%s", w.Code, w.Body)
	}
	w = f.do("GET", "/api/board/threads/"+deletedTid, "bob@ctf.local", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("bob reading a deleted thread: status=%d body=%s, want 404", w.Code, w.Body)
	}
	w = f.do("GET", "/api/board/threads/"+deletedTid, "alice@ctf.local", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("even the author reading their own deleted thread: status=%d body=%s, want 404", w.Code, w.Body)
	}
	deletedList := f.decode(f.do("GET", "/api/board/threads", "bob@ctf.local", nil))
	deletedTs, _ := deletedList["threads"].([]any)
	if len(deletedTs) != 0 {
		t.Fatalf("deleted thread must not appear in a non-admin listing, got %+v", deletedList)
	}
	w = f.do("GET", "/api/admin/board/threads/"+deletedTid, boardFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin reading the deleted thread via boardAdminGetThread: status=%d body=%s, want 200", w.Code, w.Body)
	}
}

// TestBoard_ModerationDeletedMessage_BodyScrubbedForEveryone proves
// state=deleted on a MESSAGE scrubs its body to "" in every response,
// including the admin's.
func TestBoard_ModerationDeletedMessage_BodyScrubbedForEveryone(t *testing.T) {
	f := newBoardFixture(t)
	alice := f.createAs("alice@ctf.local", "all", "s", "secret opening body")
	tid := alice["id"].(string)
	msgs, _ := alice["messages"].([]any)
	mid := msgs[0].(map[string]any)["id"].(string)

	w := f.do("POST", "/api/admin/board/messages/"+mid+"/state", boardFixtureAdmin, map[string]any{"state": "deleted"})
	if w.Code != http.StatusOK {
		t.Fatalf("delete message: status=%d body=%s", w.Code, w.Body)
	}
	result := f.decode(w)
	if result["state"] != "deleted" {
		t.Fatalf("expected state=deleted in the result, got %+v", result)
	}

	// Admin's own view (via boardAdminGetThread, the dedicated admin
	// single-thread read path) still shows the message (state=deleted),
	// but body="".
	got := f.decode(f.do("GET", "/api/admin/board/threads/"+tid, boardFixtureAdmin, nil))
	adminMsgs, _ := got["messages"].([]any)
	if len(adminMsgs) != 1 {
		t.Fatalf("expected the deleted message to remain listed for admin, got %+v", got)
	}
	if adminMsgs[0].(map[string]any)["body"] != "" {
		t.Fatalf("expected the deleted message's body to be scrubbed to \"\" even for admin, got %+v", adminMsgs[0])
	}
	if adminMsgs[0].(map[string]any)["state"] != "deleted" {
		t.Fatalf("expected the message's own state=deleted to still be visible to admin, got %+v", adminMsgs[0])
	}

	// The AUTHOR (a non-admin viewer) gets the STRONGER omission behaviour:
	// board.go's own doc distinguishes "hidden/deleted messages are omitted
	// from the slice ENTIRELY" for isAdmin=false from "body scrubbed to ''"
	// for isAdmin=true — a deleted message vanishes completely from a
	// participant's own view, it is not merely blanked.
	got = f.decode(f.do("GET", "/api/board/threads/"+tid, "alice@ctf.local", nil))
	authorMsgs, _ := got["messages"].([]any)
	if len(authorMsgs) != 0 {
		t.Fatalf("expected the deleted message to be OMITTED ENTIRELY from the author's own (non-admin) view, got %+v", got)
	}
}

// TestBoard_InvalidModerationState400 proves board.ErrInvalidState surfaces
// as a stable 400 for both the thread-state and message-state routes.
func TestBoard_InvalidModerationState400(t *testing.T) {
	f := newBoardFixture(t)
	th := f.createAs("alice@ctf.local", "all", "s", "b")
	tid := th["id"].(string)
	msgs, _ := th["messages"].([]any)
	mid := msgs[0].(map[string]any)["id"].(string)

	w := f.do("POST", "/api/admin/board/threads/"+tid+"/state", boardFixtureAdmin, map[string]any{"state": "not-a-state"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid thread state: status=%d body=%s, want 400", w.Code, w.Body)
	}
	w = f.do("POST", "/api/admin/board/messages/"+mid+"/state", boardFixtureAdmin, map[string]any{"state": "not-a-state"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid message state: status=%d body=%s, want 400", w.Code, w.Body)
	}
}

// --- flag-shape rejection (fairness gate) -------------------------------------

// TestBoard_FlagShapeRejected_ThreeWritePaths proves every free-text board
// write (thread creation, own follow-up, admin reply) rejects a
// FALCO{...}-shaped body with 400, regardless of whether the braces
// contain a real, in-play flag value (this is a SHAPE check, never a
// value comparison — see flagShapePattern's own doc).
func TestBoard_FlagShapeRejected_ThreeWritePaths(t *testing.T) {
	const flaggy = "the flag is FALCO{not-even-real} trust me"

	t.Run("create_thread", func(t *testing.T) {
		f := newBoardFixture(t)
		w := f.do("POST", "/api/board/threads", "alice@ctf.local", map[string]any{"audience": "all", "subject": "s", "body": flaggy})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
		}
	})
	// create_thread_subject proves the SUBJECT is checked too, independent
	// of body (security+qa review, app#292 Phase 3 — subject was NOT
	// checked in Phase 2, a public audience=all thread's subject is
	// rendered to every participant exactly like its body). The body here
	// is deliberately clean, so a subject-only gate is the only thing that
	// can turn this 400 — removing the subject check makes this red.
	t.Run("create_thread_subject", func(t *testing.T) {
		f := newBoardFixture(t)
		w := f.do("POST", "/api/board/threads", "alice@ctf.local", map[string]any{"audience": "all", "subject": flaggy, "body": "clean body, no flag here"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
		}
	})
	// create_thread_subject_empty_braces is flagShapePattern's own
	// documented boundary case (`FALCO{}` — empty braces — is still
	// rejected) exercised specifically through subject, not body.
	t.Run("create_thread_subject_empty_braces", func(t *testing.T) {
		f := newBoardFixture(t)
		w := f.do("POST", "/api/board/threads", "alice@ctf.local", map[string]any{"audience": "all", "subject": "FALCO{}", "body": "clean body, no flag here"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
		}
	})
	t.Run("append_message", func(t *testing.T) {
		f := newBoardFixture(t)
		tid := f.createAs("alice@ctf.local", "all", "s", "b")["id"].(string)
		w := f.do("POST", "/api/board/threads/"+tid+"/messages", "alice@ctf.local", map[string]any{"body": flaggy})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
		}
	})
	t.Run("admin_reply", func(t *testing.T) {
		f := newBoardFixture(t)
		tid := f.createAs("alice@ctf.local", "admin", "s", "b")["id"].(string)
		w := f.do("POST", "/api/admin/board/threads/"+tid+"/reply", boardFixtureAdmin, map[string]any{"body": flaggy})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
		}
	})
}

// TestBoard_BareFalcoWordAllowed is flagShapePattern's negative case: the
// bare word "FALCO" with no braces must NOT be rejected — a participant
// should still be able to say "I'm stuck on the FALCO mission" in a support
// thread. Covers both body (Phase 2) and subject (Phase 3 — the new check
// added alongside body's) independently, so a subject check that
// over-rejects (matching bare "FALCO" too) is caught here.
func TestBoard_BareFalcoWordAllowed(t *testing.T) {
	t.Run("body", func(t *testing.T) {
		f := newBoardFixture(t)
		w := f.do("POST", "/api/board/threads", "alice@ctf.local", map[string]any{
			"audience": "all", "subject": "s", "body": "I'm stuck on the FALCO mission, help?",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("bare FALCO word in body: status=%d body=%s, want 200", w.Code, w.Body)
		}
	})
	t.Run("subject", func(t *testing.T) {
		f := newBoardFixture(t)
		w := f.do("POST", "/api/board/threads", "alice@ctf.local", map[string]any{
			"audience": "all", "subject": "stuck on the FALCO mission", "body": "help?",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("bare FALCO word in subject: status=%d body=%s, want 200", w.Code, w.Body)
		}
	})
}

// --- validation caps -----------------------------------------------------------

func TestBoard_ValidationCaps(t *testing.T) {
	longSubject := strings.Repeat("a", 121)
	longBody := strings.Repeat("b", 4097)

	cases := []struct {
		name    string
		subject string
		body    string
	}{
		{"subject too long", longSubject, "ok"},
		{"body too long", "ok", longBody},
		{"empty subject", "", "ok"},
		{"empty body", "ok", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newBoardFixture(t)
			w := f.do("POST", "/api/board/threads", "alice@ctf.local", map[string]any{"audience": "all", "subject": c.subject, "body": c.body})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
			}
		})
	}
}

func TestBoard_ValidationCaps_BoundaryExactSucceeds(t *testing.T) {
	subject := strings.Repeat("a", 120)
	body := strings.Repeat("b", 4096)

	f := newBoardFixture(t)
	w := f.do("POST", "/api/board/threads", "alice@ctf.local", map[string]any{"audience": "all", "subject": subject, "body": body})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 (subject=120 runes / body=4096 bytes is the cap itself, not one over)", w.Code, w.Body)
	}
	th := f.decode(w)
	if th["subject"] != subject {
		t.Fatalf("subject not round-tripped verbatim: got %v", th["subject"])
	}
}

// --- decode-error path (Issue #113 discipline, mirrors qa_errorleak_test.go)

func TestBoard_ErrorLeak_InvalidBody_CreateThread(t *testing.T) {
	f := newBoardFixture(t)
	w := f.doRaw("POST", "/api/board/threads", "alice@ctf.local", "{")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", w.Code)
	}
	got := f.decode(w)
	if got["error"] != "invalid request body" {
		t.Fatalf("expected the stable errMsgInvalidBody text, got %+v", got)
	}
}

func TestBoard_ErrorLeak_InvalidBody_AppendMessage(t *testing.T) {
	f := newBoardFixture(t)
	tid := f.createAs("alice@ctf.local", "all", "s", "b")["id"].(string)
	w := f.doRaw("POST", "/api/board/threads/"+tid+"/messages", "alice@ctf.local", "{")
	got := f.decode(w)
	if w.Code != http.StatusBadRequest || got["error"] != "invalid request body" {
		t.Fatalf("status=%d body=%+v, want 400 with the stable invalid-body text", w.Code, got)
	}
}

func TestBoard_ErrorLeak_InvalidBody_AdminReply(t *testing.T) {
	f := newBoardFixture(t)
	tid := f.createAs("alice@ctf.local", "admin", "s", "b")["id"].(string)
	w := f.doRaw("POST", "/api/admin/board/threads/"+tid+"/reply", boardFixtureAdmin, "{")
	got := f.decode(w)
	if w.Code != http.StatusBadRequest || got["error"] != "invalid request body" {
		t.Fatalf("status=%d body=%+v, want 400 with the stable invalid-body text", w.Code, got)
	}
}

// --- structural: the declared route set is exactly app#292 Phase 2's ten --

// TestBoard_DeclaredRouteSetIsExactlyPhase2sElevenRoutes mechanically pins
// the board route family: 6 participant (all under /api/board/) + 5
// operator (all under /api/admin/board/, including the post-review
// gap-close boardAdminGetThread) = 11. Mirrors P25's
// TestQA_DeclaredRouteSetIsExactlyDecision1sSevenRoutes.
func TestBoard_DeclaredRouteSetIsExactlyPhase2sElevenRoutes(t *testing.T) {
	f := newBoardFixture(t)
	want := map[string]bool{
		"GET /api/board/threads":                     true,
		"GET /api/board/threads/{tid}":                true,
		"POST /api/board/threads":                     true,
		"POST /api/board/threads/{tid}/messages":      true,
		"POST /api/board/threads/{tid}/like":          true,
		"POST /api/board/threads/{tid}/unlike":        true,
		"GET /api/admin/board/threads":                true,
		"GET /api/admin/board/threads/{tid}":          true,
		"POST /api/admin/board/threads/{tid}/reply":   true,
		"POST /api/admin/board/threads/{tid}/state":   true,
		"POST /api/admin/board/messages/{mid}/state":  true,
	}
	got := map[string]bool{}
	for _, rt := range f.srv.Routes() {
		if _, ok := want[rt.MuxPattern()]; ok {
			got[rt.MuxPattern()] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("expected exactly the 11 app#292 Phase 2 routes, found %d of them in Routes(): %v", len(got), got)
	}
}
