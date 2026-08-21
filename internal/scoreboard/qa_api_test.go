package scoreboard_test

// P25 QA ticket-chat handler tests (ADR-0006). TestAuthz_AllDeclaredGatesEnforced
// (authz_test.go) and TestOriginGuard_AllProtectedRoutesEnforced
// (origin_guard_test.go) already derive their case tables from srv.Routes()
// and so exercise every QA route's authz/origin-guard classification
// generically; this file adds the QA-SPECIFIC behavioural assertions ADR-0006's
// own Verification section calls out by name, which those generic loops
// cannot: the composite-key IDOR check (Verification 3, including the
// WRITE-path case security-engineer finding 2 added explicitly), the
// author/author_role server-hardcoding (Decision 1 / finding 1), the derived
// `answered` field and the "participant path never flips it" self-detection
// property (Decision 1 / finding 5), and the shared create+message rate-limit
// bucket (Decision 1).

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/qa"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

const (
	qaFixtureOrigin = "https://scoreboard.ctf.local"
	qaFixtureAdmin  = "admin@ctf.local"
)

type qaFixture struct {
	t   *testing.T
	srv *scoreboard.Handler
}

func newQAFixture(t *testing.T, extra ...scoreboard.Option) *qaFixture {
	t.Helper()
	cat := catalog.Catalog{
		"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "qaapi.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	qaSt, err := qa.Open(filepath.Join(t.TempDir(), "qaapi-qa.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { qaSt.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	opts := append([]scoreboard.Option{
		scoreboard.WithAdminEmails([]string{qaFixtureAdmin}),
		scoreboard.WithAllowedOrigins([]string{qaFixtureOrigin}),
		scoreboard.WithQA(qaSt),
	}, extra...)
	srv := scoreboard.NewHandler(cat, st, logger, opts...)
	return &qaFixture{t: t, srv: srv}
}

// do issues a request carrying Origin (so origin-guarded write routes are
// never collaterally denied by P23-2 — this file exercises the authz/IDOR
// gates, not the origin guard, which already has its own dedicated coverage
// in origin_guard_test.go) and, when email is non-empty,
// X-Auth-Request-Email.
func (f *qaFixture) do(method, target, email string, body any) *httptest.ResponseRecorder {
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
	r.Header.Set("Origin", qaFixtureOrigin)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func (f *qaFixture) decode(w *httptest.ResponseRecorder) map[string]any {
	f.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		f.t.Fatalf("decode JSON: %v (body=%s)", err, w.Body)
	}
	return m
}

// createAs is a convenience wrapper: alice (or whoever email belongs to)
// opens a ticket as {user}, asserting 200, and returns the decoded
// QuestionThread.
func (f *qaFixture) createAs(user, email, subject, body string) map[string]any {
	f.t.Helper()
	w := f.do("POST", "/api/users/"+user+"/questions", email, map[string]any{"subject": subject, "body": body})
	if w.Code != http.StatusOK {
		f.t.Fatalf("create as %s (email=%s): status=%d body=%s", user, email, w.Code, w.Body)
	}
	return f.decode(w)
}

// --- create / list ----------------------------------------------------------

func TestQA_CreateAndListRoundTrip(t *testing.T) {
	f := newQAFixture(t)
	th := f.createAs("alice", "alice@ctf.local", "help me", "how do I do X?")
	if th["user"] != "alice" || th["subject"] != "help me" {
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

	w := f.do("GET", "/api/users/alice/questions", "alice@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: status=%d body=%s", w.Code, w.Body)
	}
	list := f.decode(w)
	qs, _ := list["questions"].([]any)
	if len(qs) != 1 {
		t.Fatalf("expected 1 ticket in the list, got %+v", list)
	}
	summary := qs[0].(map[string]any)
	if summary["answered"] != false {
		t.Fatalf("must not be answered yet: %+v", summary)
	}
	if _, hasUser := summary["user"]; hasUser {
		t.Fatalf("participant's own listing must NOT carry a user field, got %+v", summary)
	}
	if summary["message_count"].(float64) != 1 {
		t.Fatalf("expected message_count=1, got %+v", summary)
	}
}

// TestQA_AuthorFieldsAreServerHardcoded_Create is security-engineer finding
// 1 (HIGH): a participant sending author/author_role in the create body
// must have them silently ignored — the recorded message is always
// author_role="participant", author="{user}".
func TestQA_AuthorFieldsAreServerHardcoded_Create(t *testing.T) {
	f := newQAFixture(t)
	w := f.do("POST", "/api/users/alice/questions", "alice@ctf.local", map[string]any{
		"subject":     "s",
		"body":        "b",
		"author":      "mallory",
		"author_role": "admin",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("create: status=%d body=%s", w.Code, w.Body)
	}
	th := f.decode(w)
	msgs, _ := th["messages"].([]any)
	m0 := msgs[0].(map[string]any)
	if m0["author_role"] != "participant" || m0["author"] != "alice" {
		t.Fatalf("expected author_role/author to be server-hardcoded (participant/alice), got %+v", m0)
	}
}

// TestQA_AuthorFieldsAreServerHardcoded_Message is finding 1 applied to the
// follow-up-message route.
func TestQA_AuthorFieldsAreServerHardcoded_Message(t *testing.T) {
	f := newQAFixture(t)
	th := f.createAs("alice", "alice@ctf.local", "s", "b")
	qid := th["id"].(string)

	w := f.do("POST", "/api/users/alice/questions/"+qid+"/messages", "alice@ctf.local", map[string]any{
		"body":        "follow-up",
		"author":      "mallory",
		"author_role": "admin",
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

// TestQA_ValidationCaps asserts subject/body length caps (ADR-0006 Decision
// 1: subject <=120 runes, body <=4096 bytes) reject with 400, and empty
// values are rejected too.
func TestQA_ValidationCaps(t *testing.T) {
	longSubject := make([]byte, 121)
	for i := range longSubject {
		longSubject[i] = 'a'
	}
	longBody := make([]byte, 4097)
	for i := range longBody {
		longBody[i] = 'b'
	}

	cases := []struct {
		name    string
		subject string
		body    string
	}{
		{"subject too long", string(longSubject), "ok"},
		{"body too long", "ok", string(longBody)},
		{"empty subject", "", "ok"},
		{"empty body", "ok", ""},
	}
	// Each case gets its OWN fixture: questionLimiter's burst (3) is shared
	// across every write this handler serves, so four sequential creates
	// against ONE fixture would hit 429 on the last case before its body is
	// ever validated — testing the rate limiter instead of the validation
	// this test is about.
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newQAFixture(t)
			w := f.do("POST", "/api/users/alice/questions", "alice@ctf.local", map[string]any{"subject": c.subject, "body": c.body})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body)
			}
		})
	}
}

// --- self / mismatch / prefix-adjacent / admin 4-way ------------------------
// (ADR-0006 Verification 2, same shape as journey_api_test.go's
// TestJourneyWriteGate_StepCheck_HeaderPresent.)

// TestQA_WriteGate_CreateQuestion_FourWay uses a FRESH fixture per branch
// (rather than four calls against one shared fixture): questionLimiter's
// burst (3) is shared across every QA write, and every branch below reaches
// the rate limiter BEFORE the identity gate under test runs (h.og wraps
// questionMW wraps createQuestion — see api.go's Routes()) — a mismatched
// or prefix-adjacent identity's request still consumes a token even though
// the handler goes on to 403 it. Four calls on one bucket would 429 the
// last branch before its 403/200 is ever decided.
func TestQA_WriteGate_CreateQuestion_FourWay(t *testing.T) {
	body := map[string]any{"subject": "s", "body": "b"}

	t.Run("self", func(t *testing.T) {
		f := newQAFixture(t)
		if w := f.do("POST", "/api/users/alice/questions", "alice@ctf.local", body); w.Code != http.StatusOK {
			t.Fatalf("self create must 200, got %d body=%s", w.Code, w.Body)
		}
	})
	t.Run("cross_user", func(t *testing.T) {
		f := newQAFixture(t)
		if w := f.do("POST", "/api/users/alice/questions", "mallory@ctf.local", body); w.Code != http.StatusForbidden {
			t.Fatalf("cross-user create must 403, got %d body=%s", w.Code, w.Body)
		}
	})
	t.Run("prefix_adjacent", func(t *testing.T) {
		// alice2@ must NOT satisfy alice (I8 anti-mismatch)
		f := newQAFixture(t)
		if w := f.do("POST", "/api/users/alice/questions", "alice2@ctf.local", body); w.Code != http.StatusForbidden {
			t.Fatalf("alice2 creating for alice must 403, got %d body=%s", w.Code, w.Body)
		}
	})
	t.Run("admin", func(t *testing.T) {
		f := newQAFixture(t, scoreboard.WithAdminEmails([]string{"root@ctf.local"}))
		if w := f.do("POST", "/api/users/alice/questions", "root@ctf.local", body); w.Code != http.StatusOK {
			t.Fatalf("admin create must 200, got %d body=%s", w.Code, w.Body)
		}
	})
}

// TestQA_WriteGate_PostMessage_FourWay — same fresh-fixture-per-subtest
// reasoning as TestQA_WriteGate_CreateQuestion_FourWay above (questionMW's
// 3-token burst is shared across every QA write and is consumed BEFORE the
// identity gate under test runs — h.og wraps questionMW wraps postMessage,
// api.go's Routes() — so a mismatched/prefix-adjacent call would still
// spend a token even though the handler later 403s it). Each subtest
// creates its own ticket (1st token) then makes the one postMessage call
// under test (2nd token), leaving headroom in its OWN fixture's bucket.
func TestQA_WriteGate_PostMessage_FourWay(t *testing.T) {
	body := map[string]any{"body": "follow-up"}

	t.Run("self", func(t *testing.T) {
		f := newQAFixture(t)
		qid := f.createAs("alice", "alice@ctf.local", "s", "b")["id"].(string)
		if w := f.do("POST", "/api/users/alice/questions/"+qid+"/messages", "alice@ctf.local", body); w.Code != http.StatusOK {
			t.Fatalf("self post must 200, got %d body=%s", w.Code, w.Body)
		}
	})
	t.Run("cross_user", func(t *testing.T) {
		f := newQAFixture(t)
		qid := f.createAs("alice", "alice@ctf.local", "s", "b")["id"].(string)
		if w := f.do("POST", "/api/users/alice/questions/"+qid+"/messages", "mallory@ctf.local", body); w.Code != http.StatusForbidden {
			t.Fatalf("cross-user post must 403, got %d body=%s", w.Code, w.Body)
		}
	})
	t.Run("prefix_adjacent", func(t *testing.T) {
		f := newQAFixture(t)
		qid := f.createAs("alice", "alice@ctf.local", "s", "b")["id"].(string)
		if w := f.do("POST", "/api/users/alice/questions/"+qid+"/messages", "alice2@ctf.local", body); w.Code != http.StatusForbidden {
			t.Fatalf("alice2 posting for alice must 403, got %d body=%s", w.Code, w.Body)
		}
	})
	t.Run("admin", func(t *testing.T) {
		f := newQAFixture(t, scoreboard.WithAdminEmails([]string{"root@ctf.local"}))
		qid := f.createAs("alice", "alice@ctf.local", "s", "b")["id"].(string)
		if w := f.do("POST", "/api/users/alice/questions/"+qid+"/messages", "root@ctf.local", body); w.Code != http.StatusOK {
			t.Fatalf("admin post must 200, got %d body=%s", w.Code, w.Body)
		}
	})
}

func TestQA_ReadGate_ListAndGetQuestion_ThreeWay(t *testing.T) {
	f := newQAFixture(t, scoreboard.WithAdminEmails([]string{"root@ctf.local"}))
	th := f.createAs("alice", "alice@ctf.local", "s", "b")
	qid := th["id"].(string)

	for _, target := range []string{"/api/users/alice/questions", "/api/users/alice/questions/" + qid} {
		if w := f.do("GET", target, "alice@ctf.local", nil); w.Code != http.StatusOK {
			t.Fatalf("%s: self read must 200, got %d body=%s", target, w.Code, w.Body)
		}
		if w := f.do("GET", target, "mallory@ctf.local", nil); w.Code != http.StatusForbidden {
			t.Fatalf("%s: cross-user read must 403, got %d body=%s", target, w.Code, w.Body)
		}
		if w := f.do("GET", target, "root@ctf.local", nil); w.Code != http.StatusOK {
			t.Fatalf("%s: admin read must 200, got %d body=%s", target, w.Code, w.Body)
		}
	}
}

// --- IDOR: composite-key ownership check (ADR-0006 Verification 3) --------

// TestQA_IDOR_CrossUserGetQuestion404 proves the READ side: bob (a
// legitimately-authenticated participant, not a mismatched identity) hitting
// alice's OWN {user} path segment cannot happen (selfOrAdmin already blocks
// that — see the four-way tests above); the interesting IDOR case is bob
// reading through HIS OWN {user} path with alice's qid, which selfOrAdmin
// happily authorizes (bob may read routes under /api/users/bob/...) — the
// qid does not belong to him, and only the composite-key check inside
// qa.Store catches that.
func TestQA_IDOR_CrossUserGetQuestion404(t *testing.T) {
	f := newQAFixture(t)
	alice := f.createAs("alice", "alice@ctf.local", "alice's ticket", "b")
	qid := alice["id"].(string)

	w := f.do("GET", "/api/users/bob/questions/"+qid, "bob@ctf.local", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("bob reading alice's qid via his own user path: status=%d body=%s, want 404", w.Code, w.Body)
	}
	// Self access still works.
	w = f.do("GET", "/api/users/alice/questions/"+qid, "alice@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("alice reading her own qid: status=%d body=%s, want 200", w.Code, w.Body)
	}
}

// TestQA_IDOR_CrossUserPostMessage404 is Verification 3's WRITE-path case
// (security-engineer finding 2, HIGH) — the one a read-only IDOR test would
// leave unexercised: bob posting a follow-up to alice's qid through his OWN
// {user} path (selfOrAdminWrite authorizes bob-as-bob; the qid ownership
// check is what must still reject it).
func TestQA_IDOR_CrossUserPostMessage404(t *testing.T) {
	f := newQAFixture(t)
	alice := f.createAs("alice", "alice@ctf.local", "alice's ticket", "b")
	qid := alice["id"].(string)

	w := f.do("POST", "/api/users/bob/questions/"+qid+"/messages", "bob@ctf.local", map[string]any{"body": "sneaky"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("bob posting to alice's qid via his own user path: status=%d body=%s, want 404", w.Code, w.Body)
	}

	// Confirm the rejected cross-user post left no trace: alice's thread
	// still has exactly her one opening message.
	got := f.decode(f.do("GET", "/api/users/alice/questions/"+qid, "alice@ctf.local", nil))
	msgs, _ := got["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("expected the rejected cross-user post to leave the thread untouched, got %d messages: %+v", len(msgs), got)
	}
}

func TestQA_UnknownQid404(t *testing.T) {
	f := newQAFixture(t, scoreboard.WithAdminEmails([]string{"root@ctf.local"}))
	cases := []struct {
		method, target, email string
		body                  any
	}{
		{"GET", "/api/users/alice/questions/does-not-exist", "alice@ctf.local", nil},
		{"POST", "/api/users/alice/questions/does-not-exist/messages", "alice@ctf.local", map[string]any{"body": "x"}},
		{"GET", "/api/admin/questions/does-not-exist", "root@ctf.local", nil},
		{"POST", "/api/admin/questions/does-not-exist/reply", "root@ctf.local", map[string]any{"body": "x"}},
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

// --- operator ---------------------------------------------------------------

func TestQA_AdminListAndReply_FlipsAnswered(t *testing.T) {
	f := newQAFixture(t, scoreboard.WithAdminEmails([]string{qaFixtureAdmin}))
	th := f.createAs("alice", "alice@ctf.local", "help", "b")
	qid := th["id"].(string)
	f.createAs("bob", "bob@ctf.local", "also help", "b2")

	// Admin list spans every participant and carries `user`.
	list := f.decode(f.do("GET", "/api/admin/questions", qaFixtureAdmin, nil))
	qs, _ := list["questions"].([]any)
	if len(qs) != 2 {
		t.Fatalf("expected 2 tickets across both users, got %+v", list)
	}
	for _, raw := range qs {
		s := raw.(map[string]any)
		if _, ok := s["user"]; !ok {
			t.Fatalf("admin listing entries must carry user, got %+v", s)
		}
	}

	// Not yet answered.
	got := f.decode(f.do("GET", "/api/admin/questions/"+qid, qaFixtureAdmin, nil))
	if got["user"] != "alice" {
		t.Fatalf("expected alice's thread, got %+v", got)
	}

	// Reply flips answered for alice's ticket only.
	replied := f.decode(f.do("POST", "/api/admin/questions/"+qid+"/reply", qaFixtureAdmin, map[string]any{
		"body": "we're looking into it", "author": "mallory", "author_role": "participant",
	}))
	msgs, _ := replied["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages after reply, got %+v", replied)
	}
	reply := msgs[1].(map[string]any)
	// finding 1: author/author_role in the body are ignored even here.
	if reply["author_role"] != "admin" || reply["author"] != qaFixtureAdmin {
		t.Fatalf("expected server-hardcoded admin/%s, got %+v", qaFixtureAdmin, reply)
	}

	list = f.decode(f.do("GET", "/api/admin/questions", qaFixtureAdmin, nil))
	qs, _ = list["questions"].([]any)
	answered := map[string]bool{}
	for _, raw := range qs {
		s := raw.(map[string]any)
		answered[s["user"].(string)] = s["answered"].(bool)
	}
	if !answered["alice"] {
		t.Fatal("alice's ticket must be answered after the admin reply")
	}
	if answered["bob"] {
		t.Fatal("bob's ticket must remain unanswered — the reply must not leak across tickets")
	}
}

// TestQA_ParticipantPathAdminMisuseNeverFlipsAnswered is security-engineer
// finding 5 (LOW): if an admin identity is mistakenly sent through the
// PARTICIPANT follow-up route instead of the dedicated admin reply route,
// selfOrAdminWrite's admin branch lets it through — but postMessage
// hardcodes author_role="participant" unconditionally, so the ticket's
// derived `answered` must NOT flip. This is the self-detecting signal
// ADR-0006 accepts instead of a technical block.
func TestQA_ParticipantPathAdminMisuseNeverFlipsAnswered(t *testing.T) {
	f := newQAFixture(t, scoreboard.WithAdminEmails([]string{qaFixtureAdmin}))
	th := f.createAs("alice", "alice@ctf.local", "help", "b")
	qid := th["id"].(string)

	w := f.do("POST", "/api/users/alice/questions/"+qid+"/messages", qaFixtureAdmin, map[string]any{"body": "misused path"})
	if w.Code != http.StatusOK {
		t.Fatalf("admin via participant path (self-or-admin-write's admin branch): status=%d body=%s, want 200", w.Code, w.Body)
	}
	updated := f.decode(w)
	msgs, _ := updated["messages"].([]any)
	last := msgs[len(msgs)-1].(map[string]any)
	if last["author_role"] != "participant" {
		t.Fatalf("expected the misused reply to record author_role=participant (self-detecting signal), got %+v", last)
	}

	list := f.decode(f.do("GET", "/api/users/alice/questions", "alice@ctf.local", nil))
	qs, _ := list["questions"].([]any)
	if qs[0].(map[string]any)["answered"] != false {
		t.Fatalf("ticket must still be unanswered — a reply through the participant path must never flip it, got %+v", qs[0])
	}
}

// --- rate limiting -----------------------------------------------------------

// TestQA_RateLimit_SharedBucketBetweenCreateAndMessage proves ADR-0006
// Decision 1's shared bucket: burst 3 total across BOTH createQuestion and
// postQuestionMessage for the same client IP, not 3 each.
func TestQA_RateLimit_SharedBucketBetweenCreateAndMessage(t *testing.T) {
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := newQAFixture(t, scoreboard.WithNow(func() time.Time { return fixedNow }))

	// 1st: create (consumes 1 of 3).
	th := f.createAs("alice", "alice@ctf.local", "s1", "b1")
	qid := th["id"].(string)

	// 2nd: a follow-up message on the SAME bucket (consumes 2 of 3).
	if w := f.do("POST", "/api/users/alice/questions/"+qid+"/messages", "alice@ctf.local", map[string]any{"body": "f1"}); w.Code != http.StatusOK {
		t.Fatalf("2nd (message): status=%d body=%s, want 200", w.Code, w.Body)
	}

	// 3rd: another create (consumes 3 of 3, the burst).
	if w := f.do("POST", "/api/users/alice/questions", "alice@ctf.local", map[string]any{"subject": "s2", "body": "b2"}); w.Code != http.StatusOK {
		t.Fatalf("3rd (create): status=%d body=%s, want 200", w.Code, w.Body)
	}

	// 4th: burst exhausted, regardless of which of the two routes it hits.
	w := f.do("POST", "/api/users/alice/questions/"+qid+"/messages", "alice@ctf.local", map[string]any{"body": "f2"})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request (over shared burst): status=%d body=%s, want 429", w.Code, w.Body)
	}
}

// --- structural: the declared route set is exactly ADR-0006 Decision 1's --

// TestQA_DeclaredRouteSetIsExactlyDecision1sSevenRoutes mechanically pins
// ADR-0006 Verification 4's "no participant-to-participant path exists"
// claim: the 7 QA routes registered are EXACTLY Decision 1's table — in
// particular, there is no route through which one participant's {user} path
// segment can address ANOTHER participant as a message recipient (every
// participant route's {user} names the CALLER's own inbox, and the only
// party a message can be addressed "to" is implicit — the operator, via the
// admin routes' isAdmin gate, never another {user}).
func TestQA_DeclaredRouteSetIsExactlyDecision1sSevenRoutes(t *testing.T) {
	f := newQAFixture(t)
	want := map[string]bool{
		"GET /api/users/{user}/questions":                 true,
		"POST /api/users/{user}/questions":                true,
		"GET /api/users/{user}/questions/{qid}":           true,
		"POST /api/users/{user}/questions/{qid}/messages": true,
		"GET /api/admin/questions":                        true,
		"GET /api/admin/questions/{qid}":                  true,
		"POST /api/admin/questions/{qid}/reply":           true,
	}
	got := map[string]bool{}
	for _, rt := range f.srv.Routes() {
		if _, ok := want[rt.MuxPattern()]; ok {
			got[rt.MuxPattern()] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("expected exactly the 7 ADR-0006 Decision 1 routes, found %d of them in Routes(): %v", len(got), got)
	}
}
