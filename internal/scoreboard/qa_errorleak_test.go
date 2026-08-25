package scoreboard_test

// Issue #194 (Issue #113's own scope explicitly excluded qa.go — see that
// issue's text): internal/scoreboard/api/qa.go must never put a raw
// err.Error() from a JSON decode failure or a qa.Store/SQLite call into a
// response body, for the exact same reasons errorleak_test.go already pins
// for api.go. This file applies that same two-fault-injection-shape
// contract to qa.go's three json.NewDecoder call sites and its
// store-error branches, using this package's qaFixture (qa_api_test.go)
// rather than duplicating a second fixture type. newQAFixture's default
// options already wire qaFixtureAdmin as an admin email, so none of the
// admin-route tests below need to pass scoreboard.WithAdminEmails again.
//
// The four validQuestionSubject/validQuestionBody validation-error sites
// qa.go deliberately still returns err.Error() for (the same exception
// api.go's validDisplayName gets, per #113) are NOT covered here — they are
// self-crafted, non-leaking messages by construction, and
// TestQA_ValidationCaps* (qa_api_test.go) already pins their 400 behavior.
import "testing"

// --- decode-error path (malformed JSON body) --------------------------------

func TestErrorLeak_QA_InvalidBody_CreateQuestion(t *testing.T) {
	f := newQAFixture(t)
	w := f.doRaw("POST", "/api/users/alice/questions", "alice@ctf.local", "{")
	assertErrorBody(t, w, 400, "invalid request body")
}

func TestErrorLeak_QA_InvalidBody_PostMessage(t *testing.T) {
	f := newQAFixture(t)
	th := f.createAs("alice", "alice@ctf.local", "s", "b")
	qid := th["id"].(string)
	w := f.doRaw("POST", "/api/users/alice/questions/"+qid+"/messages", "alice@ctf.local", "{")
	assertErrorBody(t, w, 400, "invalid request body")
}

func TestErrorLeak_QA_InvalidBody_AdminReply(t *testing.T) {
	f := newQAFixture(t)
	th := f.createAs("alice", "alice@ctf.local", "s", "b")
	qid := th["id"].(string)
	w := f.doRaw("POST", "/api/admin/questions/"+qid+"/reply", qaFixtureAdmin, "{")
	assertErrorBody(t, w, 400, "invalid request body")
}

// --- store-error path (real SQLite failure via closed qa handle) -----------
//
// Closing f.qa before the call is fault injection with a REAL driver, not a
// mock, exactly matching errorleak_test.go's own store-error tests against
// the main store: h.qa.<Op> genuinely returns an error (sql.ErrConnDone-
// shaped), so these tests would catch a regression that reintroduced
// err.Error() in the body the way api.go's original leak (Issue #113)
// manifested — even though qa.go's current store-error branches already use
// the safe strings below (this is a REGRESSION guard, not a bug-fix proof).

func TestErrorLeak_QA_StoreError_ListQuestions(t *testing.T) {
	f := newQAFixture(t)
	if err := f.qa.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.do("GET", "/api/users/alice/questions", "alice@ctf.local", nil)
	assertErrorBody(t, w, 500, "could not list questions")
}

func TestErrorLeak_QA_StoreError_CreateQuestion(t *testing.T) {
	f := newQAFixture(t)
	if err := f.qa.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.do("POST", "/api/users/alice/questions", "alice@ctf.local", map[string]any{"subject": "s", "body": "b"})
	assertErrorBody(t, w, 500, "could not create question")
}

func TestErrorLeak_QA_StoreError_GetQuestion(t *testing.T) {
	f := newQAFixture(t)
	qid := f.createAs("alice", "alice@ctf.local", "s", "b")["id"].(string)
	if err := f.qa.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.do("GET", "/api/users/alice/questions/"+qid, "alice@ctf.local", nil)
	assertErrorBody(t, w, 500, "could not load question")
}

func TestErrorLeak_QA_StoreError_PostMessage(t *testing.T) {
	f := newQAFixture(t)
	qid := f.createAs("alice", "alice@ctf.local", "s", "b")["id"].(string)
	if err := f.qa.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.do("POST", "/api/users/alice/questions/"+qid+"/messages", "alice@ctf.local", map[string]any{"body": "follow-up"})
	assertErrorBody(t, w, 500, "could not append message")
}

func TestErrorLeak_QA_StoreError_AdminListQuestions(t *testing.T) {
	f := newQAFixture(t)
	if err := f.qa.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.do("GET", "/api/admin/questions", qaFixtureAdmin, nil)
	assertErrorBody(t, w, 500, "could not list questions")
}

func TestErrorLeak_QA_StoreError_AdminGetQuestion(t *testing.T) {
	f := newQAFixture(t)
	qid := f.createAs("alice", "alice@ctf.local", "s", "b")["id"].(string)
	if err := f.qa.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.do("GET", "/api/admin/questions/"+qid, qaFixtureAdmin, nil)
	assertErrorBody(t, w, 500, "could not load question")
}

func TestErrorLeak_QA_StoreError_AdminReply(t *testing.T) {
	f := newQAFixture(t)
	qid := f.createAs("alice", "alice@ctf.local", "s", "b")["id"].(string)
	if err := f.qa.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.do("POST", "/api/admin/questions/"+qid+"/reply", qaFixtureAdmin, map[string]any{"body": "reply"})
	assertErrorBody(t, w, 500, "could not reply")
}
