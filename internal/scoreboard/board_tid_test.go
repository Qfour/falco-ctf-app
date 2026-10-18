package scoreboard_test

// The {tid} path value of every board route is checked for the shape of a thread
// id before anything else uses it. One that is not a 32-hex id gets the same
// fixed 404 as an unknown thread, with nothing of the input in the body; the
// unlike route, which never looks the thread up, cannot return a caller-chosen
// string as LikeResult.tid.
//
// This file is the ONLY machine guard for it: ADR-0039 D5's token probe covers
// JSON request bodies, not path parameters (D5 "probe しないもの"; extending it to
// path parameters is S3b, app#464).

import (
	"bytes"
	"fmt"
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

const boardTIDNotFoundBody = `{"error":"thread not found"}`

func badTIDs() []string {
	return []string{
		"%E2%80%AE",                              // a bidi override
		strings.Repeat("a", 4096),                // far too long
		strings.ToUpper(strings.Repeat("a", 32)), // right length, upper case
		strings.Repeat("a", 31),                  // one short
		strings.Repeat("a", 33),                  // one long
		strings.Repeat("g", 32),                  // not hex
		"..%2f..%2fadmin",                        // path-like
		"%ff%fe",                                 // not UTF-8
	}
}

func TestBoardTID_BadShapeIsTheFixed404OnEveryRoute(t *testing.T) {
	f := newBoardFixture(t)
	routes := []struct {
		name, method, tmpl, email string
		body                      any
	}{
		{"get", "GET", "/api/board/threads/%s", "alice@ctf.local", nil},
		{"append", "POST", "/api/board/threads/%s/messages", "alice@ctf.local", map[string]any{"body": "hello"}},
		{"like", "POST", "/api/board/threads/%s/like", "alice@ctf.local", map[string]any{}},
		{"unlike", "POST", "/api/board/threads/%s/unlike", "alice@ctf.local", map[string]any{}},
		{"admin get", "GET", "/api/admin/board/threads/%s", boardFixtureAdmin, nil},
		{"admin reply", "POST", "/api/admin/board/threads/%s/reply", boardFixtureAdmin, map[string]any{"body": "hello"}},
		{"admin state", "POST", "/api/admin/board/threads/%s/state", boardFixtureAdmin, map[string]any{"pinned": true}},
	}
	n := 0
	for _, rt := range routes {
		for _, tid := range badTIDs() {
			email := rt.email
			if email != boardFixtureAdmin {
				// A distinct seat per request keeps the per-identity rate limiter
				// from turning a request away before the handler.
				n++
				email = fmt.Sprintf("user%d@ctf.local", n)
			}
			w := f.do(rt.method, strings.Replace(rt.tmpl, "%s", tid, 1), email, rt.body)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s tid=%.30q: status=%d body=%.120s, want 404", rt.name, tid, w.Code, w.Body)
				continue
			}
			if strings.TrimSpace(w.Body.String()) != boardTIDNotFoundBody {
				t.Errorf("%s tid=%.30q: body=%.120s, want the fixed %s", rt.name, tid, w.Body, boardTIDNotFoundBody)
			}
		}
	}
}

// A request that is not allowed in the first place keeps its 403: the shape
// check comes after the identity / admin gate on every route, so a bad tid is
// never an oracle for who is an admin or a canonical participant.
func TestBoardTID_BadShapeDoesNotChangeTheDeniedStatus(t *testing.T) {
	f := newBoardFixture(t)
	bad := "%E2%80%AE"
	denied := []struct {
		name, method, tmpl, email string
		body                      any
	}{
		{"admin get (non-admin)", "GET", "/api/admin/board/threads/%s", "alice@ctf.local", nil},
		{"admin reply (non-admin)", "POST", "/api/admin/board/threads/%s/reply", "alice@ctf.local", map[string]any{"body": "x"}},
		{"admin state (non-admin)", "POST", "/api/admin/board/threads/%s/state", "alice@ctf.local", map[string]any{"pinned": true}},
		{"get (non-canonical identity)", "GET", "/api/board/threads/%s", "alice@evil.example", nil},
		{"append (non-canonical identity)", "POST", "/api/board/threads/%s/messages", "alice@evil.example", map[string]any{"body": "x"}},
		{"like (non-canonical identity)", "POST", "/api/board/threads/%s/like", "alice@evil.example", map[string]any{}},
		{"unlike (non-canonical identity)", "POST", "/api/board/threads/%s/unlike", "alice@evil.example", map[string]any{}},
	}
	for _, d := range denied {
		w := f.do(d.method, strings.Replace(d.tmpl, "%s", bad, 1), d.email, d.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status=%d body=%.120s, want 403", d.name, w.Code, w.Body)
		}
	}
	w := f.do("POST", "/api/admin/board/messages/"+bad+"/state", "alice@ctf.local", map[string]any{"state": "hidden"})
	if w.Code != http.StatusForbidden {
		t.Errorf("message state (non-admin): status=%d body=%.120s, want 403", w.Code, w.Body)
	}
}

// With the board store CLOSED every lookup fails, so a handler that reaches the
// store with an ill-formed id answers 500 and logs it. The shape check must
// answer first on each route: fixed 404 (also for a malformed body on the routes
// that decode one), and the id never reaches the log (the production logger is
// the JSON handler, which writes U+202E unescaped).
func TestBoardTID_BadShapeNeverReachesTheStoreNorTheLog(t *testing.T) {
	cat := catalog.Catalog{"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"}}
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bs, err := board.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	srv := scoreboard.NewHandler(cat, st, slog.New(slog.NewJSONHandler(&logs, nil)),
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain),
		scoreboard.WithAdminEmails([]string{boardFixtureAdmin}),
		scoreboard.WithAllowedOrigins([]string{boardFixtureOrigin}),
		scoreboard.WithBoard(bs),
	)
	bs.Close()
	f := &boardFixture{t: t, srv: srv, board: bs}

	marker := "zzprobe" + strings.Repeat("q", 25) // 32 chars, not hex
	ids := []string{marker, marker + "%E2%80%AE", "%E2%80%AE" + marker}
	routes := []struct {
		name, method, tmpl, email string
		body                      any
		rawBody                   bool // also send a malformed body
	}{
		{"get", "GET", "/api/board/threads/%s", "u1@ctf.local", nil, false},
		{"append", "POST", "/api/board/threads/%s/messages", "u2@ctf.local", map[string]any{"body": "hello"}, true},
		{"like", "POST", "/api/board/threads/%s/like", "u3@ctf.local", map[string]any{}, false},
		{"unlike", "POST", "/api/board/threads/%s/unlike", "u4@ctf.local", map[string]any{}, false},
		{"admin get", "GET", "/api/admin/board/threads/%s", boardFixtureAdmin, nil, false},
		{"admin reply", "POST", "/api/admin/board/threads/%s/reply", boardFixtureAdmin, map[string]any{"body": "hello"}, true},
		{"admin state", "POST", "/api/admin/board/threads/%s/state", boardFixtureAdmin, map[string]any{"pinned": true}, true},
		{"admin message state", "POST", "/api/admin/board/messages/%s/state", boardFixtureAdmin, map[string]any{"state": "hidden"}, true},
	}
	n := 0
	for _, rt := range routes {
		want := boardTIDNotFoundBody
		if rt.name == "admin message state" {
			want = `{"error":"message not found"}`
		}
		for _, id := range ids {
			email := rt.email
			if email != boardFixtureAdmin {
				n++
				email = fmt.Sprintf("p%d@ctf.local", n) // distinct seat: no rate limiter in the way
			}
			target := strings.Replace(rt.tmpl, "%s", id, 1)
			check := func(what string, w *httptest.ResponseRecorder) {
				if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
					t.Errorf("%s %s id=%.40q: status=%d body=%.100s, want 404 %s (the store was reached?)", rt.name, what, id, w.Code, w.Body, want)
				}
			}
			check("", f.do(rt.method, target, email, rt.body))
			if rt.rawBody {
				check("(malformed body)", f.doRaw(rt.method, target, email, "{not json"))
			}
		}
	}
	out := logs.String()
	for _, leak := range []string{marker, "\u202e", `\u202e`} {
		if strings.Contains(out, leak) {
			t.Errorf("an ill-formed id reached the log (%q): %.300s", leak, out)
		}
	}
}

// A real thread id still works end to end, and LikeResult.tid is that id.
func TestBoardTID_RealIDStillWorksAndIsEchoedAsIs(t *testing.T) {
	f := newBoardFixture(t)
	th := f.createAs("alice@ctf.local", "all", "subject", "body")
	tid, _ := th["id"].(string)
	if len(tid) != 32 {
		t.Fatalf("thread id = %q, want 32 hex", tid)
	}
	for _, route := range []string{"like", "unlike"} {
		w := f.do("POST", "/api/board/threads/"+tid+"/"+route, "bob@ctf.local", map[string]any{})
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s, want 200", route, w.Code, w.Body)
		}
		if got := f.decode(w)["tid"]; got != tid {
			t.Fatalf("%s: tid=%v, want %s", route, got, tid)
		}
	}
	// An unlike of a well-formed id that names no thread stays a harmless 200.
	if w := f.do("POST", "/api/board/threads/"+strings.Repeat("0", 32)+"/unlike", "bob@ctf.local", map[string]any{}); w.Code != http.StatusOK {
		t.Fatalf("unlike of an unknown well-formed id: status=%d body=%s, want 200", w.Code, w.Body)
	}
}
