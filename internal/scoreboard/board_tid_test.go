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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// unknownWellFormedID has the shape of a board id but names no thread: it passes
// the shape check and reaches the store, which answers "not found".
var unknownWellFormedID = strings.Repeat("0", 32)

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

// idRoute is one route of the live route table whose pattern carries a board id.
type idRoute struct {
	rt    apispec.Route
	param string // "tid" or "mid"
}

// boardIDRoutes derives, from the route table the mux actually serves, every
// route with a {tid} or {mid} path parameter, so a new such route is covered
// without anyone editing a list. The set must be non-empty and at least the 8
// known at the time of writing.
func boardIDRoutes(t *testing.T, h *scoreboard.Handler) []idRoute {
	t.Helper()
	var out []idRoute
	for _, rt := range h.Routes() {
		for _, p := range []string{"tid", "mid"} {
			if strings.Contains(rt.Pattern, "{"+p+"}") {
				out = append(out, idRoute{rt, p})
			}
		}
	}
	if len(out) < 8 {
		t.Fatalf("derived only %d board id routes from Routes(), want at least 8: %v", len(out), out)
	}
	return out
}

// seatFor returns the identity to call a route with: the admin for an admin
// route, else a distinct seat (so a per-identity rate limiter never turns the
// request away before the handler).
func seatFor(rt apispec.Route, n int) string {
	if rt.Authz == apispec.AuthzAdmin {
		return boardFixtureAdmin
	}
	return fmt.Sprintf("p%d@ctf.local", n)
}

func fillID(pattern, param, id string) string {
	return strings.Replace(pattern, "{"+param+"}", id, 1)
}

func notFoundBodyFor(param string) string {
	if param == "mid" {
		return `{"error":"message not found"}`
	}
	return boardTIDNotFoundBody
}

func TestBoardTID_BadShapeIsTheFixed404OnEveryRoute(t *testing.T) {
	f := newBoardFixture(t)
	n := 0
	for _, ir := range boardIDRoutes(t, f.srv) {
		for _, id := range badTIDs() {
			n++
			var body any
			if ir.rt.Method != "GET" {
				body = map[string]any{}
			}
			w := f.do(ir.rt.Method, fillID(ir.rt.Pattern, ir.param, id), seatFor(ir.rt, n), body)
			want := notFoundBodyFor(ir.param)
			if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
				t.Errorf("%s %s id=%.30q: status=%d body=%.120s, want 404 %s", ir.rt.Method, ir.rt.Pattern, id, w.Code, w.Body, want)
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
	n := 0
	for _, ir := range boardIDRoutes(t, f.srv) {
		want := notFoundBodyFor(ir.param)
		for _, id := range ids {
			n++
			email := seatFor(ir.rt, n)
			target := fillID(ir.rt.Pattern, ir.param, id)
			check := func(what string, w *httptest.ResponseRecorder) {
				if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
					t.Errorf("%s %s %s id=%.40q: status=%d body=%.100s, want 404 %s (the store was reached?)", ir.rt.Method, ir.rt.Pattern, what, id, w.Code, w.Body, want)
				}
			}
			var body any
			if ir.rt.Method != "GET" {
				body = map[string]any{}
			}
			check("", f.do(ir.rt.Method, target, email, body))
			if ir.rt.Method != "GET" {
				check("(malformed body)", f.doRaw(ir.rt.Method, target, email, "{not json"))
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
	if w := f.do("POST", "/api/board/threads/"+unknownWellFormedID+"/unlike", "bob@ctf.local", map[string]any{}); w.Code != http.StatusOK {
		t.Fatalf("unlike of an unknown well-formed id: status=%d body=%s, want 200", w.Code, w.Body)
	}
}

// Every board id in the spec carries the same `pattern`, and it is the
// expression board.ValidID matches: the parameters {tid} / {mid} and the five
// response nodes that echo an id.
func TestSpecBoardIDPatternsAreTheValidIDExpression(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi-scoreboard.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	at := func(path ...string) string {
		var cur any = doc
		for _, k := range path {
			m, ok := cur.(map[string]any)
			if !ok {
				return ""
			}
			cur = m[k]
		}
		s, _ := cur.(string)
		return s
	}
	nodes := map[string][]string{
		"parameter Tid":          {"components", "parameters", "Tid", "schema", "pattern"},
		"parameter Mid":          {"components", "parameters", "Mid", "schema", "pattern"},
		"BoardMessage.id":        {"components", "schemas", "BoardMessage", "properties", "id", "pattern"},
		"BoardThread.id":         {"components", "schemas", "BoardThread", "properties", "id", "pattern"},
		"BoardSummary.id":        {"components", "schemas", "BoardSummary", "properties", "id", "pattern"},
		"LikeResult.tid":         {"components", "schemas", "LikeResult", "properties", "tid", "pattern"},
		"MessageStateResult.mid": {"components", "schemas", "MessageStateResult", "properties", "mid", "pattern"},
	}
	found := 0
	for name, path := range nodes {
		got := at(path...)
		if got == "" {
			t.Errorf("%s: no pattern in the spec (extraction found nothing)", name)
			continue
		}
		found++
		if got != board.IDPattern() {
			t.Errorf("%s: pattern %q, board.ValidID matches %q", name, got, board.IDPattern())
		}
	}
	if found != len(nodes) {
		t.Fatalf("found %d of %d board id nodes", found, len(nodes))
	}
}
