package scoreboard_test

// The {tid} path value of every board route is checked for the shape of a thread
// id before anything else uses it. One that is not a 32-hex id gets the same
// fixed 404 as an unknown thread, with nothing of the input in the body; the
// unlike route, which never looks the thread up, cannot return a caller-chosen
// string as LikeResult.tid.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
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
// check comes after the identity / admin gate.
func TestBoardTID_BadShapeDoesNotChangeTheDeniedStatus(t *testing.T) {
	f := newBoardFixture(t)
	if w := f.do("POST", "/api/admin/board/threads/%E2%80%AE/state", "alice@ctf.local", map[string]any{"pinned": true}); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin on an admin route with a bad tid: status=%d body=%s, want 403", w.Code, w.Body)
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
