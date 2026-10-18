package scoreboard_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// app#456: when flagShapePattern refuses a participant-written text (a board subject
// or body, a display name) the handler writes ONE Warn line, and the line carries no
// part of the refused value (a real flag must not be copied into the log
// infrastructure, app#422 policy (a)): only the seat, the field word, the route and
// the peer address.

// flagLeak is the canary the refused text holds. A real flag never appears in a test;
// this is an invented value, and it must be absent from the whole log.
const flagLeak = "FALCO{log-canary-7f3a}"

const flagLogMsg = "flag shape refused"

// flagLogKeys is the closed attribute set of the line (slog adds time, level, msg).
var flagLogKeys = []string{"field", "level", "msg", "remote_addr", "route", "seat", "time"}

// flagLogProblems is every way logs (JSON lines) departs from "exactly one
// flag-shape Warn with the closed attributes and the wanted values, and no trace of
// the canary anywhere in the log".
func flagLogProblems(logs, seat, field, route string) []string {
	var out []string
	if strings.Contains(logs, flagLeak) || strings.Contains(logs, "log-canary") {
		out = append(out, "the refused value (or part of it) is in the log")
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			out = append(out, "a log line is not JSON: "+l)
			continue
		}
		if m["msg"] == flagLogMsg {
			lines = append(lines, m)
		}
	}
	if len(lines) != 1 {
		return append(out, fmt.Sprintf("%d %q lines, want exactly 1", len(lines), flagLogMsg))
	}
	m := lines[0]
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != strings.Join(flagLogKeys, ",") {
		out = append(out, fmt.Sprintf("attributes %v, want the closed set %v", keys, flagLogKeys))
	}
	for k, want := range map[string]string{"level": "WARN", "seat": seat, "field": field, "route": route, "remote_addr": "192.0.2.1:1234"} {
		if m[k] != want {
			out = append(out, fmt.Sprintf("%s = %v, want %q", k, m[k], want))
		}
	}
	return out
}

func TestFlagShapeRefused_BoardRoutesLogOneValueFreeWarn(t *testing.T) {
	const alice = "alice@ctf.local"
	cases := []struct {
		name        string
		seat, field string
		route       string
		run         func(t *testing.T, f *boardFixture)
	}{
		{"create thread subject", "alice", "subject", "POST /api/board/threads", func(t *testing.T, f *boardFixture) {
			expect400(t, f.do("POST", "/api/board/threads", alice, map[string]any{"audience": "all", "subject": "the " + flagLeak, "body": "b"}))
		}},
		{"create thread body", "alice", "body", "POST /api/board/threads", func(t *testing.T, f *boardFixture) {
			expect400(t, f.do("POST", "/api/board/threads", alice, map[string]any{"audience": "all", "subject": "s", "body": "the " + flagLeak}))
		}},
		{"participant follow-up", "alice", "body", "POST /api/board/threads/{tid}/messages", func(t *testing.T, f *boardFixture) {
			tid := f.createAs(alice, "all", "s", "b")["id"].(string)
			expect400(t, f.do("POST", "/api/board/threads/"+tid+"/messages", alice, map[string]any{"body": flagLeak}))
		}},
		{"admin reply", "staff", "body", "POST /api/admin/board/threads/{tid}/reply", func(t *testing.T, f *boardFixture) {
			tid := f.createAs(alice, "admin", "s", "b")["id"].(string)
			expect400(t, f.do("POST", "/api/admin/board/threads/"+tid+"/reply", boardFixtureAdmin, map[string]any{"body": flagLeak}))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := newBoardFixtureLogged(t, &logs)
			c.run(t, f)
			if p := flagLogProblems(logs.String(), c.seat, c.field, c.route); len(p) != 0 {
				t.Fatalf("%v\nlog:\n%s", p, logs.String())
			}
		})
	}
}

func TestFlagShapeRefused_DisplayNameRoutesLogOneValueFreeWarn(t *testing.T) {
	routes := map[string]string{
		"participant POST /api/users/{user}/profile":      "POST /api/users/{user}/profile",
		"admin POST /api/admin/users/{user}/display-name": "POST /api/admin/users/{user}/display-name",
	}
	for _, rt := range displayNameRoutes {
		t.Run(rt.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := newFixtureLogged(t, nil, &logs)
			expect400(t, rt.send(f, rt.target, "the "+flagLeak))
			if p := flagLogProblems(logs.String(), "alice", "display_name", routes[rt.name]); len(p) != 0 {
				t.Fatalf("%v\nlog:\n%s", p, logs.String())
			}
		})
	}
}

// A refusal for any OTHER reason (a forbidden character, a length) writes no
// flag-shape line.
func TestFlagShapeRefused_OtherRefusalsDoNotLogIt(t *testing.T) {
	for _, rt := range displayNameRoutes {
		t.Run(rt.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := newFixtureLogged(t, nil, &logs)
			expect400(t, rt.send(f, rt.target, "Ali\u200bce"))
			if strings.Contains(logs.String(), flagLogMsg) {
				t.Fatalf("a non-flag refusal wrote the flag-shape line:\n%s", logs.String())
			}
		})
	}
}

// Mutation: the checker goes red on a line that carries the value, an extra
// attribute, or a second line, so the tests above do pin "no value, closed set, one line".
func TestFlagShapeRefused_CheckerCatchesALeakingLine(t *testing.T) {
	good := `{"time":"t","level":"WARN","msg":"flag shape refused","seat":"alice","field":"body","route":"POST /api/board/threads","remote_addr":"192.0.2.1:1234"}`
	if p := flagLogProblems(good, "alice", "body", "POST /api/board/threads"); len(p) != 0 {
		t.Fatalf("the reference line is rejected: %v", p)
	}
	for name, logs := range map[string]string{
		"the value in an attribute":     strings.Replace(good, `"seat":"alice"`, `"seat":"alice","value":"`+flagLeak+`"`, 1),
		"the value in the field":        strings.Replace(good, `"field":"body"`, `"field":"`+flagLeak+`"`, 1),
		"a part of the value in a line": good + "\n" + `{"msg":"other","x":"log-canary"}`,
		"an extra attribute, no value":  strings.Replace(good, `"seat":"alice"`, `"seat":"alice","tid":"t1"`, 1),
		"a second flag-shape line":      good + "\n" + good,
		"no flag-shape line at all":     `{"msg":"other"}`,
		"a wrong seat":                  strings.Replace(good, `"alice"`, `"bob"`, 1),
	} {
		if p := flagLogProblems(logs, "alice", "body", "POST /api/board/threads"); len(p) == 0 {
			t.Errorf("%s: the checker accepted it", name)
		}
	}
}

func expect400(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Result().StatusCode; got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}
