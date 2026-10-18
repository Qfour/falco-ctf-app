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
// infrastructure): only the seat (where the text would have been stored), the actor
// (self | admin), the field word, the route and the peer host.

// flagLeak is the canary the refused text holds. A real flag never appears in a test;
// this is an invented value, and no fragment of it may be in the log.
const flagLeak = "FALCO{log-canary-7f3a}"

// flagLeakFragments are pieces of flagLeak that must be absent from the whole log.
var flagLeakFragments = []string{"FALCO{", "canary", "7f3a", "log-"}

const flagLogMsg = "flag shape refused"

// flagLogKeys is the closed attribute set of the line (slog adds time, level, msg).
var flagLogKeys = []string{"actor", "field", "level", "msg", "remote_addr", "route", "seat", "time"}

// flagWant is what the one line must say.
type flagWant struct{ seat, actor, field, route string }

// flagLogProblems is every way the log departs from: the request added exactly one
// line, it is the flag-shape Warn with the closed attributes and the wanted values,
// and no fragment of the canary is anywhere in the whole log. whole is the entire
// log; delta is what the refused request added to it.
func flagLogProblems(whole, delta string, w flagWant) []string {
	var out []string
	for _, frag := range flagLeakFragments {
		if strings.Contains(whole, frag) {
			out = append(out, fmt.Sprintf("the log holds the fragment %q of the refused value", frag))
		}
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(delta), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			out = append(out, "a log line is not JSON: "+l)
			continue
		}
		lines = append(lines, m)
	}
	if len(lines) != 1 {
		return append(out, fmt.Sprintf("the refused request added %d log lines, want exactly 1 (the %q Warn)", len(lines), flagLogMsg))
	}
	m := lines[0]
	if m["msg"] != flagLogMsg {
		return append(out, fmt.Sprintf("the added line is %v, want %q", m["msg"], flagLogMsg))
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != strings.Join(flagLogKeys, ",") {
		out = append(out, fmt.Sprintf("attributes %v, want the closed set %v", keys, flagLogKeys))
	}
	for k, want := range map[string]string{"level": "WARN", "seat": w.seat, "actor": w.actor, "field": w.field, "route": w.route, "remote_addr": "192.0.2.1"} {
		if m[k] != want {
			out = append(out, fmt.Sprintf("%s = %v, want %q", k, m[k], want))
		}
	}
	return out
}

// runLogged runs act after setup and returns the whole log and what act added.
func runLogged(logs *bytes.Buffer, setup func(), act func()) (whole, delta string) {
	if setup != nil {
		setup()
	}
	before := logs.Len()
	act()
	return logs.String(), logs.String()[before:]
}

func TestFlagShapeRefused_BoardRoutesLogOneValueFreeWarn(t *testing.T) {
	const alice = "alice@ctf.local"
	cases := []struct {
		name  string
		want  flagWant
		setup func(f *boardFixture) string // returns the thread id
		act   func(f *boardFixture, tid string) *httptest.ResponseRecorder
	}{
		{"create thread subject", flagWant{"alice", "self", "subject", "POST /api/board/threads"}, nil,
			func(f *boardFixture, _ string) *httptest.ResponseRecorder {
				return f.do("POST", "/api/board/threads", alice, map[string]any{"audience": "all", "subject": "the " + flagLeak, "body": "b"})
			}},
		{"create thread body", flagWant{"alice", "self", "body", "POST /api/board/threads"}, nil,
			func(f *boardFixture, _ string) *httptest.ResponseRecorder {
				return f.do("POST", "/api/board/threads", alice, map[string]any{"audience": "all", "subject": "s", "body": "the " + flagLeak})
			}},
		{"participant follow-up", flagWant{"alice", "self", "body", "POST /api/board/threads/{tid}/messages"},
			func(f *boardFixture) string { return f.createAs(alice, "all", "s", "b")["id"].(string) },
			func(f *boardFixture, tid string) *httptest.ResponseRecorder {
				return f.do("POST", "/api/board/threads/"+tid+"/messages", alice, map[string]any{"body": flagLeak})
			}},
		{"admin reply", flagWant{"staff", "admin", "body", "POST /api/admin/board/threads/{tid}/reply"},
			func(f *boardFixture) string { return f.createAs(alice, "admin", "s", "b")["id"].(string) },
			func(f *boardFixture, tid string) *httptest.ResponseRecorder {
				return f.do("POST", "/api/admin/board/threads/"+tid+"/reply", boardFixtureAdmin, map[string]any{"body": flagLeak})
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := newBoardFixtureLogged(t, &logs)
			var tid string
			whole, delta := runLogged(&logs, func() {
				if c.setup != nil {
					tid = c.setup(f)
				}
			}, func() { expect400(t, c.act(f, tid)) })
			if p := flagLogProblems(whole, delta, c.want); len(p) != 0 {
				t.Fatalf("%v\nlog:\n%s", p, whole)
			}
		})
	}
}

func TestFlagShapeRefused_DisplayNameRoutesLogOneValueFreeWarn(t *testing.T) {
	for _, rt := range displayNameRoutes {
		t.Run(rt.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := newFixtureLogged(t, nil, &logs)
			actor := "self"
			if strings.Contains(rt.pattern, "/admin/") {
				actor = "admin"
			}
			whole, delta := runLogged(&logs, nil, func() { expect400(t, rt.send(f, rt.target, "the "+flagLeak)) })
			if p := flagLogProblems(whole, delta, flagWant{"alice", actor, "display_name", rt.pattern}); len(p) != 0 {
				t.Fatalf("%v\nlog:\n%s", p, whole)
			}
		})
	}
}

// An operator who sets a participant's profile is actor=admin, and the seat is the
// seat the name would have been stored on (not the operator).
func TestFlagShapeRefused_AdminOnAParticipantProfileIsActorAdmin(t *testing.T) {
	var logs bytes.Buffer
	f := newFixtureLogged(t, nil, &logs)
	whole, delta := runLogged(&logs, nil, func() {
		expect400(t, f.doAdmin("POST", "/api/users/alice/profile", map[string]any{"display_name": "the " + flagLeak}))
	})
	if p := flagLogProblems(whole, delta, flagWant{"alice", "admin", "display_name", "POST /api/users/{user}/profile"}); len(p) != 0 {
		t.Fatalf("%v\nlog:\n%s", p, whole)
	}
}

// A refusal for any OTHER reason writes no flag-shape line: a forbidden character, and
// a flag-shaped name too long to pass the length check first (the length check comes
// before the flag-shape one, so the flag shape is not what decided it).
func TestFlagShapeRefused_OnlyWhenTheFlagShapeDecided(t *testing.T) {
	tooLongFlagShape := "FALCO{" + strings.Repeat("a", 40) + "}"
	for _, rt := range displayNameRoutes {
		for label, name := range map[string]string{"a forbidden character": "Ali\u200bce", "a flag shape over 32 runes": tooLongFlagShape} {
			t.Run(rt.name+"/"+label, func(t *testing.T) {
				var logs bytes.Buffer
				f := newFixtureLogged(t, nil, &logs)
				expect400(t, rt.send(f, rt.target, name))
				if strings.Contains(logs.String(), flagLogMsg) {
					t.Fatalf("the flag-shape line was written for a refusal it did not decide:\n%s", logs.String())
				}
			})
		}
	}
}

// Mutation: the checker goes red on a line that carries the value, an extra
// attribute, a second line, or a wrong value, so the tests above do pin "no value,
// closed set, one line".
func TestFlagShapeRefused_CheckerCatchesALeakingLine(t *testing.T) {
	want := flagWant{"alice", "self", "body", "POST /api/board/threads"}
	good := `{"time":"t","level":"WARN","msg":"flag shape refused","seat":"alice","actor":"self","field":"body","route":"POST /api/board/threads","remote_addr":"192.0.2.1"}`
	if p := flagLogProblems(good, good, want); len(p) != 0 {
		t.Fatalf("the reference line is rejected: %v", p)
	}
	other := `{"msg":"other","x":"1"}`
	for name, c := range map[string]struct{ whole, delta string }{
		"the value in an attribute":    {strings.Replace(good, `"seat":"alice"`, `"seat":"alice","value":"`+flagLeak+`"`, 1), ""},
		"the value in the field":       {strings.Replace(good, `"field":"body"`, `"field":"`+flagLeak+`"`, 1), ""},
		"a fragment in an older line":  {other + "\n" + `{"msg":"x","y":"canary"}` + "\n" + good, good},
		"another fragment (the tail)":  {good + "\n" + `{"msg":"x","y":"7f3a"}`, good},
		"an extra attribute, no value": {strings.Replace(good, `"seat":"alice"`, `"seat":"alice","tid":"t1"`, 1), ""},
		"a second line added":          {good + "\n" + other, good + "\n" + other},
		"no flag-shape line at all":    {other, other},
		"a wrong seat":                 {strings.Replace(good, `"alice"`, `"bob"`, 1), ""},
		"a wrong actor":                {strings.Replace(good, `"self"`, `"admin"`, 1), ""},
		"the port kept in remote_addr": {strings.Replace(good, `192.0.2.1"`, `192.0.2.1:1234"`, 1), ""},
	} {
		delta := c.delta
		if delta == "" {
			delta = c.whole
		}
		if p := flagLogProblems(c.whole, delta, want); len(p) == 0 {
			t.Errorf("%s: the checker accepted it", name)
		}
	}
}

func expect400(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Result().StatusCode; got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", got, w.Body)
	}
}
