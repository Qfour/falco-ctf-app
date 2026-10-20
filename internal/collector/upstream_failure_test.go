package collector

// app#486 (ADR-0041 review-5x): the collector's answer when the scoreboard is
// unreachable was untested. ErrorHandler answers 502 with one fixed body that
// names neither the upstream address nor the error, and logs the REGISTERED
// pattern (r.Pattern), not the URL: the URL carries the participant-chosen {cid}
// (and, on exfil, was rewritten to /internal/exfil/{cid}).

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpstreamDown_Answers502WithFixedBodyAndLogsThePattern(t *testing.T) {
	// An upstream that drops every connection without a response (hijack, close):
	// the proxy's round trip fails the same way a down scoreboard does, and unlike
	// a closed port there is no race with another process taking the port.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		conn.Close()
	}))
	t.Cleanup(dead.Close)
	deadURL := dead.URL
	hostPort := strings.TrimPrefix(deadURL, "http://")

	var logs bytes.Buffer
	h, err := New(deadURL, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := httptest.NewServer(h)
	t.Cleanup(c.Close)

	const cid = "10-final-exfil"
	for _, tc := range []struct{ name, route, pattern string }{
		{"submit", "submit", "POST /api/challenges/{cid}/submit"},
		{"exfil", "exfil", "POST /api/challenges/{cid}/exfil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()
			resp := do(t, "POST", c.URL+"/api/challenges/"+cid+"/"+tc.route, `{"user":"user1","flag":"FALCO{x}"}`)
			defer resp.Body.Close()
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status = %d body=%v, want 502", resp.StatusCode, body)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			if len(body) != 1 || body["error"] != "scoreboard unavailable" {
				t.Fatalf("body = %v, want exactly {\"error\": \"scoreboard unavailable\"}", body)
			}
			raw, _ := json.Marshal(body)
			for _, leak := range []string{hostPort, "127.0.0.1", "dial", "EOF", "reset", cid} {
				if strings.Contains(string(raw), leak) {
					t.Fatalf("the body names %q: %s", leak, raw)
				}
			}

			// The one error record: the pattern is the registered route, no value
			// of it carries the cid the participant chose.
			var rec map[string]any
			for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var m map[string]any
				if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "upstream forward failed" {
					if rec != nil {
						t.Fatalf("more than one 'upstream forward failed' record:\n%s", logs.String())
					}
					rec = m
				}
			}
			if rec == nil {
				t.Fatalf("no 'upstream forward failed' record:\n%s", logs.String())
			}
			if rec["level"] != "ERROR" || rec["pattern"] != tc.pattern {
				t.Fatalf("record = %v, want level ERROR and pattern %q", rec, tc.pattern)
			}
			for k, v := range rec {
				if s, ok := v.(string); ok && strings.Contains(s, cid) {
					t.Fatalf("record attribute %q carries the cid: %q", k, s)
				}
			}
		})
	}
}
