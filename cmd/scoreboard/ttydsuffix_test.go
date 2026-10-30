package main

import (
	"strings"
	"testing"
)

// ADR-0047 D6 (app#532): PORTAL_TTYD_SUFFIX is checked at start-up. The grammar's
// own rows are run in internal/scoreboard/view (TestValidateTtydSuffix_SharedCaseTable);
// this pins the env wiring: unset and empty start, a DNS name starts and is returned
// as given, anything else is an error that names the variable and not the value.
func TestTtydSuffixFromEnv(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		want    string
		wantErr bool
	}{
		{"unset is not configured", map[string]string{}, "", false},
		{"empty is not configured", map[string]string{"PORTAL_TTYD_SUFFIX": ""}, "", false},
		{"the chart default's form", map[string]string{"PORTAL_TTYD_SUFFIX": "ctf-event.dev"}, "ctf-event.dev", false},
		{"nip.io form", map[string]string{"PORTAL_TTYD_SUFFIX": "10.0.0.5.nip.io"}, "10.0.0.5.nip.io", false},
		{"upper case", map[string]string{"PORTAL_TTYD_SUFFIX": "Ctf-Event.dev"}, "", true},
		{"trailing dot", map[string]string{"PORTAL_TTYD_SUFFIX": "ctf-event.dev."}, "", true},
		{"port", map[string]string{"PORTAL_TTYD_SUFFIX": "ctf-event.dev:443"}, "", true},
		{"scheme", map[string]string{"PORTAL_TTYD_SUFFIX": "https://ctf-event.dev"}, "", true},
		{"space", map[string]string{"PORTAL_TTYD_SUFFIX": "ctf-event.dev x"}, "", true},
		{"bidi override", map[string]string{"PORTAL_TTYD_SUFFIX": "ctf-event.dev\u202e"}, "", true},
		{"CR LF", map[string]string{"PORTAL_TTYD_SUFFIX": "ctf-event.dev\r\nX-Injected: 1"}, "", true},
		{"254 characters", map[string]string{"PORTAL_TTYD_SUFFIX": strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 62)}, "", true},
		{"label of 64", map[string]string{"PORTAL_TTYD_SUFFIX": strings.Repeat("a", 64) + ".dev"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ttydSuffixFromEnv(envMap(c.env))
			if c.wantErr {
				if err == nil {
					t.Fatalf("got (%q, nil), want an error", got)
				}
				msg := err.Error()
				if !strings.Contains(msg, "PORTAL_TTYD_SUFFIX") || !strings.Contains(msg, "not a DNS name") {
					t.Errorf("error %q must name PORTAL_TTYD_SUFFIX and say it is not a DNS name", msg)
				}
				if v := c.env["PORTAL_TTYD_SUFFIX"]; strings.Contains(msg, v) || strings.ContainsAny(msg, "\u202e\r\n") {
					t.Errorf("error %q carries the value", msg)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got (%q, %v), want (%q, nil)", got, err, c.want)
			}
		})
	}
}
