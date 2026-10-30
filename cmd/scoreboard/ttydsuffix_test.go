package main

import (
	"os"
	"path/filepath"
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

// main() must take PORTAL_TTYD_SUFFIX from ttydSuffixFromEnv only, and stop when it
// errors. TestTtydSuffixFromEnv proves what the function returns; this pins main()
// to calling it (a deleted call, or a direct read of the variable that skips the
// check, would leave the grammar tested and the binary unchecked), to exiting 1 on
// its error, and to handing the checked value on to the handler.
func TestMainChecksPortalTtydSuffixAtStartup(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var all, main strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(src)
		if f == "main.go" {
			main.Write(src)
		}
	}
	if main.Len() == 0 {
		t.Fatal("cmd/scoreboard/main.go was not read")
	}
	code := all.String()
	for want, n := range map[string]int{
		`"PORTAL_TTYD_SUFFIX"`:                        1, // read in ttydSuffixFromEnv and nowhere else
		"ttydSuffixFromEnv(serverutil.Env)":           1,
		"scoreboard.WithTtydSuffix(portalTtydSuffix)": 1,
	} {
		if c := strings.Count(code, want); c != n {
			t.Errorf("%q appears %d time(s) in cmd/scoreboard, want %d", want, c, n)
		}
	}
	// Whitespace-insensitive: the call, then the error branch that logs and exits 1.
	squashed := strings.Join(strings.Fields(main.String()), "")
	const wantBranch = `portalTtydSuffix,err:=ttydSuffixFromEnv(serverutil.Env)iferr!=nil{logger.Error("refusingtostart","err",err)os.Exit(1)}`
	if !strings.Contains(squashed, wantBranch) {
		t.Errorf("main.go must call ttydSuffixFromEnv and exit 1 on its error, in the form %s", wantBranch)
	}
}
