package harness

import (
	"os"
	"strings"
	"testing"
)

func TestChromiumFlags_AreAllowlistedAndNoneBanned(t *testing.T) {
	flags, err := ChromiumFlags(LaunchConfig{HostRules: HostResolverRules(map[string]string{"user1.e2e.test": "127.0.0.1:9"}), SPKIHash: "abc="})
	if err != nil {
		t.Fatal(err)
	}
	if len(flags) == 0 {
		t.Fatal("no launch flags")
	}
	names := map[string]bool{}
	for _, f := range flags {
		names[f.Name] = true
	}
	// The ones ADR-0031 H1 (f) names explicitly.
	for _, want := range []string{"disable-dev-shm-usage", "host-resolver-rules", "ignore-certificate-errors-spki-list"} {
		if !names[want] {
			t.Errorf("--%s is missing from the launch flags", want)
		}
	}
	for _, b := range BannedChromiumFlags {
		if names[b] {
			t.Errorf("--%s is banned but present", b)
		}
	}
}

func TestCheckFlags_RejectsPlantedViolations(t *testing.T) {
	cases := []struct {
		name  string
		flags []Flag
		want  string
	}{
		{"web security off", []Flag{{"disable-web-security", true}}, "banned"},
		{"certificate checks off for everything", []Flag{{"ignore-certificate-errors", true}}, "banned"},
		{"site isolation off", []Flag{{"disable-features", "site-per-process"}}, "banned"},
		{"a switch nobody reviewed", []Flag{{"remote-allow-origins", "*"}}, "allowlist"},
		{"a switch given twice", []Flag{{"headless", true}, {"headless", true}}, "twice"},
		{"an empty resolver rule", []Flag{{"host-resolver-rules", ""}}, "empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckFlags(c.flags)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("CheckFlags(%v) = %v, want an error mentioning %q", c.flags, err, c.want)
			}
		})
	}
}

func TestHostResolverRules_MapsNamedHostsAndRefusesTheRest(t *testing.T) {
	got := HostResolverRules(map[string]string{"user1.e2e.test": "127.0.0.1:4443"})
	if got != "MAP user1.e2e.test 127.0.0.1:4443, EXCLUDE 127.0.0.1, MAP * ~NOTFOUND" {
		t.Errorf("rules = %q", got)
	}
}

// A missing browser fails the run; it never skips it (ADR-0031 V6).
func TestChromiumPath_MissingBrowserIsAnError(t *testing.T) {
	getenv := func(k string) string {
		if k == "E2E_CHROMIUM" {
			return "/nonexistent/chromium"
		}
		return ""
	}
	if p, err := ChromiumPath(getenv, os.Stat); err == nil {
		t.Fatalf("ChromiumPath found %q although it does not exist", p)
	}
	dir := t.TempDir()
	if _, err := ChromiumPath(func(string) string { return dir }, os.Stat); err == nil {
		t.Error("ChromiumPath accepted a directory")
	}
	f := dir + "/not-executable"
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ChromiumPath(func(string) string { return f }, os.Stat); err == nil {
		t.Error("ChromiumPath accepted a file that is not executable")
	}
}

// The live command line is checked, not only the list we built: each case is a
// switch that reaches a process by a route the static checks do not see.
func TestCheckArgv_AcceptsOnlyTheAllowlistPlusChromedpsOwn(t *testing.T) {
	const bin = "/usr/lib/chromium/chromium"
	good := []string{bin, "--headless", "--lang=ja-JP", "--host-resolver-rules=MAP * ~NOTFOUND",
		"--user-data-dir=/tmp/x/profile", "--remote-debugging-pipe", "about:blank"}
	if err := CheckArgv(bin, good); err != nil {
		t.Fatalf("a command line made of allowed switches was refused: %v", err)
	}
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"empty", nil, "started as"},
		{"a wrapper script instead of the binary", append([]string{"/usr/bin/chromium"}, good[1:]...), "wrapper"},
		{"certificate errors off, added by ModifyCmdFunc", append(append([]string{}, good...), "--ignore-certificate-errors"), "banned"},
		{"web security off", append(append([]string{}, good...), "--disable-web-security"), "banned"},
		{"a proxy server", append(append([]string{}, good...), "--proxy-server=http://evil.example:3128"), "allowlist"},
		{"a listening debug port", append(append([]string{}, good...), "--remote-debugging-port=9222"), "allowlist"},
		{"a bare URL other than about:blank", append(append([]string{}, good...), "http://evil.example/"), "not a --switch"},
		{"a switch one of chromedp's defaults would add", append(append([]string{}, good...), "--enable-automation"), "allowlist"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckArgv(bin, c.argv)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("CheckArgv(%q) = %v, want an error mentioning %q", c.argv, err, c.want)
			}
		})
	}
}

func TestReadArgv_ReadsAProcessCommandLine(t *testing.T) {
	// No skip without /proc: make test (Dockerfile.test) and make e2e run on
	// Linux, and the live-argv check (V3) depends on reading it.
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		t.Fatalf("no /proc/self/cmdline (%v): the browser's live command line could not be checked either", err)
	}
	argv, err := ReadArgv(os.Getpid())
	if err != nil || len(argv) == 0 {
		t.Fatalf("ReadArgv(self) = %q, %v", argv, err)
	}
	if _, err := ReadArgv(-1); err == nil {
		t.Error("ReadArgv of a process that does not exist succeeded")
	}
}
