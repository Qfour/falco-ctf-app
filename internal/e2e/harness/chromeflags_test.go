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
