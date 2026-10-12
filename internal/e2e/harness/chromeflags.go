package harness

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Flag is one Chromium command-line switch (name without the leading "--").
// Value is true for a bare switch, otherwise a string.
type Flag struct {
	Name  string
	Value any
}

// AllowedChromiumFlags is the complete set of switches the harness may launch
// Chromium with (ADR-0031 H1 (f), V3). A switch outside this list is a bug in
// the harness; chromedp's DefaultExecAllocatorOptions are NOT used, because
// they bring a dozen switches nobody reviewed (site-per-process off,
// popup blocking off, ...).
var AllowedChromiumFlags = map[string]string{
	"headless":                            "no UI; the new headless of the same binary",
	"no-sandbox":                          "the build step runs as root; only first-party loopback pages are loaded",
	"disable-gpu":                         "software rendering",
	"disable-dev-shm-usage":               "BuildKit's /dev/shm is 64 MiB",
	"no-first-run":                        "no first-run UI",
	"no-default-browser-check":            "no default-browser prompt",
	"disable-extensions":                  "no extensions",
	"disable-background-networking":       "no component-update / safe-browsing traffic of its own",
	"mute-audio":                          "no audio device",
	"lang":                                "ja-JP, the language the portal is written for",
	"hide-scrollbars":                     "stable screenshots",
	"host-resolver-rules":                 "maps the ttyd stub's name; everything else NOTFOUND",
	"ignore-certificate-errors-spki-list": "trusts the ttyd stub's key only",
}

// BannedChromiumFlags are switches that must never appear, whatever the
// allowlist says: they switch off the checks the harness exists to run.
var BannedChromiumFlags = []string{
	"disable-web-security",
	"ignore-certificate-errors",
	"allow-running-insecure-content",
	"disable-site-isolation-trials",
	"disable-features",
	"disable-popup-blocking",
	"remote-debugging-address",
}

// LaunchConfig carries the two run-specific values.
type LaunchConfig struct {
	// HostRules is a host-resolver-rules value (see HostResolverRules).
	HostRules string
	// SPKIHash is the TLS stub's key hash; empty when there is no stub (the
	// switch is then not passed at all).
	SPKIHash string
}

// ChromiumFlags returns the switches for one launch, and checks them.
func ChromiumFlags(c LaunchConfig) ([]Flag, error) {
	flags := []Flag{
		{"headless", true},
		{"no-sandbox", true},
		{"disable-gpu", true},
		{"disable-dev-shm-usage", true},
		{"no-first-run", true},
		{"no-default-browser-check", true},
		{"disable-extensions", true},
		{"disable-background-networking", true},
		{"mute-audio", true},
		{"hide-scrollbars", true},
		{"lang", "ja-JP"},
		{"host-resolver-rules", c.HostRules},
	}
	if c.SPKIHash != "" {
		flags = append(flags, Flag{"ignore-certificate-errors-spki-list", c.SPKIHash})
	}
	return flags, CheckFlags(flags)
}

// CheckFlags rejects a switch outside the allowlist or on the ban list, and a
// value-carrying switch with no value.
func CheckFlags(flags []Flag) error {
	banned := map[string]bool{}
	for _, b := range BannedChromiumFlags {
		banned[b] = true
	}
	seen := map[string]bool{}
	for _, f := range flags {
		switch {
		case banned[f.Name]:
			return fmt.Errorf("harness: Chromium switch --%s is banned", f.Name)
		case AllowedChromiumFlags[f.Name] == "":
			return fmt.Errorf("harness: Chromium switch --%s is not in the allowlist", f.Name)
		case seen[f.Name]:
			return fmt.Errorf("harness: Chromium switch --%s given twice", f.Name)
		}
		seen[f.Name] = true
		if s, ok := f.Value.(string); ok && s == "" {
			return fmt.Errorf("harness: Chromium switch --%s has an empty value", f.Name)
		}
	}
	return nil
}

// HostResolverRules builds a --host-resolver-rules value that maps each given
// name to its loopback host:port and answers NOTFOUND for every other name —
// except the loopback address itself, which the proxy lives at (the rules apply
// to IP literals too, so without the EXCLUDE even the proxy would not resolve).
// A rule applies in order, first match wins.
func HostResolverRules(mapping map[string]string) string {
	names := make([]string, 0, len(mapping))
	for n := range mapping {
		names = append(names, n)
	}
	sort.Strings(names)
	rules := make([]string, 0, len(names)+1)
	for _, n := range names {
		rules = append(rules, "MAP "+n+" "+mapping[n])
	}
	rules = append(rules, "EXCLUDE 127.0.0.1", "MAP * ~NOTFOUND")
	return strings.Join(rules, ", ")
}

// DefaultChromium is the browser binary itself, not Alpine's
// /usr/bin/chromium launcher script: the script sources /etc/chromium/*.conf
// and adds switches of its own (--ozone-platform-hint, --user-data-dir), which
// would put switches outside AllowedChromiumFlags on the command line.
const DefaultChromium = "/usr/lib/chromium/chromium"

// ChromiumPath finds the browser. There is no search and no fallback: a missing
// browser must fail the run (ADR-0031 V6), never skip it.
func ChromiumPath(getenv func(string) string, stat func(string) (os.FileInfo, error)) (string, error) {
	path := getenv("E2E_CHROMIUM")
	if path == "" {
		path = DefaultChromium
	}
	fi, err := stat(path)
	if err != nil {
		return "", fmt.Errorf("harness: Chromium not found at %s (Dockerfile.e2e installs it; override with E2E_CHROMIUM): %w", path, err)
	}
	if fi.IsDir() || fi.Mode()&0o111 == 0 {
		return "", errors.New("harness: " + path + " is not an executable file")
	}
	return path, nil
}
