package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic fixtures only (public repo): defaults are FALCO{dev-...}
// placeholders, "event" values are obviously fake.
const (
	defStealth = "FALCO{dev-stealth-read}"
	defSilent  = "FALCO{dev-silent-search}"
	defExfil   = "FALCO{dev-final-exfil}"

	evStealth = "FALCO{test-event-stealth}"
	evSilent  = "FALCO{test-event-silent}"
	evExfil   = "FALCO{test-event-exfil}"
)

// newFullCatalog mirrors the shape of the real catalog: three evade
// challenges plus trigger challenges that carry no flag.
func newFullCatalog() Catalog {
	return Catalog{
		"00-tutorial":      {ID: "00-tutorial", Type: "trigger", ExpectedRules: []string{"r"}},
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}},
		"03-stealth-read":  {ID: "03-stealth-read", Type: "evade", ExpectedFlag: defStealth},
		"05-silent-search": {ID: "05-silent-search", Type: "evade", ExpectedFlag: defSilent},
		"10-final-exfil":   {ID: "10-final-exfil", Type: "evade", ExpectedFlag: defExfil},
	}
}

func writeFlags(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "flags.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func flagsBody(pairs ...string) string {
	var b strings.Builder
	b.WriteString("flags:\n")
	for i := 0; i+1 < len(pairs); i += 2 {
		b.WriteString("  " + pairs[i] + ": " + pairs[i+1] + "\n")
	}
	return b.String()
}

// scoped returns the catalog the scoreboard would score for the given
// scenario challenge list (nil = no scenario pinned, score everything) and
// the full catalog to validate against — the same pair main.go passes.
func scoped(t *testing.T, scenario []string) (c, known Catalog) {
	t.Helper()
	known = newFullCatalog()
	if scenario == nil {
		return known, known
	}
	c, err := known.Restrict(scenario)
	if err != nil {
		t.Fatal(err)
	}
	return c, known
}

func TestApplyFlagOverrides_EmptyPathIsNoop(t *testing.T) {
	c, known := scoped(t, nil)
	if err := c.ApplyFlagOverrides("", known); err != nil {
		t.Fatalf("empty path should be no-op, got %v", err)
	}
	for id, want := range map[string]string{"03-stealth-read": defStealth, "05-silent-search": defSilent, "10-final-exfil": defExfil} {
		if got := c[id].ExpectedFlag; got != want {
			t.Fatalf("%s: placeholder flag should be untouched, got %q", id, got)
		}
	}
}

func TestApplyFlagOverrides_MissingFileFailsClosed(t *testing.T) {
	c, known := scoped(t, nil)
	if err := c.ApplyFlagOverrides("/nonexistent/flags.yaml", known); err == nil {
		t.Fatal("expected error for missing file when path is set")
	}
}

func TestApplyFlagOverrides(t *testing.T) {
	fullScenario := []string{"01-initial-recon", "03-stealth-read", "05-silent-search", "10-final-exfil"}
	tutorialScenario := []string{"00-tutorial", "01-initial-recon", "03-stealth-read"}
	triggerOnlyScenario := []string{"00-tutorial", "01-initial-recon"}

	tests := []struct {
		name     string
		scenario []string // nil = no scenario pinned
		body     string
		wantErr  string            // substring; "" = must succeed
		want     map[string]string // expected ExpectedFlag per in-scope id on success
	}{
		{
			name: "no scenario, all three evade flags supplied: all overridden",
			body: flagsBody("03-stealth-read", evStealth, "05-silent-search", evSilent, "10-final-exfil", evExfil),
			want: map[string]string{"03-stealth-read": evStealth, "05-silent-search": evSilent, "10-final-exfil": evExfil},
		},
		{
			name:    "no scenario, one evade flag missing: rejected",
			body:    flagsBody("03-stealth-read", evStealth, "10-final-exfil", evExfil),
			wantErr: "05-silent-search",
		},
		{
			name:    "no scenario, two evade flags missing: both named",
			body:    flagsBody("03-stealth-read", evStealth),
			wantErr: "05-silent-search, 10-final-exfil",
		},
		{
			name:     "full scenario, all three supplied: all overridden",
			scenario: fullScenario,
			body:     flagsBody("03-stealth-read", evStealth, "05-silent-search", evSilent, "10-final-exfil", evExfil),
			want:     map[string]string{"03-stealth-read": evStealth, "05-silent-search": evSilent, "10-final-exfil": evExfil},
		},
		{
			name:     "full scenario, one evade flag missing: rejected",
			scenario: fullScenario,
			body:     flagsBody("03-stealth-read", evStealth, "05-silent-search", evSilent),
			wantErr:  "10-final-exfil",
		},
		{
			name:     "subset scenario, only its own evade flag supplied: accepted",
			scenario: tutorialScenario,
			body:     flagsBody("03-stealth-read", evStealth),
			want:     map[string]string{"03-stealth-read": evStealth},
		},
		{
			name:     "subset scenario, full event file reused: accepted, out-of-scope entries ignored",
			scenario: tutorialScenario,
			body:     flagsBody("03-stealth-read", evStealth, "05-silent-search", evSilent, "10-final-exfil", evExfil),
			want:     map[string]string{"03-stealth-read": evStealth},
		},
		{
			name:     "subset scenario, its evade flag missing while others are supplied: rejected",
			scenario: tutorialScenario,
			body:     flagsBody("05-silent-search", evSilent, "10-final-exfil", evExfil),
			wantErr:  "03-stealth-read",
		},
		{
			name:     "trigger-only scenario, full event file: accepted, nothing to cover",
			scenario: triggerOnlyScenario,
			body:     flagsBody("03-stealth-read", evStealth, "05-silent-search", evSilent, "10-final-exfil", evExfil),
			want:     map[string]string{},
		},
		{
			name:    "supplied value equals the repository default: rejected",
			body:    flagsBody("03-stealth-read", defStealth, "05-silent-search", evSilent, "10-final-exfil", evExfil),
			wantErr: "repository default",
		},
		{
			name:     "out-of-scope entry equals the repository default: still rejected",
			scenario: tutorialScenario,
			body:     flagsBody("03-stealth-read", evStealth, "10-final-exfil", defExfil),
			wantErr:  "repository default",
		},
		{
			name:    "unknown challengeId: rejected",
			body:    flagsBody("03-stealth-read", evStealth, "05-silent-search", evSilent, "10-final-exfil", evExfil, "99-nope", "FALCO{test-x}"),
			wantErr: "unknown challengeId",
		},
		{
			name:    "entry for a trigger challenge: rejected",
			body:    flagsBody("03-stealth-read", evStealth, "05-silent-search", evSilent, "10-final-exfil", evExfil, "01-initial-recon", "FALCO{test-x}"),
			wantErr: "only evade challenges have flags",
		},
		{
			name:    "malformed flag value: rejected",
			body:    flagsBody("03-stealth-read", "not-a-flag", "05-silent-search", evSilent, "10-final-exfil", evExfil),
			wantErr: "must match FALCO{...}",
		},
		{
			name:    "empty flags map: rejected",
			body:    "flags: {}\n",
			wantErr: "no flags found",
		},
		{
			name:    "no flags key at all: rejected",
			body:    "other: 1\n",
			wantErr: "no flags found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, known := scoped(t, tc.scenario)
			before := make(map[string]string, len(c))
			for id, ch := range c {
				before[id] = ch.ExpectedFlag
			}
			err := c.ApplyFlagOverrides(writeFlags(t, tc.body), known)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tc.wantErr)
				}
				// Error text names ids, never values.
				for _, v := range []string{evStealth, evSilent, evExfil, defStealth, defSilent, defExfil} {
					if strings.Contains(err.Error(), v) {
						t.Fatalf("error text leaks a flag value: %q", err)
					}
				}
				// A rejected file applies nothing (no partial override).
				for id, ch := range c {
					if ch.ExpectedFlag != before[id] {
						t.Fatalf("%s: flag changed although the file was rejected", id)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for id, want := range tc.want {
				if got := c[id].ExpectedFlag; got != want {
					t.Fatalf("%s: ExpectedFlag = %q, want %q", id, got, want)
				}
			}
			// After a successful apply no in-scope evade challenge may still
			// carry its repository default.
			for id, ch := range c {
				if ch.Type == "evade" && ch.ExpectedFlag == newFullCatalog()[id].ExpectedFlag {
					t.Fatalf("%s: still scored against the repository default after a successful apply", id)
				}
			}
		})
	}
}

// The real challenges/ + scenarios/ trees must keep accepting an event flags
// file that supplies exactly the catalog's evade challenges — this is the
// shape the platform's events/<date>/flags.sops.yaml has. Guards against a
// new evade challenge or scenario silently changing what an event file needs.
func TestApplyFlagOverrides_RealCatalogAndScenarios(t *testing.T) {
	const challengesDir = "../../challenges"
	full, err := Load(challengesDir)
	if err != nil {
		t.Fatal(err)
	}
	var pairs []string
	for _, id := range full.IDs() {
		if full[id].Type == "evade" {
			pairs = append(pairs, id, "FALCO{test-event-"+id+"}")
		}
	}
	if len(pairs) == 0 {
		t.Fatal("no evade challenges found in the real catalog; test would prove nothing")
	}
	path := writeFlags(t, flagsBody(pairs...))

	scenarioFiles, err := filepath.Glob("../../scenarios/*/scenario.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarioFiles) == 0 {
		t.Fatal("no scenarios found; test would prove nothing")
	}
	scopes := map[string][]string{"(no scenario)": nil}
	for _, f := range scenarioFiles {
		sc, err := LoadScenario(f)
		if err != nil {
			t.Fatal(err)
		}
		scopes[sc.ID] = sc.Challenges
	}
	for name, ids := range scopes {
		t.Run(name, func(t *testing.T) {
			known, err := Load(challengesDir)
			if err != nil {
				t.Fatal(err)
			}
			c := known
			if ids != nil {
				if c, err = known.Restrict(ids); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.ApplyFlagOverrides(path, known); err != nil {
				t.Fatalf("complete event flags file rejected: %v", err)
			}
		})
	}
}
