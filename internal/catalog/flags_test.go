package catalog

import (
	"bufio"
	"errors"
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

// applyTo runs the same code path LoadScored uses after loading: restrict the
// full fixture catalog to scenario (nil = no scenario pinned) and apply the
// flags file. It returns the scored catalog and the untouched full catalog.
func applyTo(t *testing.T, scenario []string, flagsPath string) (scored, full Catalog, err error) {
	t.Helper()
	full = newFullCatalog()
	scored, err = full.scored(scenario, flagsPath)
	return scored, full, err
}

func TestScored_EmptyPathAppliesNothing(t *testing.T) {
	c, _, err := applyTo(t, nil, "")
	if err != nil {
		t.Fatalf("empty path should apply nothing, got %v", err)
	}
	for id, want := range map[string]string{"03-stealth-read": defStealth, "05-silent-search": defSilent, "10-final-exfil": defExfil} {
		if got := c[id].ExpectedFlag; got != want {
			t.Fatalf("%s: placeholder flag should be untouched, got %q", id, got)
		}
	}
}

func TestScored_MissingFileFailsClosed(t *testing.T) {
	_, _, err := applyTo(t, nil, "/nonexistent/flags.yaml")
	if !errors.Is(err, ErrFlagOverrides) {
		t.Fatalf("expected ErrFlagOverrides for a missing file when a path is set, got %v", err)
	}
}

func TestScored(t *testing.T) {
	fullScenario := []string{"01-initial-recon", "03-stealth-read", "05-silent-search", "10-final-exfil"}
	tutorialScenario := []string{"00-tutorial", "01-initial-recon", "03-stealth-read"}
	triggerOnlyScenario := []string{"00-tutorial", "01-initial-recon"}
	all3 := func(a, b, c string) string {
		return flagsBody("03-stealth-read", a, "05-silent-search", b, "10-final-exfil", c)
	}

	tests := []struct {
		name     string
		scenario []string // nil = no scenario pinned
		body     string
		wantErr  string            // substring; "" = must succeed
		want     map[string]string // expected ExpectedFlag per in-scope id on success
	}{
		{
			name: "no scenario, all three evade flags supplied: all overridden",
			body: all3(evStealth, evSilent, evExfil),
			want: map[string]string{"03-stealth-read": evStealth, "05-silent-search": evSilent, "10-final-exfil": evExfil},
		},
		{
			name:    "no scenario, one evade flag missing: rejected",
			body:    flagsBody("03-stealth-read", evStealth, "10-final-exfil", evExfil),
			wantErr: "in scope: 05-silent-search",
		},
		{
			name:    "no scenario, two evade flags missing: both named",
			body:    flagsBody("03-stealth-read", evStealth),
			wantErr: "05-silent-search, 10-final-exfil",
		},
		{
			name:     "full scenario, all three supplied: all overridden",
			scenario: fullScenario,
			body:     all3(evStealth, evSilent, evExfil),
			want:     map[string]string{"03-stealth-read": evStealth, "05-silent-search": evSilent, "10-final-exfil": evExfil},
		},
		{
			name:     "full scenario, one evade flag missing: rejected",
			scenario: fullScenario,
			body:     flagsBody("03-stealth-read", evStealth, "05-silent-search", evSilent),
			wantErr:  "in scope: 10-final-exfil",
		},
		{
			name:     "subset scenario, only its own evade flag supplied: accepted",
			scenario: tutorialScenario,
			body:     flagsBody("03-stealth-read", evStealth),
			want:     map[string]string{"03-stealth-read": evStealth},
		},
		{
			name:     "subset scenario, full event file reused: accepted, out-of-scope entries not applied",
			scenario: tutorialScenario,
			body:     all3(evStealth, evSilent, evExfil),
			want:     map[string]string{"03-stealth-read": evStealth},
		},
		{
			name:     "subset scenario, its evade flag missing while others are supplied: rejected",
			scenario: tutorialScenario,
			body:     flagsBody("05-silent-search", evSilent, "10-final-exfil", evExfil),
			wantErr:  "in scope: 03-stealth-read",
		},
		{
			name:     "trigger-only scenario, full event file: accepted, nothing to cover",
			scenario: triggerOnlyScenario,
			body:     all3(evStealth, evSilent, evExfil),
			want:     map[string]string{},
		},
		{
			name:    "value equals that challenge's repository default: rejected",
			body:    all3(defStealth, evSilent, evExfil),
			wantErr: "repository default",
		},
		{
			name:    "value equals ANOTHER challenge's repository default: rejected",
			body:    all3(defSilent, evSilent, evExfil),
			wantErr: "repository default",
		},
		{
			name:     "out-of-scope entry equals a repository default: still rejected",
			scenario: tutorialScenario,
			body:     flagsBody("03-stealth-read", evStealth, "10-final-exfil", defExfil),
			wantErr:  "repository default",
		},
		{
			name:    "two challenges share one value: rejected",
			body:    all3(evStealth, evStealth, evExfil),
			wantErr: "every challenge needs its own value",
		},
		{
			name:     "out-of-scope entry shares a value with an in-scope one: still rejected",
			scenario: tutorialScenario,
			body:     flagsBody("03-stealth-read", evStealth, "10-final-exfil", evStealth),
			wantErr:  "every challenge needs its own value",
		},
		{
			name:    "same challengeId twice: rejected (not left to the YAML decoder's defaults)",
			body:    all3(evStealth, evSilent, evExfil) + "  03-stealth-read: FALCO{test-event-other}\n",
			wantErr: "appears more than once",
		},
		{
			name:    "two top-level flags keys: rejected",
			body:    flagsBody("03-stealth-read", evStealth) + flagsBody("05-silent-search", evSilent, "10-final-exfil", evExfil),
			wantErr: "`flags:` appears more than once",
		},
		{
			name:    "second YAML document: rejected",
			body:    all3(evStealth, evSilent, evExfil) + "---\nflags:\n  03-stealth-read: FALCO{test-event-other}\n",
			wantErr: "single YAML document",
		},
		{
			name:    "unknown challengeId: rejected",
			body:    all3(evStealth, evSilent, evExfil) + "  99-nope: FALCO{test-x}\n",
			wantErr: `unknown challengeId "99-nope"`,
		},
		{
			name:    "entry for a trigger challenge: rejected",
			body:    all3(evStealth, evSilent, evExfil) + "  01-initial-recon: FALCO{test-x}\n",
			wantErr: "only evade challenges have flags",
		},
		{
			name:    "value without the FALCO{} wrapper: rejected",
			body:    all3("not-a-flag", evSilent, evExfil),
			wantErr: `flag for "03-stealth-read" must match`,
		},
		{
			name:    "key and value swapped: rejected without echoing the key",
			body:    "flags:\n  " + evStealth + ": 03-stealth-read\n",
			wantErr: "line 2: malformed entry",
		},
		{
			name:    "value on the line after the key: rejected",
			body:    "flags:\n  03-stealth-read:\n    " + evStealth + "\n",
			wantErr: "line 2",
		},
		{
			name:    "list instead of a map: rejected",
			body:    "flags:\n  - " + evStealth + "\n",
			wantErr: "no flags found",
		},
		{
			name:    "broken YAML: rejected without the decoder's message",
			body:    "flags:\n  03-stealth-read: " + evStealth + "\n :: [" + evSilent + "\n",
			wantErr: "not valid YAML",
		},
		{
			name:    "empty flags map: rejected",
			body:    "flags: {}\n",
			wantErr: "no flags found",
		},
		{
			name:    "no flags key at all: rejected",
			body:    "other: 1\n",
			wantErr: "line 1: unexpected top-level key",
		},
		{
			name:    "another top-level key next to flags: rejected without echoing it",
			body:    all3(evStealth, evSilent, evExfil) + "not-a-flag: 1\n",
			wantErr: "line 5: unexpected top-level key",
		},
		{
			name:    "inline comment after a value: rejected",
			body:    "flags:\n  03-stealth-read: " + evStealth + " # note\n  05-silent-search: " + evSilent + "\n  10-final-exfil: " + evExfil + "\n",
			wantErr: "line 2: flag for \"03-stealth-read\" must be a plain string written literally",
		},
		{
			name:    "escaped value whose decoded form appears in an inline comment: rejected",
			body:    "flags:\n  03-stealth-read: \"FALCO{test-event-\\x73tealth}\" # " + evStealth + "\n  05-silent-search: " + evSilent + "\n  10-final-exfil: " + evExfil + "\n",
			wantErr: "line 2: flag for \"03-stealth-read\" must be a plain string written literally",
		},
		{
			// Generated here rather than kept in testdata/flags-parity: a
			// tracked file with a NUL byte is "binary" to git grep, which
			// scripts/check-flags.sh cannot scan. The planting side has the
			// same case in scripts/check-flags-file-validation.sh.
			name:    "NUL byte inside a comment: rejected",
			body:    "flags:\n  # a\x00b\n  03-stealth-read: " + evStealth + "\n  05-silent-search: " + evSilent + "\n  10-final-exfil: " + evExfil + "\n",
			wantErr: "not valid YAML",
		},
		{
			name:    "empty file: rejected",
			body:    "",
			wantErr: "no flags found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, full, err := applyTo(t, tc.scenario, writeFlags(t, tc.body))

			// The source catalog always keeps its repository defaults.
			for id, ch := range newFullCatalog() {
				if full[id].ExpectedFlag != ch.ExpectedFlag {
					t.Fatalf("%s: the full catalog was modified", id)
				}
			}

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !errors.Is(err, ErrFlagOverrides) {
					t.Fatalf("error is not ErrFlagOverrides: %v", err)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tc.wantErr)
				}
				// Error text names ids and line numbers, never values.
				for _, v := range []string{"test-event", "dev-stealth", "dev-silent", "dev-final", "not-a-flag", "FALCO{test", "FALCO{dev"} {
					if strings.Contains(err.Error(), v) {
						t.Fatalf("error text leaks flag-file content (%q): %q", v, err)
					}
				}
				// A rejected file yields no catalog at all (no partial override).
				if c != nil {
					t.Fatal("a catalog was returned although the file was rejected")
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

// Values that the two readers of the flags file used to interpret
// differently, or that helm --set-string cannot carry verbatim, are outside
// the flag character set and rejected.
func TestScored_FlagCharacterSet(t *testing.T) {
	rejected := map[string]string{
		"'' escape in single quotes":    `'FALCO{test-it''s}'`,
		"\\t escape in double quotes":   `"FALCO{test-ev\t03}"`,
		"\\x41 escape in double quotes": `"FALCO{test-ev\x41}"`,
		"backslash in a plain value":    `FALCO{test-ev\03}`,
		"comma":                         `FALCO{test-ev,03}`,
		"comma followed by key=value":   `FALCO{test-e,ttyd.frameAncestors=evil}`,
		"space":                         `FALCO{test-a b}`,
		"dot":                           `FALCO{test.a}`,
		"empty braces":                  `FALCO{}`,
	}
	for name, raw := range rejected {
		t.Run(name, func(t *testing.T) {
			body := "flags:\n  03-stealth-read: " + raw + "\n  05-silent-search: " + evSilent + "\n  10-final-exfil: " + evExfil + "\n"
			c, _, err := applyTo(t, nil, writeFlags(t, body))
			if !errors.Is(err, ErrFlagOverrides) || c != nil {
				t.Fatalf("expected the file to be rejected, got err=%v", err)
			}
			if strings.Contains(err.Error(), "test-") {
				t.Fatalf("error text leaks the value: %q", err)
			}
		})
	}
	for _, ok := range []string{"FALCO{abc}", "FALCO{A-b_9}", `"FALCO{quoted-ok}"`, `'FALCO{quoted-ok}'`} {
		body := "flags:\n  03-stealth-read: " + ok + "\n  05-silent-search: " + evSilent + "\n  10-final-exfil: " + evExfil + "\n"
		c, _, err := applyTo(t, nil, writeFlags(t, body))
		if err != nil {
			t.Fatalf("%s: unexpected rejection: %v", ok, err)
		}
		if got, want := c["03-stealth-read"].ExpectedFlag, strings.Trim(ok, `"'`); got != want {
			t.Fatalf("%s: ExpectedFlag = %q, want %q", ok, got, want)
		}
	}
}

// LoadScored is what cmd/scoreboard calls. With a scenario pinned, the flags
// from the file must end up in the catalog that is actually scored.
func TestLoadScored_RealCatalogAndScenarios(t *testing.T) {
	const challengesDir = "../../challenges"
	full, err := Load(challengesDir)
	if err != nil {
		t.Fatal(err)
	}
	event := map[string]string{}
	var pairs []string
	for _, id := range full.IDs() {
		if full[id].Type == "evade" {
			event[id] = "FALCO{test-event-" + id + "}"
			pairs = append(pairs, id, event[id])
		}
	}
	if len(pairs) == 0 {
		t.Fatal("no evade challenges found in the real catalog; test would prove nothing")
	}
	complete := writeFlags(t, flagsBody(pairs...))
	incomplete := writeFlags(t, flagsBody(pairs[2:]...)) // drops the first evade id
	droppedID := pairs[0]

	scenarioFiles, err := filepath.Glob("../../scenarios/*/scenario.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarioFiles) == 0 {
		t.Fatal("no scenarios found; test would prove nothing")
	}
	for _, scenarioFile := range append([]string{""}, scenarioFiles...) {
		name := scenarioFile
		if name == "" {
			name = "(no scenario)"
		}
		t.Run(name, func(t *testing.T) {
			got, err := LoadScored(challengesDir, scenarioFile, complete)
			if err != nil {
				t.Fatalf("complete event flags file rejected: %v", err)
			}
			if len(got.Order) != len(got.Catalog) {
				t.Fatalf("Order has %d ids, catalog has %d", len(got.Order), len(got.Catalog))
			}
			if (scenarioFile == "") != (got.ScenarioID == "") {
				t.Fatalf("ScenarioID = %q for scenario file %q", got.ScenarioID, scenarioFile)
			}
			evade := 0
			for id, ch := range got.Catalog {
				if ch.Type != "evade" {
					continue
				}
				evade++
				if ch.ExpectedFlag != event[id] {
					t.Fatalf("%s: scored catalog does not carry the flag from the file", id)
				}
			}
			if scenarioFile == "" && evade != len(event) {
				t.Fatalf("scored %d evade challenges, want %d", evade, len(event))
			}

			// Without a flags file: same scope, repository defaults.
			plain, err := LoadScored(challengesDir, scenarioFile, "")
			if err != nil {
				t.Fatal(err)
			}
			for id, ch := range plain.Catalog {
				if ch.ExpectedFlag != full[id].ExpectedFlag {
					t.Fatalf("%s: flag changed although no flags file was given", id)
				}
			}

			// A file missing an evade id is rejected exactly when that id
			// is in scope.
			_, err = LoadScored(challengesDir, scenarioFile, incomplete)
			_, inScope := got.Catalog[droppedID]
			if inScope && !errors.Is(err, ErrFlagOverrides) {
				t.Fatalf("%s is in scope but a file without it was accepted (err=%v)", droppedID, err)
			}
			if !inScope && err != nil {
				t.Fatalf("%s is out of scope but a file without it was rejected: %v", droppedID, err)
			}
		})
	}
}

// TestFlagsFileParity runs the shared cases in testdata/flags-parity — the
// same files scripts/check-flags-file-validation.sh feeds to the planting-side
// validator — and holds this side to the `go` column of cases.tsv. Every
// accepted input must be read as exactly expected.tsv, so an input both sides
// accept is interpreted identically by both.
func TestFlagsFileParity(t *testing.T) {
	const dir = "testdata/flags-parity"
	want := map[string]string{}
	for _, line := range readLines(t, filepath.Join(dir, "expected.tsv")) {
		f := strings.Split(line, "\t")
		if len(f) != 2 {
			t.Fatalf("expected.tsv: bad line %q", line)
		}
		want[f[0]] = f[1]
	}
	full, err := Load("../../challenges")
	if err != nil {
		t.Fatal(err)
	}
	cases, shellOnlyAccepts := 0, 0
	for _, line := range readLines(t, filepath.Join(dir, "cases.tsv")) {
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			t.Fatalf("cases.tsv: bad line %q", line)
		}
		file, goWant, shellWant := f[0], f[1], f[2]
		cases++
		if goWant == "reject" && shellWant == "accept" {
			shellOnlyAccepts++
		}
		t.Run(file, func(t *testing.T) {
			c, err := full.scored(nil, filepath.Join(dir, file))
			switch goWant {
			case "accept":
				if err != nil {
					t.Fatalf("expected accept, got: %v", err)
				}
				for id, ch := range c {
					if ch.Type != "evade" {
						continue
					}
					if ch.ExpectedFlag != want[id] {
						t.Fatalf("%s: read as %q, expected.tsv says %q", id, ch.ExpectedFlag, want[id])
					}
				}
			case "reject":
				if !errors.Is(err, ErrFlagOverrides) {
					t.Fatalf("expected reject, got err=%v", err)
				}
				if strings.Contains(err.Error(), "FALCO{dev-") || strings.Contains(err.Error(), "parity-") || strings.Contains(err.Error(), "dev-decoy") {
					t.Fatalf("error text leaks flag-file content: %q", err)
				}
			default:
				t.Fatalf("cases.tsv: unknown verdict %q", goWant)
			}
		})
	}
	if cases < 73 {
		t.Fatalf("only %d parity cases read; the manifest was truncated", cases)
	}
	// The pre-check must never be the more permissive side: a file it lets
	// through and the scoreboard refuses would deploy workspaces against a
	// scoreboard that cannot start.
	if shellOnlyAccepts != 0 {
		t.Fatalf("%d case(s) are accepted by the planting side only", shellOnlyAccepts)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var out []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		if l := sc.Text(); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("%s: no data lines", path)
	}
	return out
}
