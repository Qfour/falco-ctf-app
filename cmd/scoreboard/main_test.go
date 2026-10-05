package main

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
)

// TestHintPenaltySchedule covers the #40 env resolution: SCORE_HINT_PENALTIES
// (preferred, comma-separated schedule) wins over the legacy single-value
// SCORE_HINT_PENALTY, and any malformed/unset input fails soft to
// scoring.DefaultHintPenalties (the CEO-confirmed [10, 30, 50] schedule) — a
// fat-fingered env must never crash the process nor silently produce free
// hints.
func TestHintPenaltySchedule(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	setEnv := func(t *testing.T, key, val string) {
		t.Helper()
		old, had := os.LookupEnv(key)
		if val == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, val)
		}
		t.Cleanup(func() {
			if had {
				os.Setenv(key, old)
			} else {
				os.Unsetenv(key)
			}
		})
	}

	eq := func(t *testing.T, got, want []int) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	}

	t.Run("both unset falls back to default", func(t *testing.T) {
		setEnv(t, "SCORE_HINT_PENALTIES", "")
		setEnv(t, "SCORE_HINT_PENALTY", "")
		eq(t, hintPenaltySchedule(logger), scoring.DefaultHintPenalties)
	})

	t.Run("SCORE_HINT_PENALTIES parses the CSV schedule", func(t *testing.T) {
		setEnv(t, "SCORE_HINT_PENALTIES", "10,30,50")
		setEnv(t, "SCORE_HINT_PENALTY", "")
		eq(t, hintPenaltySchedule(logger), []int{10, 30, 50})
	})

	t.Run("SCORE_HINT_PENALTIES wins over legacy SCORE_HINT_PENALTY", func(t *testing.T) {
		setEnv(t, "SCORE_HINT_PENALTIES", "5,15,25")
		setEnv(t, "SCORE_HINT_PENALTY", "999")
		eq(t, hintPenaltySchedule(logger), []int{5, 15, 25})
	})

	t.Run("legacy SCORE_HINT_PENALTY applies as a single-entry schedule", func(t *testing.T) {
		setEnv(t, "SCORE_HINT_PENALTIES", "")
		setEnv(t, "SCORE_HINT_PENALTY", "20")
		eq(t, hintPenaltySchedule(logger), []int{20})
	})

	t.Run("malformed SCORE_HINT_PENALTIES falls back to default (fail-soft)", func(t *testing.T) {
		setEnv(t, "SCORE_HINT_PENALTIES", "10,oops,50")
		setEnv(t, "SCORE_HINT_PENALTY", "")
		eq(t, hintPenaltySchedule(logger), scoring.DefaultHintPenalties)
	})

	t.Run("malformed legacy SCORE_HINT_PENALTY falls back to default (fail-soft)", func(t *testing.T) {
		setEnv(t, "SCORE_HINT_PENALTIES", "")
		setEnv(t, "SCORE_HINT_PENALTY", "not-a-number")
		eq(t, hintPenaltySchedule(logger), scoring.DefaultHintPenalties)
	})

	t.Run("SCORE_HINT_PENALTIES with whitespace trims per entry", func(t *testing.T) {
		setEnv(t, "SCORE_HINT_PENALTIES", " 10 , 30 , 50 ")
		setEnv(t, "SCORE_HINT_PENALTY", "")
		eq(t, hintPenaltySchedule(logger), []int{10, 30, 50})
	})
}

// fakeEnv returns a getenv with the given values and the caller's fallback
// for everything else — the shape of serverutil.Env.
func fakeEnv(vals map[string]string) func(key, fallback string) string {
	return func(key, fallback string) string {
		if v, ok := vals[key]; ok {
			return v
		}
		return fallback
	}
}

func writeFlagsFile(t *testing.T, pairs ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("flags:\n")
	for i := 0; i+1 < len(pairs); i += 2 {
		b.WriteString("  " + pairs[i] + ": " + pairs[i+1] + "\n")
	}
	p := filepath.Join(t.TempDir(), "flags.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// scoredFromEnv is the scoreboard's catalog wiring. Given SCENARIO_FILE and
// FLAGS_FILE, the catalog it returns — the one main() scores with — must
// carry the file's flags, and an incomplete file must be an error.
func TestScoredFromEnv(t *testing.T) {
	const (
		challenges = "../../challenges"
		tutorial   = "../../scenarios/tutorial-intro/scenario.yaml" // evade in scope: 03 only
		full       = "../../scenarios/nimbusbreach-full/scenario.yaml"
		ev03       = "FALCO{test-wiring-03}"
		ev05       = "FALCO{test-wiring-05}"
		ev10       = "FALCO{test-wiring-10}"
	)
	all := writeFlagsFile(t, "03-stealth-read", ev03, "05-silent-search", ev05, "10-final-exfil", ev10)
	no03 := writeFlagsFile(t, "05-silent-search", ev05, "10-final-exfil", ev10)
	no10 := writeFlagsFile(t, "03-stealth-read", ev03, "05-silent-search", ev05)

	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
		want    map[string]string // id -> ExpectedFlag in the scored catalog
		absent  []string          // ids that must not be in the scored catalog
	}{
		{
			name: "scenario pinned + flags file: scored catalog carries the file's flag",
			env:  map[string]string{"CHALLENGES_DIR": challenges, "SCENARIO_FILE": tutorial, "FLAGS_FILE": all},
			want: map[string]string{"03-stealth-read": ev03}, absent: []string{"05-silent-search", "10-final-exfil"},
		},
		{
			name: "full scenario + flags file: all three flags applied",
			env:  map[string]string{"CHALLENGES_DIR": challenges, "SCENARIO_FILE": full, "FLAGS_FILE": all},
			want: map[string]string{"03-stealth-read": ev03, "05-silent-search": ev05, "10-final-exfil": ev10},
		},
		{
			name: "no scenario + flags file: all three flags applied",
			env:  map[string]string{"CHALLENGES_DIR": challenges, "FLAGS_FILE": all},
			want: map[string]string{"03-stealth-read": ev03, "05-silent-search": ev05, "10-final-exfil": ev10},
		},
		{
			name:    "scenario pinned, its evade id missing from the file: error",
			env:     map[string]string{"CHALLENGES_DIR": challenges, "SCENARIO_FILE": tutorial, "FLAGS_FILE": no03},
			wantErr: true,
		},
		{
			name:    "full scenario, one evade id missing from the file: error",
			env:     map[string]string{"CHALLENGES_DIR": challenges, "SCENARIO_FILE": full, "FLAGS_FILE": no10},
			wantErr: true,
		},
		{
			name:    "no scenario, one evade id missing from the file: error",
			env:     map[string]string{"CHALLENGES_DIR": challenges, "FLAGS_FILE": no10},
			wantErr: true,
		},
		{
			name: "no FLAGS_FILE (local dev): repository defaults",
			env:  map[string]string{"CHALLENGES_DIR": challenges, "SCENARIO_FILE": full},
			want: map[string]string{"03-stealth-read": "FALCO{dev-stealth-read}", "05-silent-search": "FALCO{dev-silent-search}", "10-final-exfil": "FALCO{dev-final-exfil}"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, scored, err := scoredFromEnv(fakeEnv(tc.env))
			if cfg.challengesDir != tc.env["CHALLENGES_DIR"] || cfg.scenarioFile != tc.env["SCENARIO_FILE"] || cfg.flagsFile != tc.env["FLAGS_FILE"] {
				t.Fatalf("env not read as given: %+v", cfg)
			}
			if tc.wantErr {
				if !errors.Is(err, catalog.ErrFlagOverrides) {
					t.Fatalf("expected catalog.ErrFlagOverrides, got %v", err)
				}
				if scored.Catalog != nil {
					t.Fatal("a catalog was returned although the flags file was rejected")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for id, want := range tc.want {
				if got := scored.Catalog[id].ExpectedFlag; got != want {
					t.Fatalf("%s: scored ExpectedFlag = %q, want %q", id, got, want)
				}
			}
			for _, id := range tc.absent {
				if _, ok := scored.Catalog[id]; ok {
					t.Fatalf("%s is outside the scenario but is in the scored catalog", id)
				}
			}
		})
	}
}

// main() must take its catalog from scoredFromEnv, once, and never build or
// replace one itself. TestScoredFromEnv proves what scoredFromEnv returns;
// this pins main() to using exactly that: across the package's non-test
// sources there is ONE catalog.LoadScored call (inside scoredFromEnv), ONE
// scoredFromEnv call (in main), one binding of `cat` (from that result), and
// no other way of obtaining or rewriting a catalog. A second LoadScored call
// whose result replaces `cat` — e.g. one without the flags file — fails here.
func TestMainTakesCatalogOnlyFromScoredFromEnv(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(src)
		n++
	}
	if n < 2 {
		t.Fatalf("read %d non-test source file(s); expected at least main.go and catalog.go", n)
	}
	code := all.String()
	exactlyOnce := []string{
		"catalog.LoadScored(",
		"catalog.LoadScored(cfg.challengesDir, cfg.scenarioFile, cfg.flagsFile)",
		"scoredFromEnv(serverutil.Env)",
		"catCfg, scored, err := scoredFromEnv(serverutil.Env)",
		"cat, scenarioID, order := scored.Catalog, scored.ScenarioID, scored.Order",
	}
	for _, want := range exactlyOnce {
		if c := strings.Count(code, want); c != 1 {
			t.Fatalf("%q appears %d time(s) in cmd/scoreboard, want exactly 1", want, c)
		}
	}
	// Whitespace-insensitive, so `cat  =` / `cat, err =` style rebinding
	// is caught as well.
	// (each source line keeps one leading tab so that `cat` only matches at
	// the start of a statement, not inside a longer identifier).
	var sq strings.Builder
	for _, line := range strings.Split(code, "\n") {
		sq.WriteString("\t" + strings.Join(strings.Fields(line), "") + "\n")
	}
	squashed := sq.String()
	banned := []string{
		"catalog.Load(", "catalog.LoadScenario(", ".Restrict(",
		"\tcat=", "\tcat,err=", "\tcat,err:=", "\tcat:=", "scored.Catalog=", "scored.Catalog[",
	}
	for _, b := range banned {
		if strings.Contains(squashed, b) {
			t.Fatalf("cmd/scoreboard must not contain %q: the scored catalog comes from scoredFromEnv only", b)
		}
	}
	for key, want := range map[string]int{`"FLAGS_FILE"`: 1, `"SCENARIO_FILE"`: 1, `"CHALLENGES_DIR"`: 1} {
		if c := strings.Count(code, key); c != want {
			t.Fatalf("%s is read %d time(s) in cmd/scoreboard, want %d (in scoredFromEnv)", key, c, want)
		}
	}
}
