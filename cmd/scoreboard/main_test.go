package main

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

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

// main.go must obtain its catalog from catalog.LoadScored and nothing else:
// that one call restricts to the scenario and applies FLAGS_FILE against the
// right catalog. Restricting or loading the catalog by hand here would
// reintroduce a second catalog value that the flag override could be applied
// to by mistake (leaving the scored one on repository defaults, silently).
// The behaviour of LoadScored itself — a pinned scenario's scored catalog
// carries the file's flags — is covered in internal/catalog.
func TestMainLoadsCatalogOnlyThroughLoadScored(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	if n := strings.Count(code, "catalog.LoadScored(challengesDir, scenarioFile, flagsFile)"); n != 1 {
		t.Fatalf("main.go calls catalog.LoadScored(challengesDir, scenarioFile, flagsFile) %d time(s), want exactly 1", n)
	}
	for _, banned := range []string{"catalog.Load(", "catalog.LoadScenario(", ".Restrict("} {
		if strings.Contains(code, banned) {
			t.Fatalf("main.go must not call %s directly; use catalog.LoadScored", banned)
		}
	}
}
