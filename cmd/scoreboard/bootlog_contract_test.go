package main

import (
	"os"
	"strings"
	"testing"
)

// The scoreboard's boot log is read by the platform's scripts/verify.sh [flags]
// block (cross-repo contract; the row is "scoreboard 起動ログ" in
// .claude/rules/falco-ctf-app-conventions.md). verify.sh matches these records
// by SUBSTRING on the raw slog JSONHandler line, e.g.
//
//	grep -F '"msg":"stored user slug check"'      and then
//	*'"level":"INFO"'* && *'"solved_violations":0'* && *'"exfil_violations":0'*
//
// so what is pinned here is the exact serialized text, written as string
// LITERALS. Do not replace them with storedUserCheckMsg / storedNameCheckMsg or
// any other constant: the other tests compare through the constants, so a rename
// of the msg or of an attribute stays green there, and the platform then reads
// "no record" (未検証) instead of failing. Changing any literal below is a
// cross-repo change: land it together with scripts/verify.sh,
// docs/operations.md §3.1 and docs/P13-RUNBOOK.md §2 on the platform side.

func TestBootLogContract_StoredUserSlugCheck_GoldenLiterals(t *testing.T) {
	clean, recs := bootUsersLog(t, nil, nil)
	if len(recs) != 1 {
		t.Fatalf("clean: want exactly 1 record, got %d: %s", len(recs), clean)
	}
	for _, want := range []string{
		`"level":"INFO"`,
		`"msg":"stored user slug check"`,
		`"solved_violations":0`,
		`"exfil_violations":0`,
	} {
		if !strings.Contains(clean, want) {
			t.Errorf("clean record lacks the literal %s: %s", want, clean)
		}
	}
	assertKeys(t, "clean slug record", recs[0], "time", "level", "msg", "solved_violations", "exfil_violations")

	warn, wrecs := bootUsersLog(t, []string{"Bad User"}, []string{"UPPER"})
	if len(wrecs) != 1 {
		t.Fatalf("warn: want exactly 1 record, got %d: %s", len(wrecs), warn)
	}
	for _, want := range []string{
		`"level":"WARN"`,
		`"msg":"stored user slug check"`,
		`"solved_violations":1`,
		`"exfil_violations":1`,
	} {
		if !strings.Contains(warn, want) {
			t.Errorf("warn record lacks the literal %s: %s", want, warn)
		}
	}
	assertKeys(t, "warn slug record", wrecs[0], "time", "level", "msg", "solved_violations", "exfil_violations", "remedy")
}

func TestBootLogContract_StoredDisplayNameCheck_GoldenLiterals(t *testing.T) {
	clean, recs := bootLog(t, map[string]string{"user1": "Alice"})
	if len(recs) != 1 {
		t.Fatalf("clean: want exactly 1 record, got %d: %s", len(recs), clean)
	}
	for _, want := range []string{
		`"level":"INFO"`,
		`"msg":"stored display name check"`,
		`"violations":0`,
	} {
		if !strings.Contains(clean, want) {
			t.Errorf("clean record lacks the literal %s: %s", want, clean)
		}
	}
	assertKeys(t, "clean name record", recs[0], "time", "level", "msg", "violations")

	warn, wrecs := bootLog(t, map[string]string{"user3": "zero\u200bwidth", "user7": "rlo\u202eevil"})
	if len(wrecs) != 1 {
		t.Fatalf("warn: want exactly 1 record, got %d: %s", len(wrecs), warn)
	}
	for _, want := range []string{
		`"level":"WARN"`,
		`"msg":"stored display name check"`,
		`"violations":2`,
	} {
		if !strings.Contains(warn, want) {
			t.Errorf("warn record lacks the literal %s: %s", want, warn)
		}
	}
	// The Warn record also carries seats / seats_truncated / remedy for the
	// operator; verify.sh does not read them, so they are not part of the contract.
	for _, k := range []string{"time", "level", "msg", "violations"} {
		if _, has := wrecs[0][k]; !has {
			t.Errorf("warn name record lacks the key %q: %s", k, warn)
		}
	}
}

// main() exits on an unusable flags file with this record; verify.sh greps the
// bare text `flag overrides failed` (no JSON key), and its selftest feeds it at
// level ERROR. The exit path cannot run in a unit test, so the literal and its
// level are pinned in the source the way the other main.go wiring tests do.
func TestBootLogContract_FlagOverridesFailed_GoldenLiteral(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	const call = `logger.Error("flag overrides failed",`
	if c := strings.Count(string(src), call); c != 1 {
		t.Fatalf("%s appears %d time(s) in main.go, want exactly 1 (msg and level are read by platform scripts/verify.sh)", call, c)
	}
}

// assertKeys fails unless rec has exactly the wanted key set, so an attribute
// that is renamed (or a stray one added to the INFO line) is caught by name.
func assertKeys(t *testing.T, what string, rec map[string]any, want ...string) {
	t.Helper()
	got := map[string]bool{}
	for k := range rec {
		got[k] = true
	}
	for _, k := range want {
		if !got[k] {
			t.Errorf("%s: missing key %q (have %v)", what, k, rec)
		}
		delete(got, k)
	}
	for k := range got {
		t.Errorf("%s: unexpected key %q", what, k)
	}
}
