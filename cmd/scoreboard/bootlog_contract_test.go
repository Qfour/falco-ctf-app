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
	// `remedy` is a helper for the operator that verify.sh does not read: adding or
	// dropping it must not turn this red, only the contract keys are required.
	for _, k := range []string{"time", "level", "msg", "solved_violations", "exfil_violations"} {
		if _, has := wrecs[0][k]; !has {
			t.Errorf("warn slug record lacks the key %q: %s", k, warn)
		}
	}
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
// level ERROR. The exit path cannot run in a unit test, so the call is pinned in
// the source: the Error call must be the line right after the
// `errors.Is(err, catalog.ErrFlagOverrides)` branch opens. A source-string test
// does not pin that the branch runs (only its text and order), which is why the
// call is tied to that `if` line instead of just counted.
func TestBootLogContract_FlagOverridesFailed_GoldenLiteral(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(src), "\n")
	const branch = `if errors.Is(err, catalog.ErrFlagOverrides) {`
	const call = `logger.Error("flag overrides failed",`
	found := 0
	for i, l := range lines {
		if strings.Contains(l, `"flag overrides failed"`) {
			found++
			if i == 0 || strings.TrimSpace(lines[i-1]) != branch || !strings.HasPrefix(strings.TrimSpace(l), call) {
				t.Errorf("main.go:%d: %q must be %s on the line right after %s (msg and level are read by platform scripts/verify.sh)", i+1, strings.TrimSpace(l), call, branch)
			}
		}
	}
	if found != 1 {
		t.Fatalf("main.go has %d lines with \"flag overrides failed\", want exactly 1", found)
	}
}

// The records are serialized by slog.NewJSONHandler with nil options on stdout;
// verify.sh matches that text. Replacing the handler (TextHandler, a ReplaceAttr
// that renames level / msg) changes every record at once, so pin the one
// construction. Source-string test: it pins the text, not that logger is the one
// passed to the checks (the TestMain*Check* wiring tests pin the calls).
func TestBootLogContract_LoggerIsJSONHandlerWithNilOptions(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	const want = `slog.New(slog.NewJSONHandler(os.Stdout, nil))`
	if c := strings.Count(string(src), want); c != 1 {
		t.Fatalf("%s appears %d time(s) in main.go, want exactly 1 (the boot log is read as slog JSONHandler text by platform scripts/verify.sh)", want, c)
	}
	if c := strings.Count(string(src), "slog.New("); c != 1 {
		t.Fatalf("slog.New( appears %d time(s) in main.go, want exactly 1", c)
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
