package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/store"
)

// bootUsersLog opens a fresh store, seeds solves and receipts straight into it
// (bypassing the API's write-time slug check, as an older release did), runs the
// boot check and returns the raw output and decoded records.
func bootUsersLog(t *testing.T, solvedUsers, exfilUsers []string) (string, []map[string]any) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, u := range solvedUsers {
		if _, err := st.MarkSolved(u, "10-final-exfil", "2026-10-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range exfilUsers {
		if err := st.RecordExfil(u, "10-final-exfil", "FALCO{dev-x}", "2026-10-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	warnStoredUsers(slog.New(slog.NewJSONHandler(&buf, nil)), st)
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		recs = append(recs, m)
	}
	return buf.String(), recs
}

func TestWarnStoredUsers_CountsOnlyAndNeverTheValue(t *testing.T) {
	out, recs := bootUsersLog(t,
		[]string{"user1", "Bad User", "user2"},
		[]string{"user1", "evil\u202euser", "UPPER", "x_y"})
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 log record, got %d: %s", len(recs), out)
	}
	r := recs[0]
	if r["level"] != "WARN" || r["msg"] != storedUserCheckMsg {
		t.Fatalf("want WARN %q, got: %s", storedUserCheckMsg, out)
	}
	if r["solved_violations"] != float64(1) || r["exfil_violations"] != float64(3) {
		t.Fatalf("counts = solved %v exfil %v, want 1 and 3: %s", r["solved_violations"], r["exfil_violations"], out)
	}
	remedy, _ := r["remedy"].(string)
	for _, must := range []string{"new PVC", "/api/admin/reset"} {
		if !strings.Contains(remedy, must) {
			t.Errorf("remedy lacks %q: %q", must, remedy)
		}
	}
	// Neither a value nor a list of them, and no valid seat either.
	for _, leak := range []string{"Bad", "evil", "UPPER", "x_y", "\u202e", `\u202e`, "user1", "user2"} {
		if strings.Contains(out, leak) {
			t.Errorf("log leaks %q: %s", leak, out)
		}
	}
	for _, k := range []string{"seats", "users"} {
		if _, has := r[k]; has {
			t.Errorf("record carries %q: %s", k, out)
		}
	}
}

func TestWarnStoredUsers_CleanAndEmptyReportZeroAtInfo(t *testing.T) {
	for name, c := range map[string][2][]string{
		"empty": {nil, nil},
		"clean": {{"user1"}, {"user2", "a-b"}},
	} {
		_, recs := bootUsersLog(t, c[0], c[1])
		if len(recs) != 1 || recs[0]["level"] != "INFO" ||
			recs[0]["solved_violations"] != float64(0) || recs[0]["exfil_violations"] != float64(0) {
			t.Fatalf("%s: want one INFO with zero counts, got %v", name, recs)
		}
		if _, has := recs[0]["remedy"]; has {
			t.Errorf("%s: a clean check carries no remedy", name)
		}
	}
}

// main() calls the check exactly once, after store.Open and before serving.
func TestWarnStoredUsers_IsWiredInMainAfterOpen(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	const call = "warnStoredUsers(logger, st)"
	if c := strings.Count(code, call); c != 1 {
		t.Fatalf("%q appears %d time(s) in main.go, want exactly 1", call, c)
	}
	open := strings.Index(code, "store.Open(dbPath)")
	at := strings.Index(code, call)
	serve := strings.Index(code, "serverutil.Serve(")
	if open < 0 || serve < 0 || !(open < at && at < serve) {
		t.Fatalf("want store.Open (%d) < %s (%d) < serverutil.Serve (%d) in main.go", open, call, at, serve)
	}
}
