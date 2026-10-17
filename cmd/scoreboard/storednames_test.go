package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/store"
)

// These tests pin the WIRING of the boot check: Warn / Info switch, the count,
// the seat cap, that no name value is logged, and where main() calls it. The
// inputs below are NOT a statement of the display-name rule (that lives in
// internal/scoreboard/api/testdata/display-name-parity/cases.yaml and is checked
// by api.TestStoredDisplayNameViolations_*): they are just values the rule
// refuses or accepts, there to make the wiring observable.

// bootLog opens a fresh store, seeds display names straight into it (bypassing
// the API's write-time validation, as an older release did), runs the boot
// check and returns the raw log output and its decoded records.
func bootLog(t *testing.T, names map[string]string) (string, []map[string]any) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "scoreboard.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	for seat, name := range names {
		if err := st.SetDisplayName(seat, name, "2026-10-01T00:00:00Z"); err != nil {
			t.Fatalf("SetDisplayName(%q): %v", seat, err)
		}
	}
	var buf bytes.Buffer
	warnStoredDisplayNames(slog.New(slog.NewJSONHandler(&buf, nil)), st)
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

func TestWarnStoredDisplayNames_ViolationsWarnWithSeatsAndCount(t *testing.T) {
	// Synthetic values: a ZWSP (Cf), a C1 NEL, a RLO bidi override, a metachar,
	// a 33-rune name — all refused by validDisplayName — plus two that pass.
	out, recs := bootLog(t, map[string]string{
		"user3":  "zero\u200bwidth",
		"user1":  "nel\u0085name",
		"user7":  "rlo\u202eevil",
		"user9":  "<b>bold</b>",
		"user11": strings.Repeat("a", 33),
		"user2":  "Alice",
		"user4":  "テスト名",
		"user5":  "", // empty = unset, shown as the seat: not a violation
	})
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 log record, got %d: %s", len(recs), out)
	}
	r := recs[0]
	if r["level"] != "WARN" {
		t.Fatalf("level = %v, want WARN: %s", r["level"], out)
	}
	if r["violations"] != float64(5) {
		t.Fatalf("violations = %v, want 5: %s", r["violations"], out)
	}
	seats, _ := r["seats"].([]any)
	want := []any{"user1", "user11", "user3", "user7", "user9"}
	if len(seats) != len(want) {
		t.Fatalf("seats = %v, want %v", seats, want)
	}
	for i := range want {
		if seats[i] != want[i] {
			t.Fatalf("seats = %v, want %v", seats, want)
		}
	}
	if r["msg"] != storedNameCheckMsg {
		t.Errorf("msg = %v, want the shared %q", r["msg"], storedNameCheckMsg)
	}
	if r["seats_truncated"] != false {
		t.Errorf("seats_truncated = %v, want false for 5 seats: %s", r["seats_truncated"], out)
	}
	remedy, _ := r["remedy"].(string)
	for _, must := range []string{"profile-reset", "admin display-name", "Origin", "restart"} {
		if !strings.Contains(remedy, must) {
			t.Errorf("remedy lacks %q: %q", must, remedy)
		}
	}
	// The value of a refused name must never reach the log, in any encoding.
	for _, secret := range []string{"zero", "width", "nel", "evil", "rlo", "bold", "aaaaaaaa", "\u200b", "\u0085", "\u202e", `\u200b`, `\u0085`, `\u202e`} {
		if strings.Contains(out, secret) {
			t.Errorf("log leaks name content %q: %s", secret, out)
		}
	}
	// Names that pass are not reported.
	for _, ok := range []string{"user2", "user4", "user5", "Alice"} {
		if strings.Contains(out, ok) {
			t.Errorf("log mentions a passing seat/name %q: %s", ok, out)
		}
	}
}

func TestWarnStoredDisplayNames_AllValidReportsZeroAtInfo(t *testing.T) {
	out, recs := bootLog(t, map[string]string{
		"user1": "Alice",
		"user2": "👩\u200d💻 dev", // ZWJ between two emoji is allowed
		"user3": "",
	})
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 log record, got %d: %s", len(recs), out)
	}
	if recs[0]["msg"] != storedNameCheckMsg {
		t.Fatalf("Info msg = %v, want the same %q as the Warn", recs[0]["msg"], storedNameCheckMsg)
	}
	if _, has := recs[0]["remedy"]; has {
		t.Errorf("a clean check carries no remedy: %s", out)
	}
	if recs[0]["level"] != "INFO" || recs[0]["violations"] != float64(0) {
		t.Fatalf("want INFO with violations=0, got: %s", out)
	}
	if _, has := recs[0]["seats"]; has {
		t.Errorf("zero-violation record should carry no seats: %s", out)
	}
}

func TestWarnStoredDisplayNames_EmptyStoreReportsZero(t *testing.T) {
	_, recs := bootLog(t, nil)
	if len(recs) != 1 || recs[0]["level"] != "INFO" || recs[0]["violations"] != float64(0) {
		t.Fatalf("empty store: want one INFO violations=0, got %v", recs)
	}
}

func TestWarnStoredDisplayNames_SeatCapBoundary(t *testing.T) {
	for _, tc := range []struct {
		n         int
		truncated bool
	}{
		{maxLoggedSeats, false},
		{maxLoggedSeats + 1, true},
		{maxLoggedSeats + 10, true},
	} {
		t.Run(strconv.Itoa(tc.n), func(t *testing.T) {
			names := map[string]string{}
			var all []string
			for i := 0; i < tc.n; i++ {
				seat := "user" + strconv.Itoa(i)
				names[seat] = "bad\u200bname"
				all = append(all, seat)
			}
			sort.Strings(all) // lexicographic, as the check returns them
			_, recs := bootLog(t, names)
			r := recs[0]
			if r["violations"] != float64(tc.n) {
				t.Fatalf("violations = %v, want %d (the count is never capped)", r["violations"], tc.n)
			}
			if r["seats_truncated"] != tc.truncated {
				t.Fatalf("seats_truncated = %v, want %v", r["seats_truncated"], tc.truncated)
			}
			want := all
			if len(want) > maxLoggedSeats {
				want = want[:maxLoggedSeats]
			}
			var got []string
			for _, v := range r["seats"].([]any) {
				got = append(got, v.(string))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("seats = %v\nwant the first %d of the sorted list %v", got, len(want), want)
			}
		})
	}
}

// TestMainCallsTheStoredNameCheckAfterStoreOpen pins the wiring in main.go the way
// TestMainTakesCatalogOnlyFromScoredFromEnv pins the catalog: ONE call, after the
// store is opened (the check reads the store) and before the server listens.
func TestMainCallsTheStoredNameCheckAfterStoreOpen(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	const call = "warnStoredDisplayNames(logger, st)"
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
