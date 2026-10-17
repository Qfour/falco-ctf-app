package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/store"
)

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
	if !strings.Contains(r["msg"].(string), "profile-reset") {
		t.Errorf("warning does not name the admin remedy: %v", r["msg"])
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

func TestWarnStoredDisplayNames_SeatListIsBoundedCountIsNot(t *testing.T) {
	names := map[string]string{}
	for i := 0; i < maxLoggedSeats+10; i++ {
		names["user"+strconv.Itoa(i)] = "bad\u200bname"
	}
	_, recs := bootLog(t, names)
	r := recs[0]
	if r["violations"] != float64(maxLoggedSeats+10) {
		t.Fatalf("violations = %v, want %d", r["violations"], maxLoggedSeats+10)
	}
	if got := len(r["seats"].([]any)); got != maxLoggedSeats {
		t.Fatalf("seats len = %d, want %d", got, maxLoggedSeats)
	}
	if r["seats_truncated"] != true {
		t.Fatalf("seats_truncated = %v, want true", r["seats_truncated"])
	}
}
