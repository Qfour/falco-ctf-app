package identityobs

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"reflect"
	"testing"
)

// app#479: the one Warn a second seat gate logs has a closed attribute set and
// takes no user, so a refused value cannot reach the log through it.
func TestLogGraderRefused_ClosedAttributes(t *testing.T) {
	var buf bytes.Buffer
	r := httptest.NewRequest("POST", "/api/challenges/04-detect/submit-detect", nil)
	r.Pattern = "POST /api/challenges/{cid}/submit-detect"
	r.RemoteAddr = "[2001:db8::1]:443"
	LogGraderRefused(slog.New(slog.NewJSONHandler(&buf, nil)), r, "SubmitDetect")
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("not one JSON line: %q", buf.String())
	}
	delete(line, "time")
	want := map[string]any{
		"level": "WARN", "msg": "grader refused a non-seat user", "entry": "SubmitDetect",
		"route": "POST /api/challenges/{cid}/submit-detect", "remote_addr": "2001:db8::1",
	}
	if !reflect.DeepEqual(line, want) {
		t.Fatalf("line = %v, want %v", line, want)
	}
	// The signature has no string for a user: (logger, request, entry).
	if got := reflect.TypeOf(LogGraderRefused).NumIn(); got != 3 {
		t.Fatalf("LogGraderRefused takes %d parameters, want 3 (logger, request, entry): a user must not be passable", got)
	}
}
