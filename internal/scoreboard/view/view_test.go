package view

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandlerPortal_RenderFailureIsJSON proves GET /portal's error path
// (Handler.portal, when renderPortal fails) answers a JSON {"error": ...}
// body via httpx.WriteJSON, not http.Error's text/plain (Issue #159 /
// ADR-0005 Decision 5 point 4 — this was one of the two documented non-2xx
// deviations; ratelimit_test.go's TestMiddleware_Returns429JSON covers the
// other). A ttydSuffix containing CR/LF fails writeSecurityHeaders'
// validateTtydSuffix BEFORE any bytes are written to the ResponseWriter
// (mirrors csp_test.go's TestWriteSecurityHeaders_RejectsControlCharInSuffix),
// so the 500 path is exercised cleanly with no partial text/html body
// already flushed ahead of it.
func TestHandlerPortal_RenderFailureIsJSON(t *testing.T) {
	h := New(nil, nil, "ctf-event.dev\r\nX-Injected: 1", slog.New(slog.DiscardHandler))

	r := httptest.NewRequest("GET", "/portal", nil)
	w := httptest.NewRecorder()
	h.portal(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type: got %q, want %q", ct, "application/json")
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v (body=%s)", err, w.Body.String())
	}
	if _, ok := body["error"]; !ok {
		t.Fatalf("expected an \"error\" key in the body, got %v", body)
	}
}
