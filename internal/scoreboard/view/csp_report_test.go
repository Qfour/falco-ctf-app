package view

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

// cspReportHandler returns POST /csp-report's fully-wired handler (rate
// limiter included) from a FRESH Handler — mirrors what Register actually
// installs (view.go's Routes()), rather than calling h.cspReport directly,
// so these tests exercise the same handler chain production traffic hits.
// "Fresh" matters because ratelimit.Limiter carries per-key state; sharing
// one across test cases would make an earlier case's requests count against
// a later case's burst.
func cspReportHandler(t *testing.T, logger *slog.Logger) http.Handler {
	t.Helper()
	h := New(nil, nil, "", logger)
	for _, rt := range h.Routes() {
		if rt.Pattern == cspReportPath {
			return rt.Handler
		}
	}
	t.Fatal("Routes() did not register " + cspReportPath)
	return nil
}

func doCSPReport(t *testing.T, h http.Handler, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, cspReportPath, bytes.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestCSPReport_AcceptsLegacyFormat proves a report-uri-style
// (application/csp-report) violation report is accepted (204, empty body —
// RFC 9110 6.4.1) and logged with every field the legacy shape carries.
func TestCSPReport_AcceptsLegacyFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := cspReportHandler(t, logger)

	before := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("accepted"))

	body := []byte(`{"csp-report":{"document-uri":"https://app.ctf.local/portal","blocked-uri":"https://evil.example/x.js","violated-directive":"script-src-elem","effective-directive":"script-src-elem","disposition":"enforce"}}`)
	w := doCSPReport(t, h, "application/csp-report", body)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusNoContent, w.Body)
	}
	if w.Body.Len() != 0 {
		t.Errorf("204 response must have an empty body, got %d bytes", w.Body.Len())
	}

	if after := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("accepted")); after != before+1 {
		t.Errorf(`"accepted" metric = %v, want %v`, after, before+1)
	}

	logLine := buf.String()
	for _, want := range []string{
		"csp violation report",
		"format=csp-report",
		"document_uri=https://app.ctf.local/portal",
		"blocked_uri=https://evil.example/x.js",
		"violated_directive=script-src-elem",
		"disposition=enforce",
		// remote_addr AND client_ip both present (R1-F3, /review-5x):
		// httptest.NewRequest defaults RemoteAddr to "192.0.2.1:1234", and
		// with no X-Forwarded-For header ratelimit.ClientIP falls back to
		// the SAME host (minus the port) — see
		// TestCSPReport_LogsClientIPFromXFF below for the case where they
		// diverge.
		"remote_addr=192.0.2.1:1234",
		"client_ip=192.0.2.1",
	} {
		if !strings.Contains(logLine, want) {
			t.Errorf("log line missing %q; got: %s", want, logLine)
		}
	}
}

// TestCSPReport_LogsClientIPFromXFF is R1-F3's (/review-5x) dedicated
// regression test: remote_addr and client_ip must be able to DIVERGE in the
// log, proving client_ip is actually reading X-Forwarded-For (the same key
// ratelimit.ClientIP — and therefore h.cspReportLimiter — uses) rather than
// just echoing RemoteAddr under a second name. Without this, an abuse
// investigation correlating rate-limit hits against log lines would have no
// way to line them up (RemoteAddr alone is ingress-nginx's own pod IP,
// constant across every caller — see newCSPReportLimiter's doc).
func TestCSPReport_LogsClientIPFromXFF(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := cspReportHandler(t, logger)

	r := httptest.NewRequest(http.MethodPost, cspReportPath, bytes.NewReader([]byte(`{"csp-report":{"blocked-uri":"https://evil.example"}}`)))
	r.Header.Set("Content-Type", "application/csp-report")
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusNoContent, w.Body)
	}
	logLine := buf.String()
	// remote_addr keeps httptest's synthetic TCP peer (the "ingress pod IP"
	// stand-in) — it must NOT pick up the XFF value.
	if !strings.Contains(logLine, "remote_addr=192.0.2.1:1234") {
		t.Errorf("expected remote_addr to stay the raw TCP peer, unaffected by X-Forwarded-For; got: %s", logLine)
	}
	// client_ip must reflect XFF's LEFTMOST entry (ratelimit.ClientIP's
	// documented behaviour) — the SAME value the rate limiter keyed this
	// request's bucket on.
	if !strings.Contains(logLine, "client_ip=203.0.113.7") {
		t.Errorf("expected client_ip to reflect X-Forwarded-For's leftmost entry; got: %s", logLine)
	}
	if strings.Contains(logLine, "client_ip=192.0.2.1") {
		t.Errorf("client_ip must not fall back to RemoteAddr when X-Forwarded-For is present; got: %s", logLine)
	}
}

// TestCSPReport_AcceptsReportsAPIFormat proves a report-to-style
// (application/reports+json) BATCH is accepted, that a csp-violation entry
// is logged with its camelCase fields correctly mapped, and that a
// differently-typed entry in the SAME batch is silently skipped rather than
// logged as if it carried CSP fields it does not have (reportsAPIEntry's
// doc).
func TestCSPReport_AcceptsReportsAPIFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := cspReportHandler(t, logger)

	batch := []map[string]any{
		{
			"type": "csp-violation",
			"body": map[string]any{
				"documentURL":        "https://app.ctf.local/portal",
				"blockedURL":         "https://evil.example/y.js",
				"effectiveDirective": "connect-src",
				"disposition":        "enforce",
			},
		},
		{
			"type": "deprecation",
			"body": map[string]any{"id": "SomeDeprecatedAPI"},
		},
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	w := doCSPReport(t, h, "application/reports+json", raw)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusNoContent, w.Body)
	}

	logLine := buf.String()
	if !strings.Contains(logLine, "format=reports+json") {
		t.Errorf("log line missing format=reports+json; got: %s", logLine)
	}
	if !strings.Contains(logLine, "blocked_uri=https://evil.example/y.js") {
		t.Errorf("log line missing the csp-violation entry's blocked_uri; got: %s", logLine)
	}
	if strings.Contains(logLine, "SomeDeprecatedAPI") {
		t.Errorf("the non-csp-violation batch entry must not be logged as if it were a CSP report; got: %s", logLine)
	}
	// Exactly one "csp violation report" line — the deprecation entry must
	// not have produced a second, garbage one.
	if n := strings.Count(logLine, "csp violation report"); n != 1 {
		t.Errorf("expected exactly 1 logged violation (batch has 1 csp-violation + 1 unrelated entry), got %d; log: %s", n, logLine)
	}
}

// TestCSPReport_RejectsUnsupportedContentType proves a Content-Type outside
// the two accepted shapes is rejected BEFORE the body is even parsed — the
// route's threat-model doc says the Content-Type allowlist is one of the
// defenses against this route performing no per-identity check at the app
// layer (any authenticated CTF login can reach it — see
// charts/scoreboard/templates/ingress-journey.yaml's /csp-report entry —
// but none of them are trusted not to forge the body).
func TestCSPReport_RejectsUnsupportedContentType(t *testing.T) {
	h := cspReportHandler(t, slog.New(slog.DiscardHandler))

	before := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("bad_content_type"))

	w := doCSPReport(t, h, "text/plain", []byte(`{"csp-report":{}}`))
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusUnsupportedMediaType, w.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("415 body did not decode as JSON: %v (body=%s)", err, w.Body)
	}
	if _, ok := body["error"]; !ok {
		t.Errorf("415 body missing \"error\" key (contract: non-2xx is always {\"error\": string}): %s", w.Body)
	}
	if after := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("bad_content_type")); after != before+1 {
		t.Errorf(`"bad_content_type" metric = %v, want %v`, after, before+1)
	}

	// A missing Content-Type entirely must be rejected the same way, not
	// treated as a default/legacy shape.
	w2 := doCSPReport(t, h, "", []byte(`{}`))
	if w2.Code != http.StatusUnsupportedMediaType {
		t.Errorf("missing Content-Type: status = %d, want %d", w2.Code, http.StatusUnsupportedMediaType)
	}
}

// TestCSPReport_RejectsOversizedBody proves a body over maxCSPReportBytes is
// rejected with 413 rather than being read into memory and logged in full —
// a route with no per-identity check at the app layer must not let any
// caller inflate this service's memory/log volume via an arbitrarily large
// body.
func TestCSPReport_RejectsOversizedBody(t *testing.T) {
	h := cspReportHandler(t, slog.New(slog.DiscardHandler))

	before := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("too_large"))

	huge := strings.Repeat("A", maxCSPReportBytes+1)
	body := []byte(`{"csp-report":{"blocked-uri":"` + huge + `"}}`)
	w := doCSPReport(t, h, "application/csp-report", body)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusRequestEntityTooLarge, w.Body)
	}
	if after := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("too_large")); after != before+1 {
		t.Errorf(`"too_large" metric = %v, want %v`, after, before+1)
	}
}

// TestCSPReport_RejectsMalformedJSON proves a body whose Content-Type is
// accepted but whose bytes are not valid JSON for that shape is a 400, not
// a panic or a silently-empty log line.
func TestCSPReport_RejectsMalformedJSON(t *testing.T) {
	h := cspReportHandler(t, slog.New(slog.DiscardHandler))

	before := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("decode_error"))

	w := doCSPReport(t, h, "application/csp-report", []byte("not json"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusBadRequest, w.Body)
	}
	if after := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("decode_error")); after != before+1 {
		t.Errorf(`"decode_error" metric = %v, want %v`, after, before+1)
	}

	w2 := doCSPReport(t, h, "application/reports+json", []byte(`{"not":"an array"}`))
	if w2.Code != http.StatusBadRequest {
		t.Errorf("reports+json non-array body: status = %d, want %d", w2.Code, http.StatusBadRequest)
	}
}

// TestCSPReport_RateLimitEnforced proves the per-source-IP token bucket
// (newCSPReportLimiter) actually gates this route: past its burst, the NEXT
// request from the same key gets 429, JSON-encoded (ratelimit.Middleware's
// contract). Uses a deliberately tiny bucket (constructed directly, not
// cspReportHandler's production-sized one) so the test doesn't need to fire
// 51 requests to observe the boundary.
func TestCSPReport_RateLimitEnforced(t *testing.T) {
	h := New(nil, nil, "", slog.New(slog.DiscardHandler))
	h.cspReportLimiter = ratelimit.New(0 /* no refill within the test */, 2 /* burst */)
	var wrapped http.Handler
	for _, rt := range h.Routes() {
		if rt.Pattern == cspReportPath {
			wrapped = rt.Handler
		}
	}
	if wrapped == nil {
		t.Fatal("Routes() did not register " + cspReportPath)
	}

	body := []byte(`{"csp-report":{"blocked-uri":"https://evil.example"}}`)
	for i := 0; i < 2; i++ {
		w := doCSPReport(t, wrapped, "application/csp-report", body)
		if w.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want %d (within burst)", i+1, w.Code, http.StatusNoContent)
		}
	}
	w := doCSPReport(t, wrapped, "application/csp-report", body)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request (past burst=2): status = %d, want %d; body=%s", w.Code, http.StatusTooManyRequests, w.Body)
	}
	var errBody map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("429 body did not decode as JSON: %v (body=%s)", err, w.Body)
	}
	if _, ok := errBody["error"]; !ok {
		t.Errorf("429 body missing \"error\" key: %s", w.Body)
	}
}

// TestCSPReport_LogEscapesInjectedControlChars is the escaping test: a
// forged report field carrying CR/LF must not be able to forge additional
// log lines (classic log injection). The property being verified is
// NARROWER than "attribute vs. message string" — that distinction turns
// out not to matter here (verified empirically while writing this test:
// slog's Handler quotes/escapes control characters in EVERY field of a
// record, including the message itself, regardless of how that field's
// value was built). What actually protects this endpoint is simpler and
// more absolute: every log write goes through h.logger (an *slog.Logger),
// never a raw fmt.Fprintf/os.Stdout.WriteString straight to the underlying
// writer — see csp_report.go's logCSPViolation doc, corrected to say
// exactly this after that empirical check.
//
// See TestCSPReport_TruncatesOverlongFields's mutation-proof for a
// DIFFERENT property in this same file (maxCSPReportFieldLen truncation)
// that WAS confirmed to fail red under a real code mutation (removing
// truncateCSPReportField's body) — the report accompanying this PR records
// that run. This test's own line-count assertion still stands on its own
// merits (it directly demonstrates the escaped output is safe to store
// one-record-per-line), it just isn't independently mutation-proven the
// same way, because there is no legitimate one-line code change inside
// logCSPViolation that would defeat it without ALSO removing the
// h.logger.Warn call outright (at which point no log line — safe or
// unsafe — would be produced, and this test would correctly fail for an
// unrelated reason: zero output).
func TestCSPReport_LogEscapesInjectedControlChars(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := cspReportHandler(t, logger)

	const injected = "https://evil.example\r\nfake_log_field=forged-line\nlevel=ERROR msg=\"totally real error\""
	payload := struct {
		Report struct {
			BlockedURI string `json:"blocked-uri"`
		} `json:"csp-report"`
	}{}
	payload.Report.BlockedURI = injected
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	w := doCSPReport(t, h, "application/csp-report", body)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusNoContent, w.Body)
	}

	out := buf.String()
	// Exactly one newline-terminated log record was written — if the
	// injected CR/LF had reached the log stream unescaped, this handler's
	// SINGLE Warn call would have produced multiple lines instead.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 log line, got %d (injected CR/LF was not escaped): %q", len(lines), out)
	}
	// The forged content must still be PRESENT (as escaped text) — this is
	// not a test that the field got dropped, only that it can't forge
	// structure. A real newline would break this Contains into a substring
	// spanning what SHOULD be per-line boundaries; escaped, it survives on
	// the one line intact.
	if !strings.Contains(out, "forged-line") {
		t.Errorf("expected the injected content to still appear (escaped) in the log line, got: %q", out)
	}
	if strings.Contains(out, "msg=\"totally real error\"\n") {
		t.Errorf("injected content produced what looks like a second, forged log record: %q", out)
	}
}

// TestCSPReport_TruncatesOverlongFields proves a single field far past
// maxCSPReportFieldLen is truncated before logging (maxCSPReportFieldLen's
// doc: keeps one field from dominating a log line), without needing the
// whole request to hit maxCSPReportBytes to exercise it.
func TestCSPReport_TruncatesOverlongFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := cspReportHandler(t, logger)

	long := strings.Repeat("x", maxCSPReportFieldLen+200)
	payload := struct {
		Report struct {
			BlockedURI string `json:"blocked-uri"`
		} `json:"csp-report"`
	}{}
	payload.Report.BlockedURI = long
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	w := doCSPReport(t, h, "application/csp-report", body)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
	out := buf.String()
	if strings.Contains(out, long) {
		t.Errorf("the full %d-rune field was logged verbatim; expected truncation", len(long))
	}
	if !strings.Contains(out, "(truncated)") {
		t.Errorf("expected a truncation marker in the log line, got: %q", out)
	}
}

// TestCSPReport_NilLoggerDoesNotPanic proves a Handler built with a nil
// logger (view.New's documented "tests" case) still serves the route
// without panicking — logCSPViolation nil-checks before calling h.logger,
// mirroring every other handler in this package (e.g. Handler.index's
// `if h.logger != nil` guard).
func TestCSPReport_NilLoggerDoesNotPanic(t *testing.T) {
	h := &Handler{cspReportLimiter: ratelimit.New(100, 100)}
	r := httptest.NewRequest(http.MethodPost, cspReportPath, bytes.NewReader([]byte(`{"csp-report":{"blocked-uri":"x"}}`)))
	r.Header.Set("Content-Type", "application/csp-report")
	w := httptest.NewRecorder()
	h.cspReport(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

// TestCSPReport_RegisteredInRoutes is a lightweight parity sanity check
// (the REAL parity gate is apispec_parity_test.go's TestAPISpec_V1 in the
// parent package): the route this file exercises through cspReportHandler
// must actually be the one Routes() declares for production wiring — a
// helper bug here (wrong Pattern match, wrong http.Handler) would make
// every test above pass against something Register never installs.
func TestCSPReport_RegisteredInRoutes(t *testing.T) {
	h := New(nil, nil, "", slog.New(slog.DiscardHandler))
	found := false
	for _, rt := range h.Routes() {
		if rt.Method == http.MethodPost && rt.Pattern == cspReportPath {
			found = true
			if rt.Handler == nil {
				t.Error("POST /csp-report route has a nil Handler")
			}
		}
	}
	if !found {
		t.Fatal("POST /csp-report is not in Routes()")
	}
}

// TestCSPReport_AcceptsReportsAPIFormat_MultipleCSPViolationEntries is
// TestCSPReport_AcceptsReportsAPIFormat's counterpart for the OTHER
// direction of the type filter: a batch containing MULTIPLE genuine
// csp-violation entries (not one csp-violation + one unrelated type) must
// log AND count every one of them, not just the first — a loop bug that
// only processed batch[0] would pass every other test in this file (they
// all use single-entry-of-interest batches) while silently dropping
// evidence for a real multi-violation page load (R2-F6, /review-5x).
func TestCSPReport_AcceptsReportsAPIFormat_MultipleCSPViolationEntries(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := cspReportHandler(t, logger)

	before := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("accepted"))

	batch := []map[string]any{
		{
			"type": "csp-violation",
			"body": map[string]any{
				"documentURL":        "https://app.ctf.local/portal",
				"blockedURL":         "https://evil.example/first.js",
				"effectiveDirective": "script-src-elem",
				"disposition":        "enforce",
			},
		},
		{
			"type": "csp-violation",
			"body": map[string]any{
				"documentURL":        "https://app.ctf.local/portal",
				"blockedURL":         "https://evil.example/second.js",
				"effectiveDirective": "connect-src",
				"disposition":        "enforce",
			},
		},
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	w := doCSPReport(t, h, "application/reports+json", raw)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusNoContent, w.Body)
	}

	logLine := buf.String()
	if !strings.Contains(logLine, "blocked_uri=https://evil.example/first.js") {
		t.Errorf("log missing the FIRST batch entry's blocked_uri; got: %s", logLine)
	}
	if !strings.Contains(logLine, "blocked_uri=https://evil.example/second.js") {
		t.Errorf("log missing the SECOND batch entry's blocked_uri; got: %s", logLine)
	}
	if n := strings.Count(logLine, "csp violation report"); n != 2 {
		t.Errorf("expected exactly 2 logged violations (batch has 2 csp-violation entries), got %d; log: %s", n, logLine)
	}
	if after := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("accepted")); after != before+2 {
		t.Errorf(`"accepted" metric = %v, want %v (both entries counted)`, after, before+2)
	}
}

// TestCSPReport_ReportsAPIEmptyArray proves an empty application/reports+json
// batch (`[]`) — a legal Reporting API payload a browser could in principle
// send (e.g. a report queued then superseded before delivery) — decodes
// cleanly and is accepted (204), logging nothing rather than erroring or
// panicking on a zero-length range.
func TestCSPReport_ReportsAPIEmptyArray(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := cspReportHandler(t, logger)

	before := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("accepted"))

	w := doCSPReport(t, h, "application/reports+json", []byte(`[]`))
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusNoContent, w.Body)
	}
	if w.Body.Len() != 0 {
		t.Errorf("204 response must have an empty body, got %d bytes", w.Body.Len())
	}
	if logLine := buf.String(); logLine != "" {
		t.Errorf("expected no log line for an empty batch, got: %s", logLine)
	}
	if after := testutil.ToFloat64(metrics.CSPViolationReports.WithLabelValues("accepted")); after != before {
		t.Errorf(`"accepted" metric = %v, want unchanged at %v (empty batch logs nothing)`, after, before)
	}
}
