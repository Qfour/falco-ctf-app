package view

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

// cspReportPath is the single same-origin sink both CSP reporting
// mechanisms portalCSP wires up point at (csp.go's report-uri directive
// value AND the Reporting-Endpoints header's csp-endpoint URL). A constant,
// not an operator-supplied value, so — unlike PORTAL_TTYD_SUFFIX — it needs
// no control-character validation before being concatenated into a header.
const cspReportPath = "/csp-report"

// maxCSPReportBytes caps the request body POST /csp-report will read.
// A real CSP violation report (either format) is a few hundred bytes; 16KiB
// comfortably covers a batched application/reports+json payload (browsers
// can coalesce several violations from one page load into one POST) without
// giving an unauthenticated caller a large-body vector against this route's
// own memory/log volume — the report is decoded and logged, never streamed
// or persisted, so the bound only needs to be "generous for a legitimate
// report", not "generous for arbitrary uploads".
const maxCSPReportBytes = 16 * 1024

// maxCSPReportFieldLen truncates any single string field before it is
// logged. The whole request body is already bounded by maxCSPReportBytes,
// so this is not a second size defense — it exists so ONE field (e.g. a
// forged blocked-uri several KB long) cannot dominate a single log line and
// make the operator-facing fields (document-uri, directive) scroll off
// screen. Reports are attacker-forgeable content (see the package doc
// below), so every field that reaches the logger goes through this.
const maxCSPReportFieldLen = 500

const (
	contentTypeCSPReport   = "application/csp-report"   // legacy report-uri (CSP2)
	contentTypeReportsJSON = "application/reports+json" // Reporting API report-to (CSP3)
)

// legacyCSPReport is the `{"csp-report": {...}}` body shape a browser using
// the deprecated report-uri directive sends (Content-Type:
// application/csp-report). Field names are the CSP2 spec's hyphenated keys,
// unrelated to the camelCase Reporting API shape below — the two formats
// are NOT interchangeable, which is why they get separate structs rather
// than one with dual json tags (Go allows only one tag per field).
type legacyCSPReport struct {
	DocumentURI        string `json:"document-uri"`
	ViolatedDirective  string `json:"violated-directive"`
	EffectiveDirective string `json:"effective-directive"`
	Disposition        string `json:"disposition"`
	BlockedURI         string `json:"blocked-uri"`
	SourceFile         string `json:"source-file"`
	ScriptSample       string `json:"script-sample"`
}

// reportsAPIEntry is one element of the JSON array a browser using the
// report-to directive (routed via the Reporting-Endpoints header) POSTs
// (Content-Type: application/reports+json). A single POST can batch several
// entries, and — because "csp-endpoint" is a group NAME, not a type filter —
// nothing stops a browser from also routing a different report `type`
// (Deprecation, Intervention, ...) at this same URL if a future change ever
// declares this group elsewhere. Type is checked below and anything other
// than "csp-violation" is skipped rather than logged as if it had CSP
// fields it does not have.
type reportsAPIEntry struct {
	Type string `json:"type"`
	Body struct {
		DocumentURL        string `json:"documentURL"`
		EffectiveDirective string `json:"effectiveDirective"`
		Disposition        string `json:"disposition"`
		BlockedURL         string `json:"blockedURL"`
		SourceFile         string `json:"sourceFile"`
		Sample             string `json:"sample"`
	} `json:"body"`
}

// truncateCSPReportField bounds a value taken from an untrusted report body
// before it is handed to the logger (see maxCSPReportFieldLen's doc). It
// truncates by rune, not byte, so it never splits a multi-byte UTF-8
// sequence and hands slog a string with a stray invalid-encoding tail.
func truncateCSPReportField(s string) string {
	r := []rune(s)
	if len(r) <= maxCSPReportFieldLen {
		return s
	}
	return string(r[:maxCSPReportFieldLen]) + "…(truncated)"
}

// cspReport handles POST /csp-report — the sink csp.go's portalCSP
// (report-uri directive) and writeSecurityHeaders (Reporting-Endpoints
// header, report-to's csp-endpoint group) both point browsers at, so a CSP
// violation on GET / or GET /portal becomes an observable log line + metric
// instead of silently vanishing in the browser console (Issue #95 / P23-6
// follow-up).
//
// Threat model: reachable by ANY authenticated CTF login, not just the
// caller reporting a genuine violation of their OWN page load — mirrors
// /portal's own ingress-layer gate (any login, no host<->email binding;
// see charts/scoreboard/templates/ingress-journey.yaml's /csp-report entry,
// added there specifically because this route's initial landing OMITTED it
// and fell through to the admin-only catch-all, 403ing every non-admin
// participant's browser-emitted report — R5=R1, /review-5x). This is
// narrower than "the public internet" (a never-logged-in client cannot
// reach it through ingress at all) but still NOT scoped to "the calling
// user's own resources" the way selfOrAdmin routes are — x-ctf-authz: none
// means the Go handler itself performs no per-identity check, so the
// request body must be treated as attacker-forgeable content regardless of
// WHICH authenticated account sent it (a malicious/compromised participant
// account — or the participant's own browser under a real XSS attempt this
// very CSP is meant to catch — can POST anything here), exactly like a
// Falco webhook event (internal/scoreboard/ingest) is attacker-influenced
// by whatever runs inside a challenge pod. The defenses below are listed in
// ACTUAL EXECUTION ORDER (outermost middleware first), not by importance:
//  1. rate-limit per source IP (h.cspReportLimiter.Middleware, wired in
//     Routes() — runs BEFORE cspReport is even entered);
//  2. Content-Type validation (the first thing cspReport itself does,
//     before touching the body at all);
//  3. body-size bound (maxCSPReportBytes, via http.MaxBytesReader — applied
//     only once Content-Type has already passed);
//  4. and, regardless of the above, the content is NEVER persisted — it is
//     logged (with every field passed through slog as a structured
//     attribute, so control characters/newlines in a forged field are
//     quoted/escaped by slog's handler rather than able to forge additional
//     log lines) and counted, and that is the full extent of what this
//     endpoint does. No scoring-integrity table is anywhere near this code
//     path.
func (h *Handler) cspReport(w http.ResponseWriter, r *http.Request) {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (ct != contentTypeCSPReport && ct != contentTypeReportsJSON) {
		metrics.CSPViolationReports.WithLabelValues("bad_content_type").Inc()
		httpx.WriteJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "unsupported content type"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxCSPReportBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// http.MaxBytesReader is the only source of a read error here
		// (io.ReadAll over an httptest/http.Request body has no other
		// failure mode in practice) — treat any read failure as "too large"
		// rather than trying to distinguish a genuine truncated-connection
		// case, since either way there is no usable report to log.
		metrics.CSPViolationReports.WithLabelValues("too_large").Inc()
		httpx.WriteJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "report too large"})
		return
	}

	switch ct {
	case contentTypeCSPReport:
		var payload struct {
			Report legacyCSPReport `json:"csp-report"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			metrics.CSPViolationReports.WithLabelValues("decode_error").Inc()
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed report"})
			return
		}
		h.logCSPViolation(r, "csp-report",
			payload.Report.DocumentURI, payload.Report.BlockedURI,
			payload.Report.ViolatedDirective, payload.Report.EffectiveDirective,
			payload.Report.Disposition, payload.Report.SourceFile, payload.Report.ScriptSample)

	case contentTypeReportsJSON:
		var batch []reportsAPIEntry
		if err := json.Unmarshal(body, &batch); err != nil {
			metrics.CSPViolationReports.WithLabelValues("decode_error").Inc()
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed report"})
			return
		}
		for _, e := range batch {
			// Reporting API report types other than csp-violation are
			// skipped, not logged as CSP fields they don't carry — see the
			// reportsAPIEntry doc. An empty Type is treated as
			// csp-violation too: this endpoint is declared for nothing
			// else, so an empty/omitted type on a batch entry is more
			// likely a minimal/forged payload than a real, differently-typed
			// report, and dropping it silently would just lose the signal.
			if e.Type != "" && e.Type != "csp-violation" {
				continue
			}
			h.logCSPViolation(r, "reports+json",
				e.Body.DocumentURL, e.Body.BlockedURL,
				"" /* no violated-directive in this format */, e.Body.EffectiveDirective,
				e.Body.Disposition, e.Body.SourceFile, e.Body.Sample)
		}
	}

	// 204: there is no body to return (this is a fire-and-forget browser
	// beacon, not a domain action with a verdict) and, unlike httpx.WriteJSON,
	// writing NO body keeps a 204 response spec-legal (RFC 9110 6.4.1 — a
	// 204 response must not include content).
	w.WriteHeader(http.StatusNoContent)
}

// logCSPViolation writes one structured log line for one violation entry
// (either format decodes to this same call shape) and increments the
// accepted counter. Every string argument is untrusted, attacker-forgeable
// content — see cspReport's threat-model doc — so each one is truncated
// (truncateCSPReportField) before being handed to slog. The actual
// injection defense is narrower than "use an attribute instead of the
// message": slog's Handler quotes/escapes control characters (including
// CR/LF) in EVERY field of a record it writes — msg included, not just
// attributes — for both the JSON handler production uses and the text
// handler this package's tests use (verified empirically: interpolating an
// untrusted value into the message string via fmt.Sprintf, then still
// passing that through h.logger.Warn, is NOT exploitable here — the
// handler quotes the whole message value regardless of how it was built).
// What WOULD reopen the hole is bypassing slog's Handler entirely (a raw
// fmt.Fprintf/os.Stdout.WriteString instead of an h.logger call) — see
// csp_report_test.go's escaping test doc for the mutation actually proven
// against.
func (h *Handler) logCSPViolation(r *http.Request, format, documentURI, blockedURI, violatedDirective, effectiveDirective, disposition, sourceFile, sample string) {
	metrics.CSPViolationReports.WithLabelValues("accepted").Inc()
	if h.logger == nil {
		return
	}
	h.logger.Warn("csp violation report",
		"remote_addr", r.RemoteAddr,
		// client_ip is the SAME ratelimit.ClientIP(r) value the token
		// bucket above keys on (R1-F3, /review-5x) — r.RemoteAddr alone is
		// ingress-nginx's own pod IP (scoreboard sits behind the Service,
		// never sees the real peer on the TCP connection), so it is
		// constant across every caller and useless for abuse tracking.
		// ratelimit.ClientIP trusts X-Forwarded-For's leftmost entry
		// (ingress-nginx populates it); logging BOTH values — rather than
		// replacing remote_addr — keeps the raw TCP peer visible too, so a
		// future investigation can see the gap between "who actually
		// dialed us" and "who we CLAIM rate-limited this request as".
		"client_ip", ratelimit.ClientIP(r),
		"format", format,
		"document_uri", truncateCSPReportField(documentURI),
		"blocked_uri", truncateCSPReportField(blockedURI),
		"violated_directive", truncateCSPReportField(violatedDirective),
		"effective_directive", truncateCSPReportField(effectiveDirective),
		"disposition", truncateCSPReportField(disposition),
		"source_file", truncateCSPReportField(sourceFile),
		"sample", truncateCSPReportField(sample),
	)
}

// newCSPReportLimiter builds the per-source-IP token bucket POST
// /csp-report is wrapped in (Routes(), below). Unlike ingest's limiter
// (falcosidekick, one known caller) or api's submit limiter (one
// participant's own browser), this endpoint is reachable by ANY browser
// that loads the portal — every participant's own CSP violations
// legitimately arrive here, plus this is the one route on this service
// that performs no per-identity check at the app layer at all despite
// being a POST (x-ctf-authz: none is common, but every other `none` route
// is a GET; this is the only `none` POST). It is NOT reachable by a fully
// anonymous internet client, though — ingress-journey.yaml gates it behind
// the same any-authenticated-login check /portal itself requires, a never-
// logged-in caller never even reaches this handler — but that still means
// EVERY authenticated participant, not just the one whose page load
// triggered a given report, can hit it, so this limiter must assume
// forged/abusive content is possible from any of them. 5 req/s with a
// burst of 50 comfortably absorbs one participant's browser reporting
// several violations from a single bad page load (a page with N
// inline-script violates N times) while still bounding a single source
// hammering this endpoint.
//
// The KEY this bucket is keyed on (ratelimit.ClientIP — X-Forwarded-For's
// leftmost entry, falling back to RemoteAddr) is itself spoofable: XFF is a
// client-supplied header ingress-nginx forwards rather than rewrites, so a
// caller can claim any IP it likes and get its own fresh bucket every time
// (R1-F2, /review-5x). This is a pre-existing, cross-repo, Class-2 gap
// shared by EVERY ratelimit-keyed route on this service, not something
// introduced here — tracked separately as app#236 (ingress-nginx realip
// behavior under investigation by platform-engineer) rather than fixed
// per-route. Deliberately NOT blocking this endpoint's landing: unlike
// /falco/events or /api/challenges/{cid}/submit, a spoofed key here can
// only buy an attacker MORE of this endpoint's own log lines (log/metric
// flooding) — it reaches no scoring or authorization decision, so the
// residual risk is bounded to this package's own observability, not
// scoring integrity. Once app#236 lands a stronger key, this limiter
// inherits it for free (ratelimit.ClientIP is shared code, not
// reimplemented here).
func newCSPReportLimiter() *ratelimit.Limiter {
	return ratelimit.New(5 /* req/s */, 50 /* burst */)
}
