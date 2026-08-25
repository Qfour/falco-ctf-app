// Package ingest handles the falcosidekick customWebhook intake path.
//
//	POST /falco/events
//
// Filters events to the `ctf-<username>/workspace` namespace+pod pair,
// records the rule fire (presentational feed only), then hands the rule off
// to scoring.Grader.OnRuleFire — the SOLE entry point (ADR-0003 A4) that
// taints the participant's current evade mission if it forbids this rule
// (App-H2 + ADR-0003 attempt-scope persistent dirty flag) and marks any
// matching trigger-type challenge solved, in that order.
package ingest

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

type Handler struct {
	store   *store.Store
	grader  *scoring.Grader
	logger  *slog.Logger
	now     func() time.Time
	limiter *ratelimit.Limiter
}

func New(grader *scoring.Grader, s *store.Store, logger *slog.Logger, now func() time.Time) *Handler {
	// Per-source-IP token bucket. /falco/events is a high-volume internal
	// endpoint (falcosidekick batches events); rate is generous so a busy
	// CTF doesn't get throttled while still capping pathological bursts.
	return &Handler{
		store:  s,
		grader: grader,
		logger: logger,
		now:    now,
		// Intentionally fixed: sized for a single-cluster CTF (a few hundred
		// participants × low syscall-event rate). falcosidekick is the only
		// legitimate caller; this caps a misconfigured/looping sender, not a
		// tuning knob. Revisit only if load testing (scripts/load.sh) shows 429s.
		limiter: ratelimit.New(100 /* req/s */, 200 /* burst */).WithNow(now),
	}
}

// Routes returns the ingest package's declarative route table (ADR-0005
// V2) — the single artifact apispec.Register loops over AND what the parity
// tests (internal/scoreboard's *_test.go) compare against
// docs/openapi-scoreboard.yaml.
//
// This package deliberately has no Register(mux) method of its own (final
// review round, requirement 6.1: one used to exist here, calling
// apispec.Register(mux, h.Routes()) directly — the ONLY place in the
// repository other than scoreboard.Handler's NewHandler that called
// apispec.Register in production terms, but it was never actually reached
// in production: scoreboard.Handler's NewHandler always collects every
// sub-package's Routes() into one table and calls apispec.Register exactly
// once). Its sole caller was this package's own test file, which now calls
// apispec.Register(mux, h.Routes()) directly instead — the same call every
// other package's test/production wiring uses. Keeping a second, only-called-
// from-tests Register(mux) method around also worked against Requirement 3's
// "at most one apispec.Register call per mux-owning package" invariant
// (internal/apispec/register_singlecall_test.go): declaring a
// `*http.ServeMux` parameter made ingest look mux-owning to the mechanical
// detector even though it never itself holds one.
func (h *Handler) Routes() []apispec.Route {
	mw := h.limiter.Middleware(ratelimit.ClientIP)
	return []apispec.Route{
		{
			Method:           "POST",
			Pattern:          "/falco/events",
			Audience:         apispec.AudienceInternal,
			Authz:            apispec.AuthzNone,
			OriginGuarded:    false,
			CollectorForward: false,
			RateLimit:        "per-IP 100 req/s burst 200 (falcosidekick batches)",
			Handler:          mw(http.HandlerFunc(h.receive)),
		},
	}
}

func (h *Handler) receive(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	// oapi.FalcoEvent is the OpenAPI-generated contract (docs/openapi-scoreboard.yaml,
	// shared with falco-ctf-platform's falcosidekick config).
	var ev oapi.FalcoEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		metrics.FalcoEventsReceived.WithLabelValues("decode_error").Inc()
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	var ns, pod string
	if ev.OutputFields.K8sNsName != nil {
		ns = *ev.OutputFields.K8sNsName
	}
	if ev.OutputFields.K8sPodName != nil {
		pod = *ev.OutputFields.K8sPodName
	}

	if !strings.HasPrefix(ns, "ctf-") || pod != "workspace" {
		metrics.FalcoEventsReceived.WithLabelValues("ignored").Inc()
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "not a ctf workspace event"})
		return
	}

	// Defense-in-depth alongside the cluster-internal NetworkPolicy on
	// /falco/events: even if a forged request reaches this handler, the
	// container.image.repository field is part of the Falco event Falco itself
	// produces; an attacker would need to set this in the forged JSON, but
	// adding the explicit check makes the contract from AGENTS.md actionable.
	var imageRepo string
	if ev.OutputFields.ContainerImageRepository != nil {
		imageRepo = *ev.OutputFields.ContainerImageRepository
	}
	// Accept both `falco-ctf/challenge` (preferred, e.g. ghcr) and
	// `falco-ctf-challenge` (e.g. ECR cached path after retag) since the
	// substring choice depends on the registry's repo-naming conventions.
	if !strings.Contains(imageRepo, "falco-ctf/challenge") && !strings.Contains(imageRepo, "falco-ctf-challenge") {
		metrics.FalcoEventsReceived.WithLabelValues("ignored").Inc()
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "not a challenge container"})
		return
	}

	// Reject events explicitly tagged below Notice. Unknown / missing priority
	// passes through so older falcosidekick / Falco versions stay compatible.
	if ev.Priority != nil {
		switch strings.ToLower(*ev.Priority) {
		case "debug", "informational", "info":
			metrics.FalcoEventsReceived.WithLabelValues("ignored").Inc()
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "below minimum priority"})
			return
		}
	}

	user := strings.TrimPrefix(ns, "ctf-")

	// Rule-fire timestamp uses server-side now() rather than the
	// attacker-controlled ev.Time. ev.Time is retained as a log field for
	// observability (e.g. measuring Falco→scoreboard delivery latency) but
	// must not drive evade-window decisions: a forged request setting `time`
	// to the distant past could bury a forbidden fire outside the window.
	recvNow := h.now()
	tsUnix := float64(recvNow.UnixNano()) / 1e9

	if _, err := h.store.RecordRuleFire(user, ev.Rule, tsUnix); err != nil {
		h.logger.Error("record rule fire", "err", err)
		metrics.FalcoEventsReceived.WithLabelValues("store_error").Inc()
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// OnRuleFire is the Grader's single public entry point (ADR-0003 A4): it
	// resolves the participant's current mission, taints it if this rule is
	// forbidden for it (App-H2 + attempt-scope persistent dirty flag), and
	// THEN evaluates any trigger solve — that exact order is what makes the
	// twin-mission pairs (02→03, 04→05) work; see scoring package doc.
	res := h.grader.OnRuleFire(user, ev.Rule)

	// app#124 5x review (R1 + R2 converged, R4 finding F4): bump the
	// per-newly-solved trigger metric BEFORE the TaintErr check below, not
	// after. OnRuleFire already ran evaluateTrigger unconditionally (taint
	// first, trigger second — see its own doc), so a trigger solve may have
	// been durably persisted to the store even when the taint write failed.
	// The old ordering returned 500 before this loop ran whenever TaintErr
	// was set, so a solve that WAS recorded in the store never got counted
	// in SolvesTotal — no scoring impact (the store already has it), but a
	// metrics undercount that would mislead anyone debugging via Prometheus
	// rather than the DB.
	for _, r := range res.Results {
		if r.Newly {
			metrics.SolvesTotal.WithLabelValues(r.Challenge, "trigger").Inc()
		}
	}

	// ADR-0003 A5 (fail-closed criticality): a failed taint PERSISTENCE write
	// is NOT a "log and carry on" situation like a trigger-solve error below —
	// MarkDirty already set the in-memory taint (store.MarkDirty is
	// fail-closed), but the on-disk record may be missing, and falcosidekick
	// does not retry a failed webhook. Surface it loudly: bump a dedicated
	// metric and fail the request 5xx rather than hide it behind a 200.
	//
	// Only ONE FalcoEventsReceived outcome label is incremented per request
	// (app#124 5x review, R4 finding F4): "accepted" is bumped at the very
	// end, on the success path only, so a taint-error request contributes
	// solely to "taint_error" — the old code bumped "accepted" unconditionally
	// right after RecordRuleFire and then ALSO bumped "taint_error" here on
	// this path, so the label total exceeded FalcoEventsReceived's actual
	// request count.
	//
	// The response body carries a generic message, not res.TaintErr.Error()
	// (app#124 5x review, R1 finding — the same err.Error()-in-response-body
	// pattern app#113 catalogued elsewhere; internal store/driver error text
	// must not reach an HTTP client). Full detail still goes to the log line
	// above.
	if res.TaintErr != nil {
		h.logger.Error("mark dirty", "err", res.TaintErr)
		metrics.FalcoEventsReceived.WithLabelValues("taint_error").Inc()
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not persist taint"})
		return
	}

	// ADR-0008: a failed positive-proof write is continue-on-error, same
	// posture as TriggerErr below (log and carry on) — see RuleFireOutcome's
	// doc for why this does not warrant TaintErr's 5xx escalation.
	if res.ExpectedFireErr != nil {
		h.logger.Error("record expected rule fire", "err", res.ExpectedFireErr)
	}

	// Trigger-type solve decision is the Grader's job; this handler is a thin
	// driver that just bumps the solve metric for each newly-recorded solve.
	// (The Grader stamps its own receipt time from the same injected clock.)
	// A trigger-solve store error is continue-on-error, same as before A4:
	// log and carry on — it delays that mission's auto-solve to the next
	// matching fire rather than creating a false-clean gap, so it does not
	// warrant the same 5xx escalation as a taint failure.
	if res.TriggerErr != nil {
		h.logger.Error("mark solved", "err", res.TriggerErr)
	}

	metrics.FalcoEventsReceived.WithLabelValues("accepted").Inc()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"accepted": true, "user": user, "rule": ev.Rule})
}
