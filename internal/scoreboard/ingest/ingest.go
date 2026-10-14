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
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// SharedSecretHeader is the header falcosidekick's customHeaders config
// attaches to every /falco/events POST (ADR-WS-0006 Layer 2, second
// defense-in-depth layer behind the ADR-WS-0005 NetworkPolicy). The literal
// string is a cross-repo contract with falco-ctf-platform's falco values
// (customHeaders) — it must match EXACTLY; do not rename without a
// coordinated two-repo PR.
const SharedSecretHeader = "X-Falco-Shared-Secret"

// SecretMode selects how receive() treats SharedSecretHeader (ADR-WS-0006).
// The zero value behaves exactly like SecretModeOff (see receive()) so test
// fixtures that never opt in stay on today's behaviour.
type SecretMode string

const (
	// SecretModeOff performs no header check at all — today's behaviour,
	// and the wire default (cmd/scoreboard/main.go) so this feature ships
	// harmlessly ahead of/independent of the paired platform PR that starts
	// sending the header.
	SecretModeOff SecretMode = "off"
	// SecretModeWarn verifies the header, bumps metrics.FalcoEventsSecretMismatch
	// on a mismatch, and processes the request exactly as before (fail-open,
	// observability-only) — the ADR-WS-0006 rollout step before enforce.
	SecretModeWarn SecretMode = "warn"
	// SecretModeEnforce verifies the header and rejects a mismatch (missing
	// header included) with 401 before the request body is even decoded —
	// store.RecordRuleFire and everything downstream of it is never reached
	// (fail-closed).
	SecretModeEnforce SecretMode = "enforce"
)

// ParseSecretMode validates a WEBHOOK_SECRET_MODE env value. cmd/scoreboard's
// main treats a non-nil error as a boot-time fatal (ADR-WS-0006's "implementation
// handoff" note) rather than silently falling back to off — an operator typo
// must not look like enforce is active when it is not.
func ParseSecretMode(raw string) (SecretMode, error) {
	switch SecretMode(raw) {
	case SecretModeOff, SecretModeWarn, SecretModeEnforce:
		return SecretMode(raw), nil
	default:
		return "", fmt.Errorf("invalid WEBHOOK_SECRET_MODE %q: want one of %q, %q, %q", raw, SecretModeOff, SecretModeWarn, SecretModeEnforce)
	}
}

// Stable, non-leaking response-body text (Issue #113 — mirrors
// internal/scoreboard/api's errMsgInvalidBody family; package-local because
// unexported constants don't cross package boundaries). Never put err.Error()
// from a JSON decode or a store call into a response body — the decoder can
// name internal struct fields and the store can surface driver text, schema
// names, or file paths. Log the real err via h.logger next to the WriteJSON
// call; the body always gets one of these constants instead.
const (
	errMsgInvalidBody    = "invalid request body"
	errMsgRecordRuleFire = "could not record rule fire"
	errMsgForbidden      = "forbidden"
	errMsgNotJSON        = "content type must be application/json"
)

// Per-participant (namespace) rate limits, app#359. The key is the
// participant, NEVER the sender: every event arrives from the single
// falcosidekick IP, so a per-IP bucket is one bucket for the whole event and
// one participant's flood starved everyone else's forbidden-rule fires — which
// falcosidekick does not retry, so an evade read as clean (ADR-0003).
//
//   - observation: rules in no challenge's forbidden/expected rules. They feed
//     only the presentational recent_rule_fires list, so over the bucket they
//     are dropped with 429 (counted + audit-logged).
//   - scoring: rules some challenge forbids or expects. These are NEVER
//     dropped: over the bucket the normal taint predicate is still applied
//     (scoring.Grader.TaintOnOverflow: current evade mission forbids the rule
//     -> taint with the real rule, fail-closed) and the request is answered
//     200. The bucket is sized far above anything a human
//     plausibly fires, so a participant only reaches it by flooding — and then
//     only they are affected.
const (
	observationRate  = 20  // req/s per participant
	observationBurst = 100 //
	scoringRate      = 100 // req/s per participant
	scoringBurst     = 400 //
)

// RateLimitDescription is the x-ctf-rate-limit string for POST /falco/events;
// docs/openapi-scoreboard.yaml must carry the same text (StringExtParity).
const RateLimitDescription = "per-participant (ns) bucket - observation rules 20 req/s burst 100 then 429, scoring rules 100 req/s burst 400 then fail-closed taint if forbidden (never 429)"

// maxNSLabels bounds the ns label cardinality of the rate-limit metrics: a
// forged event (shared secret off) could otherwise mint unlimited series.
const maxNSLabels = 1024

// validUser mirrors internal/scoreboard/api's validUser (the auth-derived
// username slug auth-policy also enforces). The ns of an event is
// sender-supplied JSON; it becomes a limiter key, a store key and a metric
// label, so it is validated at attribution time and an event whose ns does not
// fit is "ignored" like any non-workspace event. Duplicated, not imported: api
// is not a dependency of ingest. Keep the two in step.
var validUser = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type Handler struct {
	store  *store.Store
	grader *scoring.Grader
	logger *slog.Logger
	now    func() time.Time
	// observeLimiter / scoringLimiter are keyed by participant (ns without the
	// "ctf-" prefix); see the const block above. auditLimiter throttles the
	// audit log line to ~1 per 10s per (class, participant) so a flood cannot
	// also flood the log.
	observeLimiter *ratelimit.Limiter
	scoringLimiter *ratelimit.Limiter
	auditLimiter   *ratelimit.Limiter
	// nsSeen is the set of ns values already used as a metric label (guarded
	// by nsMu); past maxNSLabels new ones are labelled "_other".
	nsMu   sync.Mutex
	nsSeen map[string]struct{}
	// sharedSecret / secretMode are ADR-WS-0006's Layer 2 shared-secret
	// verification config. See SecretMode's doc for the 3 states.
	sharedSecret string
	secretMode   SecretMode
}

func New(grader *scoring.Grader, s *store.Store, logger *slog.Logger, now func() time.Time, sharedSecret string, secretMode SecretMode) *Handler {
	// Intentionally fixed: sized for a single-cluster CTF (a few hundred
	// participants x low syscall-event rate). falcosidekick is the only
	// legitimate caller and there is deliberately NO per-sender-IP limiter any
	// more (app#359): it would be a single shared bucket, and any 429 from it
	// can drop a forbidden-rule fire. Cost of unattributed (ignored) events is
	// bounded by the 64KiB body cap and the sender being NetworkPolicy +
	// shared-secret gated (ADR-WS-0005/0006).
	return (&Handler{
		store:        s,
		grader:       grader,
		logger:       logger,
		now:          now,
		nsSeen:       make(map[string]struct{}),
		sharedSecret: sharedSecret,
		secretMode:   secretMode,
	}).WithLimits(observationRate, observationBurst, scoringRate, scoringBurst)
}

// WithLimits replaces the per-participant buckets (tests use tiny ones). Not
// for production tuning — see the const block.
func (h *Handler) WithLimits(observeRate, observeBurst, scoreRate, scoreBurst float64) *Handler {
	h.observeLimiter = ratelimit.New(observeRate, observeBurst).WithNow(h.now)
	h.scoringLimiter = ratelimit.New(scoreRate, scoreBurst).WithNow(h.now)
	h.auditLimiter = ratelimit.New(0.1, 1).WithNow(h.now)
	return h
}

// nsLabel returns ns as a metric label, or "_other" once maxNSLabels distinct
// values have been used (or ns is implausibly long).
func (h *Handler) nsLabel(ns string) string {
	h.nsMu.Lock()
	defer h.nsMu.Unlock()
	if _, ok := h.nsSeen[ns]; ok {
		return ns
	}
	if len(ns) > 63 || len(h.nsSeen) >= maxNSLabels {
		return "_other"
	}
	h.nsSeen[ns] = struct{}{}
	return ns
}

// audit logs a rate-limit event (sampled per class+participant, see
// auditLimiter). The metric is the exact count; this is the who/what trail.
// tainted is the mission id a scoring overflow tainted ("" = none).
func (h *Handler) audit(class, ns, rule, tainted string) {
	if h.auditLimiter.Allow(class + "/" + ns) {
		h.logger.Warn("falco events rate limited", "class", class, "ns", ns, "rule", rule, "tainted_mission", tainted)
	}
}

// Routes returns the ingest package's declarative route table (ADR-0005
// V2) — the single artifact apispec.NewMux loops over AND what the parity
// tests (internal/scoreboard's *_test.go) compare against
// docs/openapi-scoreboard.yaml.
//
// This package deliberately has no Register(mux)/NewMux method of its own
// (final review round, requirement 6.1: one used to exist here, calling
// apispec.Register(mux, h.Routes()) directly — the ONLY place in the
// repository other than scoreboard.Handler's NewHandler that called
// apispec.Register in production terms, but it was never actually reached
// in production: scoreboard.Handler's NewHandler always collects every
// sub-package's Routes() into one table and calls apispec.NewMux exactly
// once). Its sole caller was this package's own test file, which now calls
// apispec.NewMux(h.Routes()) directly instead — the same call every other
// package's test/production wiring uses. Keeping a second, only-called-
// from-tests mux-building method around also worked against Requirement 3's
// "at most one apispec.NewMux call per mux-owning package" invariant
// (internal/apispec/register_singlecall_test.go): declaring a
// `*http.ServeMux` field/parameter made ingest look mux-owning to the
// mechanical detector even though it never itself holds one.
func (h *Handler) Routes() []apispec.Route {
	return []apispec.Route{
		{
			Method:           "POST",
			Pattern:          "/falco/events",
			Audience:         apispec.AudienceInternal,
			Authz:            apispec.AuthzInternalClaimedIdentity,
			OriginGuarded:    false,
			CollectorForward: false,
			RateLimit:        RateLimitDescription,
			Handler:          http.HandlerFunc(h.receive),
		},
	}
}

func (h *Handler) receive(w http.ResponseWriter, r *http.Request) {
	// Internal-only route: the sole legitimate caller (falcosidekick, admitted
	// by NetworkPolicy) never sets X-Auth-Request-*. The admin ingress
	// catch-all, however, also routes /falco/events here for an admin BROWSER,
	// where oauth2-proxy always stamps the header — so any such header means the
	// browser path and is refused 403 BEFORE the secret check, the body decode
	// or anything that could record a fire or touch scoring. Without this a
	// cross-site (SameSite=None) POST from an admin session could forge events
	// (webhookSecretMode=warn lets a secret-less request through).
	if httpx.HasProxyIdentityHeader(r) {
		h.logger.Warn("falco webhook denied: browser/proxy path not accepted", "remote_addr", r.RemoteAddr)
		metrics.FalcoEventsReceived.WithLabelValues("forbidden").Inc()
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": errMsgForbidden})
		return
	}

	// ADR-WS-0006 Layer 2: shared-secret verification runs FIRST — before the
	// body is even read/decoded — so an enforce-mode mismatch never reaches
	// store.RecordRuleFire or scoring.Grader.OnRuleFire (fail-closed: no
	// scoring-integrity table is touched by a forged request). off (the
	// zero value AND the wire default) skips this block entirely, so a
	// fixture/test that never opts in reproduces today's behaviour exactly.
	if h.secretMode == SecretModeWarn || h.secretMode == SecretModeEnforce {
		// Both sides must be non-empty to count as a match: comparing two
		// empty strings with subtle.ConstantTimeCompare returns 1 (equal
		// length, equal — trivially empty — contents), which would let an
		// operator's empty-secret misconfiguration in enforce mode pass
		// every request that simply omits the header. h.sharedSecret == ""
		// is exactly the I7 "no real secret has been provisioned yet"
		// default, and that must fail closed, not fail open.
		got := r.Header.Get(SharedSecretHeader)
		matched := h.sharedSecret != "" && got != "" &&
			subtle.ConstantTimeCompare([]byte(got), []byte(h.sharedSecret)) == 1
		if !matched {
			// Deliberately a metric distinct from FalcoEventsReceived, not a
			// new outcome label on it (see that metric's "one outcome label
			// per request" exclusivity doc): an enforce-mode mismatch never
			// reaches ANY of FalcoEventsReceived's existing outcome branches
			// below (it returns here), and a warn-mode mismatch falls
			// through into one of those branches too — bumping this AND a
			// FalcoEventsReceived label for the same request would be
			// correct for warn but impossible to express as "the" single
			// outcome label for enforce.
			metrics.FalcoEventsSecretMismatch.WithLabelValues(string(h.secretMode)).Inc()
			if h.secretMode == SecretModeEnforce {
				h.logger.Warn("falco webhook shared secret mismatch, rejecting", "mode", string(h.secretMode))
				httpx.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid or missing shared secret"})
				return
			}
			h.logger.Warn("falco webhook shared secret mismatch, continuing (warn mode)", "mode", string(h.secretMode))
		}
	}

	// falcosidekick posts "application/json; charset=utf-8" (its client's
	// DefaultContentType; customHeaders here only adds the shared secret).
	// Anything else — notably what a cross-site no-cors POST can send (text/plain,
	// form-urlencoded, multipart) — is refused before the body is decoded.
	if !httpx.IsJSONContentType(r) {
		h.logger.Warn("falco webhook: unsupported content type", "content_type", r.Header.Get("Content-Type"))
		metrics.FalcoEventsReceived.WithLabelValues("unsupported_media_type").Inc()
		httpx.WriteJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": errMsgNotJSON})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	// oapi.FalcoEvent is the OpenAPI-generated contract (docs/openapi-scoreboard.yaml,
	// shared with falco-ctf-platform's falcosidekick config).
	var ev oapi.FalcoEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		h.logger.Warn("falco webhook: invalid body", "err", err)
		metrics.FalcoEventsReceived.WithLabelValues("decode_error").Inc()
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}

	var ns, pod string
	if ev.OutputFields.K8sNsName != nil {
		ns = *ev.OutputFields.K8sNsName
	}
	if ev.OutputFields.K8sPodName != nil {
		pod = *ev.OutputFields.K8sPodName
	}

	if !strings.HasPrefix(ns, "ctf-") || !validUser.MatchString(strings.TrimPrefix(ns, "ctf-")) || pod != "workspace" {
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

	// app#359: per-participant limit, applied only after attribution so the
	// bucket is the participant's, not the (single, shared) sender's. A
	// scoring-relevant event is never answered 429 — see the const block.
	if h.grader.AffectsScoring(ev.Rule) {
		if !h.scoringLimiter.Allow(user) {
			h.scoringOverflow(w, ns, user, ev.Rule)
			return
		}
	} else if !h.observeLimiter.Allow(user) {
		metrics.FalcoEventsRateLimited.WithLabelValues(h.nsLabel(ns)).Inc()
		metrics.FalcoEventsReceived.WithLabelValues("rate_limited").Inc()
		h.audit("observation_dropped", ns, ev.Rule, "")
		w.Header().Set("Retry-After", "1")
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
		return
	}

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
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgRecordRuleFire})
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
	// ADR-0008 (R1 5x review finding): logged BEFORE the TaintErr branch's
	// early return, not after — both writes land in the same SQLite file, so
	// a real disk/DB failure is likely to hit both in the same event. Logging
	// ExpectedFireErr only on the path that falls through past TaintErr would
	// silently hide "the positive-proof write also failed" whenever the two
	// happen together, undermining TaintErr's own "surface loudly" rationale.
	if res.ExpectedFireErr != nil {
		h.logger.Error("record expected rule fire", "err", res.ExpectedFireErr)
	}

	if res.TaintErr != nil {
		h.logger.Error("mark dirty", "err", res.TaintErr)
		metrics.FalcoEventsReceived.WithLabelValues("taint_error").Inc()
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not persist taint"})
		return
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

// scoringOverflow handles a scoring-relevant event over the participant's
// scoring bucket (app#359): fail-closed instead of a drop. Grader.TaintOnOverflow
// applies the normal taint predicate (current evade mission forbids this rule)
// with the real rule name; the event is otherwise NOT processed (no feed entry,
// no trigger solve / proof record) — a skipped trigger/proof fire only delays a
// solve the participant can repeat. Always counted in FalcoEventsScoringOverflow
// (an event was not fully processed); the outcome label says whether a mission
// was actually tainted. Answered like an accepted event; a failed taint write is
// the same 500 + taint_error as the normal path.
func (h *Handler) scoringOverflow(w http.ResponseWriter, ns, user, rule string) {
	metrics.FalcoEventsScoringOverflow.WithLabelValues(h.nsLabel(ns)).Inc()
	tainted, err := h.grader.TaintOnOverflow(user, rule)
	if err != nil {
		h.audit("scoring_overflow", ns, rule, tainted)
		h.logger.Error("mark dirty on overflow", "err", err)
		metrics.FalcoEventsReceived.WithLabelValues("taint_error").Inc()
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not persist taint"})
		return
	}
	outcome := "overflow_skipped"
	if tainted != "" {
		outcome = "overflow_tainted"
	}
	h.audit("scoring_overflow", ns, rule, tainted)
	metrics.FalcoEventsReceived.WithLabelValues(outcome).Inc()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"accepted": true, "user": user, "rule": rule})
}
